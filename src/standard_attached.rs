use crate::{
    create_batch_result_struct,
    errors::AlloyError,
    standard::{EdekWithKeyIdHeader, EncryptedDocument, PlaintextDocument, StandardDocumentOps},
    util::{perform_batch_action, v4_proto_from_bytes, BatchResult},
    AlloyMetadata, DocumentId, EncryptedBytes, FieldId, PlaintextBytes, TenantId,
};
use bytes::Bytes;
use futures::{future::join_all, FutureExt};
use ironcore_documents::{
    aes::IvAndCiphertext,
    v4,
    v5::{
        self,
        attached::AttachedDocument,
        key_id_header::{self, KeyId, KeyIdHeader},
    },
};
use std::{collections::HashMap, convert::identity};
use uniffi::custom_newtype;

// TODO: This newtype can't include PlaintextBytes because of a bug with generated Python
// not using forward references. If this is addressed, we can change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextAttachedDocument(pub Vec<u8>);
custom_newtype!(PlaintextAttachedDocument, Vec<u8>);
pub type PlaintextAttachedDocuments = HashMap<DocumentId, PlaintextAttachedDocument>;

// TODO: This newtype can't include EncryptedBytes because of a bug with generated Python
// not using forward references. If this is addressed, we can change it.
#[derive(Debug, Clone)]
pub struct EncryptedAttachedDocument(pub Vec<u8>);
custom_newtype!(EncryptedAttachedDocument, Vec<u8>);

pub type EncryptedAttachedDocuments = HashMap<DocumentId, EncryptedAttachedDocument>;

create_batch_result_struct!(
    StandardAttachedEncryptBatchResult,
    EncryptedAttachedDocument,
    DocumentId
);
create_batch_result_struct!(
    StandardAttachedDecryptBatchResult,
    PlaintextAttachedDocument,
    DocumentId
);
create_batch_result_struct!(
    RekeyAttachedDocumentsBatchResult,
    EncryptedAttachedDocument,
    DocumentId
);

/// API for encrypting and decrypting documents using our standard encryption.
pub trait StandardAttachedDocumentOps {
    /// Encrypt a document with the provided metadata.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key.
    /// The result is a single blob of bytes with the edek put on the front of it.
    async fn encrypt(
        &self,
        plaintext_document: PlaintextAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError>;
    /// Encrypt multiple documents with the provided metadata.
    /// A DEK (document encryption key) will be generated for each document and encrypted using a derived key.
    async fn encrypt_batch(
        &self,
        plaintext_documents: PlaintextAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedEncryptBatchResult, AlloyError>;
    /// Decrypt a document that was encrypted with the provided metadata.
    /// The document must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt(
        &self,
        attached_document: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextAttachedDocument, AlloyError>;
    /// Decrypt multiple documents that were encrypted with the provided metadata.
    /// The documents must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt_batch(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedDecryptBatchResult, AlloyError>;
    /// Decrypt the provided documents and re-encrypt them using the tenant's current key. If `new_tenant_id` is `None`,
    /// the documents will be encrypted to the original tenant.
    async fn rekey_documents(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyAttachedDocumentsBatchResult, AlloyError>;
    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    /// Note that this will not work for matching values that don't use our key_id_header format, such as cloaked search.
    fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8>;
}

pub(crate) async fn encrypt_core<T: StandardDocumentOps>(
    standard_client: &T,
    plaintext_document: PlaintextBytes,
    metadata: &AlloyMetadata,
) -> Result<EncryptedAttachedDocument, AlloyError> {
    // In order to call the encrypt on standard, we need a map. This is just a hardcoded string we will
    // use to encrypt.
    let hardcoded_id = FieldId("".to_string());
    let EncryptedDocument {
        edek: edek_with_key_id_bytes,
        // Mutable so we can removed the hardcoded key below.
        mut document,
    } = standard_client
        .encrypt(
            PlaintextDocument(
                [(hardcoded_id.clone(), plaintext_document)]
                    .into_iter()
                    .collect(),
            ),
            metadata,
        )
        .await?;
    let (key_id_header, edek_bytes) =
        key_id_header::decode_version_prefixed_value(edek_with_key_id_bytes.0.into())?;

    let edek = v4_proto_from_bytes(edek_bytes)?;

    let edoc = document
        .remove(&hardcoded_id)
        .ok_or(AlloyError::EncryptError {
            msg: "Encryption returned a document without a passed in field. This shouldn't happen."
                .to_string(),
        })?;

    Ok(EncryptedAttachedDocument(
        AttachedDocument {
            key_id_header,
            edek,
            edoc: v5::EncryptedPayload::try_from(edoc.0)?.to_aes_value_with_attached_iv(),
        }
        .write_to_bytes()?
        .to_vec(),
    ))
}

pub(crate) async fn encrypt_batch_core<T: StandardDocumentOps>(
    standard_client: &T,
    plaintext_documents: PlaintextAttachedDocuments,
    metadata: &AlloyMetadata,
) -> Result<StandardAttachedEncryptBatchResult, AlloyError> {
    let attempts = join_all(plaintext_documents.into_iter().map(
        |(document_id, plaintext_document)| {
            encrypt_core(
                standard_client,
                PlaintextBytes(plaintext_document.0),
                metadata,
            )
            .map(|encrypted_document| (document_id, encrypted_document))
        },
    ))
    .await;
    Ok(perform_batch_action(attempts, identity).into())
}

fn decode_edoc<T: StandardDocumentOps>(
    attached_document: EncryptedAttachedDocument,
) -> Result<AttachedDocument, AlloyError> {
    let attached_document_bytes: Bytes = attached_document.0.into();
    Ok(
        v4::attached::decode_attached_edoc(attached_document_bytes.clone())
            .map(|(edek, edoc)| AttachedDocument {
                key_id_header: KeyIdHeader::new(
                    T::get_edek_type(),
                    T::get_payload_type(),
                    KeyId(0),
                ),
                edek,
                edoc,
            })
            .or_else(|_| attached_document_bytes.try_into())?,
    )
}

pub(crate) async fn decrypt_core<T: StandardDocumentOps>(
    standard_client: &T,
    attached_document: EncryptedAttachedDocument,
    metadata: &AlloyMetadata,
) -> Result<PlaintextBytes, AlloyError> {
    let AttachedDocument {
        key_id_header,
        edek,
        edoc,
    } = decode_edoc::<T>(attached_document)?;
    // In order to call the decrypt on standard, we need a map. This is just a hardcoded string we will
    // use to decrypt.
    let hardcoded_id = FieldId("".to_string());
    let mut decrypted_value = standard_client
        .decrypt(
            EncryptedDocument {
                edek: EdekWithKeyIdHeader::new(key_id_header, edek),
                document: [(
                    hardcoded_id.clone(),
                    EncryptedBytes(v5::EncryptedPayload::from(edoc).write_to_bytes()),
                )]
                .into_iter()
                .collect(),
            },
            metadata,
        )
        .await?;

    let plaintext = decrypted_value
        .0
        .remove(&hardcoded_id)
        .expect("Decryption doesn't change the structure of the fields.");
    Ok(plaintext)
}

pub(crate) async fn decrypt_batch_core<T: StandardDocumentOps>(
    standard_client: &T,
    encrypted_documents: EncryptedAttachedDocuments,
    metadata: &AlloyMetadata,
) -> Result<StandardAttachedDecryptBatchResult, AlloyError> {
    let attempts = join_all(encrypted_documents.into_iter().map(
        |(document_id, encrypted_document)| {
            decrypt_core(standard_client, encrypted_document, metadata).map(|decrypted_document| {
                (
                    document_id,
                    decrypted_document.map(|x| PlaintextAttachedDocument(x.0)),
                )
            })
        },
    ))
    .await;
    Ok(perform_batch_action(attempts, identity).into())
}

pub(crate) async fn rekey_core<T: StandardDocumentOps>(
    standard_client: &T,
    encrypted_documents: EncryptedAttachedDocuments,
    metadata: &AlloyMetadata,
    new_tenant_id: Option<TenantId>,
) -> Result<RekeyAttachedDocumentsBatchResult, AlloyError> {
    let (edeks, mut edocs, decoding_errors) = encrypted_documents.into_iter().try_fold(
        (HashMap::new(), HashMap::new(), HashMap::new()),
        |(mut edeks, mut edocs, mut failures), (document_id, attached_document)| {
            let maybe_attached_document = decode_edoc::<T>(attached_document);
            match maybe_attached_document {
                Ok(attached_document) => {
                    edeks.insert(
                        document_id.clone(),
                        EdekWithKeyIdHeader::new(
                            attached_document.key_id_header,
                            attached_document.edek,
                        ),
                    );
                    edocs.insert(document_id, attached_document.edoc);
                }
                Err(e) => {
                    failures.insert(document_id, e);
                }
            };
            Ok::<_, AlloyError>((edeks, edocs, failures))
        },
    )?;
    let rekeyed_edeks = standard_client
        .rekey_edeks(edeks, metadata, new_tenant_id)
        .await?;
    let edeks_and_edocs = rekeyed_edeks
        .successes
        .into_iter()
        .map(|(document_id, edek)| {
            let maybe_doc = edocs.remove(&document_id);
            (document_id, (edek, maybe_doc))
        });
    let form_attached_document =
        |(rekeyed_edek, maybe_edoc): (EdekWithKeyIdHeader, Option<IvAndCiphertext>)| {
            let edoc = maybe_edoc.ok_or_else(|| AlloyError::InvalidInput {
                msg: "Rekey failed for document.".to_string(),
            })?;
            let (key_id_header, edek_bytes) =
                key_id_header::decode_version_prefixed_value(rekeyed_edek.0.into())?;
            let edek = v4_proto_from_bytes(edek_bytes)?;
            Ok(EncryptedAttachedDocument(
                AttachedDocument {
                    key_id_header,
                    edek,
                    edoc,
                }
                .write_to_bytes()?
                .to_vec(),
            ))
        };
    let batch_rekey_response = perform_batch_action(edeks_and_edocs, form_attached_document);
    let combined_failures = batch_rekey_response
        .failures
        .into_iter()
        .chain(rekeyed_edeks.failures)
        .chain(decoding_errors)
        .collect();
    Ok(BatchResult {
        successes: batch_rekey_response.successes,
        failures: combined_failures,
    }
    .into())
}
