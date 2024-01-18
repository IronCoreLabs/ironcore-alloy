use crate::{
    errors::AlloyError,
    standard::{EdekWithKeyIdHeader, EncryptedDocument, StandardDocumentOps},
    util::v4_proto_from_bytes,
    AlloyMetadata, PlaintextBytes,
};
use bytes::Bytes;
use ironcore_documents::{
    v4,
    v5::{
        self,
        attached::AttachedDocument,
        key_id_header::{self, EdekType, KeyId, KeyIdHeader},
    },
};
use uniffi::custom_newtype;

#[derive(Debug)]
pub struct EncryptedAttachedDocument(pub Vec<u8>);
custom_newtype!(EncryptedAttachedDocument, Vec<u8>);

/// API for encrypting and decrypting documents using our standard encryption.
pub trait StandardAttachedDocumentOps {
    /// Encrypt a field with the provided metadata.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key.
    /// The result is a single blob of bytes with the edek put on the front of it.
    async fn encrypt(
        &self,
        plaintext_field: PlaintextBytes,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError>;
    /// Decrypt a field that was encrypted with the provided metadata.
    /// The document must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt(
        &self,
        attached_field: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextBytes, AlloyError>;
    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    /// Note that this will not work for matching values that don't use our key_id_header format, such as cloaked search.
    async fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8>;
}

pub(crate) async fn encrypt_core<T: StandardDocumentOps>(
    standard_client: &T,
    plaintext_field: Vec<u8>,
    metadata: &AlloyMetadata,
) -> Result<EncryptedAttachedDocument, AlloyError> {
    // In order to call the encrypt on standard, we need a map. This is just a hardcoded string we will
    // use to encrypt.
    let hardcoded_id = "".to_string();
    let EncryptedDocument {
        edek: edek_with_key_id_bytes,
        // Mutable so we can removed the hardcoded key below.
        mut document,
    } = standard_client
        .encrypt(
            [(hardcoded_id.clone(), plaintext_field)]
                .into_iter()
                .collect(),
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
            edoc: v5::EncryptedPayload::try_from(edoc)?.to_aes_value_with_attached_iv(),
        }
        .write_to_bytes()?
        .to_vec(),
    ))
}

pub(crate) async fn decrypt_core<T: StandardDocumentOps>(
    standard_client: &T,
    attached_field: EncryptedAttachedDocument,
    metadata: &AlloyMetadata,
) -> Result<PlaintextBytes, AlloyError> {
    let attached_field_bytes: Bytes = attached_field.0.into();
    let AttachedDocument {
        key_id_header,
        edek,
        edoc,
    } = v4::attached::decode_attached_edoc(attached_field_bytes.clone())
        .map(|(edek, edoc)| AttachedDocument {
            key_id_header: KeyIdHeader::new(
                EdekType::Standalone,
                key_id_header::PayloadType::StandardEdek,
                KeyId(0),
            ),
            edek,
            edoc,
        })
        .or_else(|_| attached_field_bytes.try_into())?;
    // In order to call the decrypt on standard, we need a map. This is just a hardcoded string we will
    // use to decrypt.
    let hardcoded_id = "".to_string();
    let mut decrypted_value = standard_client
        .decrypt(
            EncryptedDocument {
                edek: EdekWithKeyIdHeader::new(key_id_header, edek),
                document: [(
                    hardcoded_id.clone(),
                    v5::EncryptedPayload::from(edoc).write_to_bytes(),
                )]
                .into_iter()
                .collect(),
            },
            metadata,
        )
        .await?;

    let plaintext = decrypted_value
        .remove(&hardcoded_id)
        .expect("Decryption doesn't change the structure of the fields.");
    Ok(plaintext)
}
