use crate::{
    errors::AlloyError,
    standard::{EdekWithKeyIdHeader, EncryptedDocument, PlaintextDocument, StandardDocumentOps},
    util::{v4_proto_from_bytes, v4_proto_to_bytes},
    AlloyMetadata, PlaintextBytes,
};
use bytes::Bytes;
use ironcore_documents::{
    aes::IvAndCiphertext,
    v4,
    v5::{
        self,
        attached::AttachedDocument,
        key_id_header::{self, EdekType, KeyId, KeyIdHeader},
    },
};
use uniffi::custom_newtype;

pub struct EncryptedAttachedDocument(pub Vec<u8>);
custom_newtype!(EncryptedAttachedDocument, Vec<u8>);

/// API for encrypting and decrypting documents using our standard encryption.
pub trait StandardAttachedDocumentOps {
    async fn encrypt(
        &self,
        plaintext_field: PlaintextBytes,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError>;
    async fn decrypt(
        &self,
        attached_field: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextBytes, AlloyError>;
    async fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8>;
}

pub(crate) async fn encrypt_core<T: StandardDocumentOps>(
    standard_client: &T,
    plaintext_field: Vec<u8>,
    metadata: &AlloyMetadata,
) -> Result<EncryptedAttachedDocument, AlloyError> {
    let hardcoded_key = "".to_string();
    let EncryptedDocument {
        edek: edek_with_key_id_bytes,
        // Mutable so we can removed the hardcoded key below.
        mut document,
    } = standard_client
        .encrypt(
            [(hardcoded_key.clone(), plaintext_field)]
                .into_iter()
                .collect(),
            metadata,
        )
        .await?;
    let (key_id_header, edek_bytes) =
        key_id_header::decode_version_prefixed_value(edek_with_key_id_bytes.0.into())?;

    let edek = v4_proto_from_bytes(edek_bytes)?;

    let edoc = document
        .remove(&hardcoded_key)
        .ok_or(AlloyError::EncryptError(
            "TSP didn't return a key we sent in. This shouldn't happen.".to_string(),
        ))?;

    Ok(EncryptedAttachedDocument(
        v5::attached::encode_attached_edoc(&AttachedDocument {
            key_id_header,
            edek,
            edoc: IvAndCiphertext(edoc.into()),
        })?
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
        .or_else(|_| v5::attached::decode_attached_edoc(attached_field_bytes))?;

    let hardcoded_id = "".to_string();
    let mut decrypted_value = standard_client
        .decrypt(
            EncryptedDocument {
                edek: EdekWithKeyIdHeader(
                    key_id_header
                        .put_header_on_document(v4_proto_to_bytes(edek))
                        .to_vec(),
                ),
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
