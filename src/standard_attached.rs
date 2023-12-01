use crate::{errors::AlloyError, AlloyMetadata, PlaintextBytes};

use rand::{CryptoRng, RngCore};
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
    async fn get_searchable_prefix(&self, id: u32) -> Vec<u8>;
}

pub(crate) fn encrypt_field_attached_core<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
    rng: &mut R,
    field: U,
    aes_dek: EncryptionKey,
    pb_edek: ironcore_documents::cmk_edek::EncryptedDek,
    metadata: &DocumentMetadata,
) -> Result<Vec<u8>, DocumentError> {
    let v4_doc = generate_cmk_v4_doc_and_sign(pb_edek, aes_dek, metadata)?;
    let payload = ironcore_documents::aes::encrypt_attached_document(
        rng,
        aes_dek,
        ironcore_documents::aes::PlaintextDocument(field.as_ref().to_vec()),
    )?;
    let encrypted = encode_attached_edoc(v4_doc, payload)?;
    Ok(encrypted.to_vec())
}
