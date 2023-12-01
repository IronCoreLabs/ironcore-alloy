use super::{config::StandardSecrets, standard::derive_aes_encryption_key};
use crate::{
    errors::AlloyError,
    standard_attached::StandardAttachedDocumentOps,
    util::{get_rng, OurReseedingRng},
    AlloyMetadata,
};
use futures::lock::Mutex;
use ironcore_documents::{
    aes::{decrypt_aes_edek, generate_aes_edek_and_sign},
    decode_attached_edoc, encode_attached_edoc,
};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct StandaloneAttachedStandardClient {
    config: Arc<StandardSecrets>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

impl StandardAttachedDocumentOps for StandaloneAttachedStandardClient {
    async fn encrypt(
        &self,
        plaintext_field: crate::PlaintextBytes,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::standard_attached::EncryptedAttachedDocument, crate::errors::AlloyError>
    {
        Ok(encrypt_field_attached(
            &self.key.key.0,
            plaintext_field,
            &mut *get_rng(&self.rng),
            metadata,
        )?)
    }

    async fn decrypt(
        &self,
        encrypted_field: crate::standard_attached::EncryptedAttachedDocument,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::PlaintextBytes, crate::errors::AlloyError> {
        Ok(decrypt_field_attached(
            &self.key.key.0,
            encrypted_field,
            metadata,
        )?)
    }

    async fn get_searchable_prefix(&self, id: u32) -> Vec<u8> {
        todo!()
    }
}

/// Encrypt all the fields of the document, attaching the encryption header to the resulting bytes.
/// Each field will generate a DEK using a derived key and use it along with a random IV to
/// encrypt the field.
pub fn encrypt_field_attached<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
    incoming_key: &[u8],
    field: U,
    rng: &mut R,
    doc_metadata: &AlloyMetadata,
) -> Result<Vec<u8>, AlloyError> {
    let per_tenant_kek = derive_aes_encryption_key(incoming_key, &doc_metadata.tenant_id);
    let (aes_dek, v4_doc) = generate_aes_edek_and_sign(rng, per_tenant_kek, "")?;
    let attached_payload = ironcore_documents::aes::encrypt_attached_document(
        rng,
        aes_dek,
        ironcore_documents::aes::PlaintextDocument(field.as_ref().to_vec()),
    )?;
    Ok(encode_attached_edoc(v4_doc, attached_payload)?.to_vec())
}

pub fn decrypt_field_attached(
    key: &[u8],
    ciphertext: Vec<u8>,
    doc_metadata: &AlloyMetadata,
) -> Result<Vec<u8>, AlloyError> {
    let per_tenant_kek = derive_aes_encryption_key(key, &doc_metadata.tenant_id);
    let (header, document_bytes) = decode_attached_edoc(ciphertext.into())?;
    let aes_dek = decrypt_aes_edek(&per_tenant_kek, &header)?;
    Ok(ironcore_documents::aes::decrypt_attached_document(&aes_dek, document_bytes.0.into())?.0)
}
