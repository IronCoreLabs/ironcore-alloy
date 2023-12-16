use crate::{
    errors::AlloyError,
    standard::StandardDocumentOps,
    standard_attached::{
        decrypt_core, encrypt_core, EncryptedAttachedDocument, StandardAttachedDocumentOps,
    },
    AlloyMetadata, PlaintextBytes,
};

use super::standard::SaasShieldStandardClient;

#[derive(uniffi::Object)]
pub struct SaasShieldStandardAttachedClient {
    standard_client: SaasShieldStandardClient,
}

impl StandardAttachedDocumentOps for SaasShieldStandardAttachedClient {
    async fn encrypt(
        &self,
        plaintext_field: PlaintextBytes,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError> {
        encrypt_core(&self.standard_client, plaintext_field, metadata).await
    }

    async fn decrypt(
        &self,
        attached_field: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextBytes, AlloyError> {
        decrypt_core(&self.standard_client, attached_field, metadata).await
    }

    async fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
        self.standard_client.get_searchable_edek_prefix(id)
    }
}
