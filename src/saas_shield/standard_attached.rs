use crate::{
    standard::StandardDocumentOps,
    standard_attached::{decrypt_core, encrypt_core, StandardAttachedDocumentOps},
};

use super::standard::SaasShieldStandardClient;

#[derive(uniffi::Object)]
pub struct SaasShieldStandardAttachedClient {
    standard_client: SaasShieldStandardClient,
}

impl StandardAttachedDocumentOps for SaasShieldStandardAttachedClient {
    async fn encrypt(
        &self,
        plaintext_field: crate::PlaintextBytes,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::standard_attached::EncryptedAttachedDocument, crate::errors::AlloyError>
    {
        encrypt_core(&self.standard_client, plaintext_field, metadata).await
    }

    async fn decrypt(
        &self,
        attached_field: crate::standard_attached::EncryptedAttachedDocument,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::PlaintextBytes, crate::errors::AlloyError> {
        decrypt_core(&self.standard_client, attached_field, metadata).await
    }

    async fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
        self.standard_client.get_searchable_edek_prefix(id)
    }
}
