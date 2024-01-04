use crate::{
    errors::AlloyError,
    standard::StandardDocumentOps,
    standard_attached::{
        decrypt_core, encrypt_core, EncryptedAttachedDocument, StandardAttachedDocumentOps,
    },
    AlloyMetadata, PlaintextBytes,
};

use super::{standard::SaasShieldStandardClient, SaasShieldSecurityEventOps, SecurityEvent};

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

#[uniffi::export(async_runtime = "tokio")]
impl SaasShieldSecurityEventOps for SaasShieldStandardAttachedClient {
    /// Log the security event `event` to the tenant's log sink.
    /// If the event time is unspecified the current time will be used.
    async fn log_security_event(
        &self,
        event: SecurityEvent,
        metadata: &AlloyMetadata,
        event_time_millis: Option<i64>,
    ) -> Result<(), AlloyError> {
        self.standard_client
            .log_security_event(event, metadata, event_time_millis)
            .await
    }
}
