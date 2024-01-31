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

#[uniffi::export(async_runtime = "tokio")]
impl StandardAttachedDocumentOps for SaasShieldStandardAttachedClient {
    /// Encrypt a field with the provided metadata.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key.
    /// The result is a single blob of bytes with the edek put on the front of it.
    async fn encrypt(
        &self,
        plaintext_field: PlaintextBytes,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError> {
        encrypt_core(&self.standard_client, plaintext_field, metadata).await
    }

    /// Decrypt a field that was encrypted with the provided metadata.
    /// The document must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt(
        &self,
        attached_field: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextBytes, AlloyError> {
        decrypt_core(&self.standard_client, attached_field, metadata).await
    }

    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    /// Note that this will not work for matching values that don't use our key_id_header format, such as cloaked search.
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
