use crate::{
    errors::AlloyError,
    standard::StandardDocumentOps,
    standard_attached::{
        decrypt_batch_core, decrypt_core, encrypt_batch_core, encrypt_core, rekey_core,
        EncryptedAttachedDocument, EncryptedAttachedDocuments, PlaintextAttachedDocument,
        PlaintextAttachedDocuments, RekeyAttachedDocumentsBatchResult,
        StandardAttachedDecryptBatchResult, StandardAttachedDocumentOps,
        StandardAttachedEncryptBatchResult,
    },
    tenant_security_client::TenantSecurityClient,
    AlloyMetadata, PlaintextBytes, TenantId,
};

use super::{standard::SaasShieldStandardClient, SaasShieldSecurityEventOps, SecurityEvent};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct SaasShieldStandardAttachedClient {
    standard_client: SaasShieldStandardClient,
}

impl SaasShieldStandardAttachedClient {
    pub(crate) fn new(tenant_security_client: Arc<TenantSecurityClient>) -> Self {
        Self {
            standard_client: SaasShieldStandardClient::new(tenant_security_client),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl StandardAttachedDocumentOps for SaasShieldStandardAttachedClient {
    /// Encrypt a document with the provided metadata.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key.
    /// The result is a single blob of bytes with the edek put on the front of it.
    async fn encrypt(
        &self,
        plaintext_document: PlaintextAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedAttachedDocument, AlloyError> {
        encrypt_core(
            &self.standard_client,
            PlaintextBytes(plaintext_document.0),
            metadata,
        )
        .await
    }

    /// Encrypt multiple documents with the provided metadata.
    /// A DEK (document encryption key) will be generated for each document and encrypted using a derived key.
    async fn encrypt_batch(
        &self,
        plaintext_documents: PlaintextAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedEncryptBatchResult, AlloyError> {
        encrypt_batch_core(&self.standard_client, plaintext_documents, metadata).await
    }

    /// Decrypt a document that was encrypted with the provided metadata.
    /// The document must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt(
        &self,
        attached_document: EncryptedAttachedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextAttachedDocument, AlloyError> {
        decrypt_core(&self.standard_client, attached_document, metadata)
            .await
            .map(|x| PlaintextAttachedDocument(x.0))
    }

    /// Decrypt multiple documents that were encrypted with the provided metadata.
    /// The documents must have been encrypted using attached encryption and not deterministic or standard encryption.
    async fn decrypt_batch(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
    ) -> Result<StandardAttachedDecryptBatchResult, AlloyError> {
        decrypt_batch_core(&self.standard_client, encrypted_documents, metadata).await
    }

    /// Decrypt the provided documents and re-encrypt them using the tenant's current key. If `new_tenant_id` is `None`,
    /// the documents will be encrypted to the original tenant.
    async fn rekey_documents(
        &self,
        encrypted_documents: EncryptedAttachedDocuments,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyAttachedDocumentsBatchResult, AlloyError> {
        rekey_core(
            &self.standard_client,
            encrypted_documents,
            metadata,
            new_tenant_id,
        )
        .await
    }

    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    /// Note that this will not work for matching values that don't use our key_id_header format, such as cloaked search.
    fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
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
