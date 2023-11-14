use crate::errors::CloakedAiError;
use crate::standard::{
    EncryptedDocument, PlaintextDocument, PlaintextDocumentWithEdek, StandardDocumentOps,
};
use crate::tenant_security_client::{TenantSecurityClient, UnwrapKeyResponse, WrapKeyResponse};
use crate::util::OurReseedingRng;
use crate::{document, get_document_header_and_edek, IronCoreMetadata};
use ironcore_documents::key_id_header::{
    get_prefix_bytes_for_search, EdekType, KeyId, PayloadType,
};
use protobuf::Message;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object, Clone)]
pub struct SaasShieldStandardClient {
    tenant_security_client: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}
impl SaasShieldStandardClient {
    pub(crate) fn new(tenant_security_client: Arc<TenantSecurityClient>) -> Self {
        SaasShieldStandardClient {
            tenant_security_client,
            rng: crate::util::create_reseeding_rng(),
        }
    }

    /// The edek type for this client
    fn get_edek_type() -> EdekType {
        EdekType::SaasShield
    }

    /// The payload type for this client
    fn get_payload_type() -> PayloadType {
        PayloadType::StandardEdek
    }
}

#[uniffi::export]
impl StandardDocumentOps for SaasShieldStandardClient {
    async fn encrypt(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &IronCoreMetadata,
    ) -> Result<EncryptedDocument, CloakedAiError> {
        let request_metadata = metadata.clone().try_into()?;
        let WrapKeyResponse {
            dek,
            edek: tsc_edek,
        } = self
            .tenant_security_client
            .wrap_key(&request_metadata)
            .await?;
        document::cmk::encrypt_document(
            self.rng.clone(),
            tsc_edek.0,
            dek.0,
            metadata,
            plaintext_document,
        )
    }
    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextDocument, CloakedAiError> {
        let request_metadata = metadata.clone().try_into()?;
        let (v4_document, edek) = get_document_header_and_edek(&encrypted_document)?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(
                &edek
                    .write_to_bytes()
                    .expect("Writing edek to bytes failed.")[..], // There shouldn't be any reason this could fail.
                &request_metadata,
            )
            .await?;
        document::cmk::decrypt_document(v4_document, dek.0, encrypted_document)
    }
    fn get_searchable_edek_prefix(&self, id: u32) -> Vec<u8> {
        get_prefix_bytes_for_search(ironcore_documents::key_id_header::KeyIdHeader::new(
            Self::get_edek_type(),
            Self::get_payload_type(),
            KeyId(id),
        ))
        .into()
    }
}
