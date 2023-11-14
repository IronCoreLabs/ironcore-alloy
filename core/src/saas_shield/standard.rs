use crate::errors::CloakedAiError;
use crate::standard::{
    decrypt_document_core, encrypt_document_core, verify_sig, EncryptedDocument, PlaintextDocument,
    StandardDocumentOps,
};
use crate::tenant_security_client::errors::TenantSecurityError;
use crate::tenant_security_client::{TenantSecurityClient, UnwrapKeyResponse, WrapKeyResponse};
use crate::util::{get_rng, OurReseedingRng};
use crate::IronCoreMetadata;
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::cmk_edek::{self, EncryptedDek};
use ironcore_documents::icl_header_v4::v4document_header::EdekWrapper;
use ironcore_documents::icl_header_v4::{self, V4DocumentHeader};
use ironcore_documents::key_id_header::{
    self, get_prefix_bytes_for_search, EdekType, KeyId, KeyIdHeader, PayloadType,
};
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
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

    fn encrypt_document<R: RngCore + CryptoRng>(
        rng: Arc<Mutex<R>>,
        tsc_edek: Vec<u8>,
        dek: Vec<u8>,
        metadata: &IronCoreMetadata,
        document: HashMap<String, Vec<u8>>,
    ) -> Result<EncryptedDocument, CloakedAiError> {
        let pb_edek: ironcore_documents::cmk_edek::EncryptedDek =
            protobuf::Message::parse_from_bytes(&tsc_edek)?;
        let kms_config_id = pb_edek.kmsConfigId as u32;
        let enc_key = tsc_dek_to_encryption_key(dek)?;
        let v4_doc = generate_cmk_v4_doc_and_sign(pb_edek, enc_key, metadata)?;

        encrypt_document_core(
            document,
            &mut *get_rng(&rng),
            enc_key,
            KeyIdHeader::new(
                Self::get_edek_type(),
                Self::get_payload_type(),
                KeyId(kms_config_id),
            ),
            v4_doc,
        )
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
        Self::encrypt_document(
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
        decrypt_document(v4_document, dek.0, encrypted_document)
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

pub(crate) fn decrypt_document(
    header: V4DocumentHeader,
    dek: Vec<u8>,
    encrypted_document: EncryptedDocument,
) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
    let enc_key = tsc_dek_to_encryption_key(dek)?;
    verify_sig(enc_key, &header)?;
    decrypt_document_core(encrypted_document.document, enc_key)
}

pub(crate) fn find_cmk_edek(edeks: &[EdekWrapper]) -> Result<&EncryptedDek, CloakedAiError> {
    let maybe_edek_wrapper = edeks.iter().find(|edek| edek.has_cmk_edek());
    let cmk_edek = maybe_edek_wrapper
        .map(|edek| edek.cmk_edek())
        .ok_or_else(|| CloakedAiError::DecryptError("No Saas Shield EDEK found.".to_string()))?;
    Ok(cmk_edek)
}

fn tsc_dek_to_encryption_key(dek: Vec<u8>) -> Result<EncryptionKey, TenantSecurityError> {
    let bytes: [u8; 32] = dek
        .try_into()
        .map_err(|_| TenantSecurityError::InvalidDek)?;
    Ok(EncryptionKey(bytes))
}

fn generate_cmk_v4_doc_and_sign(
    mut edek: EncryptedDek,
    dek: EncryptionKey,
    metadata: &IronCoreMetadata,
) -> Result<V4DocumentHeader, CloakedAiError> {
    edek.tenantId = metadata.tenant_id.0.clone().into();
    let edek_wrapper = icl_header_v4::v4document_header::EdekWrapper {
        edek: Some(icl_header_v4::v4document_header::edek_wrapper::Edek::CmkEdek(edek)),
        ..Default::default()
    };

    Ok(ironcore_documents::create_signed_header(edek_wrapper, dek))
}

fn get_document_header_and_edek(
    document: &EncryptedDocument,
) -> Result<(V4DocumentHeader, cmk_edek::EncryptedDek), CloakedAiError> {
    let (_, v4_doc_bytes) =
        key_id_header::decode_version_prefixed_value(document.edek.0.clone().into())?;
    let v4_document: V4DocumentHeader = Message::parse_from_bytes(&v4_doc_bytes[..])?;
    let edek = find_cmk_edek(&v4_document.signed_payload.edeks)?.clone();
    Ok((v4_document, edek))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::standard::EdekWithKeyIdHeader;

    #[test]
    fn get_document_header_and_edek_fails_for_bad_header() {
        let encrypted_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![0u8]),
            document: Default::default(),
        };
        assert_eq!(
            get_document_header_and_edek(&encrypted_document).unwrap_err(),
            CloakedAiError::IronCoreDocumentsError("KeyIdHeaderTooShort(1)".to_string())
        );
    }

    #[test]
    fn get_document_header_and_edek_succeeds_for_good_header() {
        // This is a SaaS Shield edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 0, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(bytes),
            document: Default::default(),
        };

        get_document_header_and_edek(&encrypted_doc).unwrap();
    }
}
