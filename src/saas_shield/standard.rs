use crate::errors::AlloyError;
use crate::standard::{
    decrypt_document_core, encrypt_document_core, encrypt_map, verify_sig, EdekWithKeyIdHeader,
    EncryptedDocument, PlaintextDocument, PlaintextDocumentWithEdek, RekeyEdeksBatchResult,
    StandardDocumentOps,
};
use crate::tenant_security_client::errors::TenantSecurityError;
use crate::tenant_security_client::{
    RequestMetadata, TenantSecurityClient, UnwrapKeyResponse, WrapKeyResponse,
};
use crate::util::{collection_to_batch_result, OurReseedingRng};
use crate::TenantId;
use crate::{alloy_client_trait::AlloyClient, AlloyMetadata};
use bytes::Bytes;
use futures::future::{join_all, FutureExt};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::cmk_edek::EncryptedDek;
use ironcore_documents::icl_header_v4::v4document_header::EdekWrapper;
use ironcore_documents::icl_header_v4::{self, V4DocumentHeader};
use ironcore_documents::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::convert::identity;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct SaasShieldStandardClient {
    tenant_security_client: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

// Standard SaaS Shield edeks could be V3 if they originated in old TSCs
#[derive(Debug)]
enum EdekParts {
    /// Key ID and document header containing the EDEK
    V5(KeyId, V4DocumentHeader),
    /// Just the EDEK, ready to be sent to the TSP
    V3(Bytes),
}

impl EdekParts {
    /// Gets the EDEK bytes regardless of the type of EDEK this was
    fn get_edek(&self) -> Result<Vec<u8>, AlloyError> {
        match self {
            EdekParts::V5(_, document) => {
                let edek = find_cmk_edek(&document.signed_payload.edeks)?;
                Ok(edek
                    .write_to_bytes()
                    .expect("Writing EDEK to bytes failed. Contact IronCore Labs support."))
            }
            EdekParts::V3(b) => Ok(b.to_vec()),
        }
    }

    /// Validates the signature in the case of V4 document header. V3 doesn't need validation
    fn validate_signature(&self, enc_key: EncryptionKey) -> Result<(), AlloyError> {
        match self {
            EdekParts::V5(_, document_header) => verify_sig(enc_key, document_header),
            EdekParts::V3(_) => Ok(()), // This is just an EDEK, so doesn't require validation
        }
    }
}

impl SaasShieldStandardClient {
    pub(crate) fn new(tenant_security_client: Arc<TenantSecurityClient>) -> Self {
        SaasShieldStandardClient {
            tenant_security_client,
            rng: crate::util::create_reseeding_rng(),
        }
    }

    fn encrypt_document<R: RngCore + CryptoRng>(
        rng: Arc<Mutex<R>>,
        tsc_edek: Vec<u8>,
        dek: EncryptionKey,
        tenant_id: TenantId,
        document: HashMap<String, Vec<u8>>,
    ) -> Result<EncryptedDocument, AlloyError> {
        let pb_edek: ironcore_documents::cmk_edek::EncryptedDek =
            protobuf::Message::parse_from_bytes(&tsc_edek)?;
        let kms_config_id = pb_edek.kmsConfigId as u32;
        let v4_doc = generate_cmk_v4_doc_and_sign(pb_edek, dek, tenant_id)?;
        encrypt_document_core(
            document,
            rng,
            dek,
            Self::create_key_id_header(kms_config_id),
            v4_doc,
        )
    }

    async fn rekey_edek_core(
        &self,
        edek: EdekWithKeyIdHeader,
        parsed_new_tenant_id: &TenantId,
        request_metadata: &RequestMetadata,
    ) -> Result<EdekWithKeyIdHeader, AlloyError> {
        let edek_parts = Self::decompose_edek_header(edek)?;
        let edek = edek_parts.get_edek()?;
        let tsp_resp = self
            .tenant_security_client
            .rekey_edek(edek, parsed_new_tenant_id, request_metadata)
            .await?;
        let dek = tsc_dek_to_encryption_key(tsp_resp.dek.0)?;
        edek_parts.validate_signature(dek)?;
        Self::encrypt_document(
            self.rng.clone(), // this isn't actually used because of the empty document
            tsp_resp.edek.0,
            dek,
            parsed_new_tenant_id.clone(),
            HashMap::new(), // empty document. We only care about the EDEK part and there's no wasted work
        )
        .map(|doc| doc.edek)
    }

    /// Break the EDEK into its V3 or V5 parts. This should be used instead of Self::decompose_key_id_header
    /// in order to support V3 headers.
    fn decompose_edek_header(
        encrypted_bytes: EdekWithKeyIdHeader,
    ) -> Result<EdekParts, AlloyError> {
        // This doesn't just call Self::decompose_key_id_header because we still want to error on incorrect EDEK/payload type
        let maybe_decomposed = ironcore_documents::key_id_header::decode_version_prefixed_value(
            Bytes::copy_from_slice(&encrypted_bytes.0),
        );
        match maybe_decomposed {
            Ok((
                KeyIdHeader {
                    key_id,
                    edek_type,
                    payload_type,
                },
                remaining_bytes,
            )) => {
                let expected_edek_type = Self::get_edek_type();
                let expected_payload_type = Self::get_payload_type();
                if edek_type == expected_edek_type && payload_type == expected_payload_type {
                    let v4_document_header = Message::parse_from_bytes(&remaining_bytes[..])?;
                    Ok(EdekParts::V5(key_id, v4_document_header))
                } else {
                    Err(AlloyError::InvalidInput(
                format!("The data indicated that this was not a {expected_edek_type} {expected_payload_type} wrapped value. Found: {edek_type}, {payload_type}"),
            ))
                }
            }
            Err(_) => Ok(EdekParts::V3(encrypted_bytes.0.into())),
        }
    }
}

impl AlloyClient for SaasShieldStandardClient {
    fn get_edek_type() -> EdekType {
        EdekType::SaasShield
    }

    fn get_payload_type() -> PayloadType {
        PayloadType::StandardEdek
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl StandardDocumentOps for SaasShieldStandardClient {
    async fn encrypt(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let WrapKeyResponse {
            dek,
            edek: tsc_edek,
        } = self
            .tenant_security_client
            .wrap_key(&request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        Self::encrypt_document(
            self.rng.clone(),
            tsc_edek.0,
            enc_key,
            metadata.tenant_id.clone(),
            plaintext_document,
        )
    }

    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let edek_parts = Self::decompose_edek_header(encrypted_document.edek)?;
        let edek = edek_parts.get_edek()?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(edek, &request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        edek_parts.validate_signature(enc_key)?;
        decrypt_document_core(encrypted_document.document, enc_key)
    }

    async fn rekey_edeks(
        &self,
        edeks: HashMap<String, EdekWithKeyIdHeader>,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyEdeksBatchResult, AlloyError> {
        let parsed_new_tenant_id = new_tenant_id.as_ref().unwrap_or(&metadata.tenant_id);
        let request_metadata = metadata.clone().try_into()?;
        let tsp_responses = join_all(edeks.into_iter().map(|(id, edek)| {
            self.rekey_edek_core(edek, parsed_new_tenant_id, &request_metadata)
                .map(|res| (id, res))
        }))
        .await;
        Ok(collection_to_batch_result(tsp_responses, identity).into())
    }

    async fn encrypt_with_existing_edek(
        &self,
        plaintext_document: PlaintextDocumentWithEdek,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError> {
        let request_metadata = metadata.clone().try_into()?;
        let edek_parts = Self::decompose_edek_header(plaintext_document.edek.clone())?;
        let edek = edek_parts.get_edek()?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(edek, &request_metadata)
            .await?;
        let enc_key = tsc_dek_to_encryption_key(dek.0)?;
        edek_parts.validate_signature(enc_key)?;
        Ok(EncryptedDocument {
            document: encrypt_map(plaintext_document.document, self.rng.clone(), enc_key)?,
            edek: plaintext_document.edek,
        })
    }
}

fn find_cmk_edek(edeks: &[EdekWrapper]) -> Result<&EncryptedDek, AlloyError> {
    let maybe_edek_wrapper = edeks.iter().find(|edek| edek.has_cmk_edek());
    let cmk_edek = maybe_edek_wrapper
        .map(|edek| edek.cmk_edek())
        .ok_or_else(|| AlloyError::DecryptError("No Saas Shield EDEK found.".to_string()))?;
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
    tenant_id: TenantId,
) -> Result<V4DocumentHeader, AlloyError> {
    edek.tenantId = tenant_id.0.into();
    let edek_wrapper = icl_header_v4::v4document_header::EdekWrapper {
        edek: Some(icl_header_v4::v4document_header::edek_wrapper::Edek::CmkEdek(edek)),
        ..Default::default()
    };

    Ok(ironcore_documents::create_signed_header(edek_wrapper, dek))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::standard::EdekWithKeyIdHeader;

    #[test]
    fn decompose_edek_header_makes_v3_for_invalid() {
        let encrypted_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![0u8]),
            document: Default::default(),
        };
        assert!(matches!(
            SaasShieldStandardClient::decompose_edek_header(encrypted_document.edek).unwrap(),
            EdekParts::V3(_)
        ));
    }

    #[test]
    fn get_document_header_and_edek_fails_for_wrong_type() {
        // This is a SaaS Shield Standard edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 1, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(bytes),
            document: Default::default(),
        };

        assert!(matches!(
            SaasShieldStandardClient::decompose_edek_header(encrypted_doc.edek).unwrap_err(),
            AlloyError::InvalidInput(_)
        ));
    }

    #[test]
    fn get_document_header_and_edek_succeeds_for_good_header() {
        // This is a SaaS Shield Standard edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 2, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(bytes),
            document: Default::default(),
        };

        assert!(SaasShieldStandardClient::decompose_edek_header(encrypted_doc.edek).is_ok());
    }
}
