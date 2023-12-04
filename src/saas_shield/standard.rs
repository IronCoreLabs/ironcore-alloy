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
use crate::{alloy_client_trait::AlloyClient, AlloyMetadata};
use crate::{EncryptedBytes, PlaintextBytes, TenantId};
use futures::future::{join_all, FutureExt};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::cmk_edek::{self, EncryptedDek};
use ironcore_documents::icl_header_v4::v4document_header::EdekWrapper;
use ironcore_documents::icl_header_v4::{self, V4DocumentHeader};
use ironcore_documents::key_id_header::{EdekType, PayloadType};
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
        dek: Vec<u8>,
        tenant_id: TenantId,
        document: HashMap<String, Vec<u8>>,
    ) -> Result<EncryptedDocument, AlloyError> {
        let pb_edek: ironcore_documents::cmk_edek::EncryptedDek =
            protobuf::Message::parse_from_bytes(&tsc_edek)?;
        let kms_config_id = pb_edek.kmsConfigId as u32;
        let enc_key = tsc_dek_to_encryption_key(dek)?;
        let v4_doc = generate_cmk_v4_doc_and_sign(pb_edek, enc_key, tenant_id)?;

        encrypt_document_core(
            document,
            rng,
            enc_key,
            Self::create_key_id_header(kms_config_id),
            v4_doc,
        )
    }

    fn get_document_header_and_edek(
        edek: EdekWithKeyIdHeader,
    ) -> Result<(V4DocumentHeader, cmk_edek::EncryptedDek), AlloyError> {
        let (_, v4_doc_bytes) = Self::decompose_key_id_header(edek.0)?;
        let v4_document: V4DocumentHeader = Message::parse_from_bytes(&v4_doc_bytes[..])?;
        let edek = find_cmk_edek(&v4_document.signed_payload.edeks)?.clone();
        Ok((v4_document, edek))
    }

    async fn rekey_edek_core(
        &self,
        edek: EdekWithKeyIdHeader,
        parsed_new_tenant_id: &TenantId,
        request_metadata: &RequestMetadata,
    ) -> Result<EdekWithKeyIdHeader, AlloyError> {
        let edek = Self::get_document_header_and_edek(edek).map(|res| {
            res.1
                .write_to_bytes()
                .expect("Writing edek to bytes failed.") // There shouldn't be any reason this could fail.
        })?;
        let tsp_resp = self
            .tenant_security_client
            .rekey_edek(edek, parsed_new_tenant_id, request_metadata)
            .await?;
        Self::encrypt_document(
            self.rng.clone(), // this isn't actually used because of the empty document
            tsp_resp.edek.0,
            tsp_resp.dek.0,
            parsed_new_tenant_id.clone(),
            HashMap::new(), // empty document. We only care about the EDEK part and there's no wasted work
        )
        .map(|doc| doc.edek)
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
        Self::encrypt_document(
            self.rng.clone(),
            tsc_edek.0,
            dek.0,
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
        let (v4_document, edek) = Self::get_document_header_and_edek(encrypted_document.edek)?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(
                edek.write_to_bytes()
                    .expect("Writing EDEK to bytes failed. Contact IronCore Labs support."), // There shouldn't be any reason this could fail.
                &request_metadata,
            )
            .await?;
        decrypt_document(v4_document, dek.0, encrypted_document.document)
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
        let (_, edek) = Self::get_document_header_and_edek(plaintext_document.edek.clone())?;
        let UnwrapKeyResponse { dek } = self
            .tenant_security_client
            .unwrap_key(
                edek.write_to_bytes()
                    .expect("Writing edek to bytes failed."), // There shouldn't be any reason this could fail.
                &request_metadata,
            )
            .await?;

        Ok(EncryptedDocument {
            document: encrypt_map(
                plaintext_document.document,
                self.rng.clone(),
                tsc_dek_to_encryption_key(dek.0)?,
            )?,
            edek: plaintext_document.edek,
        })
    }
}

fn decrypt_document(
    header: V4DocumentHeader,
    dek: Vec<u8>,
    encrypted_document: HashMap<String, EncryptedBytes>,
) -> Result<HashMap<String, PlaintextBytes>, AlloyError> {
    let enc_key = tsc_dek_to_encryption_key(dek)?;
    verify_sig(enc_key, &header)?;
    decrypt_document_core(encrypted_document, enc_key)
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
    fn get_document_header_and_edek_fails_for_bad_header() {
        let encrypted_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![0u8]),
            document: Default::default(),
        };
        assert_eq!(
            SaasShieldStandardClient::get_document_header_and_edek(encrypted_document.edek)
                .unwrap_err(),
            AlloyError::InvalidInput("Encrypted header was invalid.".to_string())
        );
    }

    #[test]
    fn get_document_header_and_edek_succeeds_for_good_header() {
        // This is a SaaS Shield Standard edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 2, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(bytes),
            document: Default::default(),
        };

        SaasShieldStandardClient::get_document_header_and_edek(encrypted_doc.edek).unwrap();
    }
}
