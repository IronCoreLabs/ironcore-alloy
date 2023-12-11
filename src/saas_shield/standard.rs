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
use crate::{EncryptedBytes, FieldId, PlaintextBytes, TenantId};
use futures::future::{join_all, FutureExt};
use ironcore_documents::aes::EncryptionKey;
use ironcore_documents::cmk_edek::{self, EncryptedDek};
use ironcore_documents::icl_header_v4::v4document_header::EdekWrapper;
use ironcore_documents::icl_header_v4::{self, V4DocumentHeader};
use ironcore_documents::v5::key_id_header::{EdekType, PayloadType};
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
        let pb_edeks: ironcore_documents::cmk_edek::EncryptedDeks =
            protobuf::Message::parse_from_bytes(&tsc_edek)?;

        // We will choose the first edek, so that's the id we want to put on the front.
        let kms_config_id = pb_edeks
            .encryptedDeks
            .first()
            .map(|edek| edek.kmsConfigId as u32)
            .unwrap_or(0);
        let enc_key = tsc_dek_to_encryption_key(dek)?;
        let v4_doc = generate_cmk_v4_doc_and_sign(pb_edeks.encryptedDeks, enc_key, tenant_id)?;

        encrypt_document_core(
            document,
            rng,
            enc_key,
            Self::create_key_id_header(kms_config_id),
            v4_doc,
        )
    }

    /// A function introduced to deal with the issue of EncryptedDeks from the TSP being mistakenly parsed as EncryptedDek.
    /// This is mostly to allow compatibility with Cloaked Search from when this was an issue.
    fn fix_encrypted_dek(
        cmk_edek: &cmk_edek::EncryptedDek,
    ) -> Result<cmk_edek::EncryptedDeks, TenantSecurityError> {
        // Real kms config ids can't ever be 0, so if it is we parse it as an EncryptedDeks (which came from the tsp).
        // Then we put the tenant_id on each of them.
        let encrypted_deks = if cmk_edek.kmsConfigId == 0 {
            let bytes = cmk_edek.write_to_bytes().expect("Writing to bytes is safe");
            let encrypted_deks: cmk_edek::EncryptedDeks =
                Message::parse_from_bytes(bytes.as_ref())?;

            encrypted_deks
                .encryptedDeks
                .into_iter()
                .map(|mut edek| {
                    edek.tenantId = cmk_edek.tenantId.clone();
                    edek
                })
                .collect()
        } else {
            // If the kms_config_id is not 0, we assume this is a edek that was generated after the fix, so we can just pass it on.
            vec![cmk_edek.clone()]
        };
        Ok(cmk_edek::EncryptedDeks {
            encryptedDeks: encrypted_deks,
            ..Default::default()
        })
    }

    /// Breaks an EdekWithKeyIdHeader into its V4DocumentHeader and EncryptedDeks bytes.
    /// If the EDEK was previously parsed as an EncryptedDek instead of an EncryptedDeks,
    /// it will be fixed first.
    fn get_document_header_and_edek(
        edek: EdekWithKeyIdHeader,
    ) -> Result<(V4DocumentHeader, Vec<u8>), AlloyError> {
        let (_, v4_doc_bytes) = Self::decompose_key_id_header(edek.0)?;
        let v4_document: V4DocumentHeader = Message::parse_from_bytes(&v4_doc_bytes[..])?;
        let fixed_edek =
            Self::fix_encrypted_dek(find_cmk_edek(&v4_document.signed_payload.edeks)?)?;
        let edek_bytes = fixed_edek
            .write_to_bytes()
            .expect("Writing to bytes is safe");
        Ok((v4_document, edek_bytes))
    }

    async fn rekey_edek_core(
        &self,
        edek: EdekWithKeyIdHeader,
        parsed_new_tenant_id: &TenantId,
        request_metadata: &RequestMetadata,
    ) -> Result<EdekWithKeyIdHeader, AlloyError> {
        let edek = Self::get_document_header_and_edek(edek).map(|(_, edek)| edek)?;
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
            .unwrap_key(edek, &request_metadata)
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
            .unwrap_key(edek, &request_metadata)
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
    encrypted_document: HashMap<FieldId, EncryptedBytes>,
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
    edeks: Vec<EncryptedDek>,
    dek: EncryptionKey,
    tenant_id: TenantId,
) -> Result<V4DocumentHeader, AlloyError> {
    let edek_wrappers = edeks
        .into_iter()
        .map(|mut edek| {
            edek.tenantId = tenant_id.0.clone().into();
            icl_header_v4::v4document_header::EdekWrapper {
                edek: Some(icl_header_v4::v4document_header::edek_wrapper::Edek::CmkEdek(edek)),
                ..Default::default()
            }
        })
        .collect();

    Ok(ironcore_documents::create_signed_proto(edek_wrappers, dek))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::standard::EdekWithKeyIdHeader;
    use ironcore_documents::v5::key_id_header::{KeyId, KeyIdHeader};

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
        let edek = EncryptedDek {
            encryptedDekData: vec![1, 2, 3].into(),
            kmsConfigId: 1,
            tenantId: "tenant".into(),
            ..Default::default()
        };
        let v4_doc = generate_cmk_v4_doc_and_sign(
            vec![edek],
            EncryptionKey([1; 32]),
            TenantId("tenant".to_string()),
        )
        .unwrap();
        let doc_bytes = v4_doc.write_to_bytes().unwrap();
        let final_bytes =
            KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(123))
                .put_header_on_document(doc_bytes);
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(final_bytes.to_vec()),
            document: Default::default(),
        };

        SaasShieldStandardClient::get_document_header_and_edek(encrypted_doc.edek).unwrap();
    }

    #[test]
    fn parse_old_document_works() {
        let edek = EdekWithKeyIdHeader(vec![
            0, 0, 0, 0, 2, 0, 10, 36, 10, 32, 64, 210, 116, 17, 37, 169, 25, 195, 73, 47, 59, 120,
            34, 200, 205, 142, 3, 154, 115, 130, 188, 198, 244, 161, 170, 163, 153, 254, 43, 237,
            157, 167, 16, 1, 18, 215, 1, 18, 212, 1, 18, 209, 1, 10, 192, 1, 10, 48, 63, 225, 165,
            108, 33, 17, 151, 119, 230, 185, 159, 203, 90, 67, 250, 185, 117, 54, 184, 68, 240,
            128, 92, 176, 48, 35, 52, 183, 27, 153, 15, 247, 241, 63, 221, 179, 246, 99, 9, 98,
            221, 121, 156, 193, 220, 197, 225, 126, 16, 255, 3, 24, 128, 5, 34, 12, 39, 49, 127,
            75, 144, 142, 37, 173, 138, 210, 233, 129, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165,
            4, 100, 135, 130, 34, 228, 127, 190, 188, 55, 199, 103, 184, 137, 98, 81, 5, 243, 99,
            119, 248, 110, 101, 114, 150, 161, 28, 100, 228, 110, 64, 123, 169, 222, 18, 73, 0,
            220, 248, 78, 140, 39, 11, 119, 244, 9, 168, 242, 190, 48, 191, 108, 152, 157, 29, 120,
            97, 56, 118, 104, 45, 144, 16, 245, 170, 9, 52, 111, 40, 22, 174, 185, 135, 102, 95,
            142, 171, 180, 163, 118, 46, 183, 105, 45, 137, 66, 170, 61, 49, 166, 47, 184, 99, 232,
            86, 42, 73, 118, 87, 194, 50, 103, 109, 176, 41, 144, 121, 250, 182, 16, 255, 3, 50,
            12, 116, 101, 110, 97, 110, 116, 45, 103, 99, 112, 45, 108,
        ]);
        let (_, edek_bytes) = SaasShieldStandardClient::get_document_header_and_edek(edek).unwrap();
        let encrypted_deks: cmk_edek::EncryptedDeks =
            Message::parse_from_bytes(&edek_bytes).unwrap();
        assert_eq!(encrypted_deks.encryptedDeks.len(), 1);
        let encrypted_dek = encrypted_deks.encryptedDeks[0].clone();
        assert_eq!(encrypted_dek.kmsConfigId, 511);
        assert_eq!(encrypted_dek.tenantId.to_string(), "tenant-gcp-l");
    }

    #[test]
    fn parse_new_document_works() {
        let edek = EdekWithKeyIdHeader(vec![
            0, 0, 1, 255, 2, 0, 10, 36, 10, 32, 69, 182, 178, 20, 76, 114, 41, 199, 199, 34, 15,
            196, 128, 11, 147, 175, 190, 68, 241, 100, 46, 76, 139, 172, 5, 41, 226, 192, 84, 1,
            40, 31, 16, 1, 18, 212, 1, 18, 209, 1, 18, 206, 1, 10, 48, 212, 43, 219, 136, 159, 154,
            211, 225, 121, 20, 9, 189, 243, 102, 44, 168, 129, 150, 238, 97, 220, 248, 152, 117,
            48, 88, 45, 150, 114, 166, 74, 193, 252, 142, 29, 203, 233, 17, 14, 80, 34, 10, 236,
            100, 10, 206, 155, 123, 16, 255, 3, 24, 128, 5, 34, 12, 62, 97, 134, 143, 164, 152,
            252, 93, 101, 80, 51, 245, 42, 120, 10, 118, 10, 113, 10, 36, 0, 165, 4, 100, 135, 130,
            34, 228, 127, 190, 188, 55, 199, 103, 184, 137, 98, 81, 5, 243, 99, 119, 248, 110, 101,
            114, 150, 161, 28, 100, 228, 110, 64, 123, 169, 222, 18, 73, 0, 220, 248, 78, 140, 39,
            11, 119, 244, 9, 168, 242, 190, 48, 191, 108, 152, 157, 29, 120, 97, 56, 118, 104, 45,
            144, 16, 245, 170, 9, 52, 111, 40, 22, 174, 185, 135, 102, 95, 142, 171, 180, 163, 118,
            46, 183, 105, 45, 137, 66, 170, 61, 49, 166, 47, 184, 99, 232, 86, 42, 73, 118, 87,
            194, 50, 103, 109, 176, 41, 144, 121, 250, 182, 16, 255, 3, 50, 12, 116, 101, 110, 97,
            110, 116, 45, 103, 99, 112, 45, 108,
        ]);
        let (_, edek_bytes) = SaasShieldStandardClient::get_document_header_and_edek(edek).unwrap();
        let encrypted_deks: cmk_edek::EncryptedDeks =
            Message::parse_from_bytes(&edek_bytes).unwrap();
        assert_eq!(encrypted_deks.encryptedDeks.len(), 1);
        let encrypted_dek = encrypted_deks.encryptedDeks[0].clone();
        assert_eq!(encrypted_dek.kmsConfigId, 511);
        assert_eq!(encrypted_dek.tenantId.to_string(), "tenant-gcp-l");
    }
}
