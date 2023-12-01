use ironcore_documents::{
    aes::{decrypt_attached_document, EncryptionKey},
    cmk_edek::EncryptedDek,
    decode_attached_edoc,
    icl_header_v4::{v4document_header::EdekWrapper, V4DocumentHeader},
    AttachedEncryptedPayload,
};
use rand::{CryptoRng, RngCore};
use std::sync::{Arc, Mutex};

use crate::{
    errors::AlloyError,
    standard::verify_sig,
    standard_attached::{
        encrypt_field_attached_core, EncryptedAttachedDocument, StandardAttachedDocumentOps,
    },
    tenant_security_client::{TenantSecurityClient, WrapKeyResponse},
    util::{get_rng, OurReseedingRng},
    AlloyMetadata,
};

#[derive(uniffi::Object)]
pub struct SaasShieldStandardAttachedClient {
    tsc: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

impl StandardAttachedDocumentOps for SaasShieldStandardAttachedClient {
    async fn encrypt(
        &self,
        plaintext_field: crate::PlaintextBytes,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::standard_attached::EncryptedAttachedDocument, crate::errors::AlloyError>
    {
        let request_metadata = metadata.clone().try_into()?;
        let WrapKeyResponse {
            dek,
            edek: tsc_edek,
        } = self.tsc.wrap_key(&request_metadata).await?;
        let encrypted_bytes = encrypt_field_attached(
            self.rng.clone(),
            tsc_edek.0,
            dek.0,
            metadata,
            plaintext_field,
        )?;
        Ok(EncryptedAttachedDocument(encrypted_bytes))
    }

    async fn decrypt(
        &self,
        attached_field: crate::standard_attached::EncryptedAttachedDocument,
        metadata: &crate::AlloyMetadata,
    ) -> Result<crate::PlaintextBytes, crate::errors::AlloyError> {
        let (header, payload) = decode_attached_edoc(attached_field.0.into())?;
        let edek = find_cmk_edek(&header.signed_payload.edeks)?;
        let request_metadata = metadata.clone().try_into()?;
        let unwrap_resp = self
            .tsc
            .unwrap_key(edek.encryptedDekData.to_vec(), &request_metadata)
            .await?;
        decrypt_field_attached(payload, unwrap_resp.dek.0, &header)
    }

    async fn get_searchable_prefix(&self, id: u32) -> Vec<u8> {
        todo!()
    }
}

pub(crate) fn encrypt_field_attached<R: RngCore + CryptoRng>(
    rng: Arc<Mutex<R>>,
    tsc_edek: Vec<u8>,
    dek: Vec<u8>,
    metadata: &AlloyMetadata,
    field: Vec<u8>,
) -> Result<Vec<u8>, AlloyError> {
    let pb_edek = protobuf::Message::parse_from_bytes(&tsc_edek)?;
    Ok(encrypt_field_attached_core(
        &mut *get_rng(&rng),
        field,
        tsc_dek_to_encryption_key(dek)?,
        pb_edek,
        metadata,
    )?)
}

fn decrypt_field_attached(
    field: AttachedEncryptedPayload,
    dek: Vec<u8>,
    header: &V4DocumentHeader,
) -> Result<Vec<u8>, AlloyError> {
    let enc_key = tsc_dek_to_encryption_key(dek)?;
    verify_sig(enc_key, header)?;
    Ok(decrypt_attached_document(&enc_key, field)?.0)
}

fn find_cmk_edek(edeks: &[EdekWrapper]) -> Result<&EncryptedDek, AlloyError> {
    let maybe_edek_wrapper = edeks.iter().find(|edek| edek.has_cmk_edek());
    let cmk_edek = maybe_edek_wrapper
        .map(|edek| edek.cmk_edek())
        .ok_or_else(|| AlloyError::DecryptError("No Saas Shield EDEK found.".to_string()))?;
    Ok(cmk_edek)
}

fn tsc_dek_to_encryption_key(dek: Vec<u8>) -> Result<EncryptionKey, AlloyError> {
    let bytes: [u8; 32] = dek
        .try_into()
        .map_err(|_| AlloyError::InvalidKey("COLT: Different error".to_string()))?; //TODO: Different error?
    Ok(ironcore_documents::aes::EncryptionKey(bytes))
}
