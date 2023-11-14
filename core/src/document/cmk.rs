use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{tenant_security_client::errors::TenantSecurityError, IronCoreMetadata};
use ironcore_documents::{
    aes::EncryptionKey,
    cmk_edek::EncryptedDek,
    icl_header_v4::{self, v4document_header::EdekWrapper, V4DocumentHeader},
    key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType},
};
use rand::{CryptoRng, RngCore};

use crate::{util::get_rng, CloakedAiError, DocumentMetadata, EncryptedDocument};

use super::{decrypt_document_core, verify_sig, DocumentError};

pub(crate) fn encrypt_document<R: RngCore + CryptoRng>(
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

    Ok(super::encrypt_document_core(
        document,
        &mut *get_rng(&rng),
        enc_key,
        KeyIdHeader::new(
            EdekType::SaasShield,
            PayloadType::StandardEdek,
            KeyId(kms_config_id),
        ),
        v4_doc,
    )?)
}

pub(crate) fn decrypt_document(
    header: V4DocumentHeader,
    dek: Vec<u8>,
    encrypted_document: EncryptedDocument,
) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
    let enc_key = tsc_dek_to_encryption_key(dek)?;
    verify_sig(enc_key, &header)?;
    Ok(decrypt_document_core(encrypted_document.document, enc_key)?)
}

pub(crate) fn find_cmk_edek(edeks: &[EdekWrapper]) -> Result<&EncryptedDek, DocumentError> {
    let maybe_edek_wrapper = edeks.iter().find(|edek| edek.has_cmk_edek());
    let cmk_edek = maybe_edek_wrapper
        .map(|edek| edek.cmk_edek())
        .ok_or_else(|| DocumentError::DecryptError("No Saas Shield EDEK found.".to_string()))?;
    Ok(cmk_edek)
}

fn tsc_dek_to_encryption_key(dek: Vec<u8>) -> Result<EncryptionKey, TenantSecurityError> {
    let bytes: [u8; 32] = dek
        .try_into()
        .map_err(|_| TenantSecurityError::InvalidDek)?; //TODO: Different error?
    Ok(ironcore_documents::aes::EncryptionKey(bytes))
}

pub(crate) fn generate_cmk_v4_doc_and_sign(
    mut edek: EncryptedDek,
    dek: EncryptionKey,
    metadata: &IronCoreMetadata,
) -> Result<V4DocumentHeader, DocumentError> {
    edek.tenantId = metadata.tenant_id.0.clone().into();
    let edek_wrapper = icl_header_v4::v4document_header::EdekWrapper {
        edek: Some(icl_header_v4::v4document_header::edek_wrapper::Edek::CmkEdek(edek)),
        ..Default::default()
    };

    Ok(ironcore_documents::create_signed_header(edek_wrapper, dek))
}
