use crate::standard::EdekWithKeyIdHeader;
use crate::tenant_security_client::KeyDeriveResponse;
use crate::{
    CloakedAiError, DeterministicEncryptedField, DeterministicPlaintextField, DocumentMetadata,
    EncryptedDocument,
};
use aes_gcm::KeyInit;
use aes_siv::siv::Aes256Siv;
use ironcore_documents::key_id_header::KeyIdHeader;
use ironcore_documents::{
    aes::EncryptionKey,
    icl_header_v4::{self},
    key_id_header::{EdekType, KeyId},
};
use itertools::Itertools;
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::{collections::HashMap, fmt::Display};

pub(crate) mod aes;
pub(crate) mod cmk;

#[derive(Debug)]
pub enum DocumentError {
    InvalidKey(String),
    EncryptError(String),
    DecryptError(String),
    IronCoreDocumentsError(ironcore_documents::Error),
}

impl From<ironcore_documents::Error> for DocumentError {
    fn from(value: ironcore_documents::Error) -> Self {
        DocumentError::IronCoreDocumentsError(value)
    }
}

impl From<DocumentError> for CloakedAiError {
    fn from(value: DocumentError) -> Self {
        match value {
            DocumentError::InvalidKey(m)
            | DocumentError::EncryptError(m)
            | DocumentError::DecryptError(m) => CloakedAiError::DocumentError(m.to_string()),
            DocumentError::IronCoreDocumentsError(error) => {
                CloakedAiError::DocumentError(error.to_string())
            }
        }
    }
}

impl Display for DocumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocumentError::InvalidKey(msg) => write!(f, "{}", msg),
            DocumentError::EncryptError(msg) => write!(f, "{}", msg),
            DocumentError::DecryptError(msg) => write!(f, "{}", msg),
            DocumentError::IronCoreDocumentsError(error) => write!(f, "{}", error),
        }
    }
}

pub(crate) fn verify_sig(
    aes_dek: EncryptionKey,
    document: &icl_header_v4::V4DocumentHeader,
) -> Result<(), DocumentError> {
    if ironcore_documents::verify_signature(aes_dek.0, document) {
        Ok(())
    } else {
        Err(DocumentError::DecryptError(
            "EDEK signature verification failed.".to_string(),
        ))
    }
}

pub(crate) fn encrypt_document_core<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
    document: HashMap<String, U>,
    rng: &mut R,
    aes_dek: EncryptionKey,
    key_id_header: KeyIdHeader,
    v4_doc: icl_header_v4::V4DocumentHeader,
) -> Result<EncryptedDocument, DocumentError> {
    let encrypted_document = document
        .into_iter()
        .map(|(label, plaintext)| {
            ironcore_documents::aes::encrypt_detached_document(
                rng,
                aes_dek,
                ironcore_documents::aes::PlaintextDocument(plaintext.as_ref().to_vec()),
            )
            .map(|c| (label, c.0.to_vec()))
        })
        .try_collect()?;
    Ok(EncryptedDocument {
        edek: EdekWithKeyIdHeader(
            key_id_header
                .put_header_on_document(
                    v4_doc
                        .write_to_bytes()
                        .expect("Writing to in memory bytes should always succeed.")
                        .into(),
                )
                .into(),
        ),
        document: encrypted_document,
    })
}

pub(crate) fn decrypt_document_core(
    document: HashMap<String, Vec<u8>>,
    dek: EncryptionKey,
) -> Result<HashMap<String, Vec<u8>>, DocumentError> {
    Ok(document
        .into_iter()
        .map(|(label, ciphertext)| {
            let dec_result =
                ironcore_documents::aes::decrypt_detached_document(&dek, ciphertext.into());
            dec_result.map(|c| (label, c.0))
        })
        .try_collect()?)
}

pub(crate) fn deterministic_encrypt(
    key: [u8; 64],
    plaintext: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    deterministic_encrypt_core(key, plaintext, &[])
}

fn deterministic_encrypt_core(
    key: [u8; 64],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    let mut cipher = Aes256Siv::new(&key.into());
    cipher
        .encrypt([associated_data], plaintext)
        .map_err(|e| DocumentError::EncryptError(e.to_string()))
}

pub(crate) fn deterministic_encrypt_current(
    key_derive_resp: &KeyDeriveResponse,
    field: DeterministicPlaintextField,
    metadata: &DocumentMetadata,
) -> Result<DeterministicEncryptedField, CloakedAiError> {
    let current_derived_key = key_derive_resp
        .get_current(&field.secret_path, &field.derivation_path)
        .ok_or_else(|| {
            DocumentError::InvalidKey(format!(
                "No current key found for the tenant: '{}'",
                metadata.tenant_id.0
            ))
        })?;
    let current_derived_key_sized: [u8; 64] = current_derived_key
        .derived_key
        .0
        .clone()
        .try_into()
        .map_err(|_| {
            DocumentError::EncryptError("The derived key was not 64 bytes.".to_string())
        })?;
    let encrypted_document =
        deterministic_encrypt(current_derived_key_sized, field.plaintext_field.as_slice())?;
    Ok(DeterministicEncryptedField::new(
        field,
        current_derived_key.tenant_secret_id.0,
        encrypted_document,
    ))
}

pub(crate) fn deterministic_decrypt(
    key: [u8; 64],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    deterministic_decrypt_core(key, ciphertext, &[])
}

fn deterministic_decrypt_core(
    key: [u8; 64],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    let mut cipher = Aes256Siv::new(&key.into());
    cipher
        .decrypt([associated_data], ciphertext)
        .map_err(|e| DocumentError::DecryptError(e.to_string()))
}

pub(crate) fn deterministic_decrypt_with_derived_keys(
    key_derive_resp: &KeyDeriveResponse,
    field: DeterministicEncryptedField,
    metadata: &DocumentMetadata,
) -> Result<DeterministicPlaintextField, CloakedAiError> {
    let (derived_key, encrypted_data) = field
        .decompose_parts()
        .and_then(|(key_id, encrypted_data)| {
            key_derive_resp
                .get_by_id(&field.secret_path, &field.derivation_path, key_id)
                .map(|derived| (derived, encrypted_data))
        })
        .ok_or_else(|| {
            DocumentError::InvalidKey(format!(
                "Key used during encryption not found for the tenant: '{}'",
                metadata.tenant_id.0
            ))
        })?;
    let derived_key_sized: [u8; 64] =
        derived_key.derived_key.0.clone().try_into().map_err(|_| {
            DocumentError::EncryptError("The derived key was not 64 bytes.".to_string())
        })?;
    Ok(
        deterministic_decrypt(derived_key_sized, &encrypted_data).map(|res| {
            DeterministicPlaintextField {
                derivation_path: field.derivation_path,
                secret_path: field.secret_path,
                plaintext_field: res,
            }
        })?,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tenant_security_client::{Base64, DerivedKey, TenantSecretAssignmentId};
    use crate::{DerivationPath, SecretPath, TenantId};
    use hex_literal::hex;
    use ironcore_documents::key_id_header::PayloadType;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub(crate) fn create_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(1u64)
    }

    // Our TSCs test the example from https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.1, but that uses Aes128 (our TSC
    // crypto dependencies are more flexible than here). So this example comes from https://github.com/RustCrypto/AEADs/blob/master/aes-siv/tests/siv.rs#L160,
    // but that may not prove much since that is this own library's test.
    #[test]
    fn test_known_deterministic() {
        let key = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f");
        let ad = hex!("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plaintext = hex!("112233445566778899aabbccddee");
        let encrypt_result = deterministic_encrypt_core(key, &plaintext, &ad).unwrap();
        let expected_encrypt = hex!("f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126");
        assert_eq!(encrypt_result.clone(), expected_encrypt);
        let decrypt_result = deterministic_decrypt_core(key, &encrypt_result, &ad).unwrap();
        assert_eq!(decrypt_result, plaintext);
    }

    #[test]
    fn test_deterministic_encrypt_current() {
        let derivation_path = DerivationPath("foo".to_string());
        let secret_path = SecretPath("bar".to_string());
        let derived_key_1 = DerivedKey {
            derived_key: Base64([1; 64].to_vec()),
            tenant_secret_id: TenantSecretAssignmentId(1),
            current: true,
        };
        let derived_key_2 = DerivedKey {
            derived_key: Base64([2; 64].to_vec()),
            tenant_secret_id: TenantSecretAssignmentId(2),
            current: false,
        };
        let derivations = [(derivation_path.clone(), vec![derived_key_1, derived_key_2])].into();
        let secrets = [(secret_path.clone(), derivations)].into();
        let derived_keys = KeyDeriveResponse {
            has_primary_config: true,
            derived_keys: secrets,
        };
        let metadata = DocumentMetadata {
            tenant_id: TenantId("tenant".to_string()),
        };
        let field = DeterministicPlaintextField {
            derivation_path: derivation_path.clone(),
            secret_path: secret_path.clone(),
            plaintext_field: vec![1, 2, 3],
        };
        let result = deterministic_encrypt_current(&derived_keys, field, &metadata).unwrap();
        assert_eq!(result.derivation_path, derivation_path);
        assert_eq!(result.secret_path, secret_path);
        assert_eq!(result.decompose_parts().unwrap().0, 1);
        assert_eq!(
            result.encrypted_field,
            vec![
                0, 0, 0, 1, 0, 0, 97, 192, 69, 142, 203, 183, 170, 80, 234, 235, 186, 41, 175, 153,
                67, 145, 31, 97, 254
            ]
        );
    }

    #[test]
    fn test_deterministic_decrypt_from_derived_keys() {
        let derivation_path = DerivationPath("foo".to_string());
        let secret_path = SecretPath("bar".to_string());
        let derived_key_1 = DerivedKey {
            derived_key: Base64([1; 64].to_vec()),
            tenant_secret_id: TenantSecretAssignmentId(1),
            current: false, // Different from when it was encrypted, but it's the secret ID that matters
        };
        let derived_key_2 = DerivedKey {
            derived_key: Base64([2; 64].to_vec()),
            tenant_secret_id: TenantSecretAssignmentId(2),
            current: true,
        };
        let derivations = [(derivation_path.clone(), vec![derived_key_1, derived_key_2])].into();
        let secrets = [(secret_path.clone(), derivations)].into();
        let derived_keys = KeyDeriveResponse {
            has_primary_config: true,
            derived_keys: secrets,
        };
        let metadata = DocumentMetadata {
            tenant_id: TenantId("tenant".to_string()),
        };
        let field = DeterministicEncryptedField {
            derivation_path: derivation_path.clone(),
            secret_path: secret_path.clone(),
            encrypted_field: vec![
                0, 0, 0, 1, 0, 0, 97, 192, 69, 142, 203, 183, 170, 80, 234, 235, 186, 41, 175, 153,
                67, 145, 31, 97, 254,
            ],
        };
        let result =
            deterministic_decrypt_with_derived_keys(&derived_keys, field, &metadata).unwrap();

        assert_eq!(result.derivation_path, derivation_path);
        assert_eq!(result.secret_path, secret_path);
        assert_eq!(result.plaintext_field, vec![1, 2, 3]);
    }

    #[test]
    fn encrypt_document_core_works() {
        let mut rng = create_rng();
        let result = encrypt_document_core(
            [("foo".to_string(), vec![100u8])].into(),
            &mut rng,
            EncryptionKey([0u8; 32]),
            KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(1)),
            Default::default(),
        )
        .unwrap();
        assert_eq!(result.edek.0, vec![0, 0, 0, 1, 2, 0]);
        assert_eq!(
            result.document.get("foo").unwrap(),
            &vec![
                0, 73, 82, 79, 78, 154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161, 178, 165,
                36, 21, 83, 179, 38, 34, 142, 237, 59, 8, 62, 249, 67, 36, 252
            ]
        );
    }
}
