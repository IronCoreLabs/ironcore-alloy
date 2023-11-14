use super::{deterministic_decrypt, deterministic_encrypt, verify_sig, DocumentError};
use crate::util::{hash256, hash512};
use crate::{CloakedAiError, DocumentMetadata, EncryptedDocument, TenantId};
use ironcore_documents::key_id_header::{self, KeyId, KeyIdHeader};
use ironcore_documents::{
    aes::{generate_aes_edek_and_sign, EncryptionKey},
    icl_header_v4,
};
use itertools::Itertools;
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::hash::Hash;

const DETERMINISTIC_HEADER_LEN: usize = 6;
const DETERMINISTIC_HEADER: [u8; DETERMINISTIC_HEADER_LEN] = [0u8; DETERMINISTIC_HEADER_LEN];

pub fn encrypt_document_deterministic<T: AsRef<str> + Eq + Hash, U: AsRef<[u8]>>(
    derivation_key: &[u8],
    document: HashMap<T, U>,
    doc_metadata: &DocumentMetadata,
) -> Result<HashMap<T, Vec<u8>>, DocumentError> {
    document
        .into_iter()
        .map(|(label, value)| {
            let derived_key =
                derive_deterministic_key(derivation_key, &doc_metadata.tenant_id, label.as_ref());
            let encrypted_value = deterministic_encrypt(derived_key, value.as_ref())?;
            Ok((
                label,
                [&DETERMINISTIC_HEADER[..], &encrypted_value[..]].concat(),
            ))
        })
        .try_collect()
}

/// Decrypt a document that was encrypted deterministically.
pub fn decrypt_document_deterministic(
    derivation_key: &[u8],
    document: HashMap<String, Vec<u8>>,
    doc_metadata: &DocumentMetadata,
) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
    Ok(document
        .into_iter()
        .map(|(label, value)| {
            if value.len() < DETERMINISTIC_HEADER.len() {
                Err(DocumentError::DecryptError(
                    "Deterministic header not present.".to_string(),
                ))
            } else {
                let derived_key = derive_deterministic_key(
                    derivation_key,
                    &doc_metadata.tenant_id,
                    label.as_ref(),
                );
                let (header, ciphertext) = value.split_at(DETERMINISTIC_HEADER_LEN);
                if header != DETERMINISTIC_HEADER {
                    Err(DocumentError::DecryptError(
                        "Deterministic header not present.".to_string(),
                    ))
                } else {
                    deterministic_decrypt(derived_key, ciphertext).map(|v| (label, v))
                }
            }
        })
        .try_collect()?)
}

fn derive_deterministic_key(derivation_key: &[u8], tenant_id: &TenantId, label: &str) -> [u8; 64] {
    let resulting_bytes: String =
        Itertools::intersperse([tenant_id.0.as_str(), label].into_iter(), "-").collect();
    hash512(derivation_key, resulting_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use assertables::*;
    use hex_literal::hex;
    use ironcore_documents::key_id_header::{EdekType, PayloadType};

    fn get_doc_metadata() -> DocumentMetadata {
        DocumentMetadata {
            tenant_id: crate::TenantId("foo".to_string()),
        }
    }

    #[test]
    fn encrypt_document_deterministic_roundtrip() {
        let document: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into_iter().collect();
        let key = hex!("aaaaaaaaaaaa");
        let encrypted =
            encrypt_document_deterministic(&key, document.clone(), &get_doc_metadata()).unwrap();
        let decrypted =
            decrypt_document_deterministic(&key, encrypted, &get_doc_metadata()).unwrap();
        assert_eq!(decrypted, document);
    }
    #[test]
    fn document_deterministic_decrypt_known_bytes() {
        let plaintext: HashMap<_, _> = [("hi".to_string(), vec![1, 2, 3])].into_iter().collect();
        let encrypted: HashMap<_, _> = [(
            "hi".to_string(),
            hex!("00000000000053aee634eb8e13150eb8a0e3e6d7f3293edd2e").to_vec(),
        )]
        .into_iter()
        .collect();
        let key = hex!("aaaaaaaaaaaa");
        let decrypted =
            decrypt_document_deterministic(&key, encrypted, &get_doc_metadata()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn document_deterministic_decrypt_fails_on_invalid_header() {
        let encrypted: HashMap<_, _> = [(
            "hi".to_string(),
            //header is only 5 bytes of 0.
            hex!("00000000009b5a29b8c370b42ded7b8926265d07adb50f2d").to_vec(),
        )]
        .into_iter()
        .collect();
        let key = hex!("aaaaaaaaaaaa");
        let error =
            decrypt_document_deterministic(&key, encrypted, &get_doc_metadata()).unwrap_err();
        assert_contains!(error.to_string(), "Deterministic header not present");
    }

    #[test]
    fn document_deterministic_decrypt_fails_on_too_short() {
        let encrypted: HashMap<_, _> = [("hi".to_string(), hex!("00").to_vec())]
            .into_iter()
            .collect();
        let key = hex!("aaaaaaaaaaaa");
        let error =
            decrypt_document_deterministic(&key, encrypted, &get_doc_metadata()).unwrap_err();
        assert_contains!(error.to_string(), "Deterministic header not present");
    }
}
