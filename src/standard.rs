use crate::{
    alloy_client_trait::AlloyClient,
    errors::AlloyError,
    util::{get_rng, BatchResult},
    AlloyMetadata, EncryptedBytes, FieldId, PlaintextBytes, TenantId,
};
use ironcore_documents::key_id_header::{get_prefix_bytes_for_search, KeyId};
use ironcore_documents::{aes::EncryptionKey, icl_header_v4, key_id_header::KeyIdHeader, v3};
use itertools::Itertools;
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uniffi::custom_newtype;

pub type PlaintextDocument = HashMap<FieldId, PlaintextBytes>;

#[derive(Debug, uniffi::Record)]
pub struct PlaintextDocumentWithEdek {
    pub edek: EdekWithKeyIdHeader,
    pub document: PlaintextDocument,
}

impl PlaintextDocumentWithEdek {
    #[uniffi::constructor]
    pub fn new(
        edek: EdekWithKeyIdHeader,
        document: PlaintextDocument,
    ) -> PlaintextDocumentWithEdek {
        PlaintextDocumentWithEdek { document, edek }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdekWithKeyIdHeader(pub Vec<u8>);
custom_newtype!(EdekWithKeyIdHeader, Vec<u8>);

impl EdekWithKeyIdHeader {
    pub fn new(key_id_header: KeyIdHeader, v4_doc: icl_header_v4::V4DocumentHeader) -> Self {
        EdekWithKeyIdHeader(
            key_id_header
                .put_header_on_document(
                    v4_doc
                        .write_to_bytes()
                        .expect("Writing to in memory bytes should always succeed."),
                )
                .into(),
        )
    }
}

/// Document and EDEK (encrypted document encryption key) generated by `document_encrypt`/`documentEncrypt`.
/// Note that `document_encrypt_deterministic`/`documentEncryptDeterministic` doesn't use this type
/// as it prefixes an encryption header to the encrypted document map instead of using a separate EDEK.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedDocument {
    /// Encrypted Document Encryption Key used when the document was encrypted
    pub edek: EdekWithKeyIdHeader,
    /// Map from field name to encrypted document bytes
    pub document: HashMap<FieldId, EncryptedBytes>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RekeyEdeksBatchResult {
    pub successes: HashMap<String, EdekWithKeyIdHeader>,
    pub failures: HashMap<String, String>,
}

impl From<BatchResult<EdekWithKeyIdHeader>> for RekeyEdeksBatchResult {
    fn from(value: BatchResult<EdekWithKeyIdHeader>) -> Self {
        Self {
            successes: value.successes,
            failures: value.failures,
        }
    }
}

/// API for encrypting and decrypting documents using our standard encryption. This class of encryption is the most
/// broadly useful and secure. If you don't have a need to match on or preserve the distance properties of the
/// encrypted value, this is likely the API you should use. Our standard encryption is fully random (or probabilistic)
/// AES 256.
pub trait StandardDocumentOps: AlloyClient {
    /// Encrypt a document with the provided metadata. The document must be a map from field identifiers to plaintext
    /// bytes, and the same metadata must be provided when decrypting the document.
    /// A DEK (document encryption key) will be generated and encrypted using a derived key, then each field of the
    /// document will be encrypted separately using a random IV and this single generated DEK.
    /// The result contains a map from field identifiers to encrypted bytes as well as the EDEK (encrypted document
    /// encryption key) used for encryption.
    /// The document is encrypted differently with each call, so the result is not suited for exact matches or indexing.
    /// For the same reason however the strongest protection of the document is provided by this method.
    /// To support these uses, see the `DeterministicFieldOps.encrypt` function.
    async fn encrypt(
        &self,
        plaintext_document: PlaintextDocument,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError>;
    /// Decrypt a document that was encrypted with the provided metadata. The document must have been encrypted with one
    /// of the `StandardDocumentOps.encrypt` functions. The result contains a map from field identifiers to decrypted
    /// bytes.
    async fn decrypt(
        &self,
        encrypted_document: EncryptedDocument,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextDocument, AlloyError>;
    /// Decrypt the provided EDEKs and re-encrypt them using the tenant's current key. If `new_tenant_id` is `None`,
    /// the EDEK will be encrypted to the original tenant. Because the underlying DEK does not change, a document
    /// associated with the old EDEK can be decrypted with the new EDEK without changing its document data.
    async fn rekey_edeks(
        &self,
        edeks: HashMap<String, EdekWithKeyIdHeader>,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<RekeyEdeksBatchResult, AlloyError>;
    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    fn get_searchable_edek_prefix(&self, id: i32) -> Vec<u8> {
        get_prefix_bytes_for_search(ironcore_documents::key_id_header::KeyIdHeader::new(
            Self::get_edek_type(),
            Self::get_payload_type(),
            KeyId(id as u32),
        ))
        .into()
    }
    /// Encrypt a document with the provided metadata. The document must be a map from field identifiers to plaintext
    /// bytes, and the same metadata must be provided when decrypting the document.
    /// The provided EDEK will be decrypted and used to encrypt each field. This is useful when updating some fields
    /// of the document.
    async fn encrypt_with_existing_edek(
        &self,
        plaintext_document: PlaintextDocumentWithEdek,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedDocument, AlloyError>;
}

pub(crate) fn verify_sig(
    aes_dek: EncryptionKey,
    document: &icl_header_v4::V4DocumentHeader,
) -> Result<(), AlloyError> {
    if ironcore_documents::verify_signature(aes_dek.0, document) {
        Ok(())
    } else {
        Err(AlloyError::DecryptError(
            "EDEK signature verification failed.".to_string(),
        ))
    }
}

/// Encrypt each of the fields of the document using the aes_dek
pub(crate) fn encrypt_document_core<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
    document: HashMap<String, U>,
    rng: Arc<Mutex<R>>,
    aes_dek: EncryptionKey,
    key_id_header: KeyIdHeader,
    v4_doc: icl_header_v4::V4DocumentHeader,
) -> Result<EncryptedDocument, AlloyError> {
    let encrypted_document = encrypt_map(document, rng, aes_dek)?;
    Ok(EncryptedDocument {
        edek: EdekWithKeyIdHeader::new(key_id_header, v4_doc),
        document: encrypted_document,
    })
}

pub(crate) fn encrypt_map<U: AsRef<[u8]>, R: RngCore + CryptoRng>(
    document: HashMap<String, U>,
    rng: Arc<Mutex<R>>,
    aes_dek: EncryptionKey,
) -> Result<HashMap<String, Vec<u8>>, AlloyError> {
    let encrypted_document = document
        .into_iter()
        .map(|(label, plaintext)| {
            ironcore_documents::aes::encrypt_detached_document(
                &mut *get_rng(&rng),
                aes_dek,
                ironcore_documents::aes::PlaintextDocument(plaintext.as_ref().to_vec()),
            )
            .map(|c| (label, c.0.to_vec()))
        })
        .try_collect()?;
    Ok(encrypted_document)
}

pub(crate) fn decrypt_document_core(
    document: HashMap<String, Vec<u8>>,
    dek: EncryptionKey,
) -> Result<HashMap<String, Vec<u8>>, AlloyError> {
    Ok(document
        .into_iter()
        .map(|(label, ciphertext)| {
            // Further validation of the IronCore MAGIC will be done inside the function
            if ciphertext.starts_with(&[3]) {
                let encrypted_payload: v3::EncryptedPayload = ciphertext.try_into()?;
                encrypted_payload.decrypt(&dek)
            } else {
                ironcore_documents::aes::decrypt_detached_document(&dek, ciphertext.into())
            }
            .map(|c| (label, c.0))
        })
        .try_collect()?)
}

#[cfg(test)]
mod test {
    use ironcore_documents::key_id_header::{EdekType, KeyId, PayloadType};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    pub(crate) fn create_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(1u64)
    }
    #[test]
    fn encrypt_document_core_works() {
        let rng = create_rng();
        let result = encrypt_document_core(
            [("foo".to_string(), vec![100u8])].into(),
            Arc::new(Mutex::new(rng)),
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
