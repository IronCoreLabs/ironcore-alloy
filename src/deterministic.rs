use crate::{
    errors::AlloyError,
    standalone::config::StandaloneSecret,
    util::{self},
    AlloyMetadata, DerivationPath, EncryptedBytes, FieldId, PlaintextBytes, Secret, SecretPath,
    TenantId,
};
use aes_gcm::KeyInit;
use aes_siv::siv::Aes256Siv;
use bytes::Bytes;
use ironcore_documents::key_id_header::{KeyId, KeyIdHeader};
use std::{collections::HashMap, sync::Arc};
use uniffi::custom_newtype;

#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedField {
    pub encrypted_field: EncryptedBytes,
    pub secret_path: SecretPath,
    pub derivation_path: DerivationPath,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PlaintextField {
    pub plaintext_field: PlaintextBytes,
    pub secret_path: SecretPath,
    pub derivation_path: DerivationPath,
}
pub type PlaintextFields = HashMap<FieldId, PlaintextField>;
pub type EncryptedFields = HashMap<FieldId, EncryptedField>;
pub type GenerateQueryResult = HashMap<FieldId, Vec<EncryptedField>>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct RotateBatchResult {
    pub successes: HashMap<FieldId, EncryptedField>,
    pub failures: HashMap<FieldId, String>, // TODO: export error instead...?
}

/// Key used for deterministic operations.
#[derive(Debug, Clone)]
pub struct DeterministicEncryptionKey(pub Vec<u8>);
custom_newtype!(DeterministicEncryptionKey, Vec<u8>);

impl DeterministicEncryptionKey {
    /// A way to generate a key from the secret, tenant_id and derivation_path. This is done in the context of
    /// a standalone secret where we don't have a TSP to call to for derivation.
    pub(crate) fn derive_from_secret(
        secret: &Secret,
        tenant_id: &TenantId,
        derivation_path: &DerivationPath,
    ) -> Self {
        let hash_result = util::hash512(
            &secret.secret[..],
            format!("{}-{}", tenant_id.0, derivation_path.0),
        );
        Self(hash_result.to_vec())
    }
}

pub trait DeterministicFieldOps {
    /// Encrypt a field with the provided metadata.
    /// Because the field is encrypted deterministically with each call, the result will be the same for repeated calls.
    /// This allows for exact matches and indexing of the encrypted field, but comes with some security considerations.
    /// If you don't need to support these use cases, we recommend using `standard` encryption instead.
    async fn encrypt(
        &self,
        plaintext_field: PlaintextField,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedField, AlloyError>;
    /// Decrypt a field that was deterministically encrypted with the provided metadata.
    async fn decrypt(
        &self,
        encrypted_field: EncryptedField,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextField, AlloyError>;
    /// Encrypt each plaintext field with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted fields should be used in tandem when querying the data store.
    async fn generate_query_field_values(
        &self,
        fields_to_query: PlaintextFields,
        metadata: &AlloyMetadata,
    ) -> Result<GenerateQueryResult, AlloyError>;
    /// TODO: docs
    async fn rotate_fields(
        &self,
        encrypted_fields: EncryptedFields,
        metadata: &AlloyMetadata,
        new_tenant_id: TenantId,
    ) -> Result<RotateBatchResult, AlloyError>;
    /// Generate a prefix that could used to search a data store for fields encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        derivation_path: DerivationPath,
        metadata: &AlloyMetadata,
    ) -> Result<Vec<u8>, AlloyError>;
}

pub(crate) fn encrypt_internal(
    key: DeterministicEncryptionKey,
    key_id_header: KeyIdHeader,
    plaintext_field: PlaintextField,
) -> Result<EncryptedField, AlloyError> {
    let current_derived_key_sized: [u8; 64] = key
        .0
        .try_into()
        .map_err(|_| AlloyError::InvalidKey("The derived key was not 64 bytes.".to_string()))?;
    let encrypted_bytes = deterministic_encrypt(
        current_derived_key_sized,
        plaintext_field.plaintext_field.as_slice(),
    )?;
    let encrypted_field = key_id_header.put_header_on_document(encrypted_bytes);
    Ok(EncryptedField {
        encrypted_field: encrypted_field.into(),
        secret_path: plaintext_field.secret_path,
        derivation_path: plaintext_field.derivation_path,
    })
}

pub(crate) fn decrypt_internal(
    key: DeterministicEncryptionKey,
    ciphertext: Bytes,
    secret_path: SecretPath,
    derivation_path: DerivationPath,
) -> Result<PlaintextField, AlloyError> {
    let sized_key: [u8; 64] = key
        .0
        .try_into()
        .map_err(|_| AlloyError::InvalidKey("The derived key was not 64 bytes.".to_string()))?;
    deterministic_decrypt(sized_key, &ciphertext).map(|res| PlaintextField {
        plaintext_field: res,
        secret_path,
        derivation_path,
    })
}

fn deterministic_encrypt(key: [u8; 64], plaintext: &[u8]) -> Result<Vec<u8>, AlloyError> {
    deterministic_encrypt_core(key, plaintext, &[])
}

fn deterministic_encrypt_core(
    key: [u8; 64],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, AlloyError> {
    let mut cipher = Aes256Siv::new(&key.into());
    cipher
        .encrypt([associated_data], plaintext)
        .map_err(|e| AlloyError::EncryptError(e.to_string()))
}

fn deterministic_decrypt(key: [u8; 64], ciphertext: &[u8]) -> Result<Vec<u8>, AlloyError> {
    deterministic_decrypt_core(key, ciphertext, &[])
}

fn deterministic_decrypt_core(
    key: [u8; 64],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, AlloyError> {
    let mut cipher = Aes256Siv::new(&key.into());
    cipher
        .decrypt([associated_data], ciphertext)
        .map_err(|e| AlloyError::DecryptError(e.to_string()))
}

pub(crate) fn check_rotation_no_op(
    encrypted_key_id: KeyId,
    maybe_current_key: &Option<Arc<StandaloneSecret>>,
    new_tenant_id: &TenantId,
    metadata: &AlloyMetadata,
) -> bool {
    maybe_current_key.as_ref().map(|k| k.id) == Some(encrypted_key_id.0)
        && new_tenant_id.0 == metadata.tenant_id.0
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

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
}
