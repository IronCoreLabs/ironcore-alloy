use crate::{
    DerivationPath, EncryptedBytes, FieldId, IronCoreMetadata, PlaintextBytes, SecretPath,
};
use std::collections::HashMap;

pub struct EncryptedField {
    encrypted_field: EncryptedBytes,
    secret_path: SecretPath,
    derivation_path: DerivationPath,
}
pub struct PlaintextField {
    plaintext_field: PlaintextBytes,
    secret_path: SecretPath,
    derivation_path: DerivationPath,
}
pub type PlaintextFields = HashMap<FieldId, PlaintextField>;
pub type GenerateQueryBatchResult = HashMap<FieldId, Vec<EncryptedField>>;

#[async_trait::async_trait]
pub trait DeterministicFieldOps {
    async fn encrypt(plaintext_field: PlaintextField, metadata: IronCoreMetadata)
        -> EncryptedField;
    async fn decrypt(encrypted_field: EncryptedField, metadata: IronCoreMetadata)
        -> PlaintextField;
    async fn generate_query_field_values(
        fields_to_query: PlaintextFields,
        metadata: IronCoreMetadata,
    ) -> GenerateQueryBatchResult;
    // include in doc comment that z85/ascii85 users should pass these bytes through `base85_compat_prefix_bytes`
    async fn get_in_rotation_prefix() -> Vec<u8>;
}
