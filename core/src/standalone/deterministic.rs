use crate::deterministic::{
    DeterministicFieldOps, EncryptedField, GenerateQueryBatchResult, PlaintextField,
    PlaintextFields,
};
use crate::{IronCoreMetadata, StandaloneConfiguration};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct StandaloneDeterministicClient {}
impl StandaloneDeterministicClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        StandaloneDeterministicClient {}
    }
}

#[async_trait::async_trait]
impl DeterministicFieldOps for StandaloneDeterministicClient {
    async fn encrypt(
        plaintext_field: PlaintextField,
        metadata: IronCoreMetadata,
    ) -> EncryptedField {
        todo!()
    }
    async fn decrypt(
        encrypted_field: EncryptedField,
        metadata: IronCoreMetadata,
    ) -> PlaintextField {
        todo!()
    }
    async fn generate_query_field_values(
        fields_to_query: PlaintextFields,
        metadata: IronCoreMetadata,
    ) -> GenerateQueryBatchResult {
        todo!()
    }
    // include in doc comment that z85/ascii85 users should pass these bytes through `base85_compat_prefix_bytes`
    async fn get_in_rotation_prefix() -> Vec<u8> {
        todo!()
    }
}
