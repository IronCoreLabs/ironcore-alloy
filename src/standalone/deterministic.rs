use super::config::RotatableSecret;
use crate::deterministic::{
    decrypt_internal, encrypt_internal, DeterministicEncryptionKey, DeterministicFieldOps,
    DeterministicRotateResult, EncryptedField, EncryptedFields, GenerateQueryResult,
    PlaintextField, PlaintextFields,
};
use crate::errors::AlloyError;
use crate::util::{check_rotation_no_op, collection_to_batch_result};
use crate::{
    alloy_client_trait::AlloyClient, AlloyMetadata, DerivationPath, SecretPath,
    StandaloneConfiguration, TenantId,
};
use ironcore_documents::v5::key_id_header::{EdekType, PayloadType};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct StandaloneDeterministicClient {
    config: Arc<HashMap<SecretPath, Arc<RotatableSecret>>>,
}
impl StandaloneDeterministicClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        StandaloneDeterministicClient {
            config: config.deterministic,
        }
    }

    /// Synchronous version of `encrypt` that takes TenantId instead of full AlloyMetadata
    fn encrypt_sync(
        &self,
        plaintext_field: PlaintextField,
        tenant_id: &TenantId,
    ) -> Result<EncryptedField, AlloyError> {
        let secret = self
            .config
            .get(&plaintext_field.secret_path)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Provided secret path `{}` does not exist in the deterministic configuration.",
                    &plaintext_field.secret_path.0
                ),
            })?;
        let current_secret =
            secret
                .current_secret
                .as_ref()
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: "No current secret exists in the deterministic configuration".to_string(),
                })?;
        let key = DeterministicEncryptionKey::derive_from_secret(
            &current_secret.secret,
            tenant_id,
            &plaintext_field.derivation_path,
        );
        let key_id_header = Self::create_key_id_header(current_secret.id);
        encrypt_internal(key, key_id_header, plaintext_field)
    }

    /// Synchronous version of `decrypt` that takes TenantId instead of full AlloyMetadata
    fn decrypt_sync(
        &self,
        encrypted_field: EncryptedField,
        tenant_id: &TenantId,
    ) -> Result<PlaintextField, AlloyError> {
        let (key_id, ciphertext) =
            Self::decompose_key_id_header(encrypted_field.encrypted_field.clone())?;
        let secret = self
            .config
            .get(&encrypted_field.secret_path)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Provided secret path `{}` does not exist in the deterministic configuration.",
                    &encrypted_field.secret_path.0
                ),
            })?;
        let standalone_secret =
            secret
                .get_secret_with_id(&key_id)
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: format!(
                        "Secret with key ID `{}` does not exist in the deterministic configuration",
                        key_id.0
                    ),
                })?;
        let key = DeterministicEncryptionKey::derive_from_secret(
            &standalone_secret.secret,
            tenant_id,
            &encrypted_field.derivation_path,
        );
        decrypt_internal(
            key,
            ciphertext,
            encrypted_field.secret_path,
            encrypted_field.derivation_path,
        )
    }
}

impl AlloyClient for StandaloneDeterministicClient {
    fn get_edek_type() -> EdekType {
        EdekType::Standalone
    }

    fn get_payload_type() -> PayloadType {
        PayloadType::DeterministicField
    }
}

#[uniffi::export]
impl DeterministicFieldOps for StandaloneDeterministicClient {
    /// Encrypt a field with the provided metadata.
    /// Because the field is encrypted deterministically with each call, the result will be the same for repeated calls.
    /// This allows for exact matches and indexing of the encrypted field, but comes with some security considerations.
    /// If you don't need to support these use cases, we recommend using `standard` encryption instead.
    async fn encrypt(
        &self,
        plaintext_field: PlaintextField,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedField, AlloyError> {
        self.encrypt_sync(plaintext_field, &metadata.tenant_id)
    }

    /// Decrypt a field that was deterministically encrypted with the provided metadata.
    async fn decrypt(
        &self,
        encrypted_field: EncryptedField,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextField, AlloyError> {
        self.decrypt_sync(encrypted_field, &metadata.tenant_id)
    }

    /// Encrypt each plaintext field with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted fields should be used in tandem when querying the data store.
    async fn generate_query_field_values(
        &self,
        fields_to_query: PlaintextFields,
        metadata: &AlloyMetadata,
    ) -> Result<GenerateQueryResult, AlloyError> {
        fields_to_query
            .into_iter()
            .map(|(field_id, plaintext_field)| {
                let secret = self
                    .config
                    .get(&plaintext_field.secret_path)
                    .ok_or_else(|| {
                        AlloyError::InvalidConfiguration{msg: format!(
                            "Provided secret path `{}` does not exist in the deterministic configuration.",
                            &plaintext_field.secret_path.0
                        )}
                    })?;
                let RotatableSecret {
                    current_secret,
                    in_rotation_secret,
                } = secret.as_ref();
                if current_secret.is_none() && in_rotation_secret.is_none() {
                    Err(AlloyError::InvalidConfiguration{msg: format!(
                        "No secrets exist in the deterministic configuration for secret path `{}`.",
                        plaintext_field.secret_path.0
                    )})?;
                }
                current_secret
                    .iter()
                    .chain(in_rotation_secret)
                    .map(|standalone_secret| {
                        let key = DeterministicEncryptionKey::derive_from_secret(
                            standalone_secret.secret.as_ref(),
                            &metadata.tenant_id,
                            &plaintext_field.derivation_path,
                        );
                        let key_id_header = Self::create_key_id_header(standalone_secret.id);
                        encrypt_internal(
                            key,
                            key_id_header,
                            plaintext_field.clone(),
                        )
                    })
                    .try_collect()
                    .map(|enc| (field_id, enc))
            })
            .try_collect()
    }

    /// Re-encrypt already encrypted fields with the Current key for the provided tenant. The `metadata` passed
    /// must contain the tenant ID that the fields were originally encrypted to. If `new_tenant_id` is empty,
    /// the fields will simply be encrypted with the same tenant's current secret.
    async fn rotate_fields(
        &self,
        encrypted_fields: EncryptedFields,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<DeterministicRotateResult, AlloyError> {
        let parsed_new_tenant_id = new_tenant_id.as_ref().unwrap_or(&metadata.tenant_id);
        let reencrypt_field = |encrypted_field: EncryptedField| {
            let (key_id, _) =
                Self::decompose_key_id_header(encrypted_field.encrypted_field.clone())?;
            let maybe_new_secret = &self
                .config
                .get(&encrypted_field.secret_path)
                .ok_or_else(|| {
                    AlloyError::InvalidConfiguration{msg: format!(
                        "Provided secret path `{}` does not exist in the deterministic configuration.",
                        &encrypted_field.secret_path.0
                    )}
                })?.current_secret;
            if check_rotation_no_op(
                key_id,
                &maybe_new_secret.as_ref().map(|k| k.id),
                parsed_new_tenant_id,
                metadata,
            ) {
                Ok(encrypted_field)
            } else {
                self.decrypt_sync(encrypted_field, &metadata.tenant_id)
                    .and_then(|decrypted_field| {
                        self.encrypt_sync(decrypted_field, parsed_new_tenant_id)
                    })
            }
        };
        Ok(collection_to_batch_result(encrypted_fields, reencrypt_field).into())
    }

    /// Generate a prefix that could used to search a data store for fields encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        _derivation_path: DerivationPath,
        _metadata: &AlloyMetadata,
    ) -> Result<Vec<u8>, AlloyError> {
        let secret =
            self.config
                .get(&secret_path)
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: format!(
                "Provided secret path `{}` does not exist in the deterministic configuration.",
                &secret_path.0
            ),
                })?;
        let in_rotation_secret =
            secret
                .in_rotation_secret
                .as_ref()
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: format!(
                "There is no in-rotation secret for path `{}` in the deterministic configuration.",
                secret_path.0
            ),
                })?;
        let key_id_header = Self::create_key_id_header(in_rotation_secret.id);
        Ok(
            ironcore_documents::v5::key_id_header::get_prefix_bytes_for_search(key_id_header)
                .into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        standalone::config::StandaloneSecret, tests::get_metadata, DerivationPath, Secret,
    };
    use assertables::*;
    use hex_literal::hex;

    fn get_default_client() -> StandaloneDeterministicClient {
        let secret = Secret {
            secret: vec![
                69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150, 190,
                245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
            ],
        };
        let standalone_secret = StandaloneSecret {
            id: 1,
            secret: Arc::new(secret),
        };
        let rotatable_secret = RotatableSecret {
            current_secret: Some(Arc::new(standalone_secret)),
            in_rotation_secret: None,
        };

        StandaloneDeterministicClient {
            config: Arc::new(
                [(
                    SecretPath("secret_path".to_string()),
                    Arc::new(rotatable_secret),
                )]
                .into(),
            ),
        }
    }

    #[tokio::test]
    async fn encrypt_document_deterministic_roundtrip() {
        let client = get_default_client();
        let field = PlaintextField {
            plaintext_field: vec![1, 2, 3],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let encrypted = client
            .encrypt(field.clone(), &get_metadata())
            .await
            .unwrap();
        let decrypted = client.decrypt(encrypted, &get_metadata()).await.unwrap();
        assert_eq!(decrypted.plaintext_field, field.plaintext_field);
    }

    #[tokio::test]
    async fn document_deterministic_decrypt_known_bytes() {
        let client = get_default_client();
        let expected = vec![1, 2, 3];
        let encrypted = EncryptedField {
            encrypted_field: vec![
                0, 0, 0, 1, 128, 0, 44, 194, 55, 224, 251, 64, 34, 109, 10, 77, 197, 32, 11, 224,
                51, 154, 218, 130, 209,
            ],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let decrypted = client.decrypt(encrypted, &get_metadata()).await.unwrap();
        assert_eq!(decrypted.plaintext_field, expected);
    }

    #[tokio::test]
    async fn document_deterministic_decrypt_fails_on_invalid_header() {
        let client = get_default_client();
        let encrypted = EncryptedField {
            encrypted_field: hex!("00000000009b5a29b8c370b42ded7b8926265d07adb50f2d").to_vec(),
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let error = client
            .decrypt(encrypted, &get_metadata())
            .await
            .unwrap_err();
        assert_contains!(error.to_string(), "Encrypted header was invalid");
    }

    #[tokio::test]
    async fn document_deterministic_decrypt_fails_on_too_short() {
        let client = get_default_client();
        let encrypted = EncryptedField {
            encrypted_field: hex!("00").to_vec(),
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };

        let error = client
            .decrypt(encrypted, &get_metadata())
            .await
            .unwrap_err();
        assert_contains!(error.to_string(), "Encrypted header was invalid");
    }
}
