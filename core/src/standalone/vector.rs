use super::config::VectorSecret;
use crate::errors::CloakedAiError;
use crate::standalone::config::RotatableSecret;
use crate::util::get_rng;
use crate::vector::{
    decrypt_internal, encrypt_internal, EncryptedVector, GenerateQueryBatchResult, PlaintextVector,
    PlaintextVectors, VectorOps,
};
use crate::{DerivationPath, IronCoreMetadata, Key, SecretPath, StandaloneConfiguration};
use ironcore_documents::key_id_header::{self, EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct StandaloneVectorClient {
    config: Arc<HashMap<SecretPath, Arc<VectorSecret>>>,
    rng: Arc<Mutex<ChaCha20Rng>>,
}
impl StandaloneVectorClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        Self {
            config: config.vector.clone(),
            rng: Arc::new(Mutex::new(ChaCha20Rng::from_entropy())),
        }
    }

    /// The edek type for this client
    fn get_edek_type() -> EdekType {
        EdekType::Standalone
    }

    /// The payload type for this client
    fn get_payload_type() -> PayloadType {
        PayloadType::VectorMetadata
    }
}

#[uniffi::export]
impl VectorOps for StandaloneVectorClient {
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &IronCoreMetadata,
    ) -> Result<EncryptedVector, CloakedAiError> {
        let vector_secret = self
            .config
            .get(&plaintext_vector.secret_path)
            .ok_or_else(|| {
                CloakedAiError::InvalidConfiguration(format!(
                    "Provided secret path `{}` does not exist in the vector configuration.",
                    &plaintext_vector.secret_path.0
                ))
            })?;
        let standalone_secret = vector_secret
            .secret
            .current_secret
            .as_ref()
            .ok_or_else(|| {
                CloakedAiError::InvalidConfiguration(
                    "No current secret exists in the vector configuration".to_string(),
                )
            })?;
        let key = Key::derive_from_secret(
            standalone_secret.secret.as_ref(),
            &metadata.tenant_id,
            &plaintext_vector.derivation_path,
        );
        encrypt_internal(
            vector_secret.approximation_factor,
            &key,
            KeyId(standalone_secret.id),
            Self::get_edek_type(),
            plaintext_vector,
            &mut *get_rng(&self.rng),
        )
    }

    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextVector, CloakedAiError> {
        let (
            KeyIdHeader {
                key_id,
                edek_type,
                payload_type,
            },
            icl_metadata_bytes,
        ) = ironcore_documents::key_id_header::decode_version_prefixed_value(
            encrypted_vector.paired_icl_info.clone().into(),
        )
        .map_err(|_| CloakedAiError::InvalidInput("Paired ICL info was invalid.".to_string()))?;
        if edek_type == Self::get_edek_type() && payload_type == Self::get_payload_type() {
            let vector_secret =
                self.config
                    .get(&encrypted_vector.secret_path)
                    .ok_or_else(|| {
                        CloakedAiError::InvalidConfiguration(format!(
                            "Provided secret path `{}` does not exist in the vector configuration.",
                            &encrypted_vector.secret_path.0
                        ))
                    })?;
            let standalone_secret = vector_secret
                .secret
                .get_secret_with_id(&key_id)
                .ok_or_else(|| {
                    CloakedAiError::InvalidConfiguration(format!(
                        "Secret with key ID `{}` does not exist in the vector configuration",
                        key_id.0
                    ))
                })?;
            let key = Key::derive_from_secret(
                standalone_secret.secret.as_ref(),
                &metadata.tenant_id,
                &encrypted_vector.derivation_path,
            );
            decrypt_internal(
                vector_secret.approximation_factor,
                &key,
                encrypted_vector,
                icl_metadata_bytes,
            )
        } else {
            Err(CloakedAiError::InvalidIv) // COLT: Error type
        }
    }

    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &IronCoreMetadata,
    ) -> Result<GenerateQueryBatchResult, CloakedAiError> {
        vectors_to_query
            .into_iter()
            .map(|(vector_id, plaintext_vector)| {
                let vector_secret =
                    self.config
                        .get(&plaintext_vector.secret_path)
                        .ok_or_else(|| {
                            CloakedAiError::InvalidConfiguration(format!(
                            "Provided secret path `{}` does not exist in the vector configuration.",
                            &plaintext_vector.secret_path.0
                        ))
                        })?;
                let RotatableSecret {
                    current_secret,
                    in_rotation_secret,
                } = vector_secret.secret.as_ref();
                if current_secret.is_none() && in_rotation_secret.is_none() {
                    Err(CloakedAiError::InvalidConfiguration(format!(
                        "No secrets exist in the vector configuration for secret path `{}`.",
                        plaintext_vector.secret_path.0
                    )))?;
                }
                current_secret
                    .iter()
                    .chain(in_rotation_secret)
                    .map(|standalone_secret| {
                        let key = Key::derive_from_secret(
                            standalone_secret.secret.as_ref(),
                            &metadata.tenant_id,
                            &plaintext_vector.derivation_path,
                        );
                        encrypt_internal(
                            vector_secret.approximation_factor,
                            &key,
                            KeyId(standalone_secret.id),
                            StandaloneVectorClient::get_edek_type(),
                            plaintext_vector.clone(),
                            &mut *get_rng(&self.rng),
                        )
                    })
                    .try_collect()
                    .map(|enc| (vector_id, enc))
            })
            .try_collect()
    }

    // TODO: Discuss if we want to make this function less consistent to avoid passing useless values.
    /// Get the byte prefix for the InRotation secret corresponding to this secret_path.
    /// Note that if you use z85 or ascii85 encoding, the result of this function should be passed to `base85_compat_prefix_bytes`
    /// before searching your datastore.
    /// Note: The derivation_path and metadata are not actually required for this function and can be passed any value.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        _derivation_path: DerivationPath,
        _metadata: &IronCoreMetadata,
    ) -> Result<Vec<u8>, CloakedAiError> {
        let vector_secret = self.config.get(&secret_path).ok_or_else(|| {
            CloakedAiError::InvalidConfiguration(format!(
                "Provided secret path `{}` does not exist in the vector configuration.",
                &secret_path.0
            ))
        })?;
        let in_rotation_secret = vector_secret
            .secret
            .in_rotation_secret
            .as_ref()
            .ok_or_else(|| {
                CloakedAiError::InvalidConfiguration(
                    "There is no in-rotation secret in the vector configuration.".to_string(),
                )
            })?;
        Ok(
            ironcore_documents::key_id_header::get_prefix_bytes_for_search(KeyIdHeader::new(
                Self::get_edek_type(),
                Self::get_payload_type(),
                KeyId(in_rotation_secret.id),
            ))
            .into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tenant_security_client::{IclFields, RequestingId};
    use crate::TenantId;
    use crate::{standalone::config::StandaloneSecret, Secret};
    use approx::assert_ulps_eq;

    fn get_default_cloaked_ai() -> StandaloneVectorClient {
        let k = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
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

        let vector_secret = VectorSecret {
            approximation_factor: 4.0f32,
            secret: Arc::new(rotatable_secret),
        };

        StandaloneVectorClient {
            rng: Arc::new(Mutex::new(k)),
            config: Arc::new(
                [(
                    SecretPath("secret_path".to_string()),
                    Arc::new(vector_secret),
                )]
                .into(),
            ),
        }
    }

    fn get_metadata() -> Arc<IronCoreMetadata> {
        IronCoreMetadata::new_simple(TenantId("foo".to_string()))
    }

    #[tokio::test]
    async fn encrypt_produces_known_value() {
        let cloaked_ai = get_default_cloaked_ai();
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let result = cloaked_ai
            .encrypt(plaintext, &get_metadata())
            .await
            .unwrap();
        assert_eq!(
            result.encrypted_vector.to_vec(),
            vec![13681085.0, 42081104.0, 82401560.0, 19847844.0, 60127316.0]
        );
        assert_eq!(
            result.paired_icl_info,
            [
                0, 0, 0, 1, 129, 0, 10, 12, 154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161,
                18, 32, 125, 78, 5, 108, 187, 19, 103, 206, 124, 199, 184, 212, 208, 35, 61, 45, 6,
                130, 55, 85, 125, 210, 5, 126, 145, 45, 240, 250, 63, 45, 168, 104
            ]
        );
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let cloaked_ai = get_default_cloaked_ai();
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let encrypt_result = cloaked_ai
            .encrypt(plaintext.clone(), &get_metadata())
            .await
            .unwrap();
        let result = cloaked_ai
            .decrypt(encrypt_result, &get_metadata())
            .await
            .unwrap();
        assert_ulps_eq!(result.plaintext_vector[..], plaintext.plaintext_vector[..]);
    }
}
