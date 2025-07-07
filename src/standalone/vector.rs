use super::config::VectorSecret;
use crate::alloy_client_trait::DecomposedHeader;
use crate::errors::AlloyError;
use crate::standalone::config::RotatableSecret;
use crate::util::{self, OurReseedingRng, perform_batch_action};
use crate::vector::{
    EncryptedVector, EncryptedVectors, GenerateVectorQueryResult, PlaintextVector,
    PlaintextVectors, VectorDecryptBatchResult, VectorEncryptBatchResult, VectorEncryptionKey,
    VectorOps, VectorRotateResult, decrypt_internal, encrypt_internal,
};
use crate::{
    AlloyMetadata, DerivationPath, SecretPath, StandaloneConfiguration, TenantId,
    alloy_client_trait::AlloyClient,
};
use ironcore_documents::v5::key_id_header::{EdekType, KeyId, PayloadType};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct StandaloneVectorClient {
    config: Arc<HashMap<SecretPath, Arc<VectorSecret>>>,
    rng: Arc<Mutex<OurReseedingRng>>,
}
impl StandaloneVectorClient {
    pub(crate) fn new(config: StandaloneConfiguration) -> Self {
        Self {
            config: config.vector.clone(),
            rng: util::create_rng_maybe_seeded(config.test_rng_seed),
        }
    }
    pub(crate) fn rotate_vector(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &AlloyMetadata,
        new_metadata: &AlloyMetadata,
    ) -> Result<EncryptedVector, AlloyError> {
        let DecomposedHeader {
            key_id: original_key_id,
            ..
        } = self.decompose_key_id_header(encrypted_vector.paired_icl_info.clone())?;

        // check if we have a current secret for this path before doing significant work
        // and that the current secret isn't the one this was encrypted with
        let vector_secret = self
            .config
            .get(&encrypted_vector.secret_path)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Provided secret path `{}` does not exist in the vector configuration.",
                    &encrypted_vector.secret_path.0
                ),
            })?;
        let standalone_secret = vector_secret
            .secret
            .current_secret
            .as_ref()
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: "No current secret exists in the vector configuration".to_string(),
            })?;

        if original_key_id.0 == standalone_secret.id && metadata.tenant_id == new_metadata.tenant_id
        {
            Ok(encrypted_vector)
        } else {
            self.decrypt_sync(encrypted_vector, metadata)
                .and_then(|decrypted_vector| self.encrypt_sync(decrypted_vector, new_metadata))
        }
    }

    fn encrypt_sync(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedVector, AlloyError> {
        let vector_secret = self
            .config
            .get(&plaintext_vector.secret_path)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Provided secret path `{}` does not exist in the vector configuration.",
                    &plaintext_vector.secret_path.0
                ),
            })?;
        let standalone_secret = vector_secret
            .secret
            .current_secret
            .as_ref()
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: "No current secret exists in the vector configuration".to_string(),
            })?;
        let key = VectorEncryptionKey::derive_from_secret(
            standalone_secret.secret.as_ref(),
            &metadata.tenant_id,
            &plaintext_vector.derivation_path,
        );
        encrypt_internal(
            vector_secret.approximation_factor,
            &key,
            KeyId(standalone_secret.id),
            self.get_edek_type(),
            plaintext_vector,
            self.rng.clone(),
            vector_secret.use_scaling_factor,
        )
    }

    fn decrypt_sync(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextVector, AlloyError> {
        let DecomposedHeader {
            key_id,
            remaining_bytes: icl_metadata_bytes,
        } = self.decompose_key_id_header(encrypted_vector.paired_icl_info.clone())?;
        let vector_secret = self
            .config
            .get(&encrypted_vector.secret_path)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Provided secret path `{}` does not exist in the vector configuration.",
                    &encrypted_vector.secret_path.0
                ),
            })?;
        let standalone_secret = vector_secret
            .secret
            .get_secret_with_id(&key_id)
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: format!(
                    "Secret with key ID `{}` does not exist in the vector configuration",
                    key_id.0
                ),
            })?;
        let use_scaling_factor = vector_secret.use_scaling_factor;
        let key = VectorEncryptionKey::derive_from_secret(
            standalone_secret.secret.as_ref(),
            &metadata.tenant_id,
            &encrypted_vector.derivation_path,
        );
        decrypt_internal(
            vector_secret.approximation_factor,
            &key,
            encrypted_vector,
            icl_metadata_bytes.into(),
            use_scaling_factor,
        )
    }
}

impl AlloyClient for StandaloneVectorClient {
    fn get_edek_type(&self) -> EdekType {
        EdekType::Standalone
    }

    fn get_payload_type(&self) -> PayloadType {
        PayloadType::VectorMetadata
    }
}

#[uniffi::export]
#[async_trait::async_trait]
impl VectorOps for StandaloneVectorClient {
    /// Encrypt a vector embedding with the provided metadata. The provided embedding is assumed to be normalized
    /// and its values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embedding.
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedVector, AlloyError> {
        self.encrypt_sync(plaintext_vector, metadata)
    }

    /// Encrypt multiple vector embeddings with the provided metadata. The provided embeddings are assumed to be normalized
    /// and their values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embeddings.
    async fn encrypt_batch(
        &self,
        plaintext_vectors: PlaintextVectors,
        metadata: &AlloyMetadata,
    ) -> Result<VectorEncryptBatchResult, AlloyError> {
        let batch_result = perform_batch_action(plaintext_vectors.0, |plaintext_vector| {
            self.encrypt_sync(plaintext_vector, metadata)
        });
        Ok(VectorEncryptBatchResult {
            successes: EncryptedVectors(batch_result.successes),
            failures: batch_result.failures,
        })
    }

    /// Decrypt a vector embedding that was encrypted with the provided metadata. The values of the embedding will
    /// be unshuffled to their original positions during decryption.
    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextVector, AlloyError> {
        self.decrypt_sync(encrypted_vector, metadata)
    }

    /// Decrypt multiple vector embeddings that were encrypted with the provided metadata. The values of the embeddings
    /// will be unshuffled to their original positions during decryption.
    /// Note that because the metadata is shared between the vectors, they all must correspond to the
    /// same tenant ID.
    async fn decrypt_batch(
        &self,
        encrypted_vectors: EncryptedVectors,
        metadata: &AlloyMetadata,
    ) -> Result<VectorDecryptBatchResult, AlloyError> {
        let batch_result = perform_batch_action(encrypted_vectors.0, |encrypted_vector| {
            self.decrypt_sync(encrypted_vector, metadata)
        });
        Ok(VectorDecryptBatchResult {
            successes: PlaintextVectors(batch_result.successes),
            failures: batch_result.failures,
        })
    }

    /// Encrypt each plaintext vector with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted vectors should be used in tandem when querying the vector database.
    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &AlloyMetadata,
    ) -> Result<GenerateVectorQueryResult, AlloyError> {
        vectors_to_query
            .0
            .into_iter()
            .map(|(vector_id, plaintext_vector)| {
                let vector_secret = self.config.get(&plaintext_vector.secret_path).ok_or_else(
                    || AlloyError::InvalidConfiguration {
                        msg: format!(
                            "Provided secret path `{}` does not exist in the vector configuration.",
                            &plaintext_vector.secret_path.0
                        ),
                    },
                )?;
                let RotatableSecret {
                    current_secret,
                    in_rotation_secret,
                } = vector_secret.secret.as_ref();
                if current_secret.is_none() && in_rotation_secret.is_none() {
                    Err(AlloyError::InvalidConfiguration {
                        msg: format!(
                            "No secrets exist in the vector configuration for secret path `{}`.",
                            plaintext_vector.secret_path.0
                        ),
                    })?;
                }
                current_secret
                    .iter()
                    .chain(in_rotation_secret)
                    .map(|standalone_secret| {
                        let key = VectorEncryptionKey::derive_from_secret(
                            standalone_secret.secret.as_ref(),
                            &metadata.tenant_id,
                            &plaintext_vector.derivation_path,
                        );
                        encrypt_internal(
                            vector_secret.approximation_factor,
                            &key,
                            KeyId(standalone_secret.id),
                            EdekType::Standalone,
                            plaintext_vector.clone(),
                            self.rng.clone(),
                            vector_secret.use_scaling_factor,
                        )
                    })
                    .try_collect()
                    .map(|enc| (vector_id, enc))
            })
            .try_collect()
            .map(GenerateVectorQueryResult)
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
        _metadata: &AlloyMetadata,
    ) -> Result<Vec<u8>, AlloyError> {
        let vector_secret =
            self.config
                .get(&secret_path)
                .ok_or_else(|| AlloyError::InvalidConfiguration {
                    msg: format!(
                        "Provided secret path `{}` does not exist in the vector configuration.",
                        &secret_path.0
                    ),
                })?;
        let in_rotation_secret = vector_secret
            .secret
            .in_rotation_secret
            .as_ref()
            .ok_or_else(|| AlloyError::InvalidConfiguration {
                msg: "There is no in-rotation secret in the vector configuration.".to_string(),
            })?;
        let key_id_header = self.create_key_id_header(in_rotation_secret.id);
        Ok(
            ironcore_documents::v5::key_id_header::get_prefix_bytes_for_search(key_id_header)
                .into(),
        )
    }

    /// Rotates vectors from the in-rotation secret for their secret path to the current secret.
    /// This can also be used to rotate data from one tenant ID to a new one, which most useful when a tenant is
    /// internally migrated.
    ///
    /// WARNINGS:
    ///     * this involves decrypting then encrypting vectors. Since the vectors are full of floating point numbers,
    ///       this process is lossy, which will cause some drift over time. If you need perfectly preserved accuracy
    ///       store the source vector encrypted with `standard` next to the encrypted vector. `standard` decrypt
    ///       that, `vector` encrypt it again, and replace the encrypted vector with the result.
    ///     * only one metadata and new tenant ID argument means each call to this needs to have one tenant's vectors.
    async fn rotate_vectors(
        &self,
        encrypted_vectors: EncryptedVectors,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<VectorRotateResult, AlloyError> {
        let new_metadata = match new_tenant_id {
            None => metadata.clone(),
            Some(tenant_id) => AlloyMetadata {
                tenant_id: tenant_id.clone(),
                ..metadata.clone()
            },
        };
        Ok(
            perform_batch_action(encrypted_vectors.0, |encrypted_vector| {
                self.rotate_vector(encrypted_vector, metadata, &new_metadata)
            })
            .into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TenantId;
    use crate::vector::VectorId;
    use crate::{Secret, standalone::config::{StandaloneSecret, StandardSecrets}};
    use approx::assert_ulps_eq;

    fn get_default_client() -> StandaloneVectorClient {
        let k = util::create_test_seeded_rng(1);
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
            use_scaling_factor: true,
        };

        StandaloneVectorClient {
            rng: k,
            config: Arc::new(
                [(
                    SecretPath("secret_path".to_string()),
                    Arc::new(vector_secret),
                )]
                .into(),
            ),
        }
    }

    fn get_in_rotation_client() -> StandaloneVectorClient {
        let rng = util::create_test_seeded_rng(1u64);
        let old_secret = Secret {
            secret: vec![
                69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150, 190,
                245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
            ],
        };
        let new_secret = Secret {
            secret: vec![
                171, 125, 247, 37, 75, 62, 23, 74, 77, 97, 196, 201, 226, 1, 171, 94, 17, 169, 175,
                52, 231, 241, 99, 6, 164, 181, 147, 86, 17, 110, 127, 218,
            ],
        };
        let old_standalone_secret = StandaloneSecret {
            id: 1,
            secret: Arc::new(old_secret),
        };
        let new_standalone_secret = StandaloneSecret {
            id: 2,
            secret: Arc::new(new_secret),
        };
        let rotatable_secret = RotatableSecret {
            current_secret: Some(Arc::new(new_standalone_secret)),
            in_rotation_secret: Some(Arc::new(old_standalone_secret)),
        };

        let vector_secret = VectorSecret {
            approximation_factor: 4.0f32,
            secret: Arc::new(rotatable_secret),
            use_scaling_factor: true,
        };

        StandaloneVectorClient {
            rng,
            config: Arc::new(
                [(
                    SecretPath("secret_path".to_string()),
                    Arc::new(vector_secret),
                )]
                .into(),
            ),
        }
    }

    fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("foo".to_string()))
    }

    #[tokio::test]
    async fn encrypt_produces_known_value() {
        let ironcore_alloy = get_default_client();
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let result = ironcore_alloy
            .encrypt(plaintext, &get_metadata())
            .await
            .unwrap();
        assert_eq!(
            result.encrypted_vector.to_vec(),
            vec![13681085.0, 42081104.0, 82401560.0, 19847844.0, 60127316.0]
        );
        assert_eq!(
            result.paired_icl_info.0,
            [
                0, 0, 0, 1, 129, 0, 10, 12, 154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161,
                18, 32, 125, 78, 5, 108, 187, 19, 103, 206, 124, 199, 184, 212, 208, 35, 61, 45, 6,
                130, 55, 85, 125, 210, 5, 126, 145, 45, 240, 250, 63, 45, 168, 104
            ]
        );
    }

    #[tokio::test]
    async fn seeded_constructor_produces_known_values() {
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
            use_scaling_factor: true,
        };

        let seeded_config = StandaloneConfiguration::new_seeded_for_testing(
            StandardSecrets::new(None, vec![]).unwrap(),
            Default::default(),
            [(
                SecretPath("secret_path".to_string()),
                Arc::new(vector_secret),
            )]
            .into(),
            1,
        );
        let ironcore_alloy = StandaloneVectorClient::new(Arc::try_unwrap(seeded_config).unwrap());
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let result = ironcore_alloy
            .encrypt(plaintext, &get_metadata())
            .await
            .unwrap();
        assert_eq!(
            result.encrypted_vector.to_vec(),
            vec![13681085.0, 42081104.0, 82401560.0, 19847844.0, 60127316.0]
        );
        assert_eq!(
            result.paired_icl_info.0,
            [
                0, 0, 0, 1, 129, 0, 10, 12, 154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161,
                18, 32, 125, 78, 5, 108, 187, 19, 103, 206, 124, 199, 184, 212, 208, 35, 61, 45, 6,
                130, 55, 85, 125, 210, 5, 126, 145, 45, 240, 250, 63, 45, 168, 104
            ]
        );
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let ironcore_alloy = get_default_client();
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let encrypt_result = ironcore_alloy
            .encrypt(plaintext.clone(), &get_metadata())
            .await
            .unwrap();
        let result = ironcore_alloy
            .decrypt(encrypt_result, &get_metadata())
            .await
            .unwrap();
        assert_ulps_eq!(result.plaintext_vector[..], plaintext.plaintext_vector[..]);
    }

    #[tokio::test]
    async fn rotate_roundtrip() {
        let alloy = get_default_client();
        let new_tenant_id = TenantId("new_tenant".to_string());
        let new_metadata = AlloyMetadata::new_simple(new_tenant_id.clone());
        let plaintext = PlaintextVector {
            plaintext_vector: vec![1., 2., 3., 4., 5.],
            secret_path: SecretPath("secret_path".to_string()),
            derivation_path: DerivationPath("deriv_path".to_string()),
        };
        let encrypt_result = alloy
            .encrypt(plaintext.clone(), &get_metadata())
            .await
            .unwrap();
        let alloy_rotated_secret = get_in_rotation_client();
        let mut rotated_result = alloy_rotated_secret
            .rotate_vectors(
                EncryptedVectors(HashMap::from_iter(
                    vec![(VectorId("one".to_string()), encrypt_result)].into_iter(),
                )),
                &get_metadata(),
                Some(new_tenant_id.clone()),
            )
            .await
            .unwrap();
        assert_eq!(rotated_result.failures, HashMap::new());
        let rotated_vector = rotated_result
            .successes
            .remove(&VectorId("one".to_string()))
            .unwrap();
        // make sure we didn't hallucinate any other vectors
        assert!(rotated_result.successes.is_empty());
        let result = alloy_rotated_secret
            .decrypt(rotated_vector.clone(), &new_metadata)
            .await
            .unwrap();
        assert_ulps_eq!(result.plaintext_vector[..], plaintext.plaintext_vector[..]);

        // the old SDK can't decrypt it, either with the old tenant_id or a new one
        alloy
            .decrypt(rotated_vector.clone(), &get_metadata())
            .await
            .expect_err("the old sdk can't decrypt the rotated value with the old tenant id");
        alloy
            .decrypt(rotated_vector, &new_metadata)
            .await
            .expect_err("the old sdk can't decrypt the value with the new tenant id");
    }
}
