use super::{derive_keys_for_path, derive_keys_many_paths, DeriveKeyChoice};
use crate::errors::CloakedAiError;
use crate::tenant_security_client::{SecretType, TenantSecurityClient};
use crate::util::{get_rng, OurReseedingRng};
use crate::vector::crypto::shuffle;
use crate::vector::{
    crypto, decrypt_internal, encrypt_internal, EncryptedVector, GenerateQueryBatchResult,
    PlaintextVector, PlaintextVectors, VectorOps,
};
use crate::{DerivationPath, IronCoreMetadata, Key, SaasShieldConfiguration, SecretPath};
use ironcore_documents::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct SaasShieldVectorClient {
    approximation_factor: Option<f32>,
    tsc: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

impl SaasShieldVectorClient {
    pub(crate) fn new(
        client: Arc<TenantSecurityClient>,
        approximation_factor: Option<f32>,
    ) -> Self {
        SaasShieldVectorClient {
            approximation_factor,
            tsc: client.clone(),
            rng: crate::util::create_reseeding_rng(),
        }
    }

    /// Encrypts a plaintext vector with the provided key/ID
    fn encrypt_core(
        &self,
        key: &Key,
        key_id: KeyId,
        plaintext_vector: PlaintextVector,
    ) -> Result<EncryptedVector, CloakedAiError> {
        let approximation_factor = self.approximation_factor.ok_or_else(|| {
            CloakedAiError::InvalidConfiguration(
                "`approximation_factor` was not set in the vector configuration.".to_string(),
            )
        })?;
        encrypt_internal(
            approximation_factor,
            key,
            key_id,
            Self::get_edek_type(),
            plaintext_vector,
            &mut *get_rng(&self.rng),
        )
    }

    fn get_edek_type() -> EdekType {
        EdekType::SaasShield
    }
    fn get_payload_type() -> PayloadType {
        PayloadType::VectorMetadata
    }
}

#[uniffi::export]
impl VectorOps for SaasShieldVectorClient {
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &IronCoreMetadata,
    ) -> Result<EncryptedVector, CloakedAiError> {
        let (key_id, key) = derive_keys_for_path(
            &self.tsc,
            metadata,
            &plaintext_vector.secret_path,
            &plaintext_vector.derivation_path,
            DeriveKeyChoice::Current,
            SecretType::Vector,
        )
        .await?;
        self.encrypt_core(&key, key_id, plaintext_vector)
    }

    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextVector, CloakedAiError> {
        let approximation_factor = self.approximation_factor.ok_or_else(|| {
            CloakedAiError::InvalidConfiguration(
                "`approximation_factor` was not set in the vector configuration.".to_string(),
            )
        })?;
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
        .map_err(|_| CloakedAiError::InvalidIv)?; //COLT: Error

        if edek_type == Self::get_edek_type() && payload_type == Self::get_payload_type() {
            let (derived_key_id, key) = derive_keys_for_path(
                &self.tsc,
                metadata,
                &encrypted_vector.secret_path,
                &encrypted_vector.derivation_path,
                DeriveKeyChoice::Specific(key_id),
                SecretType::Vector,
            )
            .await?;
            if derived_key_id != key_id {
                Err(CloakedAiError::InvalidKey(
                    "The key id on the icl_metadata and from the derivation did not match."
                        .to_string(),
                ))
            } else {
                decrypt_internal(
                    approximation_factor,
                    &key,
                    encrypted_vector,
                    icl_metadata_bytes,
                )
            }
        } else {
            Err(CloakedAiError::InvalidInput(
                "The data indicated that this was not a Saas Shield wrapped value.".to_string(),
            ))
        }
    }

    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &IronCoreMetadata,
    ) -> Result<GenerateQueryBatchResult, CloakedAiError> {
        let paths = vectors_to_query
            .values()
            .map(|vector| (vector.secret_path.clone(), vector.derivation_path.clone()))
            .collect_vec();
        let all_keys =
            derive_keys_many_paths(&self.tsc, &metadata.clone(), paths, SecretType::Vector).await?;
        vectors_to_query
            .into_iter()
            .map(|(vector_id, plaintext_vector)| {
                let keys = all_keys
                    .get(&plaintext_vector.secret_path)
                    .and_then(|deriv| deriv.get(&plaintext_vector.derivation_path))
                    .ok_or(CloakedAiError::TenantSecurityError(
                        "TSC failed to derive keys for provided path.".to_string(),
                    ))?;
                keys.iter()
                    .map(|(key_id, key)| self.encrypt_core(key, *key_id, plaintext_vector.clone()))
                    .try_collect()
                    .map(|enc| (vector_id, enc))
            })
            .collect()
    }

    /// Get the byte prefix for the InRotation secret corresponding to this secret_path/derivation_path.
    /// Note that if you use z85 or ascii85 encoding, the result of this function should be passed to `base85_compat_prefix_bytes`
    /// before searching your datastore.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        derivation_path: DerivationPath,
        metadata: &IronCoreMetadata,
    ) -> Result<Vec<u8>, CloakedAiError> {
        let (in_rotation_key_id, _) = derive_keys_for_path(
            &self.tsc,
            metadata,
            &secret_path,
            &derivation_path,
            DeriveKeyChoice::InRotation,
            SecretType::Vector,
        )
        .await?;
        Ok(
            ironcore_documents::key_id_header::get_prefix_bytes_for_search(KeyIdHeader::new(
                Self::get_edek_type(),
                Self::get_payload_type(),
                in_rotation_key_id,
            ))
            .into(),
        )
    }
}
