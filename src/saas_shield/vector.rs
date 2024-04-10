use super::{
    derive_keys_many_paths, derived_key_to_vector_encryption_key, get_in_rotation_prefix_internal,
    get_keys_for_rotation, DeriveKeyChoice, RotationKeys, SaasShieldSecurityEventOps,
    SecurityEvent,
};
use crate::alloy_client_trait::AlloyClient;
use crate::errors::AlloyError;
use crate::tenant_security_client::{DerivationType, SecretType, TenantSecurityClient};
use crate::util::{check_rotation_no_op, get_rng, perform_batch_action, OurReseedingRng};
use crate::vector::{
    decrypt_internal, encrypt_internal, get_approximation_factor, EncryptedVector,
    EncryptedVectors, GenerateVectorQueryResult, PlaintextVector, PlaintextVectors,
    VectorDecryptBatchResult, VectorEncryptBatchResult, VectorId, VectorOps, VectorRotateResult,
};
use crate::{AlloyMetadata, DerivationPath, SecretPath, TenantId, VectorEncryptionKey};
use ironcore_documents::v5::key_id_header::{EdekType, KeyId, PayloadType};
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(uniffi::Object)]
pub struct SaasShieldVectorClient {
    approximation_factor: Option<f32>,
    tenant_security_client: Arc<TenantSecurityClient>,
    rng: Arc<Mutex<OurReseedingRng>>,
}

impl SaasShieldVectorClient {
    pub(crate) fn new(
        client: Arc<TenantSecurityClient>,
        approximation_factor: Option<f32>,
    ) -> Self {
        SaasShieldVectorClient {
            approximation_factor,
            tenant_security_client: client.clone(),
            rng: crate::util::create_reseeding_rng(),
        }
    }

    fn get_secret_type() -> SecretType {
        SecretType::Vector
    }

    /// Encrypts a plaintext vector with the provided key/ID
    fn encrypt_core(
        &self,
        key: &VectorEncryptionKey,
        key_id: KeyId,
        plaintext_vector: PlaintextVector,
    ) -> Result<EncryptedVector, AlloyError> {
        let approximation_factor = get_approximation_factor(self.approximation_factor)?;
        encrypt_internal(
            approximation_factor,
            key,
            key_id,
            Self::get_edek_type(),
            plaintext_vector,
            &mut *get_rng(&self.rng),
        )
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SaasShieldSecurityEventOps for SaasShieldVectorClient {
    /// Log the security event `event` to the tenant's log sink.
    /// If the event time is unspecified the current time will be used.
    async fn log_security_event(
        &self,
        event: SecurityEvent,
        metadata: &AlloyMetadata,
        event_time_millis: Option<i64>,
    ) -> Result<(), AlloyError> {
        let request_metadata = (metadata.clone(), event_time_millis).try_into()?;
        self.tenant_security_client
            .log_security_event(&event, &request_metadata)
            .await
    }
}

impl AlloyClient for SaasShieldVectorClient {
    fn get_edek_type() -> EdekType {
        EdekType::SaasShield
    }
    fn get_payload_type() -> PayloadType {
        PayloadType::VectorMetadata
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VectorOps for SaasShieldVectorClient {
    /// Encrypt a vector embedding with the provided metadata. The provided embedding is assumed to be normalized
    /// and its values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embedding.
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &AlloyMetadata,
    ) -> Result<EncryptedVector, AlloyError> {
        let paths = [(
            plaintext_vector.secret_path.clone(),
            [plaintext_vector.derivation_path.clone()].into(),
        )]
        .into();
        let derived_keys = self
            .tenant_security_client
            .tenant_key_derive(
                paths,
                &metadata.clone().try_into()?,
                DerivationType::Sha512,
                Self::get_secret_type(),
            )
            .await?;
        let derived_key = derived_keys.get_key_for_path(
            &plaintext_vector.secret_path,
            &plaintext_vector.derivation_path,
            DeriveKeyChoice::Current,
        )?;
        let (key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
        self.encrypt_core(&key, key_id, plaintext_vector)
    }

    /// Encrypt multiple vector embeddings with the provided metadata. The provided embeddings are assumed to be normalized
    /// and their values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embeddings.
    async fn encrypt_batch(
        &self,
        plaintext_vectors: PlaintextVectors,
        metadata: &AlloyMetadata,
    ) -> Result<VectorEncryptBatchResult, AlloyError> {
        let approximation_factor = get_approximation_factor(self.approximation_factor)?;
        let paths = plaintext_vectors
            .0
            .values()
            .map(|field| (field.secret_path.clone(), field.derivation_path.clone()))
            .collect_vec();
        let all_keys = derive_keys_many_paths(
            &self.tenant_security_client,
            metadata,
            paths,
            Self::get_secret_type(),
        )
        .await?;

        let encrypt_vector = |plaintext_vector: PlaintextVector| {
            let new_derived_key = all_keys.get_key_for_path(
                &plaintext_vector.secret_path,
                &plaintext_vector.derivation_path,
                DeriveKeyChoice::Current,
            )?;
            let (new_key_id, new_vector_key) =
                derived_key_to_vector_encryption_key(new_derived_key)?;
            encrypt_internal(
                approximation_factor,
                &new_vector_key,
                new_key_id,
                Self::get_edek_type(),
                plaintext_vector,
                &mut *get_rng(&self.rng),
            )
        };
        Ok(perform_batch_action(
            plaintext_vectors
                .0
                .into_iter()
                .map(|(k, v)| (VectorId(k), v)),
            encrypt_vector,
        )
        .into())
    }

    /// Decrypt a vector embedding that was encrypted with the provided metadata. The values of the embedding will
    /// be unshuffled to their original positions during decryption.
    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &AlloyMetadata,
    ) -> Result<PlaintextVector, AlloyError> {
        let approximation_factor = get_approximation_factor(self.approximation_factor)?;
        let (key_id, icl_metadata_bytes) =
            Self::decompose_key_id_header(encrypted_vector.paired_icl_info.clone())?;

        let paths = [(
            encrypted_vector.secret_path.clone(),
            [encrypted_vector.derivation_path.clone()].into(),
        )]
        .into();
        let derived_keys = self
            .tenant_security_client
            .tenant_key_derive(
                paths,
                &metadata.clone().try_into()?,
                DerivationType::Sha512,
                Self::get_secret_type(),
            )
            .await?;
        let derived_key = derived_keys.get_key_for_path(
            &encrypted_vector.secret_path,
            &encrypted_vector.derivation_path,
            DeriveKeyChoice::Specific(key_id),
        )?;
        let (derived_key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
        if derived_key_id != key_id {
            Err(AlloyError::InvalidKey{ msg:
                    "The key ID in the paired ICL info and on the key derived for decryption did not match"
                        .to_string(),
        })
        } else {
            decrypt_internal(
                approximation_factor,
                &key,
                encrypted_vector,
                icl_metadata_bytes,
            )
        }
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
        let approximation_factor = get_approximation_factor(self.approximation_factor)?;
        let paths = encrypted_vectors
            .0
            .values()
            .map(|field| (field.secret_path.clone(), field.derivation_path.clone()))
            .collect_vec();
        let all_keys = derive_keys_many_paths(
            &self.tenant_security_client,
            metadata,
            paths,
            Self::get_secret_type(),
        )
        .await?;

        let decrypt_vector = |encrypted_vector: EncryptedVector| {
            let (original_key_id, icl_metadata_bytes) =
                Self::decompose_key_id_header(encrypted_vector.paired_icl_info.clone())?;
            let original_key = all_keys.get_key_for_path(
                &encrypted_vector.secret_path,
                &encrypted_vector.derivation_path,
                DeriveKeyChoice::Specific(original_key_id),
            )?;
            let (_, original_vector_key) = derived_key_to_vector_encryption_key(original_key)?;
            decrypt_internal(
                approximation_factor,
                &original_vector_key,
                encrypted_vector,
                icl_metadata_bytes,
            )
        };
        Ok(perform_batch_action(
            encrypted_vectors
                .0
                .into_iter()
                .map(|(k, v)| (VectorId(k), v)),
            decrypt_vector,
        )
        .into())
    }

    /// Encrypt each plaintext vector with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted vectors should be used in tandem when querying the vector database.
    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &AlloyMetadata,
    ) -> Result<GenerateVectorQueryResult, AlloyError> {
        let paths = vectors_to_query
            .0
            .values()
            .map(|vector| (vector.secret_path.clone(), vector.derivation_path.clone()))
            .collect_vec();
        let all_keys = derive_keys_many_paths(
            &self.tenant_security_client,
            metadata,
            paths,
            Self::get_secret_type(),
        )
        .await?
        .derived_keys;
        vectors_to_query
            .0
            .into_iter()
            .map(|(vector_id, plaintext_vector)| {
                let keys = all_keys
                    .get(&plaintext_vector.secret_path)
                    .and_then(|deriv| deriv.get(&plaintext_vector.derivation_path))
                    .ok_or(AlloyError::RequestError {
                        msg: "Failed to derive keys for provided path using the TSP.".to_string(),
                    })?;
                keys.iter()
                    .map(|derived_key| {
                        let (key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
                        self.encrypt_core(&key, key_id, plaintext_vector.clone())
                    })
                    .try_collect()
                    .map(|enc| (vector_id, enc))
            })
            .collect::<Result<HashMap<_, _>, _>>()
            .map(GenerateVectorQueryResult)
    }

    async fn rotate_vectors(
        &self,
        encrypted_vectors: EncryptedVectors,
        metadata: &AlloyMetadata,
        new_tenant_id: Option<TenantId>,
    ) -> Result<VectorRotateResult, AlloyError> {
        let approximation_factor = get_approximation_factor(self.approximation_factor)?;
        let parsed_new_tenant_id = new_tenant_id.as_ref().unwrap_or(&metadata.tenant_id);
        let paths = encrypted_vectors
            .0
            .values()
            .map(|field| (field.secret_path.clone(), field.derivation_path.clone()))
            .collect_vec();
        let RotationKeys {
            original_keys: original_tenant_keys,
            new_keys: new_tenant_keys,
        } = get_keys_for_rotation(
            metadata,
            parsed_new_tenant_id,
            paths,
            &self.tenant_security_client,
            Self::get_secret_type(),
        )
        .await?;
        let reencrypt_vector = |encrypted_vector: EncryptedVector| {
            let (original_key_id, icl_metadata_bytes) =
                Self::decompose_key_id_header(encrypted_vector.paired_icl_info.clone())?;
            let maybe_current_key_id = new_tenant_keys
                .get_current(
                    &encrypted_vector.secret_path,
                    &encrypted_vector.derivation_path,
                )
                .map(|k| k.tenant_secret_id.0);
            if check_rotation_no_op(
                original_key_id,
                &maybe_current_key_id,
                parsed_new_tenant_id,
                metadata,
            ) {
                Ok(encrypted_vector)
            } else {
                let original_derived_key = original_tenant_keys.get_key_for_path(
                    &encrypted_vector.secret_path,
                    &encrypted_vector.derivation_path,
                    DeriveKeyChoice::Specific(original_key_id),
                )?;
                let (_, original_vector_key) =
                    derived_key_to_vector_encryption_key(original_derived_key)?;
                let decrypted_vector = decrypt_internal(
                    approximation_factor,
                    &original_vector_key,
                    encrypted_vector,
                    icl_metadata_bytes,
                )?;
                let new_derived_key = new_tenant_keys.get_key_for_path(
                    &decrypted_vector.secret_path,
                    &decrypted_vector.derivation_path,
                    DeriveKeyChoice::Current,
                )?;
                let (new_key_id, new_vector_key) =
                    derived_key_to_vector_encryption_key(new_derived_key)?;
                encrypt_internal(
                    approximation_factor,
                    &new_vector_key,
                    new_key_id,
                    Self::get_edek_type(),
                    decrypted_vector,
                    &mut *get_rng(&self.rng),
                )
            }
        };
        Ok(perform_batch_action(encrypted_vectors.0, reencrypt_vector).into())
    }

    /// Get the byte prefix for the InRotation secret corresponding to this secret_path/derivation_path.
    /// Note that if you use z85 or ascii85 encoding, the result of this function should be passed to `base85_compat_prefix_bytes`
    /// before searching your datastore.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        derivation_path: DerivationPath,
        metadata: &AlloyMetadata,
    ) -> Result<Vec<u8>, AlloyError> {
        let paths = [(secret_path.clone(), [derivation_path.clone()].into())].into();
        let derived_keys = self
            .tenant_security_client
            .tenant_key_derive(
                paths,
                &metadata.clone().try_into()?,
                DerivationType::Sha512,
                Self::get_secret_type(),
            )
            .await?;
        get_in_rotation_prefix_internal(
            &derived_keys,
            secret_path,
            derivation_path,
            Self::get_edek_type(),
            Self::get_payload_type(),
        )
    }
}
