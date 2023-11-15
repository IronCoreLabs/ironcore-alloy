use super::{
    derive_key_for_path, derive_keys_many_paths, derived_key_to_vector_encryption_key,
    get_in_rotation_prefix_internal, DeriveKeyChoice,
};
use crate::errors::AlloyError;
use crate::tenant_security_client::{DerivationType, SecretType, TenantSecurityClient};
use crate::util::{get_rng, OurReseedingRng};
use crate::vector::{
    decrypt_internal, encrypt_internal, EncryptedVector, GenerateQueryResult, PlaintextVector,
    PlaintextVectors, VectorOps,
};
use crate::{DerivationPath, IronCoreMetadata, SecretPath, VectorEncryptionKey};
use ironcore_documents::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
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

    /// Encrypts a plaintext vector with the provided key/ID
    fn encrypt_core(
        &self,
        key: &VectorEncryptionKey,
        key_id: KeyId,
        plaintext_vector: PlaintextVector,
    ) -> Result<EncryptedVector, AlloyError> {
        let approximation_factor = self.approximation_factor.ok_or_else(|| {
            AlloyError::InvalidConfiguration(
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
                SecretType::Vector,
            )
            .await?;
        let derived_key = derive_key_for_path(
            &derived_keys,
            &plaintext_vector.secret_path,
            &plaintext_vector.derivation_path,
            DeriveKeyChoice::Current,
        )
        .await?;
        let (key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
        self.encrypt_core(&key, key_id, plaintext_vector)
    }

    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextVector, AlloyError> {
        let approximation_factor = self.approximation_factor.ok_or_else(|| {
            AlloyError::InvalidConfiguration(
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
        .map_err(|_| {
            AlloyError::InvalidInput("Paired ICL info couldn't be decoded.".to_string())
        })?;

        if edek_type == Self::get_edek_type() && payload_type == Self::get_payload_type() {
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
                    SecretType::Vector,
                )
                .await?;
            let derived_key = derive_key_for_path(
                &derived_keys,
                &encrypted_vector.secret_path,
                &encrypted_vector.derivation_path,
                DeriveKeyChoice::Specific(key_id),
            )
            .await?;
            let (derived_key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
            if derived_key_id != key_id {
                Err(AlloyError::InvalidKey(
                    "The key ID in the paired ICL info and on the key derived for decryption did not match"
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
            Err(AlloyError::InvalidInput(
                format!("The data indicated that this was not a SaaS Shield Vector wrapped value. Found: {edek_type}, {payload_type}"),
            ))
        }
    }

    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &IronCoreMetadata,
    ) -> Result<GenerateQueryResult, AlloyError> {
        let paths = vectors_to_query
            .values()
            .map(|vector| (vector.secret_path.clone(), vector.derivation_path.clone()))
            .collect_vec();
        let all_keys = derive_keys_many_paths(
            &self.tenant_security_client,
            &metadata.clone(),
            paths,
            SecretType::Vector,
        )
        .await?;
        vectors_to_query
            .into_iter()
            .map(|(vector_id, plaintext_vector)| {
                let keys = all_keys
                    .get(&plaintext_vector.secret_path)
                    .and_then(|deriv| deriv.get(&plaintext_vector.derivation_path))
                    .ok_or(AlloyError::TenantSecurityError(
                        "Failed to derive keys for provided path using the TSP.".to_string(),
                    ))?;
                keys.iter()
                    .map(|derived_key| {
                        let (key_id, key) = derived_key_to_vector_encryption_key(derived_key)?;
                        self.encrypt_core(&key, key_id, plaintext_vector.clone())
                    })
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
    ) -> Result<Vec<u8>, AlloyError> {
        let paths = [(secret_path.clone(), [derivation_path.clone()].into())].into();
        let derived_keys = self
            .tenant_security_client
            .tenant_key_derive(
                paths,
                &metadata.clone().try_into()?,
                DerivationType::Sha512,
                SecretType::Vector,
            )
            .await?;
        get_in_rotation_prefix_internal(
            &derived_keys,
            secret_path,
            derivation_path,
            Self::get_edek_type(),
            Self::get_payload_type(),
        )
        .await
    }
}
