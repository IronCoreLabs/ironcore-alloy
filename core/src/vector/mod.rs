use self::crypto::{shuffle, unshuffle, EncryptResult};
use crate::{
    errors::AlloyError,
    util::{self, AuthHash},
    DerivationPath, IronCoreMetadata, Secret, SecretPath, TenantId,
};
use bytes::Bytes;
use ironcore_documents::{
    key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType},
    vector_encryption_metadata::VectorEncryptionMetadata,
};
use itertools::Itertools;
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use std::collections::HashMap;
use uniffi::custom_newtype;

pub(crate) mod crypto;

pub type VectorId = String;

#[derive(uniffi::Record)]
pub struct EncryptedVector {
    pub encrypted_vector: Vec<f32>,
    pub secret_path: SecretPath,
    pub derivation_path: DerivationPath,
    pub paired_icl_info: Vec<u8>,
}

#[derive(Clone, uniffi::Record)]
pub struct PlaintextVector {
    pub plaintext_vector: Vec<f32>,
    pub secret_path: SecretPath,
    pub derivation_path: DerivationPath,
}
pub type PlaintextVectors = HashMap<VectorId, PlaintextVector>;
pub type GenerateQueryResult = HashMap<VectorId, Vec<EncryptedVector>>;

/// Key used to for vector encryption.
#[derive(Debug, Serialize, Clone)]
pub struct VectorEncryptionKey {
    /// The amount to scale embedding values during encryption
    pub scaling_factor: ScalingFactor,
    /// The actual key used for encryption/decryption operations
    pub key: EncryptionKey,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct ScalingFactor(pub f32); // Based on page 135 having a size 2^30
custom_newtype!(ScalingFactor, f32);

#[derive(Debug, Serialize, Clone)]
pub struct EncryptionKey(pub Vec<u8>);
custom_newtype!(EncryptionKey, Vec<u8>);

impl VectorEncryptionKey {
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
        Self::unsafe_bytes_to_key(&hash_result[..])
    }

    /// This function *will* panic on you if the slice is not of size >= 35.
    /// It will take the first 3 bytes and make it into a scaling factor and use the next 32 bytes
    /// as the encryption key. Ensure you've checked the size before calling this.
    pub(crate) fn unsafe_bytes_to_key(key_bytes: &[u8]) -> VectorEncryptionKey {
        let (scaling_factor_bytes, rest) = key_bytes.split_at(3);
        let (key_bytes, _) = rest.split_at(32);
        // Put a 0 on the front so that it's the right number of bytes for `u32::from_be_bytes`
        let scaling_byte_vec = std::iter::once(0)
            .chain(scaling_factor_bytes.iter().cloned())
            .collect_vec();
        let scaling_factor_u32: u32 = u32::from_be_bytes(
            scaling_byte_vec
                .try_into()
                .expect("The vector above is always size 4, so this shouldn't happen."),
        );
        VectorEncryptionKey {
            scaling_factor: ScalingFactor(scaling_factor_u32 as f32),
            key: EncryptionKey(key_bytes.to_vec()),
        }
    }
}

pub trait VectorOps {
    /// Encrypt a vector embedding with the provided metadata. The provided embedding is assumed to be normalized
    /// and its values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embedding.
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &IronCoreMetadata,
    ) -> Result<EncryptedVector, AlloyError>;

    /// Decrypt a vector embedding that was encrypted with the provided metadata. The values of the embedding will
    /// be unshuffled to their original positions during decryption.
    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextVector, AlloyError>;

    /// Encrypt each plaintext vector with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted vectors should be used in tandem when querying the vector database.
    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &IronCoreMetadata,
    ) -> Result<GenerateQueryResult, AlloyError>;

    /// Generate a prefix that could used to search a data store for documents encrypted using an identifier (KMS
    /// config id for SaaS Shield, secret id for Standalone). These bytes should be encoded into
    /// a format matching the encoding in the data store. z85/ascii85 users should first pass these bytes through
    /// `encode_prefix_z85` or `base85_prefix_padding`. Make sure you've read the documentation of those functions to
    /// avoid pitfalls when encoding across byte boundaries.
    async fn get_in_rotation_prefix(
        &self,
        secret_path: SecretPath,
        derivation_path: DerivationPath,
        metadata: &IronCoreMetadata,
    ) -> Result<Vec<u8>, AlloyError>;
}

pub(crate) fn get_iv_and_auth_hash(b: &[u8]) -> Result<([u8; 12], AuthHash), AlloyError> {
    let vector_proto: VectorEncryptionMetadata = protobuf::Message::parse_from_bytes(b)?;
    let iv = vector_proto.iv;
    let auth_hash = vector_proto.auth_hash;
    Ok((
        iv[..]
            .try_into()
            .map_err(|_| AlloyError::DecryptError("Invalid IV".to_string()))?,
        AuthHash(
            auth_hash[..]
                .try_into()
                .map_err(|_| AlloyError::DecryptError("Invalid authentication hash".to_string()))?,
        ),
    ))
}

pub(crate) fn encrypt_internal<R: RngCore + CryptoRng>(
    approximation_factor: f32,
    key: &VectorEncryptionKey,
    key_id: KeyId,
    edek_type: EdekType,
    plaintext_vector: PlaintextVector,
    rng: &mut R,
) -> Result<EncryptedVector, AlloyError> {
    let result = crypto::encrypt(
        key,
        approximation_factor,
        shuffle(&key.key, plaintext_vector.plaintext_vector)
            .into_iter()
            .collect(),
        rng,
    )?;
    let (header, vector_metadata) = ironcore_documents::key_id_header::create_vector_metadata(
        KeyIdHeader::new(edek_type, PayloadType::VectorMetadata, key_id),
        result.iv.to_vec().into(),
        result.auth_hash.0.to_vec().into(),
    );
    Ok(EncryptedVector {
        encrypted_vector: result.ciphertext.to_vec(),
        secret_path: plaintext_vector.secret_path,
        derivation_path: plaintext_vector.derivation_path,
        paired_icl_info: ironcore_documents::key_id_header::encode_vector_metadata(
            header,
            vector_metadata,
        )
        .to_vec(),
    })
}

pub(crate) fn decrypt_internal(
    approximation_factor: f32,
    key: &VectorEncryptionKey,
    encrypted_vector: EncryptedVector,
    icl_metadata_bytes: Bytes,
) -> Result<PlaintextVector, AlloyError> {
    let (iv, auth_hash) = get_iv_and_auth_hash(&icl_metadata_bytes)?;
    Ok(crypto::decrypt(
        key,
        approximation_factor,
        EncryptResult {
            ciphertext: encrypted_vector.encrypted_vector.into(),
            iv,
            auth_hash,
        },
    )
    .map(|r| unshuffle(&key.key, r))?)
    .map(|dec| PlaintextVector {
        plaintext_vector: dec,
        secret_path: encrypted_vector.secret_path,
        derivation_path: encrypted_vector.derivation_path,
    })
}
