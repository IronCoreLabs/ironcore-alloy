use self::crypto::{shuffle, unshuffle, EncryptResult};
use crate::{
    errors::CloakedAiError, util::AuthHash, DerivationPath, IronCoreMetadata, Key, SecretPath,
};
use bytes::Bytes;
use ironcore_documents::{
    key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType},
    vector_encryption_metadata::VectorEncryptionMetadata,
};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;

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
pub type GenerateQueryBatchResult = HashMap<VectorId, Vec<EncryptedVector>>;

pub trait VectorOps {
    /// Encrypt a vector embedding with the provided metadata. The provided embedding is assumed to be normalized
    /// and its values will be shuffled as part of the encryption.
    /// The same tenant ID must be provided in the metadata when decrypting the embedding.
    async fn encrypt(
        &self,
        plaintext_vector: PlaintextVector,
        metadata: &IronCoreMetadata,
    ) -> Result<EncryptedVector, CloakedAiError>;

    /// Decrypt a vector embedding that was encrypted with the provided metadata. The values of the embedding will
    /// be unshuffled to their original positions during decryption.
    async fn decrypt(
        &self,
        encrypted_vector: EncryptedVector,
        metadata: &IronCoreMetadata,
    ) -> Result<PlaintextVector, CloakedAiError>;

    /// Encrypt each plaintext vector with any Current and InRotation keys for the provided secret path.
    /// The resulting encrypted vectors should be used in tandem when querying the vector database.
    async fn generate_query_vectors(
        &self,
        vectors_to_query: PlaintextVectors,
        metadata: &IronCoreMetadata,
    ) -> Result<GenerateQueryBatchResult, CloakedAiError>;

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
    ) -> Result<Vec<u8>, CloakedAiError>;
}

pub(crate) fn get_iv_and_auth_hash(b: &[u8]) -> Result<([u8; 12], AuthHash), CloakedAiError> {
    let vector_proto: VectorEncryptionMetadata = protobuf::Message::parse_from_bytes(b)?;
    let iv = vector_proto.iv;
    let auth_hash = vector_proto.auth_hash;
    Ok((
        iv[..].try_into().map_err(|_| CloakedAiError::InvalidIv)?,
        AuthHash(
            auth_hash[..]
                .try_into()
                .map_err(|_| CloakedAiError::InvalidAuthHash)?,
        ),
    ))
}

pub(crate) fn encrypt_internal<R: RngCore + CryptoRng>(
    approximation_factor: f32,
    key: &Key,
    key_id: KeyId,
    edek_type: EdekType,
    plaintext_vector: PlaintextVector,
    rng: &mut R,
) -> Result<EncryptedVector, CloakedAiError> {
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
    key: &Key,
    encrypted_vector: EncryptedVector,
    icl_metadata_bytes: Bytes,
) -> Result<PlaintextVector, CloakedAiError> {
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
