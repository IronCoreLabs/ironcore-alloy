#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::errors::CloakedAiError;
use document::{deterministic_decrypt_with_derived_keys, deterministic_encrypt_current};
use ironcore_documents::cmk_edek;
use ironcore_documents::icl_header_v4::V4DocumentHeader;
use ironcore_documents::key_id_header::{self, EdekType, KeyId, KeyIdHeader, PayloadType};
use itertools::Itertools;
use protobuf::Message;
use rand::{thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use saas_shield::config::SaasShieldConfiguration;
use saas_shield::deterministic::SaasShieldDeterministicClient;
use saas_shield::standard::SaasShieldStandardClient;
use saas_shield::vector::SaasShieldVectorClient;
use serde::{Deserialize, Serialize};
use standalone::config::StandaloneConfiguration;
use standalone::deterministic::StandaloneDeterministicClient;
use standalone::standard::StandaloneStandardClient;
use standalone::vector::StandaloneVectorClient;
use standard::EncryptedDocument;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tenant_security_client::errors::TenantSecurityError;
use tenant_security_client::{
    DerivationType, DerivedKey, IclFields, RequestMetadata, RequestingId, SecretType,
    TenantSecurityClient, UnwrapKeyResponse, WrapKeyResponse,
};
use uniffi::custom_newtype;
use util::{create_reseeding_rng, create_test_seeded_rng, get_rng, OurReseedingRng};

mod deterministic;
mod document;
mod errors;
mod saas_shield;
mod standalone;
mod standard;
mod tenant_security_client;
mod util;
mod vector;

// add multi-lang scaffolding
// proc macro defined
uniffi::setup_scaffolding!();

type Edek = Vec<u8>;
type FieldId = String;
type EncryptedBytes = Vec<u8>;
type PlaintextBytes = Vec<u8>;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct SecretPath(pub String);
custom_newtype!(SecretPath, String);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct DerivationPath(pub String);
custom_newtype!(DerivationPath, String);

/// Holds metadata fields as part of an SDK call. Each encrypted value will have metadata that associates
/// it to a tenant ID as well as optional fields for other arbitrary key/value pairs and a request ID to send to the Tenant Security Proxy.
/// Only the tenant ID will be used in Standalone SDKs, which can be created easily with `new_simple()`.
#[derive(Debug, Clone, Serialize, uniffi::Object)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct IronCoreMetadata {
    tenant_id: TenantId,
    requesting_id: Option<String>,
    data_label: Option<String>,
    source_ip: Option<String>,
    object_id: Option<String>,
    request_id: Option<String>,
    timestamp: Option<String>,
    custom_fields: HashMap<String, String>,
}

#[uniffi::export]
impl IronCoreMetadata {
    /// Constructor for IronCoreMetadata which contains the tenant's ID and other metadata to send to the
    /// Tenant Security Proxy.
    ///
    /// # Arguments
    /// - `tenant_id`                     - Unique ID of tenant that is performing the operation.
    /// - `requesting_user_or_service_id` - Unique ID of user/service that is processing data. Must be non-empty.
    /// - `data_label`                    - Classification of data being processed.
    /// - `source_ip`                     - IP address of the initiator of this document request.
    /// - `object_id`                     - ID of the object/document being acted on in the host system.
    /// - `request_id`                    - Unique ID that ties host application request ID to tenant.
    /// - `timestamp`                     - An ISO 8601 timestamp of when the associated action took place. Most useful for `SecurityEvents`.
    /// - `other_data`                    - Additional String key/value pairs to add to metadata.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::constructor]
    pub fn new(
        tenant_id: TenantId,
        requesting_user_or_service_id: Option<String>,
        data_label: Option<String>,
        source_ip: Option<String>,
        object_id: Option<String>,
        request_id: Option<String>,
        timestamp: Option<String>,
        other_data: HashMap<String, String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tenant_id,
            requesting_id: requesting_user_or_service_id,
            data_label,
            source_ip,
            object_id,
            request_id,
            timestamp,
            custom_fields: other_data,
        })
    }

    /// Simplified constructor for IronCoreMetadata that only takes the tenant's ID and the
    /// ID of the user/service that is processing data.
    ///
    /// # Arguments
    /// - `tenant_id`                     - Unique ID of tenant that is performing the operation.
    #[uniffi::constructor]
    pub fn new_simple(tenant_id: TenantId) -> Arc<Self> {
        Arc::new(Self {
            tenant_id,
            requesting_id: None,
            data_label: None,
            source_ip: None,
            object_id: None,
            request_id: None,
            timestamp: None,
            custom_fields: HashMap::new(),
        })
    }
}

impl TryFrom<IronCoreMetadata> for RequestMetadata {
    type Error = CloakedAiError;
    fn try_from(value: IronCoreMetadata) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.tenant_id.into(),
            RequestingId::new(value.requesting_id.unwrap_or("Cloaked AI".to_string()))
                .map_err(|e| CloakedAiError::InvalidConfiguration(e.to_string()))?,
            value.data_label,
            value.source_ip,
            value.object_id,
            value.request_id,
            value.timestamp,
            value.custom_fields,
        ))
    }
}

// only make these top two publicly constructable to narrow public interface a bit
#[derive(uniffi::Object)]
pub struct Standalone {
    standard: Arc<StandaloneStandardClient>,
    deterministic: Arc<StandaloneDeterministicClient>,
    vector: Arc<StandaloneVectorClient>,
}
#[uniffi::export]
impl Standalone {
    #[uniffi::constructor]
    pub fn new(config: &StandaloneConfiguration) -> Arc<Self> {
        Arc::new(Self {
            standard: Arc::new(StandaloneStandardClient::new(config.clone())),
            deterministic: Arc::new(StandaloneDeterministicClient::new(config.clone())),
            vector: Arc::new(StandaloneVectorClient::new(config.clone())),
        })
    }
    pub fn standard(&self) -> Arc<StandaloneStandardClient> {
        self.standard.clone()
    }
    pub fn deterministic(&self) -> Arc<StandaloneDeterministicClient> {
        self.deterministic.clone()
    }
    pub fn vector(&self) -> Arc<StandaloneVectorClient> {
        self.vector.clone()
    }
}
#[derive(uniffi::Object)]
pub struct SaasShield {
    standard: Arc<SaasShieldStandardClient>,
    deterministic: Arc<SaasShieldDeterministicClient>,
    vector: Arc<SaasShieldVectorClient>,
}
#[uniffi::export]
impl SaasShield {
    #[uniffi::constructor]
    pub fn new(config: &SaasShieldConfiguration) -> Arc<Self> {
        Arc::new(Self {
            standard: Arc::new(SaasShieldStandardClient::new(
                config.tenant_security_client.clone(),
            )),
            deterministic: Arc::new(SaasShieldDeterministicClient::new(
                config.tenant_security_client.clone(),
            )),
            vector: Arc::new(SaasShieldVectorClient::new(
                config.tenant_security_client.clone(),
                config.approximation_factor,
            )),
        })
    }
    pub fn standard(&self) -> Arc<SaasShieldStandardClient> {
        self.standard.clone()
    }
    pub fn deterministic(&self) -> Arc<SaasShieldDeterministicClient> {
        self.deterministic.clone()
    }
    pub fn vector(&self) -> Arc<SaasShieldVectorClient> {
        self.vector.clone()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantId(pub String);
custom_newtype!(TenantId, String);

impl AsRef<[u8]> for TenantId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&str> for TenantId {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<tenant_security_client::core::TenantId> for TenantId {
    fn from(value: tenant_security_client::core::TenantId) -> Self {
        TenantId(value.0)
    }
}

impl From<TenantId> for tenant_security_client::core::TenantId {
    fn from(value: TenantId) -> Self {
        Self(value.0)
    }
}

pub struct DeterministicPlaintextField {
    pub derivation_path: DerivationPath,
    pub secret_path: SecretPath,
    pub plaintext_field: Vec<u8>,
}

pub struct DeterministicEncryptedField {
    pub derivation_path: DerivationPath,
    pub secret_path: SecretPath,
    pub encrypted_field: Vec<u8>,
}

impl DeterministicEncryptedField {
    fn new(
        field: DeterministicPlaintextField,
        tenant_secret_id: u32,
        encrypted_document: Vec<u8>,
    ) -> Self {
        DeterministicEncryptedField {
            derivation_path: field.derivation_path,
            secret_path: field.secret_path,
            encrypted_field: u32::to_be_bytes(tenant_secret_id)
                .into_iter()
                .chain([0u8; 2])
                .chain(encrypted_document)
                .collect_vec(),
        }
    }

    fn decompose_parts(&self) -> Option<(u32, Vec<u8>)> {
        let (first_four, rest) = self.encrypted_field.split_at(4);
        let tenant_secret_id = first_four.try_into().ok().map(u32::from_be_bytes)?;
        let (zeros, encrypted_data) = rest.split_at(2);
        if zeros != [0; 2] {
            None
        } else {
            Some((tenant_secret_id, encrypted_data.to_vec()))
        }
    }
}

/// Metadata required when encrypting/decrypting vector embeddings or documents.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DocumentMetadata {
    /// Tenant associated with the embedding/document. The same tenant ID must be
    /// provided when encrypting and decrypting.
    pub tenant_id: TenantId,
}

impl TryFrom<DocumentMetadata> for RequestMetadata {
    type Error = TenantSecurityError;

    fn try_from(value: DocumentMetadata) -> Result<Self, Self::Error> {
        Ok(RequestMetadata::new_simple(
            value.tenant_id.0.try_into()?,
            "Cloaked AI".to_string().try_into()?,
        ))
    }
}

impl TryFrom<&DocumentMetadata> for RequestMetadata {
    type Error = TenantSecurityError;

    fn try_from(value: &DocumentMetadata) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

impl From<&IronCoreMetadata> for DocumentMetadata {
    fn from(value: &IronCoreMetadata) -> Self {
        Self {
            tenant_id: value.tenant_id.clone(),
        }
    }
}

/// Trait for the encryption of documents
#[uniffi::export]
pub trait EncryptDocumentOps: Send + Sync {
    /// Encrypt a document with the provided metadata. The document must be a map from field names to bytes, and
    /// the same metadata must be provided when decrypting the embedding.
    /// The result contains a map from field names to encrypted bytes.
    /// Because the document is encrypted deterministically with each call, the result will be the same for repeated calls.
    /// This allows for exact matches and indexing of the encrypted document, but comes with some security considerations.
    /// If you don't need to support these use cases, we recommend using the `encrypt_document`/`encryptDocument` function instead.
    fn encrypt_document_deterministic(
        &self,
        document: HashMap<String, Vec<u8>>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, Vec<u8>>, CloakedAiError>;
}

/// Trait for the decryption of documents
#[uniffi::export]
pub trait DecryptDocumentOps: Send + Sync {
    /// Decrypt a document that was encrypted with the provided metadata. The document must have been encrypted with the
    /// `encrypt_document_deterministic`/`encryptDocumentDeterministic` function.
    /// The result contains a map from field names to decrypted bytes.
    fn decrypt_document_deterministic(
        &self,
        encrypted_document: HashMap<String, Vec<u8>>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, Vec<u8>>, CloakedAiError>;
}

/// The primary class that is able to encrypt/decrypt vector embeddings and documents.
/// If you don't need to encrypt, consider using the `CloakedAiDecrypter` instead.
#[derive(uniffi::Object)]
pub struct CloakedAiStandalone {
    key: Key,
    // Beta in the paper.
    // The paper uses a range in experimental analysis of 2^10 -> 2^30 with different
    // attribute window one wayness (AWOW) and approximate frequency-finding attack resistances.
    approximation_factor: f32,
    rng: Arc<Mutex<OurReseedingRng>>,
}

#[uniffi::export]
impl CloakedAiStandalone {
    /// Construct a CloakedAiStandalone with the provided key and approximation factor. A secure key can be created
    /// using the `generate_key`/`generateKey` function.
    /// The approximation factor should be chosen in a way that balances security with search performance.
    /// A higher approximation factor is more secure, but introduces more variance into encrypted embeddings,
    /// possibly leading to degraded performance. A lower bound for the approximation factor to start with is `sqrt(M)`,
    /// where M is the absolute value of the largest data point in the input embeddings.
    #[uniffi::constructor]
    pub fn new(key: Key, approximation_factor: f32) -> Arc<Self> {
        Arc::new(Self {
            key,
            approximation_factor,
            rng: create_reseeding_rng(),
        })
    }

    /// WARNING: only for testing, not a cryptographically secure way of seeding the RNG.
    #[uniffi::constructor]
    pub fn new_test_seeded(key: Key, approximation_factor: f32, seed: u64) -> Arc<Self> {
        Arc::new(Self {
            key,
            approximation_factor,
            rng: create_test_seeded_rng(seed),
        })
    }
}

#[uniffi::export]
impl EncryptDocumentOps for CloakedAiStandalone {
    fn encrypt_document_deterministic(
        &self,
        document_fields: HashMap<String, Vec<u8>>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
        Ok(document::aes::encrypt_document_deterministic(
            &self.key.key.0,
            document_fields,
            metadata,
        )?)
    }
}

#[uniffi::export]
impl DecryptDocumentOps for CloakedAiStandalone {
    fn decrypt_document_deterministic(
        &self,
        encrypted_document: HashMap<String, Vec<u8>>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
        document::aes::decrypt_document_deterministic(&self.key.key.0, encrypted_document, metadata)
    }
}

pub struct CloakedAiSaasShield {
    // Beta in the paper.
    // The paper uses a range in experimental analysis of 2^10 -> 2^30 with different
    // attribute window one wayness (AWOW) and approximate frequency-finding attack resistances.
    approximation_factor: f32,
    tsc: TenantSecurityClient,
    rng: Arc<Mutex<ChaCha20Rng>>,
}

impl CloakedAiSaasShield {
    pub fn new(
        tsp_address: String,
        api_key: String,
        accept_invalid_certs: bool,
        approximation_factor: f32,
    ) -> Result<Arc<CloakedAiSaasShield>, CloakedAiError> {
        let rng = Arc::new(Mutex::new(ChaCha20Rng::from_entropy()));
        let reqwest_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .expect("Failed to create http client. This means there is a system misconfiguration.");
        let tsc = TenantSecurityClient::new(tsp_address, api_key.try_into()?, reqwest_client);
        Ok(Arc::new(CloakedAiSaasShield {
            approximation_factor,
            tsc,
            rng,
        }))
    }
}

impl CloakedAiSaasShield {
    pub async fn encrypt_field_deterministic(
        &self,
        field: DeterministicPlaintextField,
        metadata: &DocumentMetadata,
    ) -> Result<DeterministicEncryptedField, CloakedAiError> {
        let request_metadata = metadata.try_into()?;
        let path = [(
            field.secret_path.clone(),
            [field.derivation_path.clone()].into(),
        )]
        .into();
        let key_derive_resp = self
            .tsc
            .tenant_key_derive(
                path,
                &request_metadata,
                DerivationType::Sha512,
                SecretType::Deterministic,
            )
            .await?;
        deterministic_encrypt_current(&key_derive_resp, field, metadata)
    }

    pub async fn encrypt_field_batch_deterministic(
        &self,
        fields: HashMap<String, DeterministicPlaintextField>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, DeterministicEncryptedField>, CloakedAiError> {
        let request_metadata = metadata.try_into()?;
        let secret_paths_and_derivation_paths = fields
            .values()
            .into_grouping_map_by(|f| f.secret_path.clone())
            .fold(HashSet::new(), |mut set, _secret_path, field| {
                set.insert(field.derivation_path.clone());
                set
            });
        let key_derive_resp = self
            .tsc
            .tenant_key_derive(
                secret_paths_and_derivation_paths,
                &request_metadata,
                DerivationType::Sha512,
                SecretType::Deterministic,
            )
            .await?;
        fields
            .into_iter()
            .map(|(label, field)| {
                deterministic_encrypt_current(&key_derive_resp, field, metadata)
                    .map(|res| (label, res))
            })
            .try_collect()
    }

    pub async fn decrypt_field_deterministic(
        &self,
        encrypted_field: DeterministicEncryptedField,
        metadata: &DocumentMetadata,
    ) -> Result<DeterministicPlaintextField, CloakedAiError> {
        let request_metadata = metadata.try_into()?;
        let path = [(
            encrypted_field.secret_path.clone(),
            [encrypted_field.derivation_path.clone()].into(),
        )]
        .into();
        let key_derive_resp = self
            .tsc
            .tenant_key_derive(
                path,
                &request_metadata,
                DerivationType::Sha512,
                SecretType::Deterministic,
            )
            .await?;
        deterministic_decrypt_with_derived_keys(&key_derive_resp, encrypted_field, metadata)
    }

    pub async fn decrypt_field_batch_deterministic(
        &self,
        encrypted_fields: HashMap<String, DeterministicEncryptedField>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, DeterministicPlaintextField>, CloakedAiError> {
        let request_metadata = metadata.try_into()?;
        let secret_paths_and_derivation_paths = encrypted_fields
            .values()
            .into_grouping_map_by(|f| f.secret_path.clone())
            .fold(HashSet::new(), |mut set, _secret_path, field| {
                set.insert(field.derivation_path.clone());
                set
            });
        let key_derive_resp = self
            .tsc
            .tenant_key_derive(
                secret_paths_and_derivation_paths,
                &request_metadata,
                DerivationType::Sha512,
                SecretType::Deterministic,
            )
            .await?;
        encrypted_fields
            .into_iter()
            .map(|(label, field)| {
                deterministic_decrypt_with_derived_keys(&key_derive_resp, field, metadata)
                    .map(|res| (label, res))
            })
            .try_collect()
    }

    /// Get the prefix bytes for the in rotation secrets. These bytes can then be used
    /// to find the data that is using your in rotation keys to migrate them.
    /// Note that if you're using an encoding mechanism like z85, base85 or ascii85 you might need further process these bytes.
    /// See base85_prefix_padding and encode_prefix_z85.
    pub async fn get_in_rotation_prefixes(
        &self,
        secret_paths: Vec<SecretPath>,
        document_metadata: DocumentMetadata,
    ) -> Result<HashMap<SecretPath, Vec<u8>>, CloakedAiError> {
        let request_metadata = document_metadata.try_into()?;
        // We don't actually care about the derivation path because we just want the current and in rotation keys back.
        let static_derivation_path: HashSet<_> = [DerivationPath("".to_string())].into();
        let secret_paths_and_derivation_paths = secret_paths
            .into_iter()
            .map(|secret_path| (secret_path, static_derivation_path.clone()))
            .collect();
        let key_derive_resp = self
            .tsc
            .tenant_key_derive(
                secret_paths_and_derivation_paths,
                &request_metadata,
                DerivationType::Sha512,
                SecretType::Deterministic,
            )
            .await?;
        Ok(get_in_rotation_key_prefixes(
            key_derive_resp.derived_keys,
            EdekType::SaasShield,
            PayloadType::DeterministicField,
        ))
    }
}

fn get_document_header_and_edek(
    document: &EncryptedDocument,
) -> Result<(V4DocumentHeader, cmk_edek::EncryptedDek), CloakedAiError> {
    let (_, v4_doc_bytes) =
        key_id_header::decode_version_prefixed_value(document.edek.0.clone().into())?;
    let v4_document: V4DocumentHeader = Message::parse_from_bytes(&v4_doc_bytes[..])?;
    let edek = document::cmk::find_cmk_edek(&v4_document.signed_payload.edeks)?.clone();
    Ok((v4_document, edek))
}

/// Applies the padding required for base85 algorithms to produce consistent string when the bytes are encoded.
/// If you're using a base85 encoding algorithm other than the directly supported z85, see our tests in `util.rs` for examples.
pub fn base85_prefix_padding(prefix_bytes: &[u8]) -> Vec<u8> {
    [prefix_bytes, &[0u8, 0]].concat()
}

/// Encode a set of prefix bytes to the appropriate z85 encoded string. This means padding the prefix using `base85_prefix_padding`
/// and truncating the string to be 7 characters instead of the 10 that's returned.
pub fn encode_prefix_z85(prefix_bytes: Vec<u8>) -> String {
    let mut z85_string = z85::encode(base85_prefix_padding(&prefix_bytes[..]));
    // For 85 bit encoding we have to strip off the last 3 characters of the z85 string
    z85_string.pop();
    z85_string.pop();
    z85_string.pop();
    z85_string
}

/// Turns the typical response for key derive into a map of the secret path to the prefix bytes
fn get_in_rotation_key_prefixes(
    derived_keys: HashMap<SecretPath, HashMap<DerivationPath, Vec<DerivedKey>>>,
    edek_type: EdekType,
    payload_type: PayloadType,
) -> HashMap<SecretPath, Vec<u8>> {
    derived_keys
        .into_iter()
        .flat_map(|(secret_path, derivation_path_to_keys)| {
            // Find the key for the secret path that isn't set to current, that's the one we want
            // to return the prefix for. There should never be more than one, so we make the first
            // one that isn't marked as current.
            derivation_path_to_keys
                .into_iter()
                .find_map(|(_, derived_keys)| {
                    derived_keys
                        .into_iter()
                        .find(|derived_key| !derived_key.current)
                })
                .map(|derived_key| (secret_path, KeyId(derived_key.tenant_secret_id.0)))
        })
        .map(|(secret_path, key_id)| {
            (
                secret_path,
                ironcore_documents::key_id_header::get_prefix_bytes_for_search(KeyIdHeader::new(
                    edek_type,
                    payload_type,
                    key_id,
                ))
                .to_vec(),
            )
        })
        .collect()
}

/// A CloakedAiStandalone instance that is only able to decrypt embeddings and documents.
/// If you need to encrypt, please see the CloakedAiStandalone struct above.
#[derive(uniffi::Object)]
pub struct CloakedAiDecrypter {
    key: Key,
    approximation_factor: f32,
}

#[uniffi::export]
impl CloakedAiDecrypter {
    /// Construct a CloakedAiDecrypter with the provided key and approximation factor. These must be
    /// identical to the values provided when the data was first encrypted.
    #[uniffi::constructor]
    pub fn new(key: Key, approximation_factor: f32) -> Arc<Self> {
        Arc::new(Self {
            key,
            approximation_factor,
        })
    }
}

#[uniffi::export]
impl DecryptDocumentOps for CloakedAiDecrypter {
    fn decrypt_document_deterministic(
        &self,
        encrypted_document: HashMap<String, Vec<u8>>,
        metadata: &DocumentMetadata,
    ) -> Result<HashMap<String, Vec<u8>>, CloakedAiError> {
        document::aes::decrypt_document_deterministic(&self.key.key.0, encrypted_document, metadata)
    }
}

/// An encrypted embedding and its generated metadata
#[derive(Debug, PartialEq, Serialize, uniffi::Record)]
pub struct EncryptedValue {
    /// The encrypted vector embedding
    pub ciphertext: Vec<f32>,
    /// Generated metadata necessary for decrypting the embedding
    pub icl_metadata: Vec<u8>,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct ScalingFactor(pub f32); // Based on page 135 having a size 2^30
custom_newtype!(ScalingFactor, f32);

#[derive(Debug, Serialize, Clone)]
pub struct EncryptionKey(pub Vec<u8>);
custom_newtype!(EncryptionKey, Vec<u8>);

// Like an EncryptionKey but not used directly for encryption
#[derive(Debug, Serialize, Clone, uniffi::Object)]
pub struct Secret {
    pub(crate) secret: Vec<u8>,
}
#[uniffi::export]
impl Secret {
    #[uniffi::constructor]
    pub fn new(secret: Vec<u8>) -> Result<Arc<Self>, CloakedAiError> {
        if secret.len() < 32 {
            Err(CloakedAiError::InvalidConfiguration(
                "Secrets must be at least 32 cryptographically random bytes.".to_string(),
            ))
        } else {
            Ok(Arc::new(Self { secret }))
        }
    }
}

/// Key used to initialize CloakedAiStandalone.
/// Can be created with the `generate_key`/`generateKey` function.
#[derive(Debug, Serialize, Clone, uniffi::Record)]
pub struct Key {
    /// The amount to scale embedding values during encryption
    pub scaling_factor: ScalingFactor,
    /// The actual key used for encryption/decryption operations
    pub key: EncryptionKey,
}

impl Key {
    /// A way to generate a key from the secret, tenant_id and derivation_path. This is done in the context of
    /// a standalone secret where we don't have a TSP to call to for derivation.
    fn derive_from_secret(
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
    pub(crate) fn unsafe_bytes_to_key(key_bytes: &[u8]) -> Key {
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
        Key {
            scaling_factor: ScalingFactor(scaling_factor_u32 as f32),
            key: EncryptionKey(key_bytes.to_vec()),
        }
    }
}

/// Generate a cryptographically-secure 32-byte key and scaling factor
/// that can be used to initialize CloakedAiStandalone
#[uniffi::export]
pub fn generate_key() -> Key {
    let mut r = thread_rng();
    let s = r.next_u32();
    let mut v: Vec<u8> = vec![0u8; 32];
    r.fill_bytes(&mut v);
    Key {
        scaling_factor: ScalingFactor(s as f32),
        key: EncryptionKey(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{standard::EdekWithKeyIdHeader, Key};
    use tenant_security_client::{Base64, TenantSecretAssignmentId};

    #[test]
    fn get_document_header_and_edek_fails_for_bad_header() {
        let encrypted_document = EncryptedDocument {
            edek: EdekWithKeyIdHeader(vec![0u8]),
            document: Default::default(),
        };
        assert_eq!(
            get_document_header_and_edek(&encrypted_document).unwrap_err(),
            CloakedAiError::IronCoreDocumentsError("KeyIdHeaderTooShort(1)".to_string())
        );
    }

    #[test]
    fn get_document_header_and_edek_succeeds_for_good_header() {
        // This is a SaaS Shield edek which is empty along with a valid header.
        let bytes = vec![0u8, 0, 0, 42, 0, 0, 18, 4, 18, 2, 18, 0];
        let encrypted_doc = EncryptedDocument {
            edek: EdekWithKeyIdHeader(bytes),
            document: Default::default(),
        };

        get_document_header_and_edek(&encrypted_doc).unwrap();
    }

    // The expect value matches an array produced in the tsp test derive_keys_produces_known_result_sha_512.
    #[test]
    fn key_derive_produces_known_result() {
        let secret = Secret {
            secret: [0u8; 32].to_vec(),
        };
        let tenant_id = TenantId("tenant".to_string());
        let derivation_path = DerivationPath("somesalt".to_string());

        let key = Key::derive_from_secret(&secret, &tenant_id, &derivation_path);

        let expected_sha512 = vec![
            82u8, 186, 45, 83, 222, 56, 178, 42, 61, 227, 197, 219, 58, 108, 227, 124, 186, 43,
            149, 126, 147, 7, 251, 173, 250, 201, 142, 180, 213, 120, 13, 80, 15, 151, 154, 116,
            33, 229, 191, 200, 97, 74, 54, 48, 196, 84, 213, 202, 84, 12, 202, 225, 20, 18, 2, 102,
            76, 165, 48, 52, 134, 76, 87, 250,
        ];

        let expected_scaling_factor: [u8; 4] = std::iter::once(0u8)
            .chain(expected_sha512[0..3].into_iter().cloned())
            .collect_vec()
            .try_into()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(expected_scaling_factor) as f32,
            key.scaling_factor.0
        );

        assert_eq!(expected_sha512[3..35], key.key.0);
    }

    // helper function to create the nested hashmaps. Groups by the secret path string and the derivation path string creating the
    // derivation keys inside as it goes.
    fn create_in_rotation_struct(
        vec: Vec<(&str, &str, KeyId, bool)>,
    ) -> HashMap<SecretPath, HashMap<DerivationPath, Vec<DerivedKey>>> {
        let secret_path_to_derivation_vec = vec
            .into_iter()
            .map(|(secret_str, derivation_str, key_id, current)| {
                (
                    SecretPath(secret_str.to_string()),
                    (
                        DerivationPath(derivation_str.to_string()),
                        DerivedKey {
                            derived_key: Base64(vec![]),
                            tenant_secret_id: TenantSecretAssignmentId(key_id.0),
                            current,
                        },
                    ),
                )
            })
            .into_group_map();
        secret_path_to_derivation_vec
            .into_iter()
            .map(|(secret, v)| (secret, v.into_iter().into_group_map()))
            .collect()
    }
    #[test]
    fn get_in_rotation_key_prefixes_works() {
        let secret_path_one = SecretPath("secret".to_string());
        let secret_path_two = SecretPath("secret2".to_string());
        let result = get_in_rotation_key_prefixes(
            create_in_rotation_struct(vec![
                (secret_path_one.0.as_str(), "derivation", KeyId(1), true),
                (secret_path_one.0.as_str(), "derivation", KeyId(2), false),
                // note that these derivation paths are different, but we don't care, just find the key id that has current set to false
                (secret_path_two.0.as_str(), "derivation1", KeyId(100), false),
                (secret_path_two.0.as_str(), "derivation", KeyId(200), true),
            ]),
            EdekType::SaasShield,
            PayloadType::StandardEdek,
        );

        assert_eq!(
            result.get(&secret_path_one).unwrap(),
            &KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(2))
                .write_to_bytes()
                .to_vec()
        );
        assert_eq!(
            result.get(&secret_path_two).unwrap(),
            &KeyIdHeader::new(EdekType::SaasShield, PayloadType::StandardEdek, KeyId(100))
                .write_to_bytes()
                .to_vec()
        );
    }

    #[test]
    fn encode_prefix_z85_works() {
        let result1 = encode_prefix_z85(vec![0, 0, 36, 10, 0, 0]);
        let result2 = encode_prefix_z85(vec![255, 255, 255, 255, 0, 0]);

        assert_eq!(result1, "001nK00"); // Hand calculated.
        assert_eq!(result2, "%nSc000"); // Hand calculated.
    }

    #[test]
    fn base85_prefix_padding_works() {
        let result1 = base85_prefix_padding(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(result1, [1, 2, 3, 4, 5, 6, 0, 0])
    }
}
