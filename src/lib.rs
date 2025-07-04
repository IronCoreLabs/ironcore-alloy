#![allow(async_fn_in_trait)]

use crate::errors::AlloyError;
use ironcore_documents::v5::key_id_header::{EdekType, KeyId, KeyIdHeader, PayloadType};
use saas_shield::config::SaasShieldConfiguration;
use saas_shield::deterministic::SaasShieldDeterministicClient;
use saas_shield::standard::SaasShieldStandardClient;
use saas_shield::standard_attached::SaasShieldStandardAttachedClient;
use saas_shield::vector::SaasShieldVectorClient;
use serde::{Deserialize, Serialize};
use standalone::config::StandaloneConfiguration;
use standalone::deterministic::StandaloneDeterministicClient;
use standalone::standard::StandaloneStandardClient;
use standalone::standard_attached::StandaloneStandardAttachedClient;
use standalone::vector::StandaloneVectorClient;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tenant_security_client::{RequestMetadata, RequestingId};
use uniffi::custom_newtype;
use vector::VectorEncryptionKey;

pub mod deterministic;
pub mod errors;
pub mod saas_shield;
pub mod standalone;
pub mod standard;
pub mod standard_attached;
mod tenant_security_client;
mod util;
pub mod vector;

// add multi-lang scaffolding
// proc macro defined
uniffi::setup_scaffolding!();

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FieldId(pub String);
custom_newtype!(FieldId, String);
impl From<String> for FieldId {
    fn from(value: String) -> Self {
        FieldId(value)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DocumentId(pub String);
custom_newtype!(DocumentId, String);
impl From<String> for DocumentId {
    fn from(value: String) -> Self {
        DocumentId(value)
    }
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct EncryptedBytes(pub Vec<u8>);
custom_newtype!(EncryptedBytes, Vec<u8>);
impl From<Vec<u8>> for EncryptedBytes {
    fn from(value: Vec<u8>) -> Self {
        EncryptedBytes(value)
    }
}
impl AsRef<[u8]> for EncryptedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PlaintextBytes(pub Vec<u8>);
custom_newtype!(PlaintextBytes, Vec<u8>);
impl From<Vec<u8>> for PlaintextBytes {
    fn from(value: Vec<u8>) -> Self {
        PlaintextBytes(value)
    }
}
impl AsRef<[u8]> for PlaintextBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
pub struct AlloyMetadata {
    tenant_id: TenantId,
    requesting_id: Option<String>,
    data_label: Option<String>,
    source_ip: Option<String>,
    object_id: Option<String>,
    request_id: Option<String>,
    custom_fields: HashMap<String, String>,
}

#[uniffi::export]
impl AlloyMetadata {
    /// Constructor for AlloyMetadata which contains the tenant's ID and other metadata to send to the
    /// Tenant Security Proxy.
    ///
    /// # Arguments
    /// - `tenant_id`                     - Unique ID of tenant that is performing the operation.
    /// - `requesting_user_or_service_id` - Unique ID of user/service that is processing data. Must be non-empty.
    /// - `data_label`                    - Classification of data being processed.
    /// - `source_ip`                     - IP address of the initiator of this document request.
    /// - `object_id`                     - ID of the object/document being acted on in the host system.
    /// - `request_id`                    - Unique ID that ties host application request ID to tenant.
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
        other_data: HashMap<String, String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tenant_id,
            requesting_id: requesting_user_or_service_id,
            data_label,
            source_ip,
            object_id,
            request_id,
            custom_fields: other_data,
        })
    }

    /// Simplified constructor for AlloyMetadata that only takes the tenant's ID and the
    /// ID of the user/service that is processing data.
    ///
    /// # Arguments
    /// - `tenant_id` - Unique ID of tenant that is performing the operation.
    #[uniffi::constructor]
    pub fn new_simple(tenant_id: TenantId) -> Arc<Self> {
        Arc::new(Self {
            tenant_id,
            requesting_id: None,
            data_label: None,
            source_ip: None,
            object_id: None,
            request_id: None,
            custom_fields: HashMap::new(),
        })
    }
}

impl TryFrom<AlloyMetadata> for RequestMetadata {
    type Error = AlloyError;
    fn try_from(value: AlloyMetadata) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.tenant_id,
            RequestingId::new(
                value
                    .requesting_id
                    .unwrap_or("IronCore Labs Alloy SDK".to_string()),
            )
            .map_err(|e| AlloyError::InvalidConfiguration { msg: e.to_string() })?,
            value.data_label,
            value.source_ip,
            value.object_id,
            value.request_id,
            None,
            value.custom_fields,
        ))
    }
}

impl TryFrom<(AlloyMetadata, Option<i64>)> for RequestMetadata {
    type Error = AlloyError;
    fn try_from(
        (value, event_time_millis): (AlloyMetadata, Option<i64>),
    ) -> Result<Self, Self::Error> {
        let time_as_u64 = match event_time_millis {
            Some(time) if time >= 0 => Ok(time as u64),
            Some(_) => Err(AlloyError::InvalidInput {
                msg: "millis times must be >= 0.".to_string(),
            }),
            None => Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time moved backwards, or it's ~584 million years in the future.")
                .as_millis() as u64),
        }?;
        let mut request_metadata: RequestMetadata = value.try_into()?;
        request_metadata.timestamp_millis = Some(time_as_u64);
        Ok(request_metadata)
    }
}
// only make these top two publicly constructable to narrow public interface a bit
#[derive(uniffi::Object)]
pub struct Standalone {
    standard: Arc<StandaloneStandardClient>,
    standard_attached: Arc<StandaloneStandardAttachedClient>,
    deterministic: Arc<StandaloneDeterministicClient>,
    vector: Arc<StandaloneVectorClient>,
}
#[uniffi::export]
impl Standalone {
    #[uniffi::constructor]
    pub fn new(config: &StandaloneConfiguration) -> Arc<Self> {
        Arc::new(Self {
            standard: Arc::new(StandaloneStandardClient::new(config.clone())),
            standard_attached: Arc::new(StandaloneStandardAttachedClient::new(config.clone())),
            deterministic: Arc::new(StandaloneDeterministicClient::new(config.clone())),
            vector: Arc::new(StandaloneVectorClient::new(config.clone())),
        })
    }
    pub fn standard(&self) -> Arc<StandaloneStandardClient> {
        self.standard.clone()
    }
    pub fn standard_attached(&self) -> Arc<StandaloneStandardAttachedClient> {
        self.standard_attached.clone()
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
    standard_attached: Arc<SaasShieldStandardAttachedClient>,
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
            standard_attached: Arc::new(SaasShieldStandardAttachedClient::new(
                config.tenant_security_client.clone(),
            )),
            deterministic: Arc::new(SaasShieldDeterministicClient::new(
                config.tenant_security_client.clone(),
            )),
            vector: Arc::new(SaasShieldVectorClient::new(
                config.tenant_security_client.clone(),
                config.approximation_factor,
                config.use_scaling_factor,
            )),
        })
    }
    pub fn standard(&self) -> Arc<SaasShieldStandardClient> {
        self.standard.clone()
    }
    pub fn standard_attached(&self) -> Arc<SaasShieldStandardAttachedClient> {
        self.standard_attached.clone()
    }
    pub fn deterministic(&self) -> Arc<SaasShieldDeterministicClient> {
        self.deterministic.clone()
    }
    pub fn vector(&self) -> Arc<SaasShieldVectorClient> {
        self.vector.clone()
    }
}

uniffi::custom_type!(KeyId, u32, {
   remote,
   lower: |s| s.0,
   try_lift: |n| Ok(KeyId(n))
});

#[uniffi::remote(Enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdekType {
    Standalone,
    SaasShield,
    DataControlPlatform,
}

#[uniffi::remote(Enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadType {
    DeterministicField,
    VectorMetadata,
    StandardEdek,
}
#[uniffi::remote(Record)]
#[derive(Debug, PartialEq)]
pub struct KeyIdHeader {
    pub key_id: KeyId,
    pub edek_type: EdekType,
    pub payload_type: PayloadType,
}

/// This module exists to prevent leaking AlloyClient functions to the various client traits
/// while still allowing them to extend it.
/// See thread here https://github.com/rust-lang/rust/issues/34537#issuecomment-1510807523
/// Note that the comment following the linked one only seems to be true for functions that take `self`.
pub(crate) mod alloy_client_trait {
    use super::*;

    #[derive(Clone, Debug, uniffi::Record)]
    pub struct DecomposedHeader {
        pub key_id: KeyId,
        pub remaining_bytes: Vec<u8>,
    }

    #[uniffi::export]
    pub trait AlloyClient: Send + Sync {
        /// Returns the only EdekType this Alloy client deals with.
        fn get_edek_type(&self) -> EdekType;

        /// Returns the only PayloadType this Alloy client deals with.
        fn get_payload_type(&self) -> PayloadType;

        fn create_key_id_header(&self, key_id: u32) -> KeyIdHeader {
            KeyIdHeader {
                key_id: KeyId(key_id),
                edek_type: self.get_edek_type(),
                payload_type: self.get_payload_type(),
            }
        }

        /// Decodes the header from the encrypted bytes, returning an error if the
        /// decoded EdekType or PayloadType is incorrect for this AlloyClient.
        /// Returns the decoded key ID and remaining non-header bytes.
        fn decompose_key_id_header(
            &self,
            encrypted_bytes: EncryptedBytes,
        ) -> Result<DecomposedHeader, AlloyError> {
            let (
                KeyIdHeader {
                    key_id,
                    edek_type,
                    payload_type,
                },
                remaining_bytes,
            ) = ironcore_documents::v5::key_id_header::decode_version_prefixed_value(
                encrypted_bytes.0.into(),
            )
            .map_err(|_| AlloyError::InvalidInput {
                msg: "Encrypted header was invalid.".to_string(),
            })?;
            let expected_edek_type = self.get_edek_type();
            let expected_payload_type = self.get_payload_type();
            if edek_type == expected_edek_type && payload_type == expected_payload_type {
                Ok(DecomposedHeader {
                    key_id,
                    remaining_bytes: remaining_bytes.to_vec(),
                })
            } else {
                Err(AlloyError::InvalidInput {
                    msg: format!(
                        "The data indicated that this was not a {expected_edek_type} {expected_payload_type} wrapped value. Found: {edek_type}, {payload_type}"
                    ),
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

// Like an EncryptionKey but not used directly for encryption
#[derive(Debug, Serialize, Clone, uniffi::Object)]
pub struct Secret {
    pub(crate) secret: Vec<u8>,
}

#[uniffi::export]
impl Secret {
    #[uniffi::constructor]
    pub fn new(secret: Vec<u8>) -> Result<Arc<Self>, AlloyError> {
        if secret.len() < 32 {
            Err(AlloyError::InvalidConfiguration {
                msg: "Secrets must be at least 32 cryptographically random bytes.".to_string(),
            })
        } else {
            Ok(Arc::new(Self { secret }))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use itertools::Itertools;

    pub fn get_metadata() -> Arc<AlloyMetadata> {
        AlloyMetadata::new_simple(TenantId("foo".to_string()))
    }

    // The expect value matches an array produced in the tsp test derive_keys_produces_known_result_sha_512.
    #[test]
    fn key_derive_produces_known_result() {
        let secret = Secret {
            secret: [0u8; 32].to_vec(),
        };
        let tenant_id = TenantId("tenant".to_string());
        let derivation_path = DerivationPath("somesalt".to_string());

        let key = VectorEncryptionKey::derive_from_secret(&secret, &tenant_id, &derivation_path);

        let expected_sha512 = [
            82u8, 186, 45, 83, 222, 56, 178, 42, 61, 227, 197, 219, 58, 108, 227, 124, 186, 43,
            149, 126, 147, 7, 251, 173, 250, 201, 142, 180, 213, 120, 13, 80, 15, 151, 154, 116,
            33, 229, 191, 200, 97, 74, 54, 48, 196, 84, 213, 202, 84, 12, 202, 225, 20, 18, 2, 102,
            76, 165, 48, 52, 134, 76, 87, 250,
        ];

        let expected_scaling_factor: [u8; 4] = std::iter::once(0u8)
            .chain(expected_sha512[0..3].iter().cloned())
            .collect_vec()
            .try_into()
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(expected_scaling_factor) as f32,
            key.scaling_factor.0
        );

        assert_eq!(expected_sha512[3..35], key.key.0);
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
