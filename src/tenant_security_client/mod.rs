use self::rest::RekeyResponse;
use crate::TenantId;
use crate::errors::AlloyError;
use crate::saas_shield::SecurityEvent;
use crate::{DerivationPath, SecretPath};
use base64_type::Base64;
use request::{AlloyHttpClientHeaders, HttpClient, TenantSecurityRequest, TspRequest};
pub use rest::{
    BatchUnwrapKeyResponse, BatchWrapKeyResponse, DerivationType, DeriveKeyChoice, DerivedKey,
    KeyDeriveResponse, SecretType, UnwrapKeyResponse, WrapKeyResponse,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
};

#[cfg(test)]
pub use rest::TenantSecretAssignmentId;

pub(crate) mod errors;
pub(crate) mod request;
mod rest;

#[derive(Debug)]
pub(crate) struct ApiKey(pub(crate) String);

impl TryFrom<String> for ApiKey {
    type Error = AlloyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        use AlloyError::InvalidConfiguration;
        Base64::from_str(value.as_str())
            .map_err(|_| InvalidConfiguration {
                msg: "API_KEY was not valid Base64.".to_string(),
            })
            .and_then(|base64| {
                if base64.len() == 12 {
                    Ok(ApiKey(value))
                } else {
                    Err(InvalidConfiguration {
                        msg: "API_KEY was not 16 characters.".to_string(),
                    })
                }
            })
    }
}

/// Tenant Security Client that can be used to encrypt and decrypt documents.
pub struct TenantSecurityClient {
    request: Arc<dyn TenantSecurityRequest + Send + Sync>,
}

impl TenantSecurityClient {
    pub fn new(
        tsp_address: String,
        client: Arc<dyn HttpClient>,
        headers: AlloyHttpClientHeaders,
    ) -> TenantSecurityClient {
        TenantSecurityClient {
            request: Arc::new(TspRequest::new(tsp_address, client, headers)),
        }
    }

    pub async fn wrap_key(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<WrapKeyResponse, AlloyError> {
        self.request.wrap_key(metadata).await
    }

    pub async fn unwrap_key(
        &self,
        edek: Vec<u8>,
        metadata: &RequestMetadata,
    ) -> Result<UnwrapKeyResponse, AlloyError> {
        let base64 = Base64(edek);
        self.request.unwrap_key(&base64, metadata).await
    }

    pub async fn batch_wrap_keys(
        &self,
        document_ids: Vec<&str>,
        metadata: &RequestMetadata,
    ) -> Result<BatchWrapKeyResponse, AlloyError> {
        self.request.batch_wrap_keys(document_ids, metadata).await
    }

    pub async fn batch_unwrap_keys(
        &self,
        edeks: HashMap<&str, Vec<u8>>,
        metadata: &RequestMetadata,
    ) -> Result<BatchUnwrapKeyResponse, AlloyError> {
        let base64_edeks = edeks
            .into_iter()
            .map(|(key, edek)| (key, Base64(edek)))
            .collect();
        self.request.batch_unwrap_keys(base64_edeks, metadata).await
    }

    pub async fn rekey_edek(
        &self,
        edek: Vec<u8>,
        new_tenant_id: &TenantId,
        metadata: &RequestMetadata,
    ) -> Result<RekeyResponse, AlloyError> {
        let base64 = Base64(edek);
        self.request
            .rekey(&new_tenant_id.0, metadata, &base64)
            .await
    }

    /// Request the Tenant Security Proxy to derive keys by using the tenant's secret and the provided
    /// salts. Returns a struct containing a HashMap from the salt string to the derived keys.
    ///
    /// # Arguments
    /// - `salt_strings` - Salts to use when deriving keys.
    /// - `metadata`     - Metadata to use for the key derive request.
    pub async fn tenant_key_derive(
        &self,
        paths: HashMap<SecretPath, HashSet<DerivationPath>>,
        metadata: &RequestMetadata,
        derivation_type: DerivationType,
        secret_type: SecretType,
    ) -> Result<KeyDeriveResponse, AlloyError> {
        self.request
            .tenant_key_derive(paths, metadata, derivation_type, secret_type)
            .await
    }

    /// Log a security event which will be sent to the tenant's log sink.
    pub async fn log_security_event(
        &self,
        event: &SecurityEvent,
        metadata: &RequestMetadata,
    ) -> Result<(), AlloyError> {
        self.request
            .log_security_event(event.to_string().as_str(), metadata)
            .await
    }
}

/// Holds metadata fields as part of an document request. Each document will have metadata that associates
/// it to a tenant ID, which service is accessing the data, as well as optional fields for other arbitrary
/// key/value pairs and a request ID to send to the Tenant Security Proxy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct RequestMetadata {
    pub tenant_id: TenantId,
    pub icl_fields: IclFields,
    pub custom_fields: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_millis: Option<u64>,
}

impl RequestMetadata {
    /// Constructor for RequestMetadata which contains the tenant's ID, the requesting service's ID,
    /// and other metadata to send to the Tenant Security Proxy.
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
    pub fn new(
        tenant_id: TenantId,
        requesting_user_or_service_id: RequestingId,
        data_label: Option<String>,
        source_ip: Option<String>,
        object_id: Option<String>,
        request_id: Option<String>,
        timestamp_millis: Option<u64>,
        other_data: HashMap<String, String>,
    ) -> RequestMetadata {
        RequestMetadata {
            tenant_id,
            timestamp_millis,
            icl_fields: IclFields {
                requesting_id: requesting_user_or_service_id,
                data_label,
                source_ip,
                object_id,
                request_id,
            },
            custom_fields: other_data,
        }
    }

    /// Simplified constructor for RequestMetadata that only takes the tenant's ID and the
    /// ID of the user/service that is processing data.
    ///
    /// # Arguments
    /// - `tenant_id`                     - Unique ID of tenant that is performing the operation.
    /// - `requesting_user_or_service_id` - Unique ID of user/service that is processing data. Must be non-empty.
    #[allow(dead_code)]
    pub fn new_simple(
        tenant_id: TenantId,
        requesting_user_or_service_id: RequestingId,
    ) -> RequestMetadata {
        RequestMetadata {
            tenant_id,
            timestamp_millis: None,
            icl_fields: IclFields {
                requesting_id: requesting_user_or_service_id,
                data_label: None,
                source_ip: None,
                object_id: None,
                request_id: None,
            },
            custom_fields: HashMap::new(),
        }
    }
}

/// Document metadata in a form that can be serialized and sent to the TSP.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct IclFields {
    /// An identifier for the requesting user or service.
    requesting_id: RequestingId,
    data_label: Option<String>,
    source_ip: Option<String>,
    object_id: Option<String>,
    request_id: Option<String>,
}

/// Unique ID of user/service that is processing data.
#[derive(Debug, Clone, Serialize)]
pub struct RequestingId(String);
impl RequestingId {
    pub fn new(id: String) -> Result<RequestingId, AlloyError> {
        id.try_into()
    }
}
impl TryFrom<String> for RequestingId {
    type Error = AlloyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(AlloyError::InvalidInput {
                msg: "RequestingId cannot be empty.".to_string(),
            })
        } else {
            Ok(RequestingId(value))
        }
    }
}
impl TryFrom<&str> for RequestingId {
    type Error = AlloyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}
