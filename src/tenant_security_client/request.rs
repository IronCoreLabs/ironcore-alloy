use super::RequestMetadata;
use super::errors::TenantSecurityProxyError;
use super::rest::{
    BatchUnwrapKeyRequest, BatchUnwrapKeyResponse, BatchWrapKeyRequest, BatchWrapKeyResponse,
    DerivationType, KeyDeriveResponse, LogSecurityEventRequest, RekeyRequest, RekeyResponse,
    SecretType, TenantDeriveKeyRequest, TspErrorResponse, UnwrapKeyRequest, UnwrapKeyResponse,
    WrapKeyResponse,
};
use crate::errors::AlloyError;
use crate::{DerivationPath, SecretPath};
use async_trait::async_trait;
use base64_type::Base64;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const TSP_API_PREFIX: &str = "/api/1/";
const WRAP_ENDPOINT: &str = "document/wrap";
const BATCH_WRAP_ENDPOINT: &str = "document/batch-wrap";
const UNWRAP_ENDPOINT: &str = "document/unwrap";
const BATCH_UNWRAP_ENDPOINT: &str = "document/batch-unwrap";
const REKEY_ENDPOINT: &str = "document/rekey";
const TENANT_KEY_DERIVE_ENDPOINT: &str = "key/derive-with-secret-path";
const SECURITY_EVENT_ENDPOINT: &str = "event/security-event";

#[derive(Debug, Clone, uniffi::Record)]
pub struct AlloyHttpClientHeaders {
    pub content_type: String,
    pub authorization: String,
}

#[derive(Debug, uniffi::Record)]
pub struct AlloyHttpClientResponse {
    pub json_body: String,
    pub status_code: u16,
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
/// Trait describing the functionality ironcore-alloy needs from a client to make SaaS Shield requests.
pub trait HttpClient: Send + Sync {
    /// Makes a call with a JSON body and returns a string of the JSON result. Only JSON requests and responses
    /// are supported, the provided headers will include a correct content type.
    async fn post_json(
        &self,
        url: String,
        json_body: String,
        headers: AlloyHttpClientHeaders,
    ) -> Result<AlloyHttpClientResponse, AlloyError>;
}

#[async_trait::async_trait]
impl HttpClient for reqwest::Client {
    async fn post_json(
        &self,
        url: String,
        json_body: String,
        headers: AlloyHttpClientHeaders,
    ) -> Result<AlloyHttpClientResponse, AlloyError> {
        let mut reqwest_header_map = HeaderMap::new();
        reqwest_header_map.insert(
            "Content-Type",
            HeaderValue::from_str(&headers.content_type).map_err(|_| AlloyError::RequestError {
                msg: format!(
                    "Bad Content-Type value provided to the HTTP client: {}",
                    headers.content_type
                ),
            })?,
        );
        let mut auth_header =
            HeaderValue::from_str(&headers.authorization).map_err(|_| AlloyError::RequestError {
                msg: format!(
                    "Bad Authorization header provided to the HTTP client: {}",
                    headers.content_type
                ),
            })?;
        auth_header.set_sensitive(true);
        reqwest_header_map.insert("Authorization", auth_header);

        let resp = self
            .post(url)
            .headers(reqwest_header_map)
            .body(json_body)
            .send()
            .await?;

        Ok(AlloyHttpClientResponse {
            status_code: resp.status().as_u16(),
            json_body: resp.text().await?,
        })
    }
}

pub struct TspRequest {
    tsp_address: String,
    client: Arc<dyn HttpClient>,
    headers: AlloyHttpClientHeaders,
}

impl TspRequest {
    pub fn new(
        tsp_address: String,
        client: Arc<dyn HttpClient>,
        headers: AlloyHttpClientHeaders,
    ) -> TspRequest {
        TspRequest {
            tsp_address,
            client,
            headers,
        }
    }

    async fn make_json_request<A: Serialize, T: DeserializeOwned>(
        &self,
        endpoint: String,
        post_data: A,
    ) -> Result<T, AlloyError> {
        let url = format!("{}{}{}", self.tsp_address, TSP_API_PREFIX, endpoint);
        let resp = self
            .client
            .post_json(
                url,
                serde_json::to_string(&post_data)?,
                self.headers.clone(),
            )
            .await?;
        match serde_json::from_str::<T>(&resp.json_body) {
            Ok(t) => Ok(t),
            Err(_) => {
                let parsed_error = serde_json::from_str::<Value>(&resp.json_body)
                    .map_err(|_| AlloyError::RequestError {
                        msg: format!(
                            "Response from the TSP URL was not valid JSON. Status: {}",
                            resp.status_code
                        ),
                    })
                    .and_then(|json| TspErrorResponse::try_from_value(json, resp.status_code))?;
                let error_variant = TenantSecurityProxyError::code_to_error(parsed_error.code);
                Err(AlloyError::TspError {
                    msg: error_variant.to_string(),
                    error: error_variant,
                    http_code: resp.status_code,
                    tsp_code: parsed_error.code,
                })
            }
        }
    }
}

/// Super-trait containing all the traits that TspRequest implements
pub(crate) trait TenantSecurityRequest: DocumentKeyOps + TenantKeyOps + EventOps {}

#[async_trait]
pub(crate) trait DocumentKeyOps {
    async fn wrap_key(&self, metadata: &RequestMetadata) -> Result<WrapKeyResponse, AlloyError>;

    async fn unwrap_key(
        &self,
        encrypted_document_key: &Base64,
        metadata: &RequestMetadata,
    ) -> Result<UnwrapKeyResponse, AlloyError>;

    async fn batch_wrap_keys(
        &self,
        document_ids: Vec<&str>,
        metadata: &RequestMetadata,
    ) -> Result<BatchWrapKeyResponse, AlloyError>;

    async fn batch_unwrap_keys(
        &self,
        encrypted_document_keys: HashMap<&str, Base64>,
        metadata: &RequestMetadata,
    ) -> Result<BatchUnwrapKeyResponse, AlloyError>;

    async fn rekey(
        &self,
        new_tenant_id: &str,
        metadata: &RequestMetadata,
        encrypted_document_key: &Base64,
    ) -> Result<RekeyResponse, AlloyError>;
}

#[async_trait]
pub(crate) trait EventOps {
    async fn log_security_event(
        &self,
        event_text: &str,
        metadata: &RequestMetadata,
    ) -> Result<(), AlloyError>;
}

#[async_trait]
impl DocumentKeyOps for TspRequest {
    async fn wrap_key(&self, metadata: &RequestMetadata) -> Result<WrapKeyResponse, AlloyError> {
        Ok(self
            .make_json_request(WRAP_ENDPOINT.to_string(), metadata)
            .await?)
    }

    async fn unwrap_key(
        &self,
        encrypted_document_key: &Base64,
        metadata: &RequestMetadata,
    ) -> Result<UnwrapKeyResponse, AlloyError> {
        let post_data = serde_json::to_value(UnwrapKeyRequest {
            encrypted_document_key,
            metadata,
        })?;
        Ok(self
            .make_json_request(UNWRAP_ENDPOINT.to_string(), post_data)
            .await?)
    }

    async fn batch_wrap_keys(
        &self,
        document_ids: Vec<&str>,
        metadata: &RequestMetadata,
    ) -> Result<BatchWrapKeyResponse, AlloyError> {
        let post_data = serde_json::to_value(BatchWrapKeyRequest {
            metadata,
            document_ids,
        })?;
        Ok(self
            .make_json_request(BATCH_WRAP_ENDPOINT.to_string(), post_data)
            .await?)
    }

    async fn batch_unwrap_keys(
        &self,
        encrypted_document_keys: HashMap<&str, Base64>,
        metadata: &RequestMetadata,
    ) -> Result<BatchUnwrapKeyResponse, AlloyError> {
        let post_data = serde_json::to_value(BatchUnwrapKeyRequest {
            metadata,
            edeks: encrypted_document_keys,
        })?;
        Ok(self
            .make_json_request(BATCH_UNWRAP_ENDPOINT.to_string(), post_data)
            .await?)
    }

    async fn rekey(
        &self,
        new_tenant_id: &str,
        metadata: &RequestMetadata,
        encrypted_document_key: &Base64,
    ) -> Result<RekeyResponse, AlloyError> {
        let post_data = serde_json::to_value(RekeyRequest {
            metadata,
            new_tenant_id,
            encrypted_document_key,
        })?;
        Ok(self
            .make_json_request(REKEY_ENDPOINT.to_string(), post_data)
            .await?)
    }
}

#[async_trait]
pub trait TenantKeyOps {
    async fn tenant_key_derive(
        &self,
        paths: HashMap<SecretPath, HashSet<DerivationPath>>,
        metadata: &RequestMetadata,
        derivation_type: DerivationType,
        secret_type: SecretType,
    ) -> Result<KeyDeriveResponse, AlloyError>;
}

#[async_trait]
impl TenantKeyOps for TspRequest {
    async fn tenant_key_derive(
        &self,
        paths: HashMap<SecretPath, HashSet<DerivationPath>>,
        metadata: &RequestMetadata,
        derivation_type: DerivationType,
        secret_type: SecretType,
    ) -> Result<KeyDeriveResponse, AlloyError> {
        let post_data = serde_json::to_value(TenantDeriveKeyRequest {
            metadata,
            paths,
            derivation_type,
            secret_type,
        })?;
        Ok(self
            .make_json_request(TENANT_KEY_DERIVE_ENDPOINT.to_string(), post_data)
            .await?)
    }
}

#[async_trait]
impl EventOps for TspRequest {
    async fn log_security_event(
        &self,
        event_text: &str,
        metadata: &RequestMetadata,
    ) -> Result<(), AlloyError> {
        let post_data = serde_json::to_value(LogSecurityEventRequest {
            metadata,
            event: event_text,
        })?;
        Ok(self
            .make_json_request(SECURITY_EVENT_ENDPOINT.to_string(), post_data)
            .await?)
    }
}

impl TenantSecurityRequest for TspRequest {}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::rest::{DerivedKey, TenantSecretAssignmentId};
    use super::*;
    use crate::TenantId;
    use std::sync::LazyLock;
    use std::{convert::TryInto, str::FromStr};

    pub static KNOWN_DEK: LazyLock<Base64> =
        LazyLock::new(|| Base64::from_str("pkg95scDyQkSadd1zhWLWDHpONGdNTaFbLawWdYefy8=").unwrap());
    pub static KNOWN_EDEK: LazyLock<Base64> = LazyLock::new(|| {
        Base64::from_str("CnYKcQokAAWBd/O5LeHFtblkTBZrWnHmJeTiuYwVUNDa14OXCksgrdukEkkA8xjtHsGe1dX7gKGiEqg9jVakzvTt0lL+aePPxDajtzguOMmdfboMWcSrh7WquRmgOXm0ig/o2WonFzsXxqHL6Cw82+goE2TsEP4D").unwrap()
    });
    pub static KNOWN_SECRET_PATH: LazyLock<SecretPath> =
        LazyLock::new(|| SecretPath("FooBarBa".to_string()));
    pub static KNOWN_DERIVATION_PATH: LazyLock<DerivationPath> =
        LazyLock::new(|| DerivationPath("derivation_path".to_string()));
    pub const KNOWN_NUM_ID: u32 = 143;

    pub struct MockOps;

    #[async_trait]
    impl DocumentKeyOps for MockOps {
        async fn wrap_key(&self, _: &RequestMetadata) -> Result<WrapKeyResponse, AlloyError> {
            Ok(WrapKeyResponse {
                dek: KNOWN_DEK.clone(),
                edek: KNOWN_EDEK.clone(),
            })
        }

        async fn unwrap_key(
            &self,
            _: &Base64,
            _: &RequestMetadata,
        ) -> Result<UnwrapKeyResponse, AlloyError> {
            Ok(UnwrapKeyResponse {
                dek: KNOWN_DEK.clone(),
            })
        }

        async fn batch_wrap_keys(
            &self,
            _: Vec<&str>,
            _: &RequestMetadata,
        ) -> Result<BatchWrapKeyResponse, AlloyError> {
            Ok(BatchWrapKeyResponse {
                keys: [(
                    "document".to_string(),
                    WrapKeyResponse {
                        dek: KNOWN_DEK.clone(),
                        edek: KNOWN_EDEK.clone(),
                    },
                )]
                .into(),
                failures: HashMap::new(),
            })
        }

        async fn batch_unwrap_keys(
            &self,
            encrypted_document_keys: HashMap<&str, Base64>,
            _metadata: &RequestMetadata,
        ) -> Result<BatchUnwrapKeyResponse, AlloyError> {
            let keys = encrypted_document_keys
                .into_keys()
                .map(|key| {
                    (
                        key.to_string(),
                        UnwrapKeyResponse {
                            dek: KNOWN_DEK.clone(),
                        },
                    )
                })
                .collect();
            Ok(BatchUnwrapKeyResponse {
                keys,
                failures: HashMap::new(),
            })
        }

        async fn rekey(
            &self,
            _new_tenant_id: &str,
            _metadata: &RequestMetadata,
            _encrypted_document_key: &Base64,
        ) -> Result<RekeyResponse, AlloyError> {
            Ok(RekeyResponse {
                dek: KNOWN_DEK.clone(),
                edek: KNOWN_EDEK.clone(),
            })
        }
    }

    #[async_trait]
    impl TenantKeyOps for MockOps {
        async fn tenant_key_derive(
            &self,
            paths: HashMap<SecretPath, HashSet<DerivationPath>>,
            _metadata: &RequestMetadata,
            _derivation_type: DerivationType,
            _secret_type: SecretType,
        ) -> Result<KeyDeriveResponse, AlloyError> {
            let derived_keys = paths
                .into_iter()
                .map(|(secret_path, derivation_paths)| {
                    (
                        secret_path.clone(),
                        derivation_paths
                            .into_iter()
                            .map(|path| {
                                (
                                    path,
                                    vec![DerivedKey {
                                        derived_key: Base64::from_str(&secret_path.0).unwrap(),
                                        tenant_secret_id: TenantSecretAssignmentId(KNOWN_NUM_ID),
                                        current: true,
                                    }],
                                )
                            })
                            .collect(),
                    )
                })
                .collect();
            Ok(KeyDeriveResponse {
                derived_keys,
                has_primary_config: true,
            })
        }
    }

    #[async_trait]
    impl EventOps for MockOps {
        async fn log_security_event(
            &self,
            _event_text: &str,
            _metadata: &RequestMetadata,
        ) -> Result<(), AlloyError> {
            Ok(())
        }
    }

    impl TenantSecurityRequest for MockOps {}

    #[tokio::test]
    async fn wrap_key_response() -> Result<(), AlloyError> {
        let key_ops = MockOps;
        let metadata =
            RequestMetadata::new_simple(TenantId("tenant".to_string()), "id".try_into()?);
        let wrap_result = key_ops.wrap_key(&metadata).await?;
        assert_eq!(wrap_result.dek, *KNOWN_DEK);
        assert_eq!(wrap_result.edek, *KNOWN_EDEK);
        Ok(())
    }

    #[tokio::test]
    async fn unwrap_key_response() -> Result<(), AlloyError> {
        let key_ops = MockOps;
        let metadata =
            RequestMetadata::new_simple(TenantId("tenant".to_string()), "id".try_into()?);
        let wrap_result = key_ops
            .unwrap_key(&Base64::from_str("edek").unwrap(), &metadata)
            .await?;
        assert_eq!(wrap_result.dek, *KNOWN_DEK);
        Ok(())
    }

    #[tokio::test]
    async fn tenant_derive_response() -> Result<(), AlloyError> {
        let key_ops = MockOps;
        let metadata =
            RequestMetadata::new_simple(TenantId("tenant".to_string()), "id".try_into()?);
        let paths = [(
            KNOWN_SECRET_PATH.clone(),
            [KNOWN_DERIVATION_PATH.clone()].into(),
        )]
        .into();
        let derive_result = key_ops
            .tenant_key_derive(paths, &metadata, DerivationType::Sha256, SecretType::Vector)
            .await?;
        let current = derive_result
            .get_current(&KNOWN_SECRET_PATH, &KNOWN_DERIVATION_PATH)
            .unwrap();
        assert_eq!(
            current.derived_key,
            Base64::from_str(&KNOWN_SECRET_PATH.0).unwrap()
        );
        assert!(current.current);
        assert_eq!(current.tenant_secret_id.0, KNOWN_NUM_ID);
        Ok(())
    }
}
