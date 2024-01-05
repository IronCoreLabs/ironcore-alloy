use super::errors::{TenantSecurityError, TenantSecurityProxyError};
use super::rest::{
    BatchUnwrapKeyRequest, BatchUnwrapKeyResponse, DerivationType, KeyDeriveResponse,
    LogSecurityEventRequest, RekeyRequest, RekeyResponse, SecretType, TenantDeriveKeyRequest,
    TspErrorResponse, UnwrapKeyRequest, UnwrapKeyResponse, WrapKeyResponse,
};
use super::{ApiKey, RequestMetadata};
use crate::{DerivationPath, SecretPath};
use async_trait::async_trait;
use base64_type::Base64;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, Response, StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const TSP_API_PREFIX: &str = "/api/1/";
const WRAP_ENDPOINT: &str = "document/wrap";
const UNWRAP_ENDPOINT: &str = "document/unwrap";
const BATCH_UNWRAP_ENDPOINT: &str = "document/batch-unwrap";
const REKEY_ENDPOINT: &str = "document/rekey";
const TENANT_KEY_DERIVE_ENDPOINT: &str = "key/derive-with-secret-path";
const SECURITY_EVENT_ENDPOINT: &str = "event/security-event";

pub struct TspRequest {
    tsp_address: String,
    api_key: ApiKey,
    client: Client,
}

impl TspRequest {
    pub fn new(tsp_address: String, api_key: ApiKey, client: Client) -> TspRequest {
        TspRequest {
            tsp_address,
            api_key,
            client,
        }
    }

    pub fn get_default_headers(&self) -> HeaderMap {
        let mut headers: HeaderMap = HeaderMap::default();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        let mut auth_header: HeaderValue = format!("cmk {}", self.api_key.0)
            .parse()
            .expect("Invalid API_KEY");
        auth_header.set_sensitive(true);
        headers.insert("Authorization", auth_header);
        headers
    }

    async fn make_json_request<A: Serialize>(
        &self,
        endpoint: String,
        post_data: A,
    ) -> Result<Response, TenantSecurityError> {
        let url = format!("{}{}{}", self.tsp_address, TSP_API_PREFIX, endpoint);
        let resp = self
            .client
            .post(url)
            .json(&post_data)
            .headers(self.get_default_headers())
            .send()
            .await?;
        match resp.status() {
            StatusCode::OK => Ok(resp),
            status => {
                let parsed_error = resp
                    .json::<Value>()
                    .await
                    .map_err(|_| {
                        TenantSecurityError::RequestError(format!(
                            "Response from the TSP URL was not valid JSON. Status: {}",
                            status.as_str()
                        ))
                    })
                    .and_then(|json| TspErrorResponse::try_from_value(json, status))?;
                Err(super::errors::TenantSecurityError::TspError(
                    TenantSecurityProxyError::code_to_error(parsed_error.code),
                    status,
                ))
            }
        }
    }
}

/// Super-trait containing all the traits that TspRequest implements
pub(crate) trait TenantSecurityRequest: DocumentKeyOps + TenantKeyOps + EventOps {}

#[async_trait]
pub(crate) trait DocumentKeyOps {
    async fn wrap_key(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<WrapKeyResponse, TenantSecurityError>;

    async fn unwrap_key(
        &self,
        encrypted_document_key: &Base64,
        metadata: &RequestMetadata,
    ) -> Result<UnwrapKeyResponse, TenantSecurityError>;

    async fn batch_unwrap_key(
        &self,
        encrypted_document_keys: HashMap<&str, Base64>,
        metadata: &RequestMetadata,
    ) -> Result<BatchUnwrapKeyResponse, TenantSecurityError>;

    async fn rekey(
        &self,
        new_tenant_id: &str,
        metadata: &RequestMetadata,
        encrypted_document_key: &Base64,
    ) -> Result<RekeyResponse, TenantSecurityError>;
}

#[async_trait]
pub(crate) trait EventOps {
    async fn log_security_event(
        &self,
        event_text: &str,
        metadata: &RequestMetadata,
    ) -> Result<(), TenantSecurityError>;
}

#[async_trait]
impl DocumentKeyOps for TspRequest {
    async fn wrap_key(
        &self,
        metadata: &RequestMetadata,
    ) -> Result<WrapKeyResponse, TenantSecurityError> {
        Ok(self
            .make_json_request(WRAP_ENDPOINT.to_string(), metadata)
            .await?
            .json::<WrapKeyResponse>()
            .await?)
    }

    async fn unwrap_key(
        &self,
        encrypted_document_key: &Base64,
        metadata: &RequestMetadata,
    ) -> Result<UnwrapKeyResponse, TenantSecurityError> {
        let post_data = serde_json::to_value(UnwrapKeyRequest {
            encrypted_document_key,
            metadata,
        })?;
        Ok(self
            .make_json_request(UNWRAP_ENDPOINT.to_string(), post_data)
            .await?
            .json::<UnwrapKeyResponse>()
            .await?)
    }

    async fn batch_unwrap_key(
        &self,
        encrypted_document_keys: HashMap<&str, Base64>,
        metadata: &RequestMetadata,
    ) -> Result<BatchUnwrapKeyResponse, TenantSecurityError> {
        let post_data = serde_json::to_value(BatchUnwrapKeyRequest {
            metadata,
            edeks: encrypted_document_keys,
        })?;
        Ok(self
            .make_json_request(BATCH_UNWRAP_ENDPOINT.to_string(), post_data)
            .await?
            .json::<BatchUnwrapKeyResponse>()
            .await?)
    }

    async fn rekey(
        &self,
        new_tenant_id: &str,
        metadata: &RequestMetadata,
        encrypted_document_key: &Base64,
    ) -> Result<RekeyResponse, TenantSecurityError> {
        let post_data = serde_json::to_value(RekeyRequest {
            metadata,
            new_tenant_id,
            encrypted_document_key,
        })?;
        Ok(self
            .make_json_request(REKEY_ENDPOINT.to_string(), post_data)
            .await?
            .json::<RekeyResponse>()
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
    ) -> Result<KeyDeriveResponse, TenantSecurityError>;
}

#[async_trait]
impl TenantKeyOps for TspRequest {
    async fn tenant_key_derive(
        &self,
        paths: HashMap<SecretPath, HashSet<DerivationPath>>,
        metadata: &RequestMetadata,
        derivation_type: DerivationType,
        secret_type: SecretType,
    ) -> Result<KeyDeriveResponse, TenantSecurityError> {
        let post_data = serde_json::to_value(TenantDeriveKeyRequest {
            metadata,
            paths,
            derivation_type,
            secret_type,
        })?;
        Ok(self
            .make_json_request(TENANT_KEY_DERIVE_ENDPOINT.to_string(), post_data)
            .await?
            .json::<KeyDeriveResponse>()
            .await?)
    }
}

#[async_trait]
impl EventOps for TspRequest {
    async fn log_security_event(
        &self,
        event_text: &str,
        metadata: &RequestMetadata,
    ) -> Result<(), TenantSecurityError> {
        let post_data = serde_json::to_value(LogSecurityEventRequest {
            metadata,
            event: event_text,
        })?;
        Ok(self
            .make_json_request(SECURITY_EVENT_ENDPOINT.to_string(), post_data)
            .await?
            .json::<()>()
            .await?)
    }
}

impl TenantSecurityRequest for TspRequest {}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::rest::{DerivedKey, TenantSecretAssignmentId};
    use super::*;
    use crate::TenantId;
    use lazy_static::lazy_static;
    use std::{convert::TryInto, str::FromStr};

    lazy_static! {
        pub static ref KNOWN_DEK: Base64 =
            Base64::from_str("pkg95scDyQkSadd1zhWLWDHpONGdNTaFbLawWdYefy8=").unwrap();
        pub static ref KNOWN_EDEK: Base64 =
            Base64::from_str("CnYKcQokAAWBd/O5LeHFtblkTBZrWnHmJeTiuYwVUNDa14OXCksgrdukEkkA8xjtHsGe1dX7gKGiEqg9jVakzvTt0lL+aePPxDajtzguOMmdfboMWcSrh7WquRmgOXm0ig/o2WonFzsXxqHL6Cw82+goE2TsEP4D").unwrap();
        pub static ref KNOWN_SECRET_PATH: SecretPath = SecretPath("FooBarBa".to_string());
        pub static ref KNOWN_DERIVATION_PATH: DerivationPath = DerivationPath("derivation_path".to_string());
        pub static ref KNOWN_NUM_ID: u32 = 143;
    }

    pub struct MockOps;

    #[async_trait]
    impl DocumentKeyOps for MockOps {
        async fn wrap_key(
            &self,
            _: &RequestMetadata,
        ) -> Result<WrapKeyResponse, TenantSecurityError> {
            Ok(WrapKeyResponse {
                dek: KNOWN_DEK.clone(),
                edek: KNOWN_EDEK.clone(),
            })
        }

        async fn unwrap_key(
            &self,
            _: &Base64,
            _: &RequestMetadata,
        ) -> Result<UnwrapKeyResponse, TenantSecurityError> {
            Ok(UnwrapKeyResponse {
                dek: KNOWN_DEK.clone(),
            })
        }

        async fn batch_unwrap_key(
            &self,
            encrypted_document_keys: HashMap<&str, Base64>,
            _metadata: &RequestMetadata,
        ) -> Result<BatchUnwrapKeyResponse, TenantSecurityError> {
            let keys = encrypted_document_keys
                .into_iter()
                .map(|(key, _)| {
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
        ) -> Result<RekeyResponse, TenantSecurityError> {
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
        ) -> Result<KeyDeriveResponse, TenantSecurityError> {
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
                                        tenant_secret_id: TenantSecretAssignmentId(*KNOWN_NUM_ID),
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
        ) -> Result<(), TenantSecurityError> {
            Ok(())
        }
    }

    impl TenantSecurityRequest for MockOps {}

    #[tokio::test]
    async fn wrap_key_response() -> Result<(), TenantSecurityError> {
        let key_ops = MockOps;
        let metadata =
            RequestMetadata::new_simple(TenantId("tenant".to_string()), "id".try_into()?);
        let wrap_result = key_ops.wrap_key(&metadata).await?;
        assert_eq!(wrap_result.dek, *KNOWN_DEK);
        assert_eq!(wrap_result.edek, *KNOWN_EDEK);
        Ok(())
    }

    #[tokio::test]
    async fn unwrap_key_response() -> Result<(), TenantSecurityError> {
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
    async fn tenant_derive_response() -> Result<(), TenantSecurityError> {
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
            .get_current(&*KNOWN_SECRET_PATH, &*KNOWN_DERIVATION_PATH)
            .unwrap();
        assert_eq!(
            current.derived_key,
            Base64::from_str(&KNOWN_SECRET_PATH.0).unwrap()
        );
        assert!(current.current);
        assert_eq!(current.tenant_secret_id.0, *KNOWN_NUM_ID);
        Ok(())
    }
}
