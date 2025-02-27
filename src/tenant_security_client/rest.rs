use super::{DerivationPath, RequestMetadata, SecretPath, errors::TenantSecurityProxyError};
use crate::errors::AlloyError;
use base64_type::Base64;
use ironcore_documents::v5::key_id_header::KeyId;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub(crate) struct LogSecurityEventRequest<'a> {
    pub event: &'a str,
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub(crate) struct UnwrapKeyRequest<'a> {
    pub encrypted_document_key: &'a Base64,
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct BatchWrapKeyRequest<'a> {
    pub document_ids: Vec<&'a str>,
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct BatchUnwrapKeyRequest<'a> {
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
    pub edeks: HashMap<&'a str, Base64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct RekeyRequest<'a> {
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
    pub new_tenant_id: &'a str,
    pub encrypted_document_key: &'a Base64,
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum DerivationType {
    #[allow(dead_code)]
    Argon2,
    #[allow(dead_code)]
    Sha256,
    Sha512,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum SecretType {
    Search,
    Deterministic,
    Vector,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub(crate) struct TenantDeriveKeyRequest<'a> {
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
    pub paths: HashMap<SecretPath, HashSet<DerivationPath>>,
    pub derivation_type: DerivationType,
    pub secret_type: SecretType,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TspErrorResponse {
    pub code: u16,
    pub message: String,
}

impl TspErrorResponse {
    pub fn try_from_value(value: Value, status: StatusCode) -> Result<Self, AlloyError> {
        serde_json::from_value::<TspErrorResponse>(value.clone()).map_err(|_| {
            AlloyError::RequestError {
                msg: format!(
                    "TSP gave an invalid response: `{}`. Status: {}",
                    value,
                    status.as_str()
                ),
            }
        })
    }
}

impl From<TspErrorResponse> for AlloyError {
    fn from(value: TspErrorResponse) -> Self {
        let error_variant = TenantSecurityProxyError::code_to_error(value.code);
        AlloyError::TspError {
            msg: error_variant.to_string(),
            error: error_variant,
            http_code: 0, // this impl is for the `failures` half of batch responses from the TSP, and the TSP doesn't send a status
            tsp_code: value.code,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WrapKeyResponse {
    pub dek: Base64,
    pub edek: Base64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnwrapKeyResponse {
    pub dek: Base64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse<T> {
    pub keys: HashMap<String, T>,
    pub failures: HashMap<String, TspErrorResponse>,
}

pub type BatchWrapKeyResponse = BatchResponse<WrapKeyResponse>;
pub type BatchUnwrapKeyResponse = BatchResponse<UnwrapKeyResponse>;
pub type RekeyResponse = WrapKeyResponse;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct TenantSecretAssignmentId(pub u32);

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKey {
    pub derived_key: Base64,
    pub tenant_secret_id: TenantSecretAssignmentId,
    pub current: bool,
}

pub type DerivedKeys = HashMap<DerivationPath, Vec<DerivedKey>>;

pub enum DeriveKeyChoice {
    Current,
    Specific(KeyId),
    InRotation, // Non-current
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyDeriveResponse {
    pub has_primary_config: bool,
    pub derived_keys: HashMap<SecretPath, DerivedKeys>,
}

impl KeyDeriveResponse {
    /// Get a key of specified type from the TSP response. Can return the
    /// current key, in-rotation key, or a key with a specific ID.
    pub fn get_key_for_path(
        &self,
        secret_path: &SecretPath,
        deriv_path: &DerivationPath,
        derive_key_choice: DeriveKeyChoice,
    ) -> Result<&DerivedKey, AlloyError> {
        match derive_key_choice {
            DeriveKeyChoice::Current => self.get_current(secret_path, deriv_path),
            DeriveKeyChoice::Specific(key_id) => self.get_by_id(secret_path, deriv_path, key_id.0),
            DeriveKeyChoice::InRotation => self.get_in_rotation(secret_path, deriv_path),
        }
        .ok_or_else(|| AlloyError::RequestError {
            msg: "The secret path, derivation path combo didn't have the requested key."
                .to_string(),
        })
    }

    /// Look for a certain salt in derived_keys and return its current key (if present)
    pub fn get_current(
        &self,
        secret_path: &SecretPath,
        derivation_path: &DerivationPath,
    ) -> Option<&DerivedKey> {
        self.derived_keys
            .get(secret_path)
            .and_then(|d| d.get(derivation_path))
            .and_then(|keys| keys.iter().find(|key| key.current))
    }

    /// Look for a certain salt in derived_keys and return its in-rotation key (if present)
    pub fn get_in_rotation(
        &self,
        secret_path: &SecretPath,
        derivation_path: &DerivationPath,
    ) -> Option<&DerivedKey> {
        self.derived_keys
            .get(secret_path)
            .and_then(|d| d.get(derivation_path))
            .and_then(|keys| keys.iter().find(|key| !key.current))
    }

    /// Look for a certain salt in derived_keys and return the id that matches key_id (if present).
    pub fn get_by_id(
        &self,
        secret_path: &SecretPath,
        derivation_path: &DerivationPath,
        key_id: u32,
    ) -> Option<&DerivedKey> {
        self.derived_keys
            .get(secret_path)
            .and_then(|d| d.get(derivation_path))
            .and_then(|keys| keys.iter().find(|key| key.tenant_secret_id.0 == key_id))
    }
}

#[cfg(test)]
mod tests {
    use super::super::request::tests::KNOWN_NUM_ID;
    use super::*;
    use std::str::FromStr;

    #[test]
    fn key_derive_get_primary() -> Result<(), AlloyError> {
        let secret_path = SecretPath("foo-bar-baz".to_string());
        let derivation_path = DerivationPath("qux".to_string());
        let mut derivation_paths = HashMap::new();
        derivation_paths.insert(
            derivation_path.clone(),
            vec![DerivedKey {
                derived_key: Base64::from_str("abc").unwrap(),
                current: true,
                tenant_secret_id: TenantSecretAssignmentId(*KNOWN_NUM_ID),
            }],
        );
        let mut derived_keys = HashMap::new();
        derived_keys.insert(secret_path.clone(), derivation_paths);
        let derive_response = KeyDeriveResponse {
            derived_keys,
            has_primary_config: true,
        };
        let primary = derive_response.get_current(&secret_path, &derivation_path);
        assert!(primary.is_some());
        let no_primary =
            derive_response.get_current(&SecretPath("not-there".to_string()), &derivation_path);
        assert!(no_primary.is_none());
        Ok(())
    }
}
