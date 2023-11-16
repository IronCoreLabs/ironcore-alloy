use super::{errors::TenantSecurityError, DerivationPath, RequestMetadata, SecretPath};
use base64_type::Base64;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub(crate) struct UnwrapKeyRequest<'a> {
    pub encrypted_document_key: &'a Base64,
    #[serde(flatten)]
    pub metadata: &'a RequestMetadata,
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
    pub fn try_from_value(value: Value, status: StatusCode) -> Result<Self, TenantSecurityError> {
        serde_json::from_value::<TspErrorResponse>(value.clone()).map_err(|_| {
            TenantSecurityError::RequestError(format!(
                "TSP gave an invalid response: `{}`. Status: {}",
                value,
                status.as_str()
            ))
        })
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct TenantSecretAssignmentId(pub u32);

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKey {
    pub derived_key: Base64,
    pub tenant_secret_id: TenantSecretAssignmentId,
    pub current: bool,
}

pub type DerivedKeys = HashMap<DerivationPath, Vec<DerivedKey>>;

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyDeriveResponse {
    pub has_primary_config: bool,
    pub derived_keys: HashMap<SecretPath, DerivedKeys>,
}

impl KeyDeriveResponse {
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
    use super::super::{errors::TenantSecurityError, request::tests::KNOWN_NUM_ID};
    use super::*;
    use std::str::FromStr;

    #[test]
    fn key_derive_get_primary() -> Result<(), TenantSecurityError> {
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