use crate::tenant_security_client::errors::TenantSecurityError;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

/// Unique ID of tenant that is performing the operation.
#[derive(Debug, Clone, Serialize)]
pub struct TenantId(pub String);
impl TenantId {
    pub fn new(id: String) -> Result<TenantId, TenantSecurityError> {
        id.try_into()
    }
    pub fn inner(&self) -> &str {
        self.0.as_str()
    }
}
impl TryFrom<String> for TenantId {
    type Error = TenantSecurityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(TenantSecurityError::NonEmptyStringError(
                "TenantId".to_string(),
            ))
        } else {
            Ok(TenantId(value))
        }
    }
}
impl TryFrom<&str> for TenantId {
    type Error = TenantSecurityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DecryptError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unwrap failure: {0}")]
    UnwrapFailure(String),
    #[error("aes failure: {0}")]
    AesFailed(String),
    #[error("signature validation failure")]
    SignatureValidation,
    #[error("invalid dek")]
    InvalidDek,
    #[error("other")]
    Other(String),
    #[error("proto error: {0}")]
    Proto(String),
}

/// Document ID used to correlate documents.
#[derive(Debug, Hash, Clone, PartialEq, Eq, Deserialize)]
pub struct DocumentId(pub String);
