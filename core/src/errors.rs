use crate::tenant_security_client::errors::TenantSecurityError;
use crate::vector::crypto::{DecryptError, EncryptError};

/// Errors related to CloakedAiStandalone
#[derive(Debug, uniffi::Error, PartialEq, Eq)]
#[uniffi(flat_error)]
pub enum CloakedAiError {
    /// Error while loading configuration.
    InvalidConfiguration(String),
    /// Error with key used to initialize CloakedAiStandalone
    InvalidKey(String),
    /// Error during decryption with provided IV
    InvalidIv,
    /// Error during decryption with provided authentication hash
    InvalidAuthHash,
    /// Error with input vector. Likely due to overflow with large values
    InvalidInput(String),
    /// Error when encrypting or decrypting documents
    DocumentError(String),
    /// Error when parsing encryption headers/metadata
    ProtobufError(String),
    /// Error with requests to TSC
    TenantSecurityError(String),
    /// Error with IronCore Documents
    IronCoreDocumentsError(String),
}
impl std::fmt::Display for CloakedAiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloakedAiError::InvalidConfiguration(message) => {
                write!(f, "Invalid configuration: '{message}'")
            }
            CloakedAiError::InvalidKey(message) => write!(f, "Invalid key: '{message}'"),
            CloakedAiError::InvalidIv => write!(f, "Invalid IV"),
            CloakedAiError::InvalidAuthHash => write!(f, "Invalid authentication hash"),
            CloakedAiError::InvalidInput(message) => write!(f, "Invalid input: '{message}'"),
            CloakedAiError::DocumentError(message) => {
                write!(f, "Failed encrypting/decrypting document: '{message}'")
            }
            CloakedAiError::ProtobufError(message) => write!(f, "Protobuf error: '{message}'"),
            CloakedAiError::TenantSecurityError(message) => {
                write!(f, "Tenant security client error: '{message}'")
            }
            CloakedAiError::IronCoreDocumentsError(message) => {
                write!(f, "IronCore Documents error: '{message}'")
            }
        }
    }
}

impl From<TenantSecurityError> for CloakedAiError {
    fn from(value: TenantSecurityError) -> Self {
        Self::TenantSecurityError(value.to_string())
    }
}

impl From<EncryptError> for CloakedAiError {
    fn from(value: EncryptError) -> Self {
        match value {
            EncryptError::InvalidKey(s) => Self::InvalidKey(s),
            EncryptError::OverflowError => Self::InvalidInput(value.to_string()),
        }
    }
}

impl From<DecryptError> for CloakedAiError {
    fn from(value: DecryptError) -> Self {
        match value {
            DecryptError::InvalidKey(s) => Self::InvalidKey(s),
            DecryptError::InvalidAuthHash => Self::InvalidAuthHash,
        }
    }
}

impl From<ironcore_documents::Error> for CloakedAiError {
    fn from(value: ironcore_documents::Error) -> Self {
        CloakedAiError::IronCoreDocumentsError(value.to_string())
    }
}

impl From<protobuf::Error> for CloakedAiError {
    fn from(value: protobuf::Error) -> Self {
        CloakedAiError::ProtobufError(value.to_string())
    }
}

impl std::error::Error for CloakedAiError {}
