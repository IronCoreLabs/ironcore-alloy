use crate::tenant_security_client::errors::TenantSecurityError;
use crate::vector::crypto::{
    DecryptError as VectorDecryptError, EncryptError as VectorEncryptError,
};

/// Errors related to IronCore Alloy SDK
#[derive(Debug, uniffi::Error, PartialEq, Eq)]
#[uniffi(flat_error)]
pub enum AlloyError {
    /// Error while loading configuration.
    InvalidConfiguration(String),
    /// Error with key used
    InvalidKey(String),
    /// Error with user input
    InvalidInput(String),
    /// Errors while encrypting
    EncryptError(String),
    /// Errors while decrypting
    DecryptError(String),
    /// Error when parsing encryption headers/metadata
    ProtobufError(String),
    /// Error with requests to TSC
    TenantSecurityError(String),
}
impl std::fmt::Display for AlloyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlloyError::InvalidConfiguration(message) => {
                write!(f, "Invalid configuration: '{message}'")
            }
            AlloyError::InvalidKey(message) => write!(f, "Invalid key: '{message}'"),
            AlloyError::InvalidInput(message) => write!(f, "Invalid input: '{message}'"),
            AlloyError::EncryptError(message) => write!(f, "Encrypt error: '{message}'"),
            AlloyError::DecryptError(message) => write!(f, "Decrypt error: '{message}'"),
            AlloyError::ProtobufError(message) => write!(f, "Protobuf error: '{message}'"),
            AlloyError::TenantSecurityError(message) => {
                write!(f, "Tenant security client error: '{message}'")
            }
        }
    }
}
impl From<TenantSecurityError> for AlloyError {
    fn from(value: TenantSecurityError) -> Self {
        Self::TenantSecurityError(value.to_string())
    }
}
impl From<VectorEncryptError> for AlloyError {
    fn from(value: VectorEncryptError) -> Self {
        match value {
            VectorEncryptError::InvalidKey(s) => Self::InvalidKey(s),
            VectorEncryptError::OverflowError => Self::InvalidInput(value.to_string()),
        }
    }
}
impl From<VectorDecryptError> for AlloyError {
    fn from(value: VectorDecryptError) -> Self {
        match value {
            VectorDecryptError::InvalidKey(s) => Self::InvalidKey(s),
            VectorDecryptError::InvalidAuthHash => {
                Self::InvalidInput("Invalid authentication hash".to_string())
            }
        }
    }
}
impl From<ironcore_documents::Error> for AlloyError {
    fn from(value: ironcore_documents::Error) -> Self {
        match value {
            ironcore_documents::Error::EdocTooShort(_)
            | ironcore_documents::Error::HeaderParseErr(_)
            | ironcore_documents::Error::InvalidVersion(_)
            | ironcore_documents::Error::NoIronCoreMagic
            | ironcore_documents::Error::SpecifiedLengthTooLong(_)
            | ironcore_documents::Error::HeaderLengthOverflow(_)
            | ironcore_documents::Error::EdekTypeError(_)
            | ironcore_documents::Error::PayloadTypeError(_)
            | ironcore_documents::Error::KeyIdHeaderTooShort(_)
            | ironcore_documents::Error::KeyIdHeaderMalformed(_) => {
                AlloyError::InvalidInput(value.to_string())
            }
            ironcore_documents::Error::ProtoSerializationErr(m) => AlloyError::ProtobufError(m),
            ironcore_documents::Error::EncryptError(m) => AlloyError::EncryptError(m),
            ironcore_documents::Error::DecryptError(m) => AlloyError::DecryptError(m),
        }
    }
}
impl From<protobuf::Error> for AlloyError {
    fn from(value: protobuf::Error) -> Self {
        AlloyError::ProtobufError(value.to_string())
    }
}
impl std::error::Error for AlloyError {}
