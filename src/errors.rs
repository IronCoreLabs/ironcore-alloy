pub use crate::tenant_security_client::errors::{
    KmsError, SecurityEventError, ServiceError, TenantSecretError, TenantSecurityProxyError,
};
use crate::vector::crypto::{
    DecryptError as VectorDecryptError, EncryptError as VectorEncryptError,
};

/// Errors related to IronCore Alloy SDK
#[derive(Debug, uniffi::Error, PartialEq, Eq, Clone)]
pub enum AlloyError {
    /// Error while loading configuration.
    InvalidConfiguration { msg: String },
    /// Error with key used
    InvalidKey { msg: String },
    /// Error with user input
    InvalidInput { msg: String },
    /// Errors while encrypting
    EncryptError { msg: String },
    /// Errors while decrypting
    DecryptError { msg: String },
    /// Error when parsing encryption headers/metadata
    ProtobufError { msg: String },
    /// Error when making a request to the TSP
    RequestError { msg: String },
    /// Error converting request data to JSON
    SerdeJsonError { msg: String },
    /// Error directly from the TSP. See https://ironcorelabs.com/docs/saas-shield/tenant-security-proxy/errors/
    /// for details about these error codes.
    TspError {
        error: TenantSecurityProxyError,
        http_code: u16,
        tsp_code: u16,
        msg: String,
    },
}

impl std::fmt::Display for AlloyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlloyError::InvalidConfiguration { msg } => {
                write!(f, "Invalid configuration: '{msg}'")
            }
            AlloyError::InvalidKey { msg } => write!(f, "Invalid key: '{msg}'"),
            AlloyError::InvalidInput { msg } => write!(f, "Invalid input: '{msg}'"),
            AlloyError::EncryptError { msg } => write!(f, "Encrypt error: '{msg}'"),
            AlloyError::DecryptError { msg } => write!(f, "Decrypt error: '{msg}'"),
            AlloyError::ProtobufError { msg } => write!(f, "Protobuf error: '{msg}'"),
            AlloyError::RequestError { msg } => write!(f, "Request error: '{msg}'"),
            AlloyError::SerdeJsonError { msg } => write!(f, "Serde JSON error: '{msg}'"),
            AlloyError::TspError {
                error,
                tsp_code,
                http_code,
                msg,
            } => write!(
                f,
                "TSP error variant: '{error}', HTTP code: {http_code}, TSP code: {tsp_code}, Message: {msg}"
            ),
        }
    }
}
impl From<VectorEncryptError> for AlloyError {
    fn from(value: VectorEncryptError) -> Self {
        match value {
            VectorEncryptError::InvalidKey(s) => Self::InvalidKey { msg: s },
            VectorEncryptError::OverflowError => Self::InvalidInput {
                msg: value.to_string(),
            },
        }
    }
}
impl From<VectorDecryptError> for AlloyError {
    fn from(value: VectorDecryptError) -> Self {
        match value {
            VectorDecryptError::InvalidKey(s) => Self::InvalidKey { msg: s },
            VectorDecryptError::InvalidAuthHash => Self::InvalidInput {
                msg: "Invalid authentication hash".to_string(),
            },
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
            | ironcore_documents::Error::KeyIdHeaderMalformed(_) => AlloyError::InvalidInput {
                msg: value.to_string(),
            },
            ironcore_documents::Error::ProtoSerializationErr(msg) => {
                AlloyError::ProtobufError { msg }
            }
            ironcore_documents::Error::EncryptError(msg) => AlloyError::EncryptError { msg },
            ironcore_documents::Error::DecryptError(msg) => AlloyError::DecryptError { msg },
        }
    }
}
impl From<protobuf::Error> for AlloyError {
    fn from(value: protobuf::Error) -> Self {
        AlloyError::ProtobufError {
            msg: value.to_string(),
        }
    }
}
impl From<reqwest::Error> for AlloyError {
    fn from(e: reqwest::Error) -> Self {
        Self::RequestError { msg: e.to_string() }
    }
}
impl From<serde_json::Error> for AlloyError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJsonError { msg: e.to_string() }
    }
}
impl std::error::Error for AlloyError {}
