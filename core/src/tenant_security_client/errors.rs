use protobuf::Error as ProtobufError;
use reqwest::StatusCode;
use std::fmt::{Display, Formatter, Result as DisplayResult};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantSecurityError {
    #[error("AES error: {0}")]
    AesError(String),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    #[error("Request error: {0}")]
    RequestError(String),

    #[error("rust-protobuf error: {0}")]
    RustProtobufError(String),

    #[error("proto error: {0}")]
    ProtoError(String),

    #[error("serde_json error: {0}")]
    SerdeJsonError(String),

    #[error("Field `{0}` cannot be empty.")]
    NonEmptyStringError(String),

    #[error("Invalid DEK length.")]
    InvalidDek,

    #[error("Invalid document.")]
    InvalidDocument,

    #[error("TSP error: {0}, Status: {}", .1.as_str())]
    TspError(TenantSecurityProxyError, StatusCode),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("key id header error: {0}")]
    KeyIdHeaderError(String),
}

impl From<base64::DecodeError> for TenantSecurityError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64DecodeError(e.to_string())
    }
}

impl From<ProtobufError> for TenantSecurityError {
    fn from(e: ProtobufError) -> Self {
        Self::RustProtobufError(e.to_string())
    }
}

impl From<reqwest::Error> for TenantSecurityError {
    fn from(e: reqwest::Error) -> Self {
        Self::RequestError(e.to_string())
    }
}

//COLT: This mapping could be better.
impl From<ironcore_documents::Error> for TenantSecurityError {
    fn from(e: ironcore_documents::Error) -> Self {
        match e {
            e @ ironcore_documents::Error::EdocTooShort(_)
            | e @ ironcore_documents::Error::HeaderParseErr(_)
            | e @ ironcore_documents::Error::InvalidVersion(_)
            | e @ ironcore_documents::Error::NoIronCoreMagic
            | e @ ironcore_documents::Error::SpecifiedLengthTooLong(_)
            | e @ ironcore_documents::Error::ProtoSerializationErr(_)
            | e @ ironcore_documents::Error::HeaderLengthOverflow(_) => {
                TenantSecurityError::ProtoError(e.to_string())
            }
            e @ ironcore_documents::Error::EncryptError(_)
            | e @ ironcore_documents::Error::DecryptError(_) => {
                TenantSecurityError::AesError(e.to_string())
            }
            e @ ironcore_documents::Error::EdekTypeError(_)
            | e @ ironcore_documents::Error::KeyIdHeaderTooShort(_)
            | e @ ironcore_documents::Error::PayloadTypeError(_)
            | e @ ironcore_documents::Error::KeyIdHeaderMalformed(_) => {
                TenantSecurityError::KeyIdHeaderError(e.to_string())
            }
        }
    }
}

impl From<serde_json::Error> for TenantSecurityError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJsonError(e.to_string())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantSecurityProxyError {
    ServiceError(ServiceError),
    KmsError(KmsError),
    SecurityEventError(SecurityEventError),
    TenantSecretError(TenantSecretError),
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceError {
    UnknownError,
    UnauthorizedRequest,
    InvalidRequestBody,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KmsError {
    NoPrimaryKmsConfiguration,
    UnknownTenantOrNoActiveKmsConfigurations,
    KmsConfigurationDisabled,
    InvalidProvidedEdek,
    KmsWrapFailed,
    KmsUnwrapFailed,
    KmsAuthorizationFailed,
    KmsConfigurationInvalid,
    KmsUnreachable,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityEventError {
    SecurityEventRejected,
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantSecretError {
    SecretCreationFailed,
}

impl TenantSecurityProxyError {
    pub fn code_to_error(code: u16) -> TenantSecurityProxyError {
        use KmsError::*;
        use SecurityEventError::*;
        use ServiceError::*;
        use TenantSecretError::*;

        match code {
            100 => Self::ServiceError(UnknownError),
            101 => Self::ServiceError(UnauthorizedRequest),
            102 => Self::ServiceError(InvalidRequestBody),
            200 => Self::KmsError(NoPrimaryKmsConfiguration),
            201 => Self::KmsError(UnknownTenantOrNoActiveKmsConfigurations),
            202 => Self::KmsError(KmsConfigurationDisabled),
            203 => Self::KmsError(InvalidProvidedEdek),
            204 => Self::KmsError(KmsWrapFailed),
            205 => Self::KmsError(KmsUnwrapFailed),
            206 => Self::KmsError(KmsAuthorizationFailed),
            207 => Self::KmsError(KmsConfigurationInvalid),
            208 => Self::KmsError(KmsUnreachable),
            301 => Self::SecurityEventError(SecurityEventRejected),
            401 => Self::TenantSecretError(SecretCreationFailed),
            _ => Self::ServiceError(UnknownError),
        }
    }

    pub fn get_code(&self) -> u16 {
        match self {
            TenantSecurityProxyError::ServiceError(e) => match e {
                ServiceError::UnknownError => 100,
                ServiceError::UnauthorizedRequest => 101,
                ServiceError::InvalidRequestBody => 102,
            },
            TenantSecurityProxyError::KmsError(e) => match e {
                KmsError::NoPrimaryKmsConfiguration => 200,
                KmsError::UnknownTenantOrNoActiveKmsConfigurations => 201,
                KmsError::KmsConfigurationDisabled => 202,
                KmsError::InvalidProvidedEdek => 203,
                KmsError::KmsWrapFailed => 204,
                KmsError::KmsUnwrapFailed => 205,
                KmsError::KmsAuthorizationFailed => 206,
                KmsError::KmsConfigurationInvalid => 207,
                KmsError::KmsUnreachable => 208,
            },
            TenantSecurityProxyError::SecurityEventError(e) => match e {
                SecurityEventError::SecurityEventRejected => 301,
            },
            TenantSecurityProxyError::TenantSecretError(e) => match e {
                TenantSecretError::SecretCreationFailed => 401,
            },
        }
    }
}

impl Display for TenantSecurityProxyError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::ServiceError(e) => write!(f, "{e}"),
            Self::KmsError(e) => write!(f, "{e}"),
            Self::SecurityEventError(e) => write!(f, "{e}"),
            Self::TenantSecretError(e) => write!(f, "{e}"),
        }
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            ServiceError::UnknownError => write!(f, "Unknown request error occurred"),
            ServiceError::UnauthorizedRequest => {
                write!(f, "Request authorization header API key was incorrect")
            }
            ServiceError::InvalidRequestBody => write!(f, "Request body was invalid"),
        }
    }
}

impl Display for KmsError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            KmsError::NoPrimaryKmsConfiguration => write!(f, "Tenant has no primary KMS configuration"),
            KmsError::UnknownTenantOrNoActiveKmsConfigurations => write!(f, "Tenant either doesn't exist or has no active KMS configurations"),
            KmsError::KmsConfigurationDisabled => write!(f, "Tenant configuration specified in EDEK is no longer active"),
            KmsError::InvalidProvidedEdek => write!(f, "Provided EDEK was not valid"),
            KmsError::KmsWrapFailed => write!(f, "Request to KMS API to wrap key returned invalid results"),
            KmsError::KmsUnwrapFailed => write!(f, "Request to KMS API to unwrap key returned invalid results"),
            KmsError::KmsAuthorizationFailed => write!(f, "Request to KMS failed because the tenant credentials were invalid or have been revoked"),
            KmsError::KmsConfigurationInvalid => write!(f, "Request to KMS failed because the key configuration was invalid or the necessary permissions for the operation were missing/revoked"),
            KmsError::KmsUnreachable => write!(f, "Request to KMS failed because KMS was unreachable"),
        }
    }
}
impl Display for SecurityEventError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            SecurityEventError::SecurityEventRejected => write!(
                f,
                "Tenant Security Proxy could not accept the security event"
            ),
        }
    }
}
impl Display for TenantSecretError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            TenantSecretError::SecretCreationFailed => write!(
                f,
                "Tenant Security Proxy failed to create a secret for the provided tenant"
            ),
        }
    }
}
