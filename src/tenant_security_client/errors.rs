use std::fmt::{Display, Formatter, Result as DisplayResult};
use thiserror::Error;

/// Errors originating from the Tenant Security Proxy.
/// These errors are broken into 4 types: service errors, KMS errors,
/// security event errors, and tenant secret errors.
#[derive(Error, Debug, PartialEq, Eq, uniffi::Enum, Clone)]
#[non_exhaustive]
pub enum TenantSecurityProxyError {
    Service { error: ServiceError },
    Kms { error: KmsError },
    SecurityEvent { error: SecurityEventError },
    TenantSecret { error: TenantSecretError },
}

/// Errors communicating with the TSP
#[derive(Debug, PartialEq, Eq, uniffi::Enum, Clone)]
#[non_exhaustive]
pub enum ServiceError {
    UnknownError,
    UnauthorizedRequest,
    InvalidRequestBody,
}

/// Errors originating from or relating to the tenant's KMS
#[derive(Debug, PartialEq, Eq, uniffi::Enum, Clone)]
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
    KmsThrottled,
    KmsAccountIssue,
}

/// Errors related to security events
#[derive(Debug, PartialEq, Eq, uniffi::Enum, Clone)]
#[non_exhaustive]
pub enum SecurityEventError {
    SecurityEventRejected,
}

/// Errors related to tenant secrets
#[derive(Debug, PartialEq, Eq, uniffi::Enum, Clone)]
#[non_exhaustive]
pub enum TenantSecretError {
    SecretCreationFailed,
}

impl TenantSecurityProxyError {
    pub(crate) fn code_to_error(code: u16) -> TenantSecurityProxyError {
        use KmsError::*;
        use SecurityEventError::*;
        use ServiceError::*;
        use TenantSecretError::*;

        match code {
            100 => Self::Service {
                error: UnknownError,
            },
            101 => Self::Service {
                error: UnauthorizedRequest,
            },
            102 => Self::Service {
                error: InvalidRequestBody,
            },
            200 => Self::Kms {
                error: NoPrimaryKmsConfiguration,
            },
            201 => Self::Kms {
                error: UnknownTenantOrNoActiveKmsConfigurations,
            },
            202 => Self::Kms {
                error: KmsConfigurationDisabled,
            },
            203 => Self::Kms {
                error: InvalidProvidedEdek,
            },
            204 => Self::Kms {
                error: KmsWrapFailed,
            },
            205 => Self::Kms {
                error: KmsUnwrapFailed,
            },
            206 => Self::Kms {
                error: KmsAuthorizationFailed,
            },
            207 => Self::Kms {
                error: KmsConfigurationInvalid,
            },
            208 => Self::Kms {
                error: KmsUnreachable,
            },
            209 => Self::Kms {
                error: KmsThrottled,
            },
            301 => Self::SecurityEvent {
                error: SecurityEventRejected,
            },
            401 => Self::TenantSecret {
                error: SecretCreationFailed,
            },
            _ => Self::Service {
                error: UnknownError,
            },
        }
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::Service { error, .. } => match error {
                ServiceError::UnknownError => 100,
                ServiceError::UnauthorizedRequest => 101,
                ServiceError::InvalidRequestBody => 102,
            },
            Self::Kms { error, .. } => match error {
                KmsError::NoPrimaryKmsConfiguration => 200,
                KmsError::UnknownTenantOrNoActiveKmsConfigurations => 201,
                KmsError::KmsConfigurationDisabled => 202,
                KmsError::InvalidProvidedEdek => 203,
                KmsError::KmsWrapFailed => 204,
                KmsError::KmsUnwrapFailed => 205,
                KmsError::KmsAuthorizationFailed => 206,
                KmsError::KmsConfigurationInvalid => 207,
                KmsError::KmsUnreachable => 208,
                KmsError::KmsThrottled => 209,
                KmsError::KmsAccountIssue => 210,
            },
            Self::SecurityEvent { error, .. } => match error {
                SecurityEventError::SecurityEventRejected => 301,
            },
            Self::TenantSecret { error, .. } => match error {
                TenantSecretError::SecretCreationFailed => 401,
            },
        }
    }
}

impl Display for TenantSecurityProxyError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::Service { error } => write!(f, "{error}"),
            Self::Kms { error } => write!(f, "{error}"),
            Self::SecurityEvent { error } => write!(f, "{error}"),
            Self::TenantSecret { error } => write!(f, "{error}"),
        }
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::UnknownError => write!(f, "Unknown request error occurred"),
            Self::UnauthorizedRequest => {
                write!(f, "Request authorization header API key was incorrect")
            }
            Self::InvalidRequestBody => write!(f, "Request body was invalid"),
        }
    }
}

impl Display for KmsError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::NoPrimaryKmsConfiguration => write!(f, "Tenant has no primary KMS configuration"),
            Self::UnknownTenantOrNoActiveKmsConfigurations => write!(f, "Tenant either doesn't exist or has no active KMS configurations"),
            Self::KmsConfigurationDisabled => write!(f, "Tenant configuration specified in EDEK is no longer active"),
            Self::InvalidProvidedEdek => write!(f, "Provided EDEK was not valid"),
            Self::KmsWrapFailed => write!(f, "Request to KMS API to wrap key returned invalid results"),
            Self::KmsUnwrapFailed => write!(f, "Request to KMS API to unwrap key returned invalid results"),
            Self::KmsAuthorizationFailed => write!(f, "Request to KMS failed because the tenant credentials were invalid or have been revoked"),
            Self::KmsConfigurationInvalid => write!(f, "Request to KMS failed because the key configuration was invalid or the necessary permissions for the operation were missing/revoked"),
            Self::KmsUnreachable => write!(f, "Request to KMS failed because KMS was unreachable"),
            Self::KmsThrottled => write!(f, "Request to KMS failed because KMS throttled the Tenant Security Proxy"),
            Self::KmsAccountIssue => write!(f, "Request to KMS failed because of an issue with the KMS account."),
        }
    }
}
impl Display for SecurityEventError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::SecurityEventRejected => write!(
                f,
                "Tenant Security Proxy could not accept the security event"
            ),
        }
    }
}
impl Display for TenantSecretError {
    fn fmt(&self, f: &mut Formatter) -> DisplayResult {
        match self {
            Self::SecretCreationFailed => write!(
                f,
                "Tenant Security Proxy failed to create a secret for the provided tenant"
            ),
        }
    }
}
