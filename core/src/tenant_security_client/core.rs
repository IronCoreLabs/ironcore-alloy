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
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct DocumentId(pub String);
