//! Structured error types for Quantum Vault core.

use thiserror::Error;

pub type QvResult<T> = std::result::Result<T, QvError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QvError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("invalid container: {0}")]
    InvalidContainer(&'static str),

    #[error("unsupported container version: {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(&'static str),

    #[error("input exceeds maximum allowed size")]
    OversizedInput,

    #[error("serialization failed")]
    Serialization,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,
}

impl From<serde_json::Error> for QvError {
    fn from(_: serde_json::Error) -> Self {
        Self::Serialization
    }
}