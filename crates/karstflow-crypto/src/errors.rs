use thiserror::Error;

/// Cryptographic operation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid signature format
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid public key format
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Batch verification failed
    #[error("Batch verification failed: {0} of {1} signatures invalid")]
    BatchVerificationFailed(usize, usize),

    /// Invalid batch size
    #[error("Invalid batch size: {0} (must be between 1 and {1})")]
    InvalidBatchSize(usize, usize),

    /// Empty batch
    #[error("Cannot verify empty batch")]
    EmptyBatch,

    /// Invalid message length
    #[error("Invalid message length: {0}")]
    InvalidMessageLength(usize),

    /// Invalid hash output size
    #[error("Invalid hash output size: expected {expected}, got {actual}")]
    InvalidHashSize { expected: usize, actual: usize },

    /// Buffer too small
    #[error("Buffer too small: need {needed} bytes, got {actual}")]
    BufferTooSmall { needed: usize, actual: usize },

    /// Internal cryptographic library error
    #[error("Internal crypto error: {0}")]
    InternalError(String),
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidSignature("bad format".to_string());
        assert!(err.to_string().contains("Invalid signature"));

        let err = CryptoError::BatchVerificationFailed(5, 10);
        assert!(err.to_string().contains("5 of 10"));

        let err = CryptoError::InvalidBatchSize(300, 256);
        assert!(err.to_string().contains("300"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = CryptoError::EmptyBatch;
        let err2 = CryptoError::EmptyBatch;
        assert_eq!(err1, err2);

        let err3 = CryptoError::InvalidBatchSize(10, 256);
        let err4 = CryptoError::InvalidBatchSize(10, 256);
        assert_eq!(err3, err4);
    }
}
