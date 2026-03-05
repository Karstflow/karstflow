//! Error types for ZK proof verification.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkProofError {
    /// Unknown proof type discriminant.
    UnknownProofType,
    /// Proof data is too short for the expected layout.
    InsufficientData,
    /// A compressed Ristretto point could not be decompressed.
    InvalidPoint,
    /// A proof point is the identity element (rejected per protocol).
    IdentityPoint,
    /// A scalar is not in canonical form (>= group order).
    InvalidScalar,
    /// The algebraic verification relation does not hold.
    VerificationFailed,
    /// Range proof specific: invalid bit length configuration.
    InvalidBitLength,
    /// Range proof specific: too many commitments in batch.
    TooManyCommitments,
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProofType => write!(f, "unknown ZK proof type"),
            Self::InsufficientData => write!(f, "insufficient proof data"),
            Self::InvalidPoint => write!(f, "invalid curve point"),
            Self::IdentityPoint => write!(f, "proof contains identity point"),
            Self::InvalidScalar => write!(f, "invalid scalar (non-canonical)"),
            Self::VerificationFailed => write!(f, "proof verification failed"),
            Self::InvalidBitLength => write!(f, "invalid range proof bit length"),
            Self::TooManyCommitments => write!(f, "too many commitments in batch"),
        }
    }
}
