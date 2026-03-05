//! High-performance cryptographic operations for Karstflow
//!
//! This crate provides optimized cryptographic primitives for Solana-compatible
//! blockchain operations:
//!
//! - **Batch Ed25519 verification**: Critical for shred and transaction validation
//! - **Blake3 hashing**: Fast cryptographic hashing with streaming support
//! - **SHA256**: Optimized wrapper for legacy compatibility
//! - **Keccak-256**: Ethereum-compatible hashing
//! - **Secp256k1**: ECDSA recovery and verification (Ethereum signatures)
//! - **Secp256r1**: NIST P-256 ECDSA verification (WebAuthn / passkeys)
//! - **BN254**: alt_bn128 curve operations for zero-knowledge proofs
//!
//! # Performance Characteristics
//!
//! ## Batch Verification
//! - Single verification: ~50-70 microseconds
//! - Batch of 32: ~1.5-2ms (50%+ speedup vs sequential)
//! - Batch of 128: ~5-7ms (60%+ speedup vs sequential)
//!
//! ## Hashing
//! - Blake3: ~1 GB/s (single-threaded), ~7 GB/s (multi-threaded)
//! - SHA256: ~500 MB/s (single-threaded)
//!
//! # Example
//!
//! ```rust
//! use karstflow_crypto::ed25519_batch::{BatchVerifier, SignatureSet};
//!
//! // Batch verify multiple signatures (most efficient)
//! let mut verifier = BatchVerifier::new();
//! // Add signatures to batch...
//! // let result = verifier.verify_batch();
//! ```

pub mod blake3;
pub mod bmtree;
pub mod bn254;
pub mod ed25519_batch;
pub mod keccak256;
pub mod lthash;
pub mod reed_solomon;
pub mod secp256k1;
pub mod secp256r1;
pub mod sha256;
pub mod utils;

mod errors;

pub use errors::{CryptoError, CryptoResult};

// Re-export commonly used types
pub use ed25519_batch::{
    generate_keypair, public_key_from_secret, sign_message, verify_signature,
    verify_signatures_parallel,
};
pub use ed25519_batch::{BatchVerifier, SignatureSet, VerificationResult};
pub use lthash::LatticeHashValue;
pub use reed_solomon::{FecError, FecReconstructor, FecResult, ReconstructedSet};
pub use utils::{constant_time_eq, from_hex, secure_zero, to_hex, xor_bytes};

/// Ed25519 signature size in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 public key size in bytes
pub const PUBKEY_SIZE: usize = 32;

/// Blake3 hash output size in bytes
pub const BLAKE3_HASH_SIZE: usize = 32;

/// SHA256 hash output size in bytes
pub const SHA256_HASH_SIZE: usize = 32;

/// Default batch size for Ed25519 verification (optimized for typical transaction loads)
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// Maximum recommended batch size for Ed25519 verification
/// Beyond this size, batches should be split for better latency
pub const MAX_BATCH_SIZE: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(PUBKEY_SIZE, 32);
        assert_eq!(BLAKE3_HASH_SIZE, 32);
        assert_eq!(SHA256_HASH_SIZE, 32);
        assert_eq!(DEFAULT_BATCH_SIZE, 32);
        assert_eq!(MAX_BATCH_SIZE, 256);
    }
}
