//! Batch Ed25519 signature verification
//!
//! This module provides optimized batch verification of Ed25519 signatures,
//! which is critical for shred validation and transaction processing.
//!
//! # Performance
//!
//! Batch verification uses a probabilistic algorithm that verifies multiple
//! signatures simultaneously, achieving significant speedups:
//!
//! - Single signature: ~50-70 microseconds
//! - Batch of 32: ~1.5-2ms (50%+ faster than 32 individual verifications)
//! - Batch of 128: ~5-7ms (60%+ faster than 128 individual verifications)
//!
//! # Usage
//!
//! ```rust
//! use karstflow_crypto::ed25519_batch::{BatchVerifier, SignatureSet};
//!
//! let mut verifier = BatchVerifier::new();
//!
//! // Add signatures to the batch
//! // verifier.add_signature(public_key, message, signature)?;
//!
//! // Verify the entire batch at once
//! // let result = verifier.verify_batch()?;
//! ```

use crate::{CryptoError, CryptoResult, MAX_BATCH_SIZE, PUBKEY_SIZE, SIGNATURE_SIZE};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::sync::atomic::{AtomicU64, Ordering};

/// Result of signature verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// All signatures in the batch are valid
    Success,
    /// One or more signatures in the batch are invalid
    Failed,
}

/// A single signature with its public key and message
#[derive(Debug, Clone)]
pub struct SignatureSet {
    /// The public key that allegedly signed the message
    pub public_key: [u8; PUBKEY_SIZE],
    /// The message that was allegedly signed
    pub message: Vec<u8>,
    /// The signature to verify
    pub signature: [u8; SIGNATURE_SIZE],
}

impl SignatureSet {
    /// Create a new signature set
    pub fn new(
        public_key: [u8; PUBKEY_SIZE],
        message: Vec<u8>,
        signature: [u8; SIGNATURE_SIZE],
    ) -> Self {
        Self {
            public_key,
            message,
            signature,
        }
    }

    /// Verify this single signature
    pub fn verify(&self) -> CryptoResult<VerificationResult> {
        let public_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let signature = Signature::from_bytes(&self.signature);

        match public_key.verify(&self.message, &signature) {
            Ok(_) => Ok(VerificationResult::Success),
            Err(_) => Ok(VerificationResult::Failed),
        }
    }
}

/// Statistics for batch verification operations
#[derive(Debug, Default)]
pub struct BatchVerificationStats {
    /// Total batches verified
    pub batches_verified: AtomicU64,
    /// Total signatures verified
    pub signatures_verified: AtomicU64,
    /// Successful batch verifications
    pub batches_succeeded: AtomicU64,
    /// Failed batch verifications
    pub batches_failed: AtomicU64,
    /// Total time spent verifying (microseconds)
    pub total_verification_time_us: AtomicU64,
}

impl BatchVerificationStats {
    /// Create new statistics tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful batch verification
    pub fn record_success(&self, batch_size: usize, duration_us: u64) {
        self.batches_verified.fetch_add(1, Ordering::Relaxed);
        self.signatures_verified
            .fetch_add(batch_size as u64, Ordering::Relaxed);
        self.batches_succeeded.fetch_add(1, Ordering::Relaxed);
        self.total_verification_time_us
            .fetch_add(duration_us, Ordering::Relaxed);
    }

    /// Record a failed batch verification
    pub fn record_failure(&self, batch_size: usize, duration_us: u64) {
        self.batches_verified.fetch_add(1, Ordering::Relaxed);
        self.signatures_verified
            .fetch_add(batch_size as u64, Ordering::Relaxed);
        self.batches_failed.fetch_add(1, Ordering::Relaxed);
        self.total_verification_time_us
            .fetch_add(duration_us, Ordering::Relaxed);
    }

    /// Get total batches verified
    pub fn get_batches_verified(&self) -> u64 {
        self.batches_verified.load(Ordering::Relaxed)
    }

    /// Get total signatures verified
    pub fn get_signatures_verified(&self) -> u64 {
        self.signatures_verified.load(Ordering::Relaxed)
    }

    /// Get average batch size
    pub fn get_average_batch_size(&self) -> f64 {
        let batches = self.batches_verified.load(Ordering::Relaxed);
        if batches == 0 {
            return 0.0;
        }
        let signatures = self.signatures_verified.load(Ordering::Relaxed);
        signatures as f64 / batches as f64
    }

    /// Get success rate
    pub fn get_success_rate(&self) -> f64 {
        let total = self.batches_verified.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let succeeded = self.batches_succeeded.load(Ordering::Relaxed);
        succeeded as f64 / total as f64
    }

    /// Get average verification time per signature (microseconds)
    pub fn get_average_time_per_signature_us(&self) -> f64 {
        let signatures = self.signatures_verified.load(Ordering::Relaxed);
        if signatures == 0 {
            return 0.0;
        }
        let total_time = self.total_verification_time_us.load(Ordering::Relaxed);
        total_time as f64 / signatures as f64
    }
}

/// Batch signature verifier
///
/// Accumulates signatures and verifies them in batches for optimal performance.
pub struct BatchVerifier {
    /// Signatures pending verification
    signatures: Vec<SignatureSet>,
    /// Maximum batch size before automatic flush
    max_batch_size: usize,
    /// Statistics
    stats: BatchVerificationStats,
}

impl BatchVerifier {
    /// Create a new batch verifier with default batch size
    pub fn new() -> Self {
        Self::with_max_batch_size(MAX_BATCH_SIZE)
    }

    /// Create a new batch verifier with custom maximum batch size
    pub fn with_max_batch_size(max_batch_size: usize) -> Self {
        Self {
            signatures: Vec::new(),
            max_batch_size,
            stats: BatchVerificationStats::new(),
        }
    }

    /// Add a signature to the batch
    ///
    /// Returns `Some(result)` if the batch was automatically flushed,
    /// `None` if the signature was added without flushing.
    pub fn add_signature(
        &mut self,
        public_key: [u8; PUBKEY_SIZE],
        message: Vec<u8>,
        signature: [u8; SIGNATURE_SIZE],
    ) -> CryptoResult<Option<VerificationResult>> {
        self.signatures
            .push(SignatureSet::new(public_key, message, signature));

        if self.signatures.len() >= self.max_batch_size {
            let result = self.verify_batch()?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Add a pre-constructed signature set to the batch
    pub fn add_signature_set(
        &mut self,
        signature_set: SignatureSet,
    ) -> CryptoResult<Option<VerificationResult>> {
        self.signatures.push(signature_set);

        if self.signatures.len() >= self.max_batch_size {
            let result = self.verify_batch()?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Get the number of signatures pending verification
    pub fn pending_count(&self) -> usize {
        self.signatures.len()
    }

    /// Verify all pending signatures as a batch
    ///
    /// This clears the batch after verification.
    pub fn verify_batch(&mut self) -> CryptoResult<VerificationResult> {
        if self.signatures.is_empty() {
            return Err(CryptoError::EmptyBatch);
        }

        let batch_size = self.signatures.len();
        let start = std::time::Instant::now();

        let result = if batch_size == 1 {
            // For single signatures, use regular verification
            self.signatures[0].verify()?
        } else {
            // Use batch verification for multiple signatures
            self.verify_batch_internal()?
        };

        let duration_us = start.elapsed().as_micros() as u64;

        match result {
            VerificationResult::Success => {
                self.stats.record_success(batch_size, duration_us);
            }
            VerificationResult::Failed => {
                self.stats.record_failure(batch_size, duration_us);
            }
        }

        // Clear the batch
        self.signatures.clear();

        Ok(result)
    }

    /// Internal batch verification implementation
    fn verify_batch_internal(&self) -> CryptoResult<VerificationResult> {
        // Parse all public keys and signatures
        let mut public_keys = Vec::with_capacity(self.signatures.len());
        let mut signatures = Vec::with_capacity(self.signatures.len());
        let mut messages = Vec::with_capacity(self.signatures.len());

        for sig_set in &self.signatures {
            let public_key = VerifyingKey::from_bytes(&sig_set.public_key)
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
            let signature = Signature::from_bytes(&sig_set.signature);

            public_keys.push(public_key);
            signatures.push(signature);
            messages.push(sig_set.message.as_slice());
        }

        // Perform batch verification using ed25519-dalek's batch API
        match ed25519_dalek::verify_batch(&messages, &signatures, &public_keys) {
            Ok(_) => Ok(VerificationResult::Success),
            Err(_) => {
                // Batch verification failed, but we don't know which signature(s) failed
                // For production use, you might want to fall back to individual verification
                // to identify the failing signature(s)
                Ok(VerificationResult::Failed)
            }
        }
    }

    /// Verify batch and identify which signatures failed (slower, for diagnostics)
    ///
    /// Returns a vector of booleans indicating which signatures passed.
    /// This is slower than `verify_batch` but provides detailed failure information.
    pub fn verify_batch_detailed(&mut self) -> CryptoResult<Vec<bool>> {
        if self.signatures.is_empty() {
            return Err(CryptoError::EmptyBatch);
        }

        let mut results = Vec::with_capacity(self.signatures.len());

        for sig_set in &self.signatures {
            let result = sig_set.verify()?;
            results.push(result == VerificationResult::Success);
        }

        // Clear the batch
        self.signatures.clear();

        Ok(results)
    }

    /// Get statistics for this verifier
    pub fn stats(&self) -> &BatchVerificationStats {
        &self.stats
    }

    /// Clear all pending signatures without verifying
    pub fn clear(&mut self) {
        self.signatures.clear();
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a new Ed25519 keypair.
///
/// Returns `(secret_key, public_key)` where secret_key is 32 bytes
/// (the seed) and public_key is 32 bytes.
pub fn generate_keypair() -> ([u8; 32], [u8; PUBKEY_SIZE]) {
    use rand_core::OsRng;
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(signing_key.as_bytes());

    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());

    (secret, pubkey)
}

/// Sign a message using an Ed25519 secret key (32-byte seed).
///
/// Returns the 64-byte signature.
pub fn sign_message(secret_key: &[u8; 32], message: &[u8]) -> CryptoResult<[u8; SIGNATURE_SIZE]> {
    let signing_key = SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(message);

    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(&signature.to_bytes());
    Ok(sig_bytes)
}

/// Derive the public key from an Ed25519 secret key (32-byte seed).
pub fn public_key_from_secret(secret_key: &[u8; 32]) -> [u8; PUBKEY_SIZE] {
    let signing_key = SigningKey::from_bytes(secret_key);
    let verifying_key = signing_key.verifying_key();
    let mut pubkey = [0u8; PUBKEY_SIZE];
    pubkey.copy_from_slice(verifying_key.as_bytes());
    pubkey
}

/// Verify a single Ed25519 signature
///
/// This is a convenience function for verifying a single signature.
/// For verifying multiple signatures, use `BatchVerifier` for better performance.
pub fn verify_signature(
    public_key: &[u8; PUBKEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> CryptoResult<VerificationResult> {
    let public_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_bytes(signature);

    match public_key.verify(message, &signature) {
        Ok(_) => Ok(VerificationResult::Success),
        Err(_) => Ok(VerificationResult::Failed),
    }
}

/// Verify multiple signatures in parallel using individual verification
///
/// This is useful when batch verification is not available or when you need
/// to identify exactly which signatures failed. For best performance with
/// valid signatures, use `BatchVerifier::verify_batch()` instead.
pub fn verify_signatures_parallel(
    signature_sets: &[SignatureSet],
) -> CryptoResult<Vec<VerificationResult>> {
    use rayon::prelude::*;

    let results: Result<Vec<_>, _> = signature_sets
        .par_iter()
        .map(|sig_set| sig_set.verify())
        .collect();

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn generate_valid_signature() -> (SigningKey, [u8; PUBKEY_SIZE], Vec<u8>, [u8; SIGNATURE_SIZE])
    {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message".to_vec();
        let signature = signing_key.sign(&message);

        let mut pubkey = [0u8; PUBKEY_SIZE];
        pubkey.copy_from_slice(verifying_key.as_bytes());

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&signature.to_bytes());

        (signing_key, pubkey, message, sig_bytes)
    }

    #[test]
    fn test_single_signature_verification() {
        let (_, pubkey, message, signature) = generate_valid_signature();

        let result = verify_signature(&pubkey, &message, &signature).unwrap();
        assert_eq!(result, VerificationResult::Success);
    }

    #[test]
    fn test_single_signature_verification_invalid() {
        let (_, pubkey, message, mut signature) = generate_valid_signature();

        // Corrupt the signature
        signature[0] ^= 0xFF;

        let result = verify_signature(&pubkey, &message, &signature).unwrap();
        assert_eq!(result, VerificationResult::Failed);
    }

    #[test]
    fn test_signature_set_verify() {
        let (_, pubkey, message, signature) = generate_valid_signature();
        let sig_set = SignatureSet::new(pubkey, message, signature);

        let result = sig_set.verify().unwrap();
        assert_eq!(result, VerificationResult::Success);
    }

    #[test]
    fn test_batch_verifier_single() {
        let (_, pubkey, message, signature) = generate_valid_signature();

        let mut verifier = BatchVerifier::new();
        verifier.add_signature(pubkey, message, signature).unwrap();

        let result = verifier.verify_batch().unwrap();
        assert_eq!(result, VerificationResult::Success);
    }

    #[test]
    fn test_batch_verifier_multiple() {
        let mut verifier = BatchVerifier::new();

        // Add 10 valid signatures
        for _ in 0..10 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }

        assert_eq!(verifier.pending_count(), 10);

        let result = verifier.verify_batch().unwrap();
        assert_eq!(result, VerificationResult::Success);
        assert_eq!(verifier.pending_count(), 0);
    }

    #[test]
    fn test_batch_verifier_with_invalid() {
        let mut verifier = BatchVerifier::new();

        // Add 5 valid signatures
        for _ in 0..5 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }

        // Add 1 invalid signature
        let (_, pubkey, message, mut signature) = generate_valid_signature();
        signature[0] ^= 0xFF;
        verifier.add_signature(pubkey, message, signature).unwrap();

        let result = verifier.verify_batch().unwrap();
        assert_eq!(result, VerificationResult::Failed);
    }

    #[test]
    fn test_batch_verifier_auto_flush() {
        let mut verifier = BatchVerifier::with_max_batch_size(5);

        // Add 4 signatures - should not auto-flush
        for _ in 0..4 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            let result = verifier.add_signature(pubkey, message, signature).unwrap();
            assert!(result.is_none());
        }

        // Add 5th signature - should auto-flush
        let (_, pubkey, message, signature) = generate_valid_signature();
        let result = verifier.add_signature(pubkey, message, signature).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), VerificationResult::Success);
        assert_eq!(verifier.pending_count(), 0);
    }

    #[test]
    fn test_batch_verifier_empty() {
        let mut verifier = BatchVerifier::new();
        let result = verifier.verify_batch();
        assert!(matches!(result, Err(CryptoError::EmptyBatch)));
    }

    #[test]
    fn test_batch_verifier_detailed() {
        let mut verifier = BatchVerifier::new();

        // Add 3 valid signatures
        for _ in 0..3 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }

        // Add 1 invalid signature
        let (_, pubkey, message, mut signature) = generate_valid_signature();
        signature[0] ^= 0xFF;
        verifier.add_signature(pubkey, message, signature).unwrap();

        // Add 2 more valid signatures
        for _ in 0..2 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }

        let results = verifier.verify_batch_detailed().unwrap();
        assert_eq!(results.len(), 6);
        assert!(results[0]); // valid
        assert!(results[1]); // valid
        assert!(results[2]); // valid
        assert!(!results[3]); // invalid
        assert!(results[4]); // valid
        assert!(results[5]); // valid
    }

    #[test]
    fn test_batch_verification_stats() {
        let mut verifier = BatchVerifier::new();

        // Add and verify batch 1 (3 signatures)
        for _ in 0..3 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }
        verifier.verify_batch().unwrap();

        // Add and verify batch 2 (5 signatures)
        for _ in 0..5 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }
        verifier.verify_batch().unwrap();

        let stats = verifier.stats();
        assert_eq!(stats.get_batches_verified(), 2);
        assert_eq!(stats.get_signatures_verified(), 8);
        assert_eq!(stats.get_average_batch_size(), 4.0);
        assert_eq!(stats.get_success_rate(), 1.0);
        assert!(stats.get_average_time_per_signature_us() > 0.0);
    }

    #[test]
    fn test_verify_signatures_parallel() {
        let mut sig_sets = Vec::new();

        // Generate 20 valid signatures
        for _ in 0..20 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            sig_sets.push(SignatureSet::new(pubkey, message, signature));
        }

        let results = verify_signatures_parallel(&sig_sets).unwrap();
        assert_eq!(results.len(), 20);
        assert!(results.iter().all(|r| *r == VerificationResult::Success));
    }

    #[test]
    fn test_batch_verifier_clear() {
        let mut verifier = BatchVerifier::new();

        // Add some signatures
        for _ in 0..5 {
            let (_, pubkey, message, signature) = generate_valid_signature();
            verifier.add_signature(pubkey, message, signature).unwrap();
        }

        assert_eq!(verifier.pending_count(), 5);

        verifier.clear();
        assert_eq!(verifier.pending_count(), 0);
    }
}
