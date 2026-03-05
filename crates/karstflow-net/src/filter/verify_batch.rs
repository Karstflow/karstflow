//! Batch signature verification for transactions using karstflow-crypto
//!
//! This module provides optimized batch verification of transaction signatures
//! using the high-performance crypto primitives from karstflow-crypto.

use bytes::Bytes;
use karstflow_constants::transaction as constants;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;

/// Re-export crypto types
pub use karstflow_crypto::{
    ed25519_batch::{BatchVerifier, VerificationResult},
    CryptoError, PUBKEY_SIZE, SIGNATURE_SIZE,
};

/// Batch signature verification errors
#[derive(Error, Debug)]
pub enum BatchVerificationError {
    #[error("Transaction too small: {0} bytes")]
    TransactionTooSmall(usize),

    #[error("Transaction too large: {0} bytes")]
    TransactionTooLarge(usize),

    #[error("Invalid signature count: {0}")]
    InvalidSignatureCount(usize),

    #[error("Failed to parse transaction: {0}")]
    ParseError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("Batch verification failed")]
    BatchVerificationFailed,
}

/// Statistics for batch signature verification
#[derive(Debug, Default)]
pub struct BatchVerificationStats {
    /// Total transactions processed
    pub transactions_processed: AtomicU64,
    /// Total signatures verified
    pub signatures_verified: AtomicU64,
    /// Successful verifications
    pub verifications_succeeded: AtomicU64,
    /// Failed verifications
    pub verifications_failed: AtomicU64,
    /// Total batches processed
    pub batches_processed: AtomicU64,
    /// Parse errors encountered
    pub parse_errors: AtomicU64,
}

impl BatchVerificationStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self, num_signatures: usize) {
        self.transactions_processed.fetch_add(1, Ordering::Relaxed);
        self.signatures_verified
            .fetch_add(num_signatures as u64, Ordering::Relaxed);
        self.verifications_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self, num_signatures: usize) {
        self.transactions_processed.fetch_add(1, Ordering::Relaxed);
        self.signatures_verified
            .fetch_add(num_signatures as u64, Ordering::Relaxed);
        self.verifications_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_batch(&self) {
        self.batches_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_total(&self) -> u64 {
        self.transactions_processed.load(Ordering::Relaxed)
    }

    pub fn get_success_rate(&self) -> f64 {
        let total = self.transactions_processed.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let succeeded = self.verifications_succeeded.load(Ordering::Relaxed);
        succeeded as f64 / total as f64
    }

    pub fn get_average_batch_size(&self) -> f64 {
        let batches = self.batches_processed.load(Ordering::Relaxed);
        if batches == 0 {
            return 0.0;
        }
        let transactions = self.transactions_processed.load(Ordering::Relaxed);
        transactions as f64 / batches as f64
    }
}

/// Parsed transaction for batch verification
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// Signatures to verify
    pub signatures: Vec<[u8; SIGNATURE_SIZE]>,
    /// Public keys corresponding to signatures
    pub public_keys: Vec<[u8; PUBKEY_SIZE]>,
    /// The message that was signed
    pub message: Vec<u8>,
    /// Number of signatures
    pub signature_count: usize,
}

/// Batch signature verifier for transactions
///
/// This verifier accumulates transaction signatures and verifies them in
/// optimized batches for maximum throughput.
pub struct TransactionBatchVerifier {
    /// Underlying batch verifier
    verifier: BatchVerifier,
    /// Statistics
    stats: Arc<BatchVerificationStats>,
    /// Maximum batch size before auto-flush
    max_batch_size: usize,
}

impl TransactionBatchVerifier {
    /// Create a new transaction batch verifier
    pub fn new() -> Self {
        Self::with_max_batch_size(constants::VERIFICATION_BATCH_SIZE)
    }

    /// Create a new verifier with custom batch size
    pub fn with_max_batch_size(max_batch_size: usize) -> Self {
        Self {
            verifier: BatchVerifier::with_max_batch_size(max_batch_size),
            stats: Arc::new(BatchVerificationStats::new()),
            max_batch_size,
        }
    }

    /// Parse a transaction to extract signatures and message
    pub fn parse_transaction(
        &self,
        transaction_data: &Bytes,
    ) -> Result<ParsedTransaction, BatchVerificationError> {
        // Validate transaction size
        let size = transaction_data.len();
        if size < constants::MIN_TRANSACTION_SIZE {
            return Err(BatchVerificationError::TransactionTooSmall(size));
        }
        if size > constants::MAX_TRANSACTION_SIZE {
            return Err(BatchVerificationError::TransactionTooLarge(size));
        }

        let mut offset = 0;

        // Read signature count (compact-u16 encoded)
        let (signature_count, compact_len) =
            self.decode_compact_u16(&transaction_data[offset..])
                .map_err(|e| BatchVerificationError::ParseError(e.to_string()))?;
        offset += compact_len;

        // Validate signature count
        if signature_count == 0 || signature_count > constants::MAX_SIGNATURES {
            return Err(BatchVerificationError::InvalidSignatureCount(
                signature_count,
            ));
        }

        // Extract signatures
        let signatures_len = signature_count * SIGNATURE_SIZE;
        if transaction_data.len() < offset + signatures_len {
            return Err(BatchVerificationError::ParseError(
                "Transaction too short for signatures".to_string(),
            ));
        }

        let mut signatures = Vec::with_capacity(signature_count);
        for i in 0..signature_count {
            let sig_offset = offset + i * SIGNATURE_SIZE;
            let mut signature = [0u8; SIGNATURE_SIZE];
            signature.copy_from_slice(&transaction_data[sig_offset..sig_offset + SIGNATURE_SIZE]);
            signatures.push(signature);
        }

        offset += signatures_len;

        // The message is everything after signatures
        let message = transaction_data[offset..].to_vec();

        // Extract public keys from message
        let public_keys = self
            .extract_public_keys(&message, signature_count)
            .map_err(|e| BatchVerificationError::ParseError(e.to_string()))?;

        Ok(ParsedTransaction {
            signatures,
            public_keys,
            message,
            signature_count,
        })
    }

    /// Add a transaction to the batch for verification
    ///
    /// Returns `Some(results)` if the batch was auto-flushed, `None` otherwise.
    pub fn add_transaction(
        &mut self,
        transaction_data: &Bytes,
    ) -> Result<Option<Vec<bool>>, BatchVerificationError> {
        // Parse transaction
        let parsed = match self.parse_transaction(transaction_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.stats.record_parse_error();
                return Err(e);
            }
        };

        // Add all signatures from this transaction to the batch
        for (sig, pubkey) in parsed.signatures.iter().zip(parsed.public_keys.iter()) {
            self.verifier
                .add_signature(*pubkey, parsed.message.clone(), *sig)?;
        }

        // Check if we need to auto-flush
        if self.verifier.pending_count() >= self.max_batch_size {
            let results = self.verify_batch_detailed()?;
            Ok(Some(results))
        } else {
            Ok(None)
        }
    }

    /// Verify all pending signatures as a batch
    pub fn verify_batch(&mut self) -> Result<VerificationResult, BatchVerificationError> {
        if self.verifier.pending_count() == 0 {
            return Ok(VerificationResult::Success);
        }

        let result = self.verifier.verify_batch()?;
        self.stats.record_batch();

        Ok(result)
    }

    /// Verify batch and get detailed results for each signature
    pub fn verify_batch_detailed(&mut self) -> Result<Vec<bool>, BatchVerificationError> {
        if self.verifier.pending_count() == 0 {
            return Ok(Vec::new());
        }

        let results = self.verifier.verify_batch_detailed()?;
        self.stats.record_batch();

        Ok(results)
    }

    /// Get the number of signatures pending verification
    pub fn pending_count(&self) -> usize {
        self.verifier.pending_count()
    }

    /// Clear all pending signatures
    pub fn clear(&mut self) {
        self.verifier.clear();
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<BatchVerificationStats> {
        &self.stats
    }

    /// Decode compact-u16 encoding (used by Solana for short lengths)
    fn decode_compact_u16(&self, data: &[u8]) -> Result<(usize, usize), String> {
        if data.is_empty() {
            return Err("Empty data".to_string());
        }

        let first_byte = data[0] as usize;

        if first_byte <= 0x7F {
            Ok((first_byte, 1))
        } else {
            if data.len() < 2 {
                return Err("Insufficient data for compact-u16".to_string());
            }
            let value = ((first_byte & 0x7F) << 8) | (data[1] as usize);
            Ok((value, 2))
        }
    }

    /// Extract public keys from transaction message
    fn extract_public_keys(
        &self,
        message: &[u8],
        signature_count: usize,
    ) -> Result<Vec<[u8; PUBKEY_SIZE]>, String> {
        if message.len() < 3 {
            return Err("Message too short".to_string());
        }

        let mut offset = 3; // Skip header

        // Read account count
        let (account_count, compact_len) = self.decode_compact_u16(&message[offset..])?;
        offset += compact_len;

        // Validate account count
        if account_count < signature_count {
            return Err("Account count less than signature count".to_string());
        }

        // Extract public keys (first signature_count accounts are signers)
        let mut public_keys = Vec::with_capacity(signature_count);
        for i in 0..signature_count {
            let key_offset = offset + i * PUBKEY_SIZE;
            if message.len() < key_offset + PUBKEY_SIZE {
                return Err("Message too short for public keys".to_string());
            }
            let mut pubkey = [0u8; PUBKEY_SIZE];
            pubkey.copy_from_slice(&message[key_offset..key_offset + PUBKEY_SIZE]);
            public_keys.push(pubkey);
        }

        Ok(public_keys)
    }
}

impl Default for TransactionBatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_verifier_creates() {
        let verifier = TransactionBatchVerifier::new();
        assert_eq!(verifier.pending_count(), 0);
    }

    #[test]
    fn test_compact_u16_decode() {
        let verifier = TransactionBatchVerifier::new();

        let data = [42u8];
        let (value, len) = verifier.decode_compact_u16(&data).unwrap();
        assert_eq!(value, 42);
        assert_eq!(len, 1);

        let data = [0x81u8, 0x23u8];
        let (value, len) = verifier.decode_compact_u16(&data).unwrap();
        assert_eq!(value, 291);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_stats() {
        let stats = BatchVerificationStats::new();

        stats.record_success(2);
        stats.record_success(3);
        stats.record_failure(1);

        assert_eq!(stats.get_total(), 3);
        assert_eq!(stats.signatures_verified.load(Ordering::Relaxed), 6);
        assert!(stats.get_success_rate() > 0.66);
        assert!(stats.get_success_rate() < 0.67);
    }
}
