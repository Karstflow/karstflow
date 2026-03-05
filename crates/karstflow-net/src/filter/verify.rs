use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use karstflow_constants::transaction as constants;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

/// Signature verification errors
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Transaction too small: {0} bytes")]
    TransactionTooSmall(usize),

    #[error("Transaction too large: {0} bytes")]
    TransactionTooLarge(usize),

    #[error("Invalid signature count: {0}")]
    InvalidSignatureCount(usize),

    #[error("Failed to parse transaction")]
    ParseError,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid public key")]
    InvalidPublicKey,
}

/// Result of signature verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Transaction signatures are valid
    Success,
    /// Transaction signatures failed verification
    Failed,
}

/// Statistics for signature verification
#[derive(Debug, Default)]
pub struct VerificationStats {
    /// Total transactions verified
    pub transactions_verified: AtomicU64,
    /// Successful verifications
    pub verifications_succeeded: AtomicU64,
    /// Failed verifications
    pub verifications_failed: AtomicU64,
}

impl VerificationStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self) {
        self.transactions_verified.fetch_add(1, Ordering::Relaxed);
        self.verifications_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.transactions_verified.fetch_add(1, Ordering::Relaxed);
        self.verifications_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_total(&self) -> u64 {
        self.transactions_verified.load(Ordering::Relaxed)
    }

    pub fn get_succeeded(&self) -> u64 {
        self.verifications_succeeded.load(Ordering::Relaxed)
    }

    pub fn get_failed(&self) -> u64 {
        self.verifications_failed.load(Ordering::Relaxed)
    }
}

/// Parsed transaction data: (signatures, message, signature_count)
type ParsedTransactionData = (Vec<[u8; constants::SIGNATURE_SIZE]>, Vec<u8>, usize);

/// Signature verifier for Solana transactions
///
/// Verifies Ed25519 signatures on transactions.
/// Uses SignatureDeduplicator from dedup module for duplicate detection.
pub struct SignatureVerifier {
    stats: Arc<VerificationStats>,
}

impl SignatureVerifier {
    /// Create a new signature verifier
    pub fn new() -> Self {
        Self {
            stats: Arc::new(VerificationStats::new()),
        }
    }

    /// Verify a transaction's signatures
    pub fn verify(
        &self,
        transaction_data: &Bytes,
    ) -> Result<VerificationResult, VerificationError> {
        // Validate transaction size
        let size = transaction_data.len();
        if size < constants::MIN_TRANSACTION_SIZE {
            return Err(VerificationError::TransactionTooSmall(size));
        }
        if size > constants::MAX_TRANSACTION_SIZE {
            return Err(VerificationError::TransactionTooLarge(size));
        }

        // Parse transaction to extract signatures and message
        let (signatures, message, signature_count) = self.parse_transaction(transaction_data)?;

        // Verify all signatures
        let verification_result = self.verify_signatures(&signatures, &message, signature_count)?;

        // Update statistics
        match verification_result {
            VerificationResult::Success => {
                self.stats.record_success();
            }
            VerificationResult::Failed => {
                self.stats.record_failure();
            }
        }

        Ok(verification_result)
    }

    /// Parse transaction to extract signatures and message
    ///
    /// Solana transaction format:
    /// - Compact-u16: signature count
    /// - `signature_count * 64 bytes`: signatures
    /// - remaining bytes: message (what gets signed)
    fn parse_transaction(&self, data: &[u8]) -> Result<ParsedTransactionData, VerificationError> {
        let mut offset = 0;

        // Read signature count (compact-u16 encoded)
        let (signature_count, compact_len) = self.decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        // Validate signature count
        if signature_count == 0 || signature_count > constants::MAX_SIGNATURES {
            return Err(VerificationError::InvalidSignatureCount(signature_count));
        }

        // Extract signatures
        let signatures_len = signature_count * constants::SIGNATURE_SIZE;
        if data.len() < offset + signatures_len {
            return Err(VerificationError::ParseError);
        }

        let mut signatures = Vec::with_capacity(signature_count);
        for i in 0..signature_count {
            let sig_offset = offset + i * constants::SIGNATURE_SIZE;
            let mut signature = [0u8; constants::SIGNATURE_SIZE];
            signature.copy_from_slice(&data[sig_offset..sig_offset + constants::SIGNATURE_SIZE]);
            signatures.push(signature);
        }

        offset += signatures_len;

        // The message is everything after signatures
        let message = data[offset..].to_vec();

        Ok((signatures, message, signature_count))
    }

    /// Decode compact-u16 encoding (used by Solana for short lengths)
    fn decode_compact_u16(&self, data: &[u8]) -> Result<(usize, usize), VerificationError> {
        if data.is_empty() {
            return Err(VerificationError::ParseError);
        }

        let first_byte = data[0] as usize;

        // Compact-u16 encoding:
        // - If first byte is 0-127: value = first byte, length = 1
        // - If first byte is 128-255: value = ((first byte & 0x7F) << 8) | second byte, length = 2
        if first_byte <= 0x7F {
            Ok((first_byte, 1))
        } else {
            if data.len() < 2 {
                return Err(VerificationError::ParseError);
            }
            let value = ((first_byte & 0x7F) << 8) | (data[1] as usize);
            Ok((value, 2))
        }
    }

    /// Verify Ed25519 signatures
    ///
    /// In Solana, signatures cover the "message" portion of the transaction.
    /// Each signature corresponds to an account in the message's account list.
    fn verify_signatures(
        &self,
        signatures: &[[u8; constants::SIGNATURE_SIZE]],
        message: &[u8],
        signature_count: usize,
    ) -> Result<VerificationResult, VerificationError> {
        // Parse message to get public keys
        let public_keys = self.extract_public_keys(message, signature_count)?;

        // Verify each signature
        for i in 0..signature_count {
            let signature_bytes = &signatures[i];
            let public_key_bytes = &public_keys[i];

            // Parse Ed25519 signature and public key
            let signature = Signature::from_bytes(signature_bytes);
            let public_key = VerifyingKey::from_bytes(public_key_bytes)
                .map_err(|_| VerificationError::InvalidPublicKey)?;

            // Verify signature over message
            if public_key.verify(message, &signature).is_err() {
                debug!("Signature verification failed for signature {}", i);
                return Ok(VerificationResult::Failed);
            }
        }

        Ok(VerificationResult::Success)
    }

    /// Extract public keys from transaction message
    ///
    /// Message format (legacy):
    /// - 3 bytes: header (required_signatures, readonly_signed, readonly_unsigned)
    /// - compact-u16: account count
    /// - [account_count * 32 bytes]: account addresses (first N are signers)
    /// - remaining: blockhash + instructions
    fn extract_public_keys(
        &self,
        message: &[u8],
        signature_count: usize,
    ) -> Result<Vec<[u8; constants::PUBKEY_SIZE]>, VerificationError> {
        if message.len() < 3 {
            return Err(VerificationError::ParseError);
        }

        let mut offset = 3; // Skip header

        // Read account count
        let (account_count, compact_len) = self.decode_compact_u16(&message[offset..])?;
        offset += compact_len;

        // Validate account count
        if account_count < signature_count {
            return Err(VerificationError::ParseError);
        }

        // Extract public keys (first signature_count accounts are signers)
        let mut public_keys = Vec::with_capacity(signature_count);
        for i in 0..signature_count {
            let key_offset = offset + i * constants::PUBKEY_SIZE;
            if message.len() < key_offset + constants::PUBKEY_SIZE {
                return Err(VerificationError::ParseError);
            }
            let mut pubkey = [0u8; constants::PUBKEY_SIZE];
            pubkey.copy_from_slice(&message[key_offset..key_offset + constants::PUBKEY_SIZE]);
            public_keys.push(pubkey);
        }

        Ok(public_keys)
    }

    /// Get verification statistics
    pub fn stats(&self) -> &Arc<VerificationStats> {
        &self.stats
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_creates() {
        let verifier = SignatureVerifier::new();
        assert_eq!(verifier.stats().get_total(), 0);
    }

    #[test]
    fn verifier_rejects_too_small() {
        let verifier = SignatureVerifier::new();
        let small_data = Bytes::from(vec![0u8; 10]);
        let result = verifier.verify(&small_data);
        assert!(matches!(
            result,
            Err(VerificationError::TransactionTooSmall(_))
        ));
    }

    #[test]
    fn verifier_rejects_too_large() {
        let verifier = SignatureVerifier::new();
        let large_data = Bytes::from(vec![0u8; 2000]);
        let result = verifier.verify(&large_data);
        assert!(matches!(
            result,
            Err(VerificationError::TransactionTooLarge(_))
        ));
    }

    #[test]
    fn compact_u16_decodes_single_byte() {
        let verifier = SignatureVerifier::new();
        let data = [42u8];
        let (value, len) = verifier.decode_compact_u16(&data).unwrap();
        assert_eq!(value, 42);
        assert_eq!(len, 1);
    }

    #[test]
    fn compact_u16_decodes_two_bytes() {
        let verifier = SignatureVerifier::new();
        let data = [0x81u8, 0x23u8]; // (0x01 << 8) | 0x23 = 291
        let (value, len) = verifier.decode_compact_u16(&data).unwrap();
        assert_eq!(value, 291);
        assert_eq!(len, 2);
    }
}
