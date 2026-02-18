/// Signature verification pipeline stage.
///
/// Receives raw transaction packets, verifies Ed25519 signatures in batches,
/// and forwards only valid transactions downstream. Invalid transactions are
/// dropped with metrics tracking. Supports round-robin work distribution
/// across multiple verifier instances and special handling for gossip votes.
use paradencer_crypto::ed25519_batch::{BatchVerifier, SignatureSet};
use paradencer_crypto::VerificationResult;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Source classification for incoming transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionSource {
    /// Transaction received via QUIC TPU protocol.
    Quic,
    /// Transaction received via gossip (typically votes).
    Gossip,
    /// Transaction received via bundle protocol.
    Bundle,
    /// Transaction forwarded from another validator.
    Forwarded,
}

/// A transaction awaiting signature verification.
#[derive(Debug, Clone)]
pub struct UnverifiedTransaction {
    /// Raw transaction payload bytes.
    pub payload: Vec<u8>,
    /// Source of this transaction.
    pub source: TransactionSource,
    /// Number of required signatures in the transaction.
    pub num_signatures: u16,
    /// Offset to the signature block within payload.
    pub signature_offset: usize,
    /// Offset to the message (signed data) within payload.
    pub message_offset: usize,
    /// Offsets of signer public keys within payload.
    pub signer_offsets: Vec<usize>,
}

/// A transaction that passed signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedTransaction {
    /// Raw transaction payload bytes (same as input).
    pub payload: Vec<u8>,
    /// Source of this transaction.
    pub source: TransactionSource,
    /// Number of valid signatures.
    pub num_signatures: u16,
}

/// Verification outcome for a single transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// All signatures are valid.
    Valid,
    /// At least one signature failed.
    InvalidSignature,
    /// Transaction payload is malformed.
    Malformed,
    /// Transaction was filtered by round-robin (not this verifier's turn).
    Filtered,
}

/// Statistics for the verification stage.
#[derive(Debug, Default)]
pub struct VerifyStats {
    pub transactions_received: AtomicU64,
    pub transactions_verified: AtomicU64,
    pub transactions_failed: AtomicU64,
    pub transactions_malformed: AtomicU64,
    pub transactions_filtered: AtomicU64,
    pub batches_processed: AtomicU64,
    pub gossip_votes_received: AtomicU64,
}

impl VerifyStats {
    pub fn snapshot(&self) -> VerifyStatsSnapshot {
        VerifyStatsSnapshot {
            transactions_received: self.transactions_received.load(Ordering::Relaxed),
            transactions_verified: self.transactions_verified.load(Ordering::Relaxed),
            transactions_failed: self.transactions_failed.load(Ordering::Relaxed),
            transactions_malformed: self.transactions_malformed.load(Ordering::Relaxed),
            transactions_filtered: self.transactions_filtered.load(Ordering::Relaxed),
            batches_processed: self.batches_processed.load(Ordering::Relaxed),
            gossip_votes_received: self.gossip_votes_received.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of verification statistics.
#[derive(Debug, Clone, Default)]
pub struct VerifyStatsSnapshot {
    pub transactions_received: u64,
    pub transactions_verified: u64,
    pub transactions_failed: u64,
    pub transactions_malformed: u64,
    pub transactions_filtered: u64,
    pub batches_processed: u64,
    pub gossip_votes_received: u64,
}

/// Configuration for the signature verification stage.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Maximum batch size before flushing verification.
    pub max_batch_size: usize,
    /// This verifier's index in the round-robin pool (0-based).
    pub round_robin_index: usize,
    /// Total number of verifiers in the pool.
    pub round_robin_count: usize,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 128,
            round_robin_index: 0,
            round_robin_count: 1,
        }
    }
}

/// Signature verification pipeline stage.
///
/// Batches incoming transactions and verifies their Ed25519 signatures
/// using the crypto module's batch verifier for optimal throughput.
pub struct VerifyStage {
    config: VerifyConfig,
    pending: VecDeque<UnverifiedTransaction>,
    stats: Arc<VerifyStats>,
    sequence_counter: u64,
}

impl VerifyStage {
    /// Create a new verification stage with default configuration.
    pub fn new() -> Self {
        Self::with_config(VerifyConfig::default())
    }

    /// Create a new verification stage with the given configuration.
    pub fn with_config(config: VerifyConfig) -> Self {
        Self {
            pending: VecDeque::with_capacity(config.max_batch_size),
            config,
            stats: Arc::new(VerifyStats::default()),
            sequence_counter: 0,
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<VerifyStats> {
        Arc::clone(&self.stats)
    }

    /// Check if this transaction should be processed by this verifier instance
    /// based on round-robin assignment.
    fn should_process(&mut self, source: TransactionSource) -> bool {
        // Gossip votes are only processed by verifier 0 to prevent
        // interleaving of vote streams across verifiers.
        if source == TransactionSource::Gossip {
            return self.config.round_robin_index == 0;
        }

        // Bundle transactions are processed by all verifiers (no round-robin).
        if source == TransactionSource::Bundle {
            return true;
        }

        // QUIC and forwarded transactions are distributed round-robin.
        let assigned = (self.sequence_counter as usize) % self.config.round_robin_count
            == self.config.round_robin_index;
        self.sequence_counter += 1;
        assigned
    }

    /// Submit a transaction for verification. Returns `Filtered` if this
    /// verifier instance should not process it (round-robin).
    pub fn submit(&mut self, tx: UnverifiedTransaction) -> VerifyOutcome {
        self.stats
            .transactions_received
            .fetch_add(1, Ordering::Relaxed);

        if tx.source == TransactionSource::Gossip {
            self.stats
                .gossip_votes_received
                .fetch_add(1, Ordering::Relaxed);
        }

        if !self.should_process(tx.source) {
            self.stats
                .transactions_filtered
                .fetch_add(1, Ordering::Relaxed);
            return VerifyOutcome::Filtered;
        }

        // Basic sanity checks before queuing.
        if tx.num_signatures == 0 || tx.payload.is_empty() {
            self.stats
                .transactions_malformed
                .fetch_add(1, Ordering::Relaxed);
            return VerifyOutcome::Malformed;
        }

        if tx.message_offset >= tx.payload.len() || tx.signature_offset >= tx.payload.len() {
            self.stats
                .transactions_malformed
                .fetch_add(1, Ordering::Relaxed);
            return VerifyOutcome::Malformed;
        }

        self.pending.push_back(tx);
        VerifyOutcome::Valid // queued for batch verification
    }

    /// Flush pending transactions through batch verification.
    /// Returns a list of verified transactions and their outcomes.
    pub fn flush(&mut self) -> Vec<(VerifiedTransaction, VerifyOutcome)> {
        if self.pending.is_empty() {
            return Vec::new();
        }

        let batch: Vec<UnverifiedTransaction> = self.pending.drain(..).collect();
        let mut results = Vec::with_capacity(batch.len());
        let mut verifier = BatchVerifier::new();

        // Build signature sets for each transaction.
        let mut tx_sig_ranges: Vec<(usize, usize)> = Vec::with_capacity(batch.len());
        let mut sig_count = 0usize;

        for tx in &batch {
            let start = sig_count;
            let added = self.add_signatures_to_batch(&mut verifier, tx);
            sig_count += added;
            tx_sig_ranges.push((start, added));
        }

        // Perform batch verification.
        let per_sig_results = if sig_count > 0 {
            verifier.verify_batch_detailed().unwrap_or_default()
        } else {
            Vec::new()
        };

        self.stats.batches_processed.fetch_add(1, Ordering::Relaxed);

        // Map per-signature results back to per-transaction outcomes.
        for (tx, (start, count)) in batch.into_iter().zip(tx_sig_ranges.iter()) {
            let all_valid = if *count == 0 {
                false
            } else {
                per_sig_results[*start..*start + *count]
                    .iter()
                    .all(|&valid| valid)
            };

            let outcome = if all_valid {
                self.stats
                    .transactions_verified
                    .fetch_add(1, Ordering::Relaxed);
                VerifyOutcome::Valid
            } else {
                self.stats
                    .transactions_failed
                    .fetch_add(1, Ordering::Relaxed);
                VerifyOutcome::InvalidSignature
            };

            results.push((
                VerifiedTransaction {
                    payload: tx.payload,
                    source: tx.source,
                    num_signatures: tx.num_signatures,
                },
                outcome,
            ));
        }

        results
    }

    /// Check if the pending batch is full and should be flushed.
    pub fn should_flush(&self) -> bool {
        self.pending.len() >= self.config.max_batch_size
    }

    /// Number of transactions awaiting verification.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Add all signatures from a transaction to the batch verifier.
    /// Returns the number of signatures added.
    fn add_signatures_to_batch(
        &self,
        verifier: &mut BatchVerifier,
        tx: &UnverifiedTransaction,
    ) -> usize {
        let mut added = 0usize;

        for i in 0..tx.num_signatures as usize {
            let sig_start = tx.signature_offset + i * 64;
            let sig_end = sig_start + 64;

            if sig_end > tx.payload.len() || i >= tx.signer_offsets.len() {
                continue;
            }

            let key_start = tx.signer_offsets[i];
            let key_end = key_start + 32;
            if key_end > tx.payload.len() {
                continue;
            }

            let message = &tx.payload[tx.message_offset..];

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&tx.payload[sig_start..sig_end]);

            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&tx.payload[key_start..key_end]);

            if verifier
                .add_signature(key_bytes, message.to_vec(), sig_bytes)
                .is_ok()
            {
                added += 1;
            }
        }

        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_payload(signing_key: &SigningKey) -> UnverifiedTransaction {
        // Build a minimal transaction-like payload:
        // [signature (64 bytes)] [pubkey (32 bytes)] [message...]
        let message = b"test transaction message";
        let signature = signing_key.sign(message);
        let pubkey = signing_key.verifying_key().to_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&signature.to_bytes()); // offset 0..64
        payload.extend_from_slice(&pubkey); // offset 64..96
        payload.extend_from_slice(message); // offset 96..

        UnverifiedTransaction {
            payload,
            source: TransactionSource::Quic,
            num_signatures: 1,
            signature_offset: 0,
            message_offset: 96,       // message starts after sig+pubkey
            signer_offsets: vec![64], // pubkey at offset 64
        }
    }

    #[test]
    fn verify_single_valid_signature() {
        let mut stage = VerifyStage::new();
        let key = SigningKey::from_bytes(&[1u8; 32]);

        let tx = make_signed_payload(&key);
        let outcome = stage.submit(tx);
        assert_eq!(outcome, VerifyOutcome::Valid); // queued

        let results = stage.flush();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, VerifyOutcome::Valid);
    }

    #[test]
    fn reject_invalid_signature() {
        let mut stage = VerifyStage::new();
        let key = SigningKey::from_bytes(&[2u8; 32]);

        let mut tx = make_signed_payload(&key);
        // Corrupt the signature
        tx.payload[0] ^= 0xFF;

        stage.submit(tx);
        let results = stage.flush();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, VerifyOutcome::InvalidSignature);
    }

    #[test]
    fn reject_malformed_transaction() {
        let mut stage = VerifyStage::new();

        let tx = UnverifiedTransaction {
            payload: vec![],
            source: TransactionSource::Quic,
            num_signatures: 1,
            signature_offset: 0,
            message_offset: 0,
            signer_offsets: vec![],
        };

        let outcome = stage.submit(tx);
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }

    #[test]
    fn reject_zero_signatures() {
        let mut stage = VerifyStage::new();

        let tx = UnverifiedTransaction {
            payload: vec![1, 2, 3],
            source: TransactionSource::Quic,
            num_signatures: 0,
            signature_offset: 0,
            message_offset: 0,
            signer_offsets: vec![],
        };

        let outcome = stage.submit(tx);
        assert_eq!(outcome, VerifyOutcome::Malformed);
    }

    #[test]
    fn round_robin_filters_quic_transactions() {
        let config = VerifyConfig {
            max_batch_size: 128,
            round_robin_index: 1,
            round_robin_count: 3,
        };
        let mut stage = VerifyStage::with_config(config);
        let key = SigningKey::from_bytes(&[3u8; 32]);

        // Submit 6 QUIC transactions; only indices 1, 4 should be processed
        // (sequence 0 → verifier 0, sequence 1 → verifier 1, ...)
        let mut accepted = 0;
        let mut filtered = 0;
        for _ in 0..6 {
            let tx = make_signed_payload(&key);
            match stage.submit(tx) {
                VerifyOutcome::Filtered => filtered += 1,
                VerifyOutcome::Valid => accepted += 1,
                _ => panic!("unexpected outcome"),
            }
        }

        assert_eq!(accepted, 2);
        assert_eq!(filtered, 4);
    }

    #[test]
    fn gossip_votes_only_on_verifier_zero() {
        // Verifier 1 should filter gossip votes
        let config = VerifyConfig {
            max_batch_size: 128,
            round_robin_index: 1,
            round_robin_count: 2,
        };
        let mut stage = VerifyStage::with_config(config);
        let key = SigningKey::from_bytes(&[4u8; 32]);

        let mut tx = make_signed_payload(&key);
        tx.source = TransactionSource::Gossip;
        assert_eq!(stage.submit(tx), VerifyOutcome::Filtered);

        // Verifier 0 should accept gossip votes
        let config0 = VerifyConfig {
            max_batch_size: 128,
            round_robin_index: 0,
            round_robin_count: 2,
        };
        let mut stage0 = VerifyStage::with_config(config0);

        let mut tx = make_signed_payload(&key);
        tx.source = TransactionSource::Gossip;
        assert_eq!(stage0.submit(tx), VerifyOutcome::Valid);
    }

    #[test]
    fn bundles_bypass_round_robin() {
        let config = VerifyConfig {
            max_batch_size: 128,
            round_robin_index: 2,
            round_robin_count: 4,
        };
        let mut stage = VerifyStage::with_config(config);
        let key = SigningKey::from_bytes(&[5u8; 32]);

        let mut tx = make_signed_payload(&key);
        tx.source = TransactionSource::Bundle;
        assert_eq!(stage.submit(tx), VerifyOutcome::Valid);
    }

    #[test]
    fn batch_verification_multiple_transactions() {
        let mut stage = VerifyStage::new();

        let keys: Vec<SigningKey> = (0..5u8)
            .map(|i| SigningKey::from_bytes(&[10 + i; 32]))
            .collect();

        for key in &keys {
            let tx = make_signed_payload(key);
            stage.submit(tx);
        }

        let results = stage.flush();
        assert_eq!(results.len(), 5);
        for (_, outcome) in &results {
            assert_eq!(*outcome, VerifyOutcome::Valid);
        }
    }

    #[test]
    fn stats_tracking() {
        let mut stage = VerifyStage::new();
        let key = SigningKey::from_bytes(&[6u8; 32]);

        // Submit valid tx
        let tx = make_signed_payload(&key);
        stage.submit(tx);

        // Submit malformed tx
        let bad = UnverifiedTransaction {
            payload: vec![],
            source: TransactionSource::Quic,
            num_signatures: 1,
            signature_offset: 0,
            message_offset: 0,
            signer_offsets: vec![],
        };
        stage.submit(bad);

        stage.flush();

        let snap = stage.stats().snapshot();
        assert_eq!(snap.transactions_received, 2);
        assert_eq!(snap.transactions_verified, 1);
        assert_eq!(snap.transactions_malformed, 1);
        assert_eq!(snap.batches_processed, 1);
    }

    #[test]
    fn should_flush_at_batch_limit() {
        let config = VerifyConfig {
            max_batch_size: 3,
            round_robin_index: 0,
            round_robin_count: 1,
        };
        let mut stage = VerifyStage::with_config(config);
        let key = SigningKey::from_bytes(&[7u8; 32]);

        assert!(!stage.should_flush());

        for _ in 0..2 {
            let tx = make_signed_payload(&key);
            stage.submit(tx);
        }
        assert!(!stage.should_flush());

        let tx = make_signed_payload(&key);
        stage.submit(tx);
        assert!(stage.should_flush());
    }

    #[test]
    fn empty_flush_returns_empty() {
        let mut stage = VerifyStage::new();
        let results = stage.flush();
        assert!(results.is_empty());
    }
}
