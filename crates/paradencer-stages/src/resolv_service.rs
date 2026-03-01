/// Service wrapper for the blockhash resolution stage.
///
/// Receives verified transactions from the signature verifier, resolves their
/// blockhash against the recent blockhash cache, and forwards valid ones to the
/// pack scheduler as `PackedTransaction`.
///
/// Transactions referencing unknown blockhashes are stashed and retried when
/// new blockhashes are registered. Expired or stash-overflow transactions are
/// dropped.
use crate::pack_stage::{PackScheduler, PackedTransaction};
use crate::resolv_stage::{ResolvOutcome, ResolvStage, ResolvedTransaction};
use crate::verify_stage::VerifiedTransaction;
use paradencer_mesh::{DualReceiveError, DualReceiver};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Statistics for the resolution service.
#[derive(Debug, Default)]
pub struct ResolvServiceStats {
    pub resolved_valid: AtomicU64,
    pub resolved_expired: AtomicU64,
    pub stashed: AtomicU64,
    pub stash_full: AtomicU64,
    pub forwarded_to_pack: AtomicU64,
}

/// Service that drives the blockhash resolution pipeline.
///
/// Takes `VerifiedTransaction` from the verify service, converts to
/// `ResolvedTransaction`, resolves the blockhash, and forwards valid
/// ones to the pack scheduler.
pub struct ResolvService {
    stage: ResolvStage,
    input: DualReceiver<VerifiedTransaction>,
    pack: PackScheduler,
    stats: Arc<ResolvServiceStats>,
    /// Maximum transactions to process per tick.
    batch_size: usize,
}

impl ResolvService {
    /// Create a new resolution service.
    pub fn new(
        stage: ResolvStage,
        input: DualReceiver<VerifiedTransaction>,
        pack: PackScheduler,
    ) -> Self {
        Self {
            stage,
            input,
            pack,
            stats: Arc::new(ResolvServiceStats::default()),
            batch_size: 64,
        }
    }

    /// Create with custom batch size.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Get shared statistics.
    pub fn stats(&self) -> Arc<ResolvServiceStats> {
        Arc::clone(&self.stats)
    }

    /// Access the pack scheduler (for submitting additional transactions or
    /// querying state).
    pub fn pack(&self) -> &PackScheduler {
        &self.pack
    }

    /// Mutable access to the pack scheduler.
    pub fn pack_mut(&mut self) -> &mut PackScheduler {
        &mut self.pack
    }

    /// Mutable access to the resolv stage (for registering new blockhashes).
    pub fn resolv_stage_mut(&mut self) -> &mut ResolvStage {
        &mut self.stage
    }

    /// Convert a verified transaction to a resolved transaction for the
    /// blockhash resolution stage.
    fn to_resolved(verified: &VerifiedTransaction) -> ResolvedTransaction {
        // Extract blockhash from the payload.
        // In a real transaction, the blockhash is at a known offset in the
        // message. For now, extract the first 32 bytes after the signature
        // block as a simplified approach.
        let blockhash = if verified.payload.len() >= 96 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&verified.payload[64..96]);
            hash
        } else {
            [0u8; 32]
        };

        ResolvedTransaction {
            payload: verified.payload.clone(),
            blockhash,
            priority_fee: 0,
            compute_units: 200_000,
            is_vote: false,
        }
    }

    /// Convert a resolved transaction with expiry into a packed transaction
    /// for the scheduler.
    fn to_packed(resolved: &ResolvedTransaction, expires_at_slot: u64) -> PackedTransaction {
        // Extract write/read accounts from the payload for conflict detection.
        // For now, use a simplified extraction.
        let write_accounts = if resolved.payload.len() >= 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&resolved.payload[..32]);
            vec![key]
        } else {
            vec![]
        };

        PackedTransaction {
            payload: resolved.payload.clone(),
            blockhash: resolved.blockhash,
            priority_fee: resolved.priority_fee,
            compute_units: resolved.compute_units,
            total_cost: 0,
            is_vote: resolved.is_vote,
            expires_at_slot,
            write_accounts,
            read_accounts: vec![],
            data_size: resolved.payload.len(),
            insertion_order: 0,
        }
    }
}

impl Service for ResolvService {
    fn name(&self) -> &'static str {
        "resolv-service"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        for _ in 0..self.batch_size {
            match self.input.try_recv() {
                Ok(Some(verified)) => {
                    let resolved = Self::to_resolved(&verified);
                    let outcome = self.stage.resolve(resolved.clone());

                    match outcome {
                        ResolvOutcome::Valid { expires_at_slot } => {
                            self.stats.resolved_valid.fetch_add(1, Ordering::Relaxed);

                            let packed = Self::to_packed(&resolved, expires_at_slot);
                            self.pack.submit(packed);
                            self.stats.forwarded_to_pack.fetch_add(1, Ordering::Relaxed);
                        }
                        ResolvOutcome::Expired => {
                            self.stats.resolved_expired.fetch_add(1, Ordering::Relaxed);
                        }
                        ResolvOutcome::Stashed => {
                            self.stats.stashed.fetch_add(1, Ordering::Relaxed);
                        }
                        ResolvOutcome::StashFull => {
                            self.stats.stash_full.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(None) => break,
                Err(DualReceiveError::Closed) => {
                    context.shutdown.request_stop();
                    return Err(RuntimeError::service_failure(
                        self.name(),
                        "input channel closed",
                    ));
                }
                Err(DualReceiveError::Overrun { .. }) => {
                    // Consumer overrun — lost data. Continue next tick.
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolv_stage::ResolvConfig;
    use crate::verify_stage::TransactionSource;
    use paradencer_mesh::bounded_link;

    fn make_verified(id: u8) -> VerifiedTransaction {
        VerifiedTransaction {
            payload: vec![id; 128],
            source: TransactionSource::Quic,
            num_signatures: 1,
        }
    }

    #[test]
    fn service_constructs() {
        let stage = ResolvStage::new();
        let (_tx, rx) = bounded_link::<VerifiedTransaction>(16);
        let pack = PackScheduler::new();

        let service = ResolvService::new(stage, DualReceiver::Channel(rx), pack);
        assert_eq!(service.name(), "resolv-service");
    }

    #[test]
    fn service_processes_transactions() {
        let mut stage = ResolvStage::new();
        // Register a blockhash so transactions can resolve.
        let test_hash = [0x01u8; 32];
        stage.register_blockhash(test_hash, 100);

        let (in_tx, in_rx) = bounded_link::<VerifiedTransaction>(16);
        let pack = PackScheduler::new();

        let mut service = ResolvService::new(stage, DualReceiver::Channel(in_rx), pack);

        // Submit a verified transaction.
        in_tx.try_send(make_verified(1)).unwrap();

        let ctx = ServiceContext::new(paradencer_runtime::ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        // Transaction was processed (either resolved or stashed).
        let total = service.stats.resolved_valid.load(Ordering::Relaxed)
            + service.stats.resolved_expired.load(Ordering::Relaxed)
            + service.stats.stashed.load(Ordering::Relaxed)
            + service.stats.stash_full.load(Ordering::Relaxed);
        assert_eq!(total, 1);
    }

    #[test]
    fn empty_input_returns_immediately() {
        let stage = ResolvStage::new();
        let (_tx, rx) = bounded_link::<VerifiedTransaction>(16);
        let pack = PackScheduler::new();

        let mut service = ResolvService::new(stage, DualReceiver::Channel(rx), pack);
        let ctx = ServiceContext::new(paradencer_runtime::ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        let total = service.stats.resolved_valid.load(Ordering::Relaxed)
            + service.stats.stashed.load(Ordering::Relaxed);
        assert_eq!(total, 0);
    }

    #[test]
    fn to_resolved_extracts_blockhash() {
        let verified = VerifiedTransaction {
            payload: vec![0xAA; 128],
            source: TransactionSource::Quic,
            num_signatures: 1,
        };

        let resolved = ResolvService::to_resolved(&verified);
        // Blockhash should be bytes 64..96 of the payload.
        assert_eq!(resolved.blockhash, [0xAA; 32]);
        assert_eq!(resolved.payload.len(), 128);
    }

    #[test]
    fn to_packed_creates_valid_transaction() {
        let resolved = ResolvedTransaction {
            payload: vec![0xBB; 128],
            blockhash: [0xCC; 32],
            priority_fee: 5000,
            compute_units: 200_000,
            is_vote: false,
        };

        let packed = ResolvService::to_packed(&resolved, 500);
        assert_eq!(packed.expires_at_slot, 500);
        assert_eq!(packed.priority_fee, 5000);
        assert_eq!(packed.compute_units, 200_000);
        assert_eq!(packed.blockhash, [0xCC; 32]);
        assert!(!packed.is_vote);
    }
}
