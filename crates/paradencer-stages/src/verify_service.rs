/// Service wrapper for the signature verification stage.
///
/// Receives unverified transactions from an input channel, runs them through
/// `VerifyStage` for Ed25519 signature verification, and forwards valid
/// transactions to the output channel for downstream processing (blockhash
/// resolution).
///
/// Invalid transactions are dropped and counted in statistics.
use crate::verify_stage::{UnverifiedTransaction, VerifiedTransaction, VerifyOutcome, VerifyStage};
use paradencer_mesh::{InPort, OutPort, ReceiveError};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Statistics for the verification service.
#[derive(Debug, Default)]
pub struct VerifyServiceStats {
    pub verified: AtomicU64,
    pub invalid_signature: AtomicU64,
    pub malformed: AtomicU64,
    pub filtered: AtomicU64,
    pub forwarded: AtomicU64,
    pub forward_failed: AtomicU64,
}

/// Service that drives the signature verification pipeline.
pub struct VerifyService {
    stage: VerifyStage,
    input: InPort<UnverifiedTransaction>,
    output: OutPort<VerifiedTransaction>,
    stats: Arc<VerifyServiceStats>,
    /// Maximum transactions to process per tick.
    batch_size: usize,
}

impl VerifyService {
    /// Create a new verification service.
    pub fn new(
        stage: VerifyStage,
        input: InPort<UnverifiedTransaction>,
        output: OutPort<VerifiedTransaction>,
    ) -> Self {
        Self {
            stage,
            input,
            output,
            stats: Arc::new(VerifyServiceStats::default()),
            batch_size: 64,
        }
    }

    /// Create with custom batch size.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Get shared statistics.
    pub fn stats(&self) -> Arc<VerifyServiceStats> {
        Arc::clone(&self.stats)
    }
}

impl Service for VerifyService {
    fn name(&self) -> &'static str {
        "verify-service"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        for _ in 0..self.batch_size {
            match self.input.try_recv() {
                Ok(Some(unverified)) => {
                    let outcome = self.stage.submit(unverified.clone());

                    match outcome {
                        VerifyOutcome::Valid => {
                            self.stats.verified.fetch_add(1, Ordering::Relaxed);

                            let verified = VerifiedTransaction {
                                payload: unverified.payload,
                                source: unverified.source,
                                num_signatures: unverified.num_signatures,
                            };

                            if self.output.try_send(verified).is_ok() {
                                self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.stats.forward_failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        VerifyOutcome::InvalidSignature => {
                            self.stats.invalid_signature.fetch_add(1, Ordering::Relaxed);
                        }
                        VerifyOutcome::Malformed => {
                            self.stats.malformed.fetch_add(1, Ordering::Relaxed);
                        }
                        VerifyOutcome::Filtered => {
                            self.stats.filtered.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Ok(None) => break,
                Err(ReceiveError::QueueClosed) => {
                    context.shutdown.request_stop();
                    return Err(RuntimeError::service_failure(
                        self.name(),
                        "input channel closed",
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_stage::{TransactionSource, VerifyConfig};
    use paradencer_mesh::bounded_link;

    fn make_unverified(id: u8) -> UnverifiedTransaction {
        UnverifiedTransaction {
            payload: vec![id; 128],
            source: TransactionSource::Quic,
            num_signatures: 1,
            signature_offset: 0,
            message_offset: 64,
            signer_offsets: vec![64],
        }
    }

    #[test]
    fn service_constructs() {
        let stage = VerifyStage::new();
        let (_in_tx, rx) = bounded_link::<UnverifiedTransaction>(16);
        let (tx, _out_rx) = bounded_link::<VerifiedTransaction>(16);

        let service = VerifyService::new(stage, rx, tx);
        assert_eq!(service.name(), "verify-service");
    }

    #[test]
    fn service_processes_transactions() {
        let config = VerifyConfig {
            round_robin_index: 0,
            round_robin_count: 1,
            ..VerifyConfig::default()
        };
        let stage = VerifyStage::with_config(config);
        let (in_tx, in_rx) = bounded_link::<UnverifiedTransaction>(16);
        let (out_tx, out_rx) = bounded_link::<VerifiedTransaction>(16);

        let mut service = VerifyService::new(stage, in_rx, out_tx);

        // Submit a transaction.
        in_tx.try_send(make_unverified(1)).unwrap();

        // Tick the service.
        let ctx = ServiceContext::new(paradencer_runtime::ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        // Check stats — transaction will likely be malformed (no real sig),
        // but the service pipeline ran.
        let total = service.stats.verified.load(Ordering::Relaxed)
            + service.stats.invalid_signature.load(Ordering::Relaxed)
            + service.stats.malformed.load(Ordering::Relaxed)
            + service.stats.filtered.load(Ordering::Relaxed);
        assert_eq!(total, 1);
    }

    #[test]
    fn empty_input_returns_immediately() {
        let stage = VerifyStage::new();
        let (in_tx, rx) = bounded_link::<UnverifiedTransaction>(16);
        let (tx, _out_rx) = bounded_link::<VerifiedTransaction>(16);

        let mut service = VerifyService::new(stage, rx, tx);
        let ctx = ServiceContext::new(paradencer_runtime::ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        let total = service.stats.verified.load(Ordering::Relaxed)
            + service.stats.malformed.load(Ordering::Relaxed);
        assert_eq!(total, 0);

        // Keep sender alive to prevent QueueClosed.
        drop(in_tx);
    }
}
