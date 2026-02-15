use crate::{InboundPacket, ShredFilterStats};
use paradencer_ingress::{
    DedupDecision, IngressPolicy, ShredDecodeOutcome, ShredDecoder, SignatureDeduplicator,
};
use paradencer_mesh::{InPort, ReceiveError};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use std::sync::Arc;
use std::time::Duration;

pub struct ShredFilter {
    incoming_packets: InPort<InboundPacket>,
    shred_decoder: ShredDecoder,
    signature_deduplicator: SignatureDeduplicator,
    shred_filter_stats: Arc<ShredFilterStats>,
}

impl ShredFilter {
    pub fn new(incoming_packets: InPort<InboundPacket>) -> Self {
        Self::with_policy_and_stats(
            incoming_packets,
            IngressPolicy::default(),
            Arc::new(ShredFilterStats::default()),
        )
    }

    pub fn with_policy_and_stats(
        incoming_packets: InPort<InboundPacket>,
        mut ingress_policy: IngressPolicy,
        shred_filter_stats: Arc<ShredFilterStats>,
    ) -> Self {
        if ingress_policy.validate().is_err() {
            ingress_policy = IngressPolicy::default();
        }
        let dedup_window_capacity = ingress_policy.dedup_window_capacity.max(1);
        let shred_decoder = match ShredDecoder::new(ingress_policy) {
            Ok(shred_decoder) => shred_decoder,
            Err(_) => unreachable!("ingress policy must be valid after fallback"),
        };

        Self {
            incoming_packets,
            shred_decoder,
            signature_deduplicator: SignatureDeduplicator::new(dedup_window_capacity),
            shred_filter_stats,
        }
    }
}

impl Service for ShredFilter {
    fn name(&self) -> &'static str {
        "shred-filter"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        match self.incoming_packets.try_recv() {
            Ok(Some(packet)) => {
                let shred = match self.shred_decoder.decode(&packet) {
                    ShredDecodeOutcome::Accepted(shred) => shred,
                    ShredDecodeOutcome::Dropped(drop_reason) => {
                        self.shred_filter_stats.increment_drop_reason(drop_reason);
                        return Ok(());
                    }
                };
                if self
                    .signature_deduplicator
                    .register(shred.dedup_fingerprint)
                    == DedupDecision::Duplicate
                {
                    self.shred_filter_stats.increment_duplicates();
                    return Ok(());
                }
                self.shred_filter_stats.increment_accepted();
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(ReceiveError::QueueClosed) => {
                context.shutdown.request_stop();
                Err(RuntimeError::service_failure(
                    self.name(),
                    "input shred packet link closed",
                ))
            }
        }
    }
}
