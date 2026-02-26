use crate::{InboundPacket, ShredFilterStats};
use paradencer_mesh::{InPort, OutPort, ReceiveError, SendError};
use paradencer_net::{
    DedupDecision, IngressPolicy, ShredDecodeOutcome, ShredDecoder, SignatureDeduplicator,
};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use paradencer_types::shred::Shred;
use std::sync::Arc;
use std::time::Duration;

pub struct ShredFilter {
    incoming_packets: InPort<InboundPacket>,
    shred_decoder: ShredDecoder,
    signature_deduplicator: SignatureDeduplicator,
    shred_filter_stats: Arc<ShredFilterStats>,
    shred_output: Option<OutPort<Shred>>,
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
        ingress_policy: IngressPolicy,
        shred_filter_stats: Arc<ShredFilterStats>,
    ) -> Self {
        Self::build(incoming_packets, ingress_policy, shred_filter_stats, None)
    }

    pub fn with_output(
        incoming_packets: InPort<InboundPacket>,
        ingress_policy: IngressPolicy,
        shred_filter_stats: Arc<ShredFilterStats>,
        shred_output: OutPort<Shred>,
    ) -> Self {
        Self::build(
            incoming_packets,
            ingress_policy,
            shred_filter_stats,
            Some(shred_output),
        )
    }

    fn build(
        incoming_packets: InPort<InboundPacket>,
        mut ingress_policy: IngressPolicy,
        shred_filter_stats: Arc<ShredFilterStats>,
        shred_output: Option<OutPort<Shred>>,
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
            shred_output,
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
                let prepared = match self.shred_decoder.decode(&packet) {
                    ShredDecodeOutcome::Accepted(prepared) => prepared,
                    ShredDecodeOutcome::Dropped(drop_reason) => {
                        self.shred_filter_stats.increment_drop_reason(drop_reason);
                        return Ok(());
                    }
                };
                if self
                    .signature_deduplicator
                    .register(prepared.dedup_fingerprint)
                    == DedupDecision::Duplicate
                {
                    self.shred_filter_stats.increment_duplicates();
                    return Ok(());
                }
                self.shred_filter_stats.increment_accepted();

                if let Some(output) = &self.shred_output {
                    if !packet.data.is_empty() {
                        match self.shred_decoder.parse_shred(&packet.data) {
                            Ok(parsed_shred) => match output.try_send(parsed_shred) {
                                Ok(()) => {}
                                Err(SendError::QueueFull(_)) => {
                                    self.shred_filter_stats.increment_drop_reason(
                                        paradencer_net::DropReason::DownstreamBackpressure,
                                    );
                                }
                                Err(SendError::QueueClosed(_)) => {
                                    context.shutdown.request_stop();
                                    return Err(RuntimeError::service_failure(
                                        self.name(),
                                        "shred output link closed",
                                    ));
                                }
                            },
                            Err(_parse_error) => {
                                // Raw bytes failed to parse into a valid shred structure.
                                // The frame-level checks passed but the shred format is invalid.
                                self.shred_filter_stats.increment_parse_failures();
                            }
                        }
                    }
                }

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
