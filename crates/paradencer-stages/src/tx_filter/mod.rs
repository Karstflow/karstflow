mod egress;
mod service;

use crate::{InboundPacket, IngressFilterStats, RawTransaction, SanitizedTransaction};
use paradencer_mesh::{InPort, OutPort};
use paradencer_net::{
    IngressPolicy, PacketDecoder, SignatureDeduplicator, SourceCostBudgetLimiter, SourceRateLimiter,
};
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct PendingEgressTransaction {
    transaction: SanitizedTransaction,
    wait_ticks: u32,
}

pub struct TxFilter {
    incoming_packets: InPort<InboundPacket>,
    outgoing_transactions: OutPort<SanitizedTransaction>,
    /// Optional output to the validator pipeline for real execution.
    /// When present, accepted transactions are forwarded with raw bytes.
    outgoing_pipeline: Option<OutPort<RawTransaction>>,
    packet_decoder: PacketDecoder,
    ingress_policy: IngressPolicy,
    signature_deduplicator: SignatureDeduplicator,
    source_rate_limiter: SourceRateLimiter,
    source_cost_budget_limiter: SourceCostBudgetLimiter,
    pending_egress_transactions: VecDeque<PendingEgressTransaction>,
    egress_retry_buffer_capacity: usize,
    egress_retry_max_wait_ticks: u32,
    ingress_filter_stats: Arc<IngressFilterStats>,
    tick_counter: u64,
}

impl TxFilter {
    pub fn new(
        incoming_packets: InPort<InboundPacket>,
        outgoing_transactions: OutPort<SanitizedTransaction>,
    ) -> Self {
        Self::with_policy(
            incoming_packets,
            outgoing_transactions,
            IngressPolicy::default(),
        )
    }

    pub fn with_policy(
        incoming_packets: InPort<InboundPacket>,
        outgoing_transactions: OutPort<SanitizedTransaction>,
        ingress_policy: IngressPolicy,
    ) -> Self {
        Self::with_policy_and_stats(
            incoming_packets,
            outgoing_transactions,
            ingress_policy,
            Arc::new(IngressFilterStats::default()),
        )
    }

    pub fn with_policy_and_stats(
        incoming_packets: InPort<InboundPacket>,
        outgoing_transactions: OutPort<SanitizedTransaction>,
        mut ingress_policy: IngressPolicy,
        ingress_filter_stats: Arc<IngressFilterStats>,
    ) -> Self {
        Self::build(
            incoming_packets,
            outgoing_transactions,
            None,
            ingress_policy,
            ingress_filter_stats,
        )
    }

    /// Create a TxFilter with both the legacy metadata output and a pipeline output.
    ///
    /// Accepted transactions are sent to both:
    /// - `outgoing_transactions` as `SanitizedTransaction` (metadata for BlockAssembler)
    /// - `outgoing_pipeline` as `RawTransaction` (raw bytes for ValidatorPipeline)
    pub fn with_policy_pipeline_and_stats(
        incoming_packets: InPort<InboundPacket>,
        outgoing_transactions: OutPort<SanitizedTransaction>,
        outgoing_pipeline: OutPort<RawTransaction>,
        ingress_policy: IngressPolicy,
        ingress_filter_stats: Arc<IngressFilterStats>,
    ) -> Self {
        Self::build(
            incoming_packets,
            outgoing_transactions,
            Some(outgoing_pipeline),
            ingress_policy,
            ingress_filter_stats,
        )
    }

    fn build(
        incoming_packets: InPort<InboundPacket>,
        outgoing_transactions: OutPort<SanitizedTransaction>,
        outgoing_pipeline: Option<OutPort<RawTransaction>>,
        mut ingress_policy: IngressPolicy,
        ingress_filter_stats: Arc<IngressFilterStats>,
    ) -> Self {
        if ingress_policy.validate().is_err() {
            ingress_policy = IngressPolicy::default();
        }
        let dedup_window_capacity = ingress_policy.dedup_window_capacity.max(1);
        let packet_decoder = match PacketDecoder::new(ingress_policy.clone()) {
            Ok(packet_decoder) => packet_decoder,
            Err(_) => unreachable!("ingress policy must be valid after fallback"),
        };
        let egress_retry_buffer_capacity = ingress_policy.egress_retry_buffer_capacity;
        let egress_retry_max_wait_ticks = ingress_policy.egress_retry_max_wait_ticks;

        Self {
            incoming_packets,
            outgoing_transactions,
            outgoing_pipeline,
            packet_decoder,
            ingress_policy,
            signature_deduplicator: SignatureDeduplicator::new(dedup_window_capacity),
            source_rate_limiter: SourceRateLimiter::new(),
            source_cost_budget_limiter: SourceCostBudgetLimiter::new(),
            pending_egress_transactions: VecDeque::with_capacity(egress_retry_buffer_capacity),
            egress_retry_buffer_capacity,
            egress_retry_max_wait_ticks,
            ingress_filter_stats,
            tick_counter: 0,
        }
    }
}
