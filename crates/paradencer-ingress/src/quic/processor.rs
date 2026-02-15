use super::*;
use crate::ingress::{
    DecodeOutcome, DedupDecision, PacketDecoder, SignatureDeduplicator, SignatureVerifier,
    SourceCostBudgetLimiter, SourceRateLimiter, VerificationResult,
};
use crate::{InboundFrame, IngressPolicy, IngressSource, PreparedTransaction};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QuicProcessorStats {
    pub packets_received: Arc<AtomicU64>,
    pub packets_accepted: Arc<AtomicU64>,
    pub packets_dropped_empty: Arc<AtomicU64>,
    pub packets_dropped_oversized: Arc<AtomicU64>,
    pub packets_dropped_source_not_allowed: Arc<AtomicU64>,
    pub packets_dropped_rate_limited: Arc<AtomicU64>,
    pub packets_dropped_cost_budget: Arc<AtomicU64>,
    pub packets_dropped_duplicate: Arc<AtomicU64>,
    pub packets_dropped_invalid_signature: Arc<AtomicU64>,
}

impl QuicProcessorStats {
    pub fn new() -> Self {
        Self {
            packets_received: Arc::new(AtomicU64::new(0)),
            packets_accepted: Arc::new(AtomicU64::new(0)),
            packets_dropped_empty: Arc::new(AtomicU64::new(0)),
            packets_dropped_oversized: Arc::new(AtomicU64::new(0)),
            packets_dropped_source_not_allowed: Arc::new(AtomicU64::new(0)),
            packets_dropped_rate_limited: Arc::new(AtomicU64::new(0)),
            packets_dropped_cost_budget: Arc::new(AtomicU64::new(0)),
            packets_dropped_duplicate: Arc::new(AtomicU64::new(0)),
            packets_dropped_invalid_signature: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accepted(&self) {
        self.packets_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_empty(&self) {
        self.packets_dropped_empty.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_oversized(&self) {
        self.packets_dropped_oversized
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_source_not_allowed(&self) {
        self.packets_dropped_source_not_allowed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_rate_limited(&self) {
        self.packets_dropped_rate_limited
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_cost_budget(&self) {
        self.packets_dropped_cost_budget
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_duplicate(&self) {
        self.packets_dropped_duplicate
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped_invalid_signature(&self) {
        self.packets_dropped_invalid_signature
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> QuicProcessorStatsSnapshot {
        QuicProcessorStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_accepted: self.packets_accepted.load(Ordering::Relaxed),
            packets_dropped_empty: self.packets_dropped_empty.load(Ordering::Relaxed),
            packets_dropped_oversized: self.packets_dropped_oversized.load(Ordering::Relaxed),
            packets_dropped_source_not_allowed: self
                .packets_dropped_source_not_allowed
                .load(Ordering::Relaxed),
            packets_dropped_rate_limited: self.packets_dropped_rate_limited.load(Ordering::Relaxed),
            packets_dropped_cost_budget: self.packets_dropped_cost_budget.load(Ordering::Relaxed),
            packets_dropped_duplicate: self.packets_dropped_duplicate.load(Ordering::Relaxed),
            packets_dropped_invalid_signature: self
                .packets_dropped_invalid_signature
                .load(Ordering::Relaxed),
        }
    }
}

impl Default for QuicProcessorStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicProcessorStatsSnapshot {
    pub packets_received: u64,
    pub packets_accepted: u64,
    pub packets_dropped_empty: u64,
    pub packets_dropped_oversized: u64,
    pub packets_dropped_source_not_allowed: u64,
    pub packets_dropped_rate_limited: u64,
    pub packets_dropped_cost_budget: u64,
    pub packets_dropped_duplicate: u64,
    pub packets_dropped_invalid_signature: u64,
}

pub struct QuicProcessor {
    policy: IngressPolicy,
    decoder: PacketDecoder,
    signature_verifier: SignatureVerifier,
    deduplicator: SignatureDeduplicator,
    rate_limiter: SourceRateLimiter,
    cost_limiter: SourceCostBudgetLimiter,
    stats: QuicProcessorStats,
    current_tick: u64,
}

fn compute_packet_id(packet: &QuicPacket) -> u64 {
    let mut hasher = DefaultHasher::new();
    packet.data.hash(&mut hasher);
    packet.stream_id.hash(&mut hasher);
    packet.remote_addr.hash(&mut hasher);
    hasher.finish()
}

impl QuicProcessor {
    pub fn new(policy: IngressPolicy) -> QuicResult<Self> {
        let decoder = PacketDecoder::new(policy.clone())?;
        let signature_verifier = SignatureVerifier::new();
        let deduplicator = SignatureDeduplicator::new(policy.dedup_window_capacity);
        let rate_limiter = SourceRateLimiter::new();
        let cost_limiter = SourceCostBudgetLimiter::new();

        Ok(Self {
            policy,
            decoder,
            signature_verifier,
            deduplicator,
            rate_limiter,
            cost_limiter,
            stats: QuicProcessorStats::new(),
            current_tick: 0,
        })
    }

    pub fn stats(&self) -> &QuicProcessorStats {
        &self.stats
    }

    pub fn process_packet(&mut self, packet: &QuicPacket) -> Option<PreparedTransaction> {
        self.stats.record_received();

        let packet_id = compute_packet_id(packet);

        let frame = InboundFrame {
            packet_id,
            payload_bytes: packet.len(),
            source: IngressSource::Quic,
        };

        let prepared = match self.decoder.decode(&frame) {
            DecodeOutcome::Accepted(tx) => tx,
            DecodeOutcome::Dropped(reason) => {
                use crate::ingress::DropReason;
                match reason {
                    DropReason::EmptyPayload => self.stats.record_dropped_empty(),
                    DropReason::OversizedPayload => self.stats.record_dropped_oversized(),
                    DropReason::SourceNotAllowed => self.stats.record_dropped_source_not_allowed(),
                    DropReason::SourceRateLimited => self.stats.record_dropped_rate_limited(),
                    DropReason::SourceCostBudgetExceeded => self.stats.record_dropped_cost_budget(),
                    DropReason::DownstreamBackpressure => {}
                }
                return None;
            }
        };

        // Verify Ed25519 signatures for transaction-sized packets
        // Skip verification for packets that are too small to be transactions
        use paradencer_constants::transaction as tx_constants;
        if packet.len() >= tx_constants::MIN_TRANSACTION_SIZE {
            match self.signature_verifier.verify(&packet.data) {
                Ok(VerificationResult::Success) => {
                    // Signatures valid, continue processing
                }
                Ok(VerificationResult::Failed) => {
                    self.stats.record_dropped_invalid_signature();
                    return None;
                }
                Err(_) => {
                    // Parsing or verification error
                    self.stats.record_dropped_invalid_signature();
                    return None;
                }
            }
        }

        if !self.rate_limiter.try_accept(
            IngressSource::Quic,
            self.current_tick,
            self.policy.quic_min_gap_ticks,
            self.policy.quic_burst_capacity,
            self.policy.quic_burst_refill_ticks,
        ) {
            self.stats.record_dropped_rate_limited();
            return None;
        }

        if !self.cost_limiter.try_consume(
            IngressSource::Quic,
            self.current_tick,
            prepared.estimated_cost_units,
            self.policy.quic_cost_budget_per_window,
            self.policy.quic_cost_budget_window_ticks,
        ) {
            self.stats.record_dropped_cost_budget();
            return None;
        }

        match self.deduplicator.register(prepared.dedup_fingerprint) {
            DedupDecision::Accepted => {
                self.stats.record_accepted();
                Some(prepared)
            }
            DedupDecision::Duplicate => {
                self.stats.record_dropped_duplicate();
                None
            }
        }
    }

    pub fn process_batch(&mut self, batch: &QuicPacketBatch) -> Vec<PreparedTransaction> {
        let mut results = Vec::with_capacity(batch.len().min(PROCESSOR_BATCH_SIZE));

        for packet in &batch.packets {
            if let Some(prepared) = self.process_packet(packet) {
                results.push(prepared);
            }
        }

        results
    }

    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::SocketAddr;

    fn test_policy() -> IngressPolicy {
        IngressPolicy {
            ingress_mode: crate::ingress::IngressMode::Synthetic,
            udp_bind_address: None,
            udp_quic_source_port: None,
            udp_gossip_source_port: None,
            udp_bundle_source_port: None,
            udp_rpc_source_port: None,
            udp_max_packets_per_tick: 64,
            max_payload_bytes: 1024,
            allow_quic_source: true,
            allow_gossip_source: false,
            allow_bundle_source: false,
            allow_rpc_source: false,
            dedup_window_capacity: 1000,
            quic_min_gap_ticks: 0,
            gossip_min_gap_ticks: 0,
            bundle_min_gap_ticks: 0,
            rpc_min_gap_ticks: 0,
            quic_burst_capacity: 1000,
            gossip_burst_capacity: 0,
            bundle_burst_capacity: 0,
            rpc_burst_capacity: 0,
            quic_burst_refill_ticks: 1,
            gossip_burst_refill_ticks: 1,
            bundle_burst_refill_ticks: 1,
            rpc_burst_refill_ticks: 1,
            quic_cost_budget_per_window: 100_000,
            gossip_cost_budget_per_window: 0,
            bundle_cost_budget_per_window: 0,
            rpc_cost_budget_per_window: 0,
            quic_cost_budget_window_ticks: 10,
            gossip_cost_budget_window_ticks: 1,
            bundle_cost_budget_window_ticks: 1,
            rpc_cost_budget_window_ticks: 1,
            egress_retry_buffer_capacity: 1024,
            egress_retry_max_wait_ticks: 6,
            synthetic_batch_size_per_tick: 1,
            synthetic_idle_ticks_between_batches: 0,
            synthetic_payload_bytes: 1200,
            synthetic_source_weight_quic: 1,
            synthetic_source_weight_gossip: 0,
            synthetic_source_weight_bundle: 0,
            synthetic_source_weight_rpc: 0,
        }
    }

    #[test]
    fn processor_accepts_valid_packet() {
        let mut processor = QuicProcessor::new(test_policy()).unwrap();
        let packet = QuicPacket::new(
            Bytes::from(vec![1, 2, 3, 4]),
            "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            1,
        );

        let result = processor.process_packet(&packet);
        assert!(result.is_some());

        let stats = processor.stats().snapshot();
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.packets_accepted, 1);
    }

    #[test]
    fn processor_rejects_empty_packet() {
        let mut processor = QuicProcessor::new(test_policy()).unwrap();
        let packet = QuicPacket::new(
            Bytes::new(),
            "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            1,
        );

        let result = processor.process_packet(&packet);
        assert!(result.is_none());

        let stats = processor.stats().snapshot();
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.packets_dropped_empty, 1);
    }

    #[test]
    fn processor_rejects_oversized_packet() {
        let mut processor = QuicProcessor::new(test_policy()).unwrap();
        let packet = QuicPacket::new(
            Bytes::from(vec![0; 2048]),
            "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            1,
        );

        let result = processor.process_packet(&packet);
        assert!(result.is_none());

        let stats = processor.stats().snapshot();
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.packets_dropped_oversized, 1);
    }

    #[test]
    fn processor_detects_duplicates() {
        let mut processor = QuicProcessor::new(test_policy()).unwrap();
        let packet = QuicPacket::new(
            Bytes::from(vec![1, 2, 3, 4]),
            "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            1,
        );

        let first = processor.process_packet(&packet);
        assert!(first.is_some());

        let second = processor.process_packet(&packet);
        assert!(second.is_none());

        let stats = processor.stats().snapshot();
        assert_eq!(stats.packets_received, 2);
        assert_eq!(stats.packets_accepted, 1);
        assert_eq!(stats.packets_dropped_duplicate, 1);
    }

    #[test]
    fn processor_handles_batch() {
        let mut processor = QuicProcessor::new(test_policy()).unwrap();
        let mut batch = QuicPacketBatch::new(1);

        for i in 0..10 {
            batch.push(QuicPacket::new(
                Bytes::from(vec![i, i + 1, i + 2]),
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
                i as u64,
            ));
        }

        let results = processor.process_batch(&batch);
        assert_eq!(results.len(), 10);

        let stats = processor.stats().snapshot();
        assert_eq!(stats.packets_received, 10);
        assert_eq!(stats.packets_accepted, 10);
    }
}
