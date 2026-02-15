use super::{
    DecodeOutcome, DedupDecision, DropReason, InboundFrame, IngressMode, IngressPolicy,
    IngressSource, PacketDecoder, SignatureDeduplicator, SourceCostBudgetLimiter,
    SourceRateLimiter,
};

#[test]
fn decoder_builds_transaction_with_cost_and_fingerprint() {
    let decoder = PacketDecoder::new(IngressPolicy::default()).unwrap();
    let frame = InboundFrame {
        packet_id: 42,
        payload_bytes: 1200,
        source: IngressSource::Quic,
    };

    let outcome = decoder.decode(&frame);
    let DecodeOutcome::Accepted(transaction) = outcome else {
        panic!("expected accepted packet");
    };
    assert_eq!(transaction.transaction_id, 42);
    assert_eq!(transaction.estimated_cost_units, 4800);
    assert!(transaction.dedup_fingerprint > 0);
}

#[test]
fn decoder_drops_empty_packet() {
    let decoder = PacketDecoder::new(IngressPolicy::default()).unwrap();
    let frame = InboundFrame {
        packet_id: 7,
        payload_bytes: 0,
        source: IngressSource::Quic,
    };

    assert_eq!(
        decoder.decode(&frame),
        DecodeOutcome::Dropped(DropReason::EmptyPayload)
    );
}

#[test]
fn decoder_drops_oversized_packet() {
    let decoder = PacketDecoder::new(IngressPolicy::default()).unwrap();
    let frame = InboundFrame {
        packet_id: 8,
        payload_bytes: 2048,
        source: IngressSource::Quic,
    };

    assert_eq!(
        decoder.decode(&frame),
        DecodeOutcome::Dropped(DropReason::OversizedPayload)
    );
}

#[test]
fn decoder_drops_packet_from_disallowed_source() {
    let policy = IngressPolicy {
        allow_bundle_source: false,
        ..IngressPolicy::default()
    };
    let decoder = PacketDecoder::new(policy).unwrap();
    let frame = InboundFrame {
        packet_id: 9,
        payload_bytes: 800,
        source: IngressSource::Bundle,
    };

    assert_eq!(
        decoder.decode(&frame),
        DecodeOutcome::Dropped(DropReason::SourceNotAllowed)
    );
}

#[test]
fn deduplicator_rejects_duplicate_fingerprints_within_window() {
    let mut deduplicator = SignatureDeduplicator::new(8);
    assert_eq!(deduplicator.register(11), DedupDecision::Accepted);
    assert_eq!(deduplicator.register(11), DedupDecision::Duplicate);
}

#[test]
fn deduplicator_forgets_old_fingerprints_after_window_rolls() {
    let mut deduplicator = SignatureDeduplicator::new(2);
    assert_eq!(deduplicator.register(1), DedupDecision::Accepted);
    assert_eq!(deduplicator.register(2), DedupDecision::Accepted);
    assert_eq!(deduplicator.register(3), DedupDecision::Accepted);
    assert_eq!(deduplicator.register(1), DedupDecision::Accepted);
}

#[test]
fn source_rate_limiter_rejects_packets_inside_min_gap_window() {
    let mut limiter = SourceRateLimiter::new();
    assert!(limiter.try_accept(IngressSource::Quic, 10, 3, 0, 1));
    assert!(!limiter.try_accept(IngressSource::Quic, 11, 3, 0, 1));
    assert!(limiter.try_accept(IngressSource::Quic, 13, 3, 0, 1));
}

#[test]
fn source_rate_limiter_applies_burst_capacity_and_refill() {
    let mut limiter = SourceRateLimiter::new();
    assert!(limiter.try_accept(IngressSource::Quic, 0, 0, 2, 3));
    assert!(limiter.try_accept(IngressSource::Quic, 1, 0, 2, 3));
    assert!(!limiter.try_accept(IngressSource::Quic, 2, 0, 2, 3));
    assert!(limiter.try_accept(IngressSource::Quic, 3, 0, 2, 3));
}

#[test]
fn source_cost_budget_limiter_rejects_when_budget_is_exceeded() {
    let mut limiter = SourceCostBudgetLimiter::new();
    assert!(limiter.try_consume(IngressSource::Quic, 0, 3000, 7000, 4));
    assert!(limiter.try_consume(IngressSource::Quic, 1, 3000, 7000, 4));
    assert!(!limiter.try_consume(IngressSource::Quic, 2, 2000, 7000, 4));
    assert!(limiter.try_consume(IngressSource::Quic, 4, 2000, 7000, 4));
}

#[test]
fn source_cost_budget_limiter_rejects_on_spent_cost_overflow() {
    let mut limiter = SourceCostBudgetLimiter::new();
    assert!(limiter.try_consume(IngressSource::Quic, 0, u64::MAX - 1, u64::MAX, 8));
    assert!(!limiter.try_consume(IngressSource::Quic, 1, 10, u64::MAX, 8));
}

#[test]
fn synthetic_source_selection_respects_weighted_distribution_order() {
    let policy = IngressPolicy {
        synthetic_source_weight_quic: 2,
        synthetic_source_weight_gossip: 1,
        synthetic_source_weight_bundle: 1,
        synthetic_source_weight_rpc: 0,
        ..IngressPolicy::default()
    };
    assert_eq!(policy.synthetic_source_for_cursor(0), IngressSource::Quic);
    assert_eq!(policy.synthetic_source_for_cursor(1), IngressSource::Quic);
    assert_eq!(policy.synthetic_source_for_cursor(2), IngressSource::Gossip);
    assert_eq!(policy.synthetic_source_for_cursor(3), IngressSource::Bundle);
    assert_eq!(policy.synthetic_source_for_cursor(4), IngressSource::Quic);
}

#[test]
fn udp_mode_rejects_non_positive_packet_budget() {
    let policy = IngressPolicy {
        ingress_mode: IngressMode::Udp,
        udp_bind_address: Some("127.0.0.1:9001".parse().unwrap()),
        udp_max_packets_per_tick: 0,
        ..IngressPolicy::default()
    };
    assert!(policy.validate().is_err());
}
