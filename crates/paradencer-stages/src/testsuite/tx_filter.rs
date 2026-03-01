use super::*;
use paradencer_mesh::{DualReceiver, DualSender};

#[test]
fn tx_filter_drops_duplicate_transactions() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let mut tx_filter = TxFilter::new(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 100,
            payload_bytes: 1200,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 100,
            payload_bytes: 1200,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    let second = transaction_inbound.try_recv().unwrap();

    assert!(first.is_some());
    assert!(second.is_none());
}

#[test]
fn tx_filter_applies_source_policy_rules() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let policy = IngressPolicy {
        allow_bundle_source: false,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 101,
            payload_bytes: 900,
            source: IngressSource::Bundle,
            data: vec![],
        })
        .unwrap();

    tx_filter.tick(&context).unwrap();
    let transaction = transaction_inbound.try_recv().unwrap();
    assert!(transaction.is_none());
}

#[test]
fn tx_filter_applies_per_source_min_gap_rate_limit() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let policy = IngressPolicy {
        quic_min_gap_ticks: 2,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 201,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 202,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 203,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    let second = transaction_inbound.try_recv().unwrap();
    let third = transaction_inbound.try_recv().unwrap();

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_none());
}

#[test]
fn tx_filter_applies_per_source_burst_rate_limit_and_refill() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(16);
    let policy = IngressPolicy {
        quic_burst_capacity: 2,
        quic_burst_refill_ticks: 3,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    for packet_id in 301..=303_u64 {
        packet_outbound
            .try_send(InboundPacket {
                packet_id,
                payload_bytes: 900,
                source: IngressSource::Quic,
                data: vec![],
            })
            .unwrap();
        tx_filter.tick(&context).unwrap();
    }

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 304,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    let second = transaction_inbound.try_recv().unwrap();
    let third = transaction_inbound.try_recv().unwrap();
    let fourth = transaction_inbound.try_recv().unwrap();
    let fifth = transaction_inbound.try_recv().unwrap();

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
    assert!(fourth.is_none());
    assert!(fifth.is_none());
}

#[test]
fn tx_filter_applies_per_source_cost_budget_window_limit() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(16);
    let policy = IngressPolicy {
        quic_cost_budget_per_window: 7_200,
        quic_cost_budget_window_ticks: 4,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    for packet_id in 401..=403_u64 {
        packet_outbound
            .try_send(InboundPacket {
                packet_id,
                payload_bytes: 900,
                source: IngressSource::Quic,
                data: vec![],
            })
            .unwrap();
        tx_filter.tick(&context).unwrap();
    }

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 404,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    let second = transaction_inbound.try_recv().unwrap();
    let third = transaction_inbound.try_recv().unwrap();
    let fourth = transaction_inbound.try_recv().unwrap();
    let fifth = transaction_inbound.try_recv().unwrap();

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
    assert!(fourth.is_none());
    assert!(fifth.is_none());
}

#[test]
fn tx_filter_buffers_and_retries_when_downstream_recovers_from_backpressure() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(1);
    let policy = IngressPolicy {
        egress_retry_buffer_capacity: 8,
        egress_retry_max_wait_ticks: 6,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 501,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 502,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    assert!(first.is_some());

    tx_filter.tick(&context).unwrap();
    let second = transaction_inbound.try_recv().unwrap();
    assert!(second.is_some());
}

#[test]
fn tx_filter_drops_buffered_tx_after_backpressure_wait_budget_is_exceeded() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(1);
    let policy = IngressPolicy {
        egress_retry_buffer_capacity: 8,
        egress_retry_max_wait_ticks: 2,
        ..IngressPolicy::default()
    };
    let mut tx_filter = TxFilter::with_policy(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 601,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 602,
            payload_bytes: 900,
            source: IngressSource::Quic,
            data: vec![],
        })
        .unwrap();

    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();
    tx_filter.tick(&context).unwrap();

    let first = transaction_inbound.try_recv().unwrap();
    assert!(first.is_some());

    tx_filter.tick(&context).unwrap();
    let second = transaction_inbound.try_recv().unwrap();
    assert!(second.is_none());
}
