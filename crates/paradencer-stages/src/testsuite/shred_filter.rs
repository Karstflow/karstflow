use super::*;
use crate::ShredFilter;
use paradencer_mesh::{DualReceiver, DualSender};
use paradencer_types::shred::Shred;

/// Build a minimal valid legacy data shred byte vector for testing.
fn build_test_shred_bytes(slot: u64, index: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    // Signature (64 bytes)
    buf.extend_from_slice(&[0u8; 64]);
    // Variant: legacy data = 0xA5 (upper nibble 0xA0 = legacy data, lower nibble 0x05)
    buf.push(0xA5);
    // Slot
    buf.extend_from_slice(&slot.to_le_bytes());
    // Index
    buf.extend_from_slice(&index.to_le_bytes());
    // Version
    buf.extend_from_slice(&1u16.to_le_bytes());
    // FEC set index
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Data header: parent_offset, flags, size
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.push(0);
    buf.extend_from_slice(&64u16.to_le_bytes());
    // Payload
    buf.extend_from_slice(&vec![0xAB; 64]);
    buf
}

#[test]
fn shred_filter_accepts_and_deduplicates_packets() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_policy_and_stats(
        DualReceiver::Channel(packet_inbound),
        IngressPolicy::default(),
        shred_stats.clone(),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 55,
            payload_bytes: 256,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 55,
            payload_bytes: 256,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();

    shred_filter.tick(&context).unwrap();
    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.accepted_shreds, 1);
    assert_eq!(snapshot.duplicate_shreds, 1);
}

#[test]
fn shred_filter_tracks_drop_reasons() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_policy_and_stats(
        DualReceiver::Channel(packet_inbound),
        IngressPolicy {
            max_payload_bytes: 64,
            allow_gossip_source: false,
            ..IngressPolicy::default()
        },
        shred_stats.clone(),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 1,
            payload_bytes: 0,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 2,
            payload_bytes: 128,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 3,
            payload_bytes: 16,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.dropped_empty_payload, 1);
    assert_eq!(snapshot.dropped_oversized_payload, 1);
    assert_eq!(snapshot.dropped_disallowed_source, 1);
}

#[test]
fn shred_filter_forwards_parsed_shreds_on_output_channel() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (shred_outbound, shred_inbound) = bounded_link::<Shred>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_output(
        DualReceiver::Channel(packet_inbound),
        IngressPolicy::default(),
        shred_stats.clone(),
        DualSender::Channel(shred_outbound),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    let shred_bytes = build_test_shred_bytes(42, 0);
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 70,
            payload_bytes: shred_bytes.len(),
            source: IngressSource::Gossip,
            data: shred_bytes,
        })
        .unwrap();

    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.accepted_shreds, 1);

    let forwarded = shred_inbound.try_recv().unwrap();
    assert!(forwarded.is_some());
    let shred = forwarded.unwrap();
    assert_eq!(shred.slot(), 42);
    assert_eq!(shred.index(), 0);
    assert!(shred.is_data());
}

#[test]
fn shred_filter_does_not_forward_when_no_output_configured() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_policy_and_stats(
        DualReceiver::Channel(packet_inbound),
        IngressPolicy::default(),
        shred_stats.clone(),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    let shred_bytes = build_test_shred_bytes(10, 1);
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 80,
            payload_bytes: shred_bytes.len(),
            source: IngressSource::Gossip,
            data: shred_bytes,
        })
        .unwrap();

    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.accepted_shreds, 1);
}

#[test]
fn shred_filter_skips_forwarding_for_empty_data_packets() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (shred_outbound, shred_inbound) = bounded_link::<Shred>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_output(
        DualReceiver::Channel(packet_inbound),
        IngressPolicy::default(),
        shred_stats.clone(),
        DualSender::Channel(shred_outbound),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Synthetic packet with metadata but no raw bytes
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 90,
            payload_bytes: 256,
            source: IngressSource::Gossip,
            data: vec![],
        })
        .unwrap();

    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.accepted_shreds, 1);

    // No shred forwarded because data was empty
    let forwarded = shred_inbound.try_recv().unwrap();
    assert!(forwarded.is_none());
}
