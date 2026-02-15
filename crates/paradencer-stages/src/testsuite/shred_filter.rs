use super::*;
use crate::ShredFilter;

#[test]
fn shred_filter_accepts_and_deduplicates_packets() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let shred_stats = std::sync::Arc::new(ShredFilterStats::default());
    let mut shred_filter = ShredFilter::with_policy_and_stats(
        packet_inbound,
        IngressPolicy::default(),
        shred_stats.clone(),
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 55,
            payload_bytes: 256,
            source: IngressSource::Gossip,
        })
        .unwrap();
    packet_outbound
        .try_send(InboundPacket {
            packet_id: 55,
            payload_bytes: 256,
            source: IngressSource::Gossip,
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
        packet_inbound,
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
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 2,
            payload_bytes: 128,
            source: IngressSource::Gossip,
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    packet_outbound
        .try_send(InboundPacket {
            packet_id: 3,
            payload_bytes: 16,
            source: IngressSource::Gossip,
        })
        .unwrap();
    shred_filter.tick(&context).unwrap();

    let snapshot = shred_stats.snapshot();
    assert_eq!(snapshot.dropped_empty_payload, 1);
    assert_eq!(snapshot.dropped_oversized_payload, 1);
    assert_eq!(snapshot.dropped_disallowed_source, 1);
}
