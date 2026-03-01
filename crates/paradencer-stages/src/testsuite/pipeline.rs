use super::*;
use paradencer_mesh::{DualReceiver, DualSender};

#[test]
fn three_stage_pipeline_moves_messages_end_to_end() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(16);

    let packet_stats = packet_outbound.stats();
    let transaction_stats = transaction_outbound.stats();

    let mut edge_intake = EdgeIntake::new(DualSender::Channel(packet_outbound));
    let mut tx_filter = TxFilter::new(
        DualReceiver::Channel(packet_inbound),
        DualSender::Channel(transaction_outbound),
    );
    let mut block_assembler = BlockAssembler::new(DualReceiver::Channel(transaction_inbound));

    let context = ServiceContext::new(ShutdownSwitch::new());

    for _ in 0..200 {
        edge_intake.tick(&context).unwrap();
        tx_filter.tick(&context).unwrap();
        block_assembler.tick(&context).unwrap();
    }

    let packet_snapshot = packet_stats.snapshot(0, None);
    let transaction_snapshot = transaction_stats.snapshot(0, None);

    assert!(packet_snapshot.enqueued_messages > 0);
    assert!(packet_snapshot.dequeued_messages > 0);
    assert!(transaction_snapshot.enqueued_messages > 0);
    assert!(transaction_snapshot.dequeued_messages > 0);
}

#[test]
fn intake_stage_records_backpressure_when_downstream_is_stalled() {
    let (packet_outbound, _packet_inbound) = bounded_link::<InboundPacket>(1);
    let packet_stats = packet_outbound.stats();

    let mut edge_intake = EdgeIntake::new(DualSender::Channel(packet_outbound));
    let context = ServiceContext::new(ShutdownSwitch::new());

    edge_intake.tick(&context).unwrap();
    edge_intake.tick(&context).unwrap();

    let snapshot = packet_stats.snapshot(0, None);
    assert!(snapshot.blocked_sends > 0);
}

#[test]
fn edge_intake_applies_weighted_source_schedule() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let policy = IngressPolicy {
        synthetic_source_weight_quic: 1,
        synthetic_source_weight_gossip: 1,
        synthetic_source_weight_bundle: 0,
        synthetic_source_weight_rpc: 0,
        ..IngressPolicy::default()
    };
    let mut edge_intake = EdgeIntake::with_policy(DualSender::Channel(packet_outbound), policy);
    let context = ServiceContext::new(ShutdownSwitch::new());

    for _ in 0..4 {
        edge_intake.tick(&context).unwrap();
    }

    let first = packet_inbound.try_recv().unwrap().unwrap();
    let second = packet_inbound.try_recv().unwrap().unwrap();
    let third = packet_inbound.try_recv().unwrap().unwrap();
    let fourth = packet_inbound.try_recv().unwrap().unwrap();

    assert_eq!(first.source, IngressSource::Quic);
    assert_eq!(second.source, IngressSource::Gossip);
    assert_eq!(third.source, IngressSource::Quic);
    assert_eq!(fourth.source, IngressSource::Gossip);
}

#[test]
fn edge_intake_respects_idle_ticks_between_batches() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let policy = IngressPolicy {
        synthetic_batch_size_per_tick: 2,
        synthetic_idle_ticks_between_batches: 1,
        ..IngressPolicy::default()
    };
    let mut edge_intake = EdgeIntake::with_policy(DualSender::Channel(packet_outbound), policy);
    let context = ServiceContext::new(ShutdownSwitch::new());

    for _ in 0..5 {
        edge_intake.tick(&context).unwrap();
    }

    let first = packet_inbound.try_recv().unwrap();
    let second = packet_inbound.try_recv().unwrap();
    let third = packet_inbound.try_recv().unwrap();
    let fourth = packet_inbound.try_recv().unwrap();
    let fifth = packet_inbound.try_recv().unwrap();

    assert!(first.is_some());
    assert!(second.is_some());
    assert!(third.is_some());
    assert!(fourth.is_some());
    assert!(fifth.is_none());
}

#[test]
fn edge_intake_udp_mode_receives_datagrams_and_classifies_source_port() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let policy = IngressPolicy {
        ingress_mode: IngressMode::Udp,
        udp_bind_address: Some("127.0.0.1:0".parse().unwrap()),
        udp_gossip_source_port: Some(19_001),
        udp_max_packets_per_tick: 4,
        ..IngressPolicy::default()
    };
    let mut edge_intake = EdgeIntake::with_policy(DualSender::Channel(packet_outbound), policy);
    let context = ServiceContext::new(ShutdownSwitch::new());
    match edge_intake.on_start(&context) {
        Ok(()) => {}
        Err(error) if error.to_string().contains("Operation not permitted") => {
            eprintln!("[tests] skipping UDP intake assertion: socket bind is not permitted");
            return;
        }
        Err(error) => panic!("failed to start udp intake stage: {error}"),
    }

    let send_socket = match UdpSocket::bind("127.0.0.1:19001") {
        Ok(socket) => socket,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("[tests] skipping UDP intake assertion: sender bind is not permitted");
            return;
        }
        Err(error) => panic!("failed to bind UDP sender socket: {error}"),
    };
    let target_addr = edge_intake.udp_local_addr().unwrap();
    if let Err(error) = send_socket.send_to(&[1_u8, 2, 3, 4], target_addr) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("[tests] skipping UDP intake assertion: UDP send is not permitted");
            return;
        }
        panic!("failed to send UDP datagram to intake socket: {error}");
    }

    let mut received_packet = None;
    for _ in 0..8 {
        edge_intake.tick(&context).unwrap();
        if let Some(packet) = packet_inbound.try_recv().unwrap() {
            received_packet = Some(packet);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let packet = received_packet.expect("expected UDP packet to be received after intake ticks");
    assert_eq!(packet.payload_bytes, 4);
    assert_eq!(packet.source, IngressSource::Gossip);
}

#[test]
fn edge_intake_routes_gossip_packets_to_shred_link_when_configured() {
    let (packet_outbound, packet_inbound) = bounded_link::<InboundPacket>(16);
    let (shred_outbound, shred_inbound) = bounded_link::<InboundPacket>(16);
    let policy = IngressPolicy {
        synthetic_source_weight_quic: 0,
        synthetic_source_weight_gossip: 1,
        synthetic_source_weight_bundle: 0,
        synthetic_source_weight_rpc: 0,
        ..IngressPolicy::default()
    };
    let mut edge_intake = EdgeIntake::with_policy_and_shred(
        DualSender::Channel(packet_outbound),
        DualSender::Channel(shred_outbound),
        policy,
    );
    let context = ServiceContext::new(ShutdownSwitch::new());

    edge_intake.tick(&context).unwrap();

    assert!(packet_inbound.try_recv().unwrap().is_none());
    let shred_packet = shred_inbound.try_recv().unwrap().unwrap();
    assert_eq!(shred_packet.source, IngressSource::Gossip);
}
