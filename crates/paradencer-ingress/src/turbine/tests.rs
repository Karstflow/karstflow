use super::*;
use crate::gossip::{ContactInfo, NodeId, ValidatorInfo};
use crate::quic::{QuicConfig, QuicEndpoint, QuicEndpointStats};
use paradencer_types::shred::{
    DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

fn create_node_id(byte: u8) -> NodeId {
    NodeId::new([byte; 32])
}

fn create_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

fn create_validator(node_id: NodeId, stake: u64, port: u16) -> ValidatorInfo {
    let contact = create_contact_info(node_id, port);
    ValidatorInfo::new(contact, stake)
}

fn create_test_shred(slot: u64, index: u32) -> Shred {
    let common_header = ShredCommonHeader {
        signature: [0; SIGNATURE_SIZE],
        variant: 0b0101,
        slot,
        index,
        version: 1,
        fec_set_index: 0,
    };

    let data_header = DataShredHeader {
        parent_offset: 1,
        flags: 0,
        size: 512,
    };

    Shred::new(
        common_header,
        ShredVariant::LegacyData(data_header),
        vec![0; 512],
    )
}

#[test]
fn test_turbine_config_validation() {
    let config = TurbineConfig::default();
    assert!(config.validate().is_ok());

    let invalid_config = TurbineConfig {
        fanout: 0,
        ..Default::default()
    };
    assert!(invalid_config.validate().is_err());
}

#[test]
fn test_turbine_config_max_reachable_nodes() {
    let config = TurbineConfig::with_fanout(200);
    // 1 root + 200 layer1 + (200 * 200) layer2
    assert_eq!(config.max_reachable_nodes(), 40201);

    let small_config = TurbineConfig::with_fanout(10);
    // 1 root + 10 layer1 + (10 * 10) layer2
    assert_eq!(small_config.max_reachable_nodes(), 111);
}

#[test]
fn test_turbine_tree_basic() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);
    let config = TurbineConfig::default();

    let tree = TurbineTree::new(root_id, root_contact, config, 100);

    assert_eq!(tree.root(), root_id);
    assert_eq!(tree.slot(), 100);
    assert_eq!(tree.total_nodes(), 1);
}

#[test]
fn test_turbine_tree_builder_layer1() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);

    let validators: Vec<_> = (1..=20)
        .map(|i| create_validator(create_node_id(i), 1000 * i as u64, 8000 + i as u16))
        .collect();

    let config = TurbineConfig::with_fanout(10);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    assert_eq!(tree.layer1_nodes().len(), 10);
    assert_eq!(tree.total_nodes(), 21); // root + 10 layer1 + 10 layer2
}

#[test]
fn test_turbine_tree_builder_layer2() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);

    let validators: Vec<_> = (1..=100)
        .map(|i| create_validator(create_node_id(i as u8), 1000, 8000 + i as u16))
        .collect();

    let config = TurbineConfig::with_fanout(5);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    assert_eq!(tree.layer1_nodes().len(), 5);
    assert!(!tree.layer2_nodes().is_empty());

    // Verify parent-child relationships
    for layer1_id in tree.layer1_nodes() {
        let parent = tree.get_parent(layer1_id);
        assert_eq!(parent, Some(root_id));

        let children = tree.get_children(layer1_id);
        for child_id in children {
            let child_parent = tree.get_parent(&child_id);
            assert_eq!(child_parent, Some(*layer1_id));
        }
    }
}

#[test]
fn test_turbine_tree_stake_weighted() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);

    // Create validators with varying stakes
    let validators = vec![
        create_validator(create_node_id(1), 100000, 8001), // Very high stake
        create_validator(create_node_id(2), 50000, 8002),
        create_validator(create_node_id(3), 1000, 8003), // Low stake
        create_validator(create_node_id(4), 75000, 8004),
        create_validator(create_node_id(5), 25000, 8005),
    ];

    let config = TurbineConfig::with_fanout(3).with_stake_weighting(true);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    assert_eq!(tree.layer1_nodes().len(), 3);
}

#[test]
fn test_turbine_tree_stale_check() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);
    let config = TurbineConfig::default();

    let tree = TurbineTree::new(root_id, root_contact, config.clone(), 100);

    assert!(!tree.is_stale(100));
    assert!(!tree.is_stale(200));
    assert!(tree.is_stale(100 + config.tree_rebuild_interval_slots));
    assert!(tree.is_stale(1000000));
}

#[test]
fn test_broadcast_stats() {
    let stats = Arc::new(TurbineStats::new());
    let broadcast_stats = BroadcastStats::new(Arc::clone(&stats));

    broadcast_stats.record_success(10, 12280);
    assert_eq!(stats.broadcast_success_count(), 1);
    assert_eq!(stats.total_shreds_broadcast(), 10);
    assert_eq!(stats.total_bytes_transmitted(), 12280);

    broadcast_stats.record_failure();
    assert_eq!(stats.broadcast_failure_count(), 1);
}

#[test]
fn test_retransmit_stats() {
    let stats = Arc::new(TurbineStats::new());
    let retransmit_stats = RetransmitStats::new(Arc::clone(&stats));

    retransmit_stats.record_retransmit(5, 6140);
    assert_eq!(stats.total_shreds_retransmitted(), 5);
    assert_eq!(stats.total_bytes_transmitted(), 6140);

    retransmit_stats.record_timeout();
    assert_eq!(
        stats
            .retransmit_timeouts
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn test_propagation_metrics() {
    let mut metrics = PropagationMetrics::new(100, 20);

    assert_eq!(metrics.slot, 100);
    assert_eq!(metrics.total_shreds, 20);
    assert!(!metrics.is_layer1_complete());
    assert!(!metrics.is_fully_complete());

    // Simulate layer1 confirmations
    for _ in 0..20 {
        metrics.record_layer1_confirmation();
    }

    assert!(metrics.is_layer1_complete());
    assert!(metrics.layer1_completion_time.is_some());
    assert_eq!(metrics.layer1_completion_percentage(), 100.0);

    // Simulate full confirmations
    for _ in 0..20 {
        metrics.record_full_confirmation();
    }

    assert!(metrics.is_fully_complete());
    assert!(metrics.full_completion_time.is_some());
    assert_eq!(metrics.full_completion_percentage(), 100.0);
}

#[test]
fn test_neighborhood_basic() {
    use std::time::Duration;

    let mut neighborhood = Neighborhood::new(5, Duration::from_secs(60));

    for i in 0..10 {
        let node_id = create_node_id(i);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)), 8000);
        let mut proximity = NetworkProximity::new(node_id, addr);
        proximity.update_rtt((i as f64 + 1.0) * 10.0);
        neighborhood.upsert_peer(proximity);
    }

    // Should only keep 5 closest peers
    assert_eq!(neighborhood.size(), 5);

    let closest = neighborhood.get_closest(3);
    assert_eq!(closest.len(), 3);
}

#[test]
fn test_proximity_estimator() {
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8000);
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 8000);
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)), 8000);
    let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8000);

    let score12 = ProximityEstimator::estimate(&addr1, &addr2);
    let score13 = ProximityEstimator::estimate(&addr1, &addr3);
    let score14 = ProximityEstimator::estimate(&addr1, &addr4);

    // Same /24 subnet should be closer than same /16
    assert!(score12.score() < score13.score());
    // Same /16 subnet should be closer than different network
    assert!(score13.score() < score14.score());
}

#[test]
fn test_broadcast_shred_creation() {
    let shred = create_test_shred(100, 5);
    let broadcast_shred = BroadcastShred::new(shred, 1);

    assert_eq!(broadcast_shred.slot, 100);
    assert_eq!(broadcast_shred.index, 5);
    assert_eq!(broadcast_shred.target_layer, 1);
}

#[test]
fn test_retransmit_request() {
    let peers = vec![create_node_id(1), create_node_id(2)];
    let mut request = RetransmitRequest::new(100, 5, peers.clone());

    assert_eq!(request.slot, 100);
    assert_eq!(request.index, 5);
    assert_eq!(request.retry_count, 0);

    request.retry();
    assert_eq!(request.retry_count, 1);
}

#[tokio::test]
async fn test_broadcaster_integration() {
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let stats = BroadcastStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let broadcaster = ShredBroadcaster::new(endpoint, stats, runtime);

    // Create and set a tree
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);
    let validators: Vec<_> = (1..=10)
        .map(|i| create_validator(create_node_id(i), 1000, 8000 + i as u16))
        .collect();

    let tree_config = TurbineConfig::with_fanout(5);
    let builder = TurbineTreeBuilder::new(tree_config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    broadcaster.update_tree(tree.clone());
    assert!(broadcaster.get_tree().is_some());
}

#[tokio::test]
async fn test_retransmit_service_integration() {
    let node_id = create_node_id(0);
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let turbine_config = TurbineConfig::default();
    let stats = RetransmitStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let service = RetransmitService::new(node_id, endpoint, turbine_config, stats, runtime);

    // Create and set a tree
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);
    let validators: Vec<_> = (1..=10)
        .map(|i| create_validator(create_node_id(i), 1000, 8000 + i as u16))
        .collect();

    let tree_config = TurbineConfig::with_fanout(5);
    let builder = TurbineTreeBuilder::new(tree_config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    service.update_tree(tree);

    // Test shred caching
    let shred = Arc::new(create_test_shred(100, 5));
    service.shred_cache.write().insert((100, 5), shred.clone());

    let cached = service.get_cached_shred(100, 5);
    assert!(cached.is_some());
}

#[test]
fn test_broadcast_manager() {
    let manager = BroadcastManager::new();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let stats = BroadcastStats::new(Arc::new(TurbineStats::new()));

    let broadcaster1 = Arc::new(ShredBroadcaster::new(
        endpoint.clone(),
        stats.clone(),
        runtime.handle().clone(),
    ));
    let broadcaster2 = Arc::new(ShredBroadcaster::new(
        endpoint,
        stats,
        runtime.handle().clone(),
    ));

    manager.register_broadcaster(100, broadcaster1);
    manager.register_broadcaster(101, broadcaster2);

    assert_eq!(manager.active_slots().len(), 2);

    let cleared = manager.clear_old_broadcasters(101);
    assert_eq!(cleared, 1);
    assert_eq!(manager.active_slots().len(), 1);
}

#[test]
fn test_turbine_stats_comprehensive() {
    let stats = TurbineStats::new();

    // Test broadcast stats
    stats.record_broadcast(10, 12280);
    stats.record_broadcast(5, 6140);
    assert_eq!(stats.total_shreds_broadcast(), 15);
    assert_eq!(stats.total_bytes_transmitted(), 18420);

    // Test retransmit stats
    stats.record_retransmit(3, 3684);
    assert_eq!(stats.total_shreds_retransmitted(), 3);
    assert_eq!(stats.total_bytes_transmitted(), 22104);

    // Test receive stats
    stats.record_received(1228);
    assert_eq!(stats.total_shreds_received(), 1);

    // Test peer counts
    stats.update_peer_counts(200, 5000);
    assert_eq!(stats.layer1_peer_count(), 200);
    assert_eq!(stats.layer2_peer_count(), 5000);

    // Test reset
    stats.reset();
    assert_eq!(stats.total_shreds_broadcast(), 0);
    assert_eq!(stats.total_shreds_retransmitted(), 0);
}

#[test]
fn test_tree_get_layer() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);

    let validators: Vec<_> = (1..=30)
        .map(|i| create_validator(create_node_id(i), 1000, 8000 + i as u16))
        .collect();

    let config = TurbineConfig::with_fanout(5);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    let layer0 = tree.get_layer(0);
    assert_eq!(layer0.len(), 1);
    assert_eq!(layer0[0], root_id);

    let layer1 = tree.get_layer(1);
    assert_eq!(layer1.len(), 5);

    let layer2 = tree.get_layer(2);
    assert!(!layer2.is_empty());

    let layer3 = tree.get_layer(3);
    assert!(layer3.is_empty());
}

#[test]
fn test_turbine_node_methods() {
    let node_id = create_node_id(1);
    let contact = create_contact_info(node_id, 8000);
    let mut node = TurbineNode::new(node_id, contact, 1000, 1);

    assert!(!node.is_root());
    assert!(node.is_leaf());

    node.add_child(create_node_id(2));
    assert!(!node.is_leaf());

    node.set_parent(create_node_id(0));
    assert_eq!(node.parent, Some(create_node_id(0)));
}

#[test]
fn test_network_proximity_ewma() {
    let node_id = create_node_id(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8000);
    let mut proximity = NetworkProximity::new(node_id, addr);

    proximity.update_rtt(100.0);
    assert_eq!(proximity.avg_rtt_ms, Some(100.0));

    proximity.update_rtt(200.0);
    // EWMA: 100.0 * 0.8 + 200.0 * 0.2 = 120.0
    assert_eq!(proximity.avg_rtt_ms, Some(120.0));

    proximity.update_rtt(100.0);
    // EWMA: 120.0 * 0.8 + 100.0 * 0.2 = 116.0
    assert_eq!(proximity.avg_rtt_ms, Some(116.0));
}
