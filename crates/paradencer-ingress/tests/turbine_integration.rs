/// Integration tests for Turbine block propagation protocol
///
/// These tests verify the end-to-end functionality of the Turbine protocol,
/// including tree construction, broadcast, and retransmit operations.
use paradencer_ingress::{
    BroadcastManager, BroadcastStats, ContactInfo, Neighborhood, NetworkProximity, NodeId,
    PropagationMetrics, ProximityEstimator, QuicConfig, QuicEndpoint, QuicEndpointStats,
    RetransmitService, RetransmitStats, ShredBroadcaster, TurbineConfig, TurbineStats, TurbineTree,
    TurbineTreeBuilder, ValidatorInfo,
};
use paradencer_types::shred::{
    DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn create_node_id(byte: u8) -> NodeId {
    NodeId::new([byte; 32])
}

fn create_contact_info(node_id: NodeId, a: u8, b: u8, c: u8, d: u8, port: u16) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

fn create_validator_with_addr(
    node_id: NodeId,
    stake: u64,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    port: u16,
) -> ValidatorInfo {
    let contact = create_contact_info(node_id, a, b, c, d, port);
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
fn test_turbine_tree_construction_small_network() {
    // Test with a small network (10 validators)
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let validators: Vec<_> = (1..=10)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::with_fanout(5);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    assert_eq!(tree.root(), root_id);
    assert_eq!(tree.layer1_nodes().len(), 5);
    assert!(tree.layer2_nodes().len() <= 5);

    // Verify tree structure
    for layer1_id in tree.layer1_nodes() {
        assert_eq!(tree.get_parent(layer1_id), Some(root_id));
    }
}

#[test]
fn test_turbine_tree_construction_large_network() {
    // Test with a large network (500 validators)
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 10, 0, 0, 1, 8000);

    let mut validators = Vec::new();

    // Create diverse stake distribution
    for i in 1..=500 {
        let stake = match i {
            1..=10 => 100_000_000,  // Large validators
            11..=50 => 50_000_000,  // Medium-large validators
            51..=200 => 10_000_000, // Medium validators
            _ => 1_000_000,         // Small validators
        };

        let node_id = create_node_id((i % 256) as u8);
        let a = ((i / 256) % 256) as u8;
        let b = 10 + ((i / 64) % 4) as u8;
        let c = ((i / 16) % 16) as u8;
        let d = (i % 16) as u8;

        validators.push(create_validator_with_addr(
            node_id,
            stake,
            a,
            b,
            c,
            d,
            8000 + (i % 1000) as u16,
        ));
    }

    let config = TurbineConfig::with_fanout(200);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 1000);

    assert_eq!(tree.layer1_nodes().len(), 200);
    assert!(!tree.layer2_nodes().is_empty());

    // Verify all layer1 nodes have root as parent
    for layer1_id in tree.layer1_nodes() {
        assert_eq!(tree.get_parent(layer1_id), Some(root_id));
    }

    // Verify all layer2 nodes have layer1 parents
    for layer2_id in tree.layer2_nodes() {
        let parent = tree.get_parent(layer2_id);
        assert!(parent.is_some());
        assert!(tree.layer1_nodes().contains(&parent.unwrap()));
    }
}

#[test]
fn test_turbine_tree_stake_weighting_distribution() {
    // Test that high-stake validators are more likely to be in layer1
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let mut validators = Vec::new();

    // 5 very high stake validators
    for i in 1..=5 {
        validators.push(create_validator_with_addr(
            create_node_id(i),
            1_000_000_000,
            127,
            0,
            0,
            1,
            8000 + i as u16,
        ));
    }

    // 95 low stake validators
    for i in 6..=100 {
        validators.push(create_validator_with_addr(
            create_node_id(i),
            1_000_000,
            127,
            0,
            0,
            1,
            8000 + i as u16,
        ));
    }

    let config = TurbineConfig::with_fanout(10).with_stake_weighting(true);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    // Count how many high-stake validators are in layer1
    let high_stake_in_layer1 = tree
        .layer1_nodes()
        .iter()
        .filter(|id| {
            if let Some(node) = tree.get_node(id) {
                node.stake >= 1_000_000_000
            } else {
                false
            }
        })
        .count();

    // With stake weighting, we should see most high-stake validators in layer1
    // Due to randomness, we expect at least 3 out of 5
    assert!(
        high_stake_in_layer1 >= 3,
        "Expected at least 3 high-stake validators in layer1, got {}",
        high_stake_in_layer1
    );
}

#[test]
fn test_turbine_tree_network_proximity() {
    // Test network proximity optimization
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 192, 168, 1, 1, 8000);

    let mut validators = Vec::new();

    // Close validators (same /24 subnet)
    for i in 1..=10 {
        validators.push(create_validator_with_addr(
            create_node_id(i),
            1_000_000,
            192,
            168,
            1,
            i,
            8000 + i as u16,
        ));
    }

    // Medium validators (same /16 subnet)
    for i in 11..=20 {
        validators.push(create_validator_with_addr(
            create_node_id(i),
            1_000_000,
            192,
            168,
            2,
            i - 10,
            8000 + i as u16,
        ));
    }

    // Far validators (different network)
    for i in 21..=30 {
        validators.push(create_validator_with_addr(
            create_node_id(i),
            1_000_000,
            10,
            0,
            0,
            i - 20,
            8000 + i as u16,
        ));
    }

    let config = TurbineConfig::with_fanout(10)
        .with_stake_weighting(true)
        .with_neighborhood_optimization(true);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    assert_eq!(tree.layer1_nodes().len(), 10);
}

#[test]
fn test_neighborhood_proximity_tracking() {
    let mut neighborhood = Neighborhood::new(10, Duration::from_secs(60));

    // Add peers with different RTTs
    for i in 0..20 {
        let node_id = create_node_id(i);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)), 8000);
        let mut proximity = NetworkProximity::new(node_id, addr);
        proximity.update_rtt((i as f64 + 1.0) * 10.0);
        neighborhood.upsert_peer(proximity);
    }

    // Should keep only 10 closest
    assert_eq!(neighborhood.size(), 10);

    let closest_5 = neighborhood.get_closest(5);
    assert_eq!(closest_5.len(), 5);

    // Closest should be nodes with lowest IDs (lowest RTT)
    assert_eq!(closest_5[0], create_node_id(0));
}

#[test]
fn test_proximity_estimator_ipv4() {
    // Same /32 (identical)
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 8000);
    let score_same = ProximityEstimator::estimate(&addr1, &addr1);
    assert_eq!(score_same.score(), 0.0);

    // Same /24
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 8000);
    let score_24 = ProximityEstimator::estimate(&addr1, &addr2);
    assert_eq!(score_24.score(), 100.0);

    // Same /16
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)), 8000);
    let score_16 = ProximityEstimator::estimate(&addr1, &addr3);
    assert_eq!(score_16.score(), 200.0);

    // Same /8
    let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 169, 1, 10)), 8000);
    let score_8 = ProximityEstimator::estimate(&addr1, &addr4);
    assert_eq!(score_8.score(), 300.0);

    // Different network
    let addr5 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8000);
    let score_diff = ProximityEstimator::estimate(&addr1, &addr5);
    assert_eq!(score_diff.score(), 400.0);
}

#[test]
fn test_turbine_stats_tracking() {
    let stats = TurbineStats::new();

    // Record broadcasts
    stats.record_broadcast(100, 122800);
    stats.record_broadcast(50, 61400);
    assert_eq!(stats.total_shreds_broadcast(), 150);
    assert_eq!(stats.total_bytes_transmitted(), 184200);
    assert_eq!(stats.broadcast_success_count(), 2);

    // Record retransmits
    stats.record_retransmit(25, 30700);
    assert_eq!(stats.total_shreds_retransmitted(), 25);
    assert_eq!(stats.total_bytes_transmitted(), 214900);

    // Record failures
    stats.record_broadcast_failure();
    assert_eq!(stats.broadcast_failure_count(), 1);

    // Update peer counts
    stats.update_peer_counts(200, 5000);
    assert_eq!(stats.layer1_peer_count(), 200);
    assert_eq!(stats.layer2_peer_count(), 5000);

    // Test reset
    stats.reset();
    assert_eq!(stats.total_shreds_broadcast(), 0);
    assert_eq!(stats.total_bytes_transmitted(), 0);
}

#[test]
fn test_propagation_metrics_tracking() {
    let mut metrics = PropagationMetrics::new(100, 50);

    assert_eq!(metrics.layer1_completion_percentage(), 0.0);
    assert_eq!(metrics.full_completion_percentage(), 0.0);

    // Simulate layer1 confirmations
    for _ in 0..25 {
        metrics.record_layer1_confirmation();
    }
    assert_eq!(metrics.layer1_completion_percentage(), 50.0);

    for _ in 0..25 {
        metrics.record_layer1_confirmation();
    }
    assert_eq!(metrics.layer1_completion_percentage(), 100.0);
    assert!(metrics.is_layer1_complete());

    // Simulate full confirmations
    for _ in 0..50 {
        metrics.record_full_confirmation();
    }
    assert_eq!(metrics.full_completion_percentage(), 100.0);
    assert!(metrics.is_fully_complete());

    // Check timing
    assert!(metrics.layer1_propagation_time_ms().is_some());
    assert!(metrics.full_propagation_time_ms().is_some());
}

#[tokio::test]
async fn test_broadcaster_lifecycle() {
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let stats = BroadcastStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let broadcaster = ShredBroadcaster::new(endpoint, stats, runtime);

    assert!(!broadcaster.is_running());

    broadcaster.start();
    assert!(broadcaster.is_running());

    broadcaster.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_broadcaster_with_tree() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let validators: Vec<_> = (1..=20)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::with_fanout(10);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    let quic_config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(quic_config, endpoint_stats).unwrap());
    let stats = BroadcastStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let broadcaster = ShredBroadcaster::new(endpoint, stats, runtime);
    broadcaster.update_tree(tree.clone());

    assert_eq!(broadcaster.get_tree().unwrap().slot(), tree.slot());
}

#[tokio::test]
async fn test_retransmit_service_lifecycle() {
    let node_id = create_node_id(0);
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let turbine_config = TurbineConfig::default();
    let stats = RetransmitStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let service = RetransmitService::new(node_id, endpoint, turbine_config, stats, runtime);

    assert!(!service.is_running());

    service.start();
    assert!(service.is_running());

    service.stop();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn test_retransmit_service_shred_cache() {
    let node_id = create_node_id(0);
    let config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
    let turbine_config = TurbineConfig::default();
    let stats = RetransmitStats::new(Arc::new(TurbineStats::new()));
    let runtime = tokio::runtime::Handle::current();

    let service = RetransmitService::new(node_id, endpoint, turbine_config, stats, runtime);

    // Add shreds to cache
    for i in 0..10 {
        let shred = Arc::new(create_test_shred(100, i));
        service.shred_cache.write().insert((100, i), shred);
    }

    // Verify cache
    for i in 0..10 {
        assert!(service.get_cached_shred(100, i).is_some());
    }

    // Clear cache
    let cleared = service.clear_cache_before_slot(101);
    assert_eq!(cleared, 10);

    for i in 0..10 {
        assert!(service.get_cached_shred(100, i).is_none());
    }
}

#[test]
fn test_broadcast_manager_multi_slot() {
    let manager = BroadcastManager::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    // Create broadcasters for multiple slots
    for slot in 100..110 {
        let config = QuicConfig::default();
        let endpoint_stats = Arc::new(QuicEndpointStats::default());
        let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
        let stats = BroadcastStats::new(Arc::new(TurbineStats::new()));
        let broadcaster = Arc::new(ShredBroadcaster::new(
            endpoint,
            stats,
            runtime.handle().clone(),
        ));
        manager.register_broadcaster(slot, broadcaster);
    }

    assert_eq!(manager.active_slots().len(), 10);

    // Clear old slots
    let cleared = manager.clear_old_broadcasters(105);
    assert_eq!(cleared, 5);
    assert_eq!(manager.active_slots().len(), 5);

    // Verify remaining slots
    for slot in 105..110 {
        assert!(manager.get_broadcaster(slot).is_some());
    }
}

#[test]
fn test_tree_rebuild_detection() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);
    let validators: Vec<_> = (1..=10)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::default();
    let builder = TurbineTreeBuilder::new(config.clone());

    // Build tree for slot 100
    let tree = builder.build(root_id, root_contact, validators, 100);

    // Check if rebuild is needed
    assert!(!tree.is_stale(100));
    assert!(!tree.is_stale(100 + config.tree_rebuild_interval_slots - 1));
    assert!(tree.is_stale(100 + config.tree_rebuild_interval_slots));
}

#[test]
fn test_layer_distribution_balance() {
    // Test that layer2 nodes are distributed evenly among layer1 nodes
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let validators: Vec<_> = (1..=100)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::with_fanout(10);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    // Count children per layer1 node
    let mut child_counts = Vec::new();
    for layer1_id in tree.layer1_nodes() {
        let children = tree.get_children(layer1_id);
        child_counts.push(children.len());
    }

    // Calculate statistics
    let total_children: usize = child_counts.iter().sum();
    let avg_children = total_children as f64 / child_counts.len() as f64;

    // Check that distribution is reasonably balanced
    for count in child_counts {
        let diff = (count as f64 - avg_children).abs();
        assert!(
            diff <= avg_children * 0.5,
            "Unbalanced distribution: {} vs avg {}",
            count,
            avg_children
        );
    }
}

#[test]
fn test_network_proximity_ewma() {
    let node_id = create_node_id(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8000);
    let mut proximity = NetworkProximity::new(node_id, addr);

    // First measurement
    proximity.update_rtt(100.0);
    assert_eq!(proximity.avg_rtt_ms, Some(100.0));

    // Second measurement (EWMA: 100 * 0.8 + 200 * 0.2 = 120)
    proximity.update_rtt(200.0);
    assert_eq!(proximity.avg_rtt_ms, Some(120.0));

    // Third measurement (EWMA: 120 * 0.8 + 100 * 0.2 = 116)
    proximity.update_rtt(100.0);
    assert_eq!(proximity.avg_rtt_ms, Some(116.0));
}

#[test]
fn test_network_proximity_loss_rate() {
    let node_id = create_node_id(1);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8000);
    let mut proximity = NetworkProximity::new(node_id, addr);

    proximity.update_rtt(50.0);
    let score_no_loss = proximity.proximity.score();

    proximity.update_loss_rate(0.1);
    let score_with_loss = proximity.proximity.score();

    // Proximity score should be higher (worse) with packet loss
    assert!(score_with_loss > score_no_loss);
}

#[test]
fn test_tree_parent_child_consistency() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let validators: Vec<_> = (1..=50)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::with_fanout(10);
    let builder = TurbineTreeBuilder::new(config);
    let tree = builder.build(root_id, root_contact, validators, 100);

    // Verify parent-child consistency
    for node_id in tree.layer1_nodes() {
        let children = tree.get_children(node_id);
        for child_id in children {
            let parent = tree.get_parent(&child_id);
            assert_eq!(
                parent,
                Some(*node_id),
                "Child's parent should match parent's child list"
            );
        }
    }
}

#[test]
fn test_turbine_config_builder_pattern() {
    let config = TurbineConfig::with_fanout(150)
        .with_neighborhood_size(30)
        .with_rebuild_interval(100_000)
        .with_stake_weighting(false)
        .with_neighborhood_optimization(false)
        .with_retransmit_batch_size(128);

    assert_eq!(config.fanout, 150);
    assert_eq!(config.neighborhood_size, 30);
    assert_eq!(config.tree_rebuild_interval_slots, 100_000);
    assert!(!config.stake_weighted_selection);
    assert!(!config.neighborhood_optimization);
    assert_eq!(config.retransmit_batch_size, 128);
}

#[test]
fn test_multiple_tree_rebuilds() {
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 127, 0, 0, 1, 8000);

    let validators: Vec<_> = (1..=20)
        .map(|i| {
            create_validator_with_addr(create_node_id(i), 1000 * i as u64, 127, 0, 0, 1, 8000 + i as u16)
        })
        .collect();

    let config = TurbineConfig::with_fanout(10);
    let builder = TurbineTreeBuilder::new(config);

    // Build multiple trees for different slots
    for slot in (100..110).step_by(2) {
        let tree = builder.build(root_id, root_contact.clone(), validators.clone(), slot);
        assert_eq!(tree.slot(), slot);
        assert_eq!(tree.layer1_nodes().len(), 10);
    }
}
