use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

fn create_test_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

#[tokio::test]
async fn test_gossip_service_push() {
    let node1_id = NodeId::random();
    let node1_info = create_test_contact_info(node1_id, 0);

    let config1 = GossipConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..GossipConfig::default()
    };

    let mut service1 = GossipService::new(node1_id, node1_info.clone(), config1)
        .await
        .unwrap();

    service1.start().await.unwrap();

    let node2_id = NodeId::random();
    let node2_info = create_test_contact_info(node2_id, 0);

    let config2 = GossipConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..GossipConfig::default()
    };

    let mut service2 = GossipService::new(node2_id, node2_info.clone(), config2)
        .await
        .unwrap();

    service2.start().await.unwrap();

    service1.cluster_info().insert(create_test_contact_info(
        node2_id,
        service2.local_addr().unwrap().port(),
    ));

    sleep(Duration::from_millis(500)).await;

    service1.stop().await;
    service2.stop().await;
}

#[tokio::test]
async fn test_gossip_message_propagation() {
    let node1_id = NodeId::random();
    let node1_info = create_test_contact_info(node1_id, 0);

    let cluster_info = Arc::new(ClusterInfo::new(
        node1_id,
        node1_info,
        Duration::from_secs(30),
        1000,
    ));

    let node2_id = NodeId::random();
    let node2_info = create_test_contact_info(node2_id, 8001);
    cluster_info.insert(node2_info);

    assert_eq!(cluster_info.size(), 1);

    let retrieved = cluster_info.get(&node2_id).unwrap();
    assert_eq!(retrieved.node_id, node2_id);
}

#[tokio::test]
async fn test_cluster_info_expiration() {
    // CrdsTable uses nanosecond timestamps with protocol-defined durations.
    // Unstaked entries expire after 15 seconds. Rather than sleeping 15s,
    // we verify the mechanism works by directly calling advance() with
    // a synthetic future timestamp.
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 8000);

    let cluster_info = Arc::new(ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_secs(30),
        1000,
    ));

    let peer_id = NodeId::random();
    let peer_info = create_test_contact_info(peer_id, 8001);
    cluster_info.insert(peer_info);

    assert_eq!(cluster_info.size(), 1);

    // Advance the table far into the future via the underlying CrdsTable
    {
        let mut table = cluster_info.crds_table().write();
        let far_future = i64::MAX / 2; // well past any expiration
        let expired = table.advance(far_future);
        assert!(expired > 0, "expected at least one entry to expire");
    }

    // Now contact_info_entries should be empty since the entry expired
    assert_eq!(cluster_info.size(), 0);
}

#[tokio::test]
async fn test_gossip_stats() {
    let stats = GossipServiceStats::new();

    stats
        .push_messages_sent
        .fetch_add(5, std::sync::atomic::Ordering::Relaxed);
    stats
        .pull_requests_sent
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);

    assert_eq!(
        stats
            .push_messages_sent
            .load(std::sync::atomic::Ordering::Relaxed),
        5
    );
    assert_eq!(
        stats
            .pull_requests_sent
            .load(std::sync::atomic::Ordering::Relaxed),
        3
    );
}

#[tokio::test]
async fn test_cluster_info_bloom_filter_pull_response() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 8000);

    let cluster = Arc::new(ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_secs(30),
        1000,
    ));

    // Insert peers
    for i in 1u8..=5 {
        let peer = create_test_contact_info(NodeId::new([i; 32]), 8000 + i as u16);
        cluster.insert(peer);
    }

    assert_eq!(cluster.size(), 5);

    // Build a bloom filter and verify it has content
    let (filter, _mask) = cluster.build_pull_filter();
    assert!(filter.bits_set() > 0);
}
