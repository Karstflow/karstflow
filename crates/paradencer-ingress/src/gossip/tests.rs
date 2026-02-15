use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

    let mut config1 = GossipConfig::default();
    config1.bind_addr = "127.0.0.1:0".parse().unwrap();

    let mut service1 = GossipService::new(node1_id, node1_info.clone(), config1)
        .await
        .unwrap();

    service1.start().await.unwrap();

    let node2_id = NodeId::random();
    let node2_info = create_test_contact_info(node2_id, 0);

    let mut config2 = GossipConfig::default();
    config2.bind_addr = "127.0.0.1:0".parse().unwrap();

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
    cluster_info.insert(node2_info.clone());

    assert_eq!(cluster_info.size(), 1);

    let retrieved = cluster_info.get(&node2_id).unwrap();
    assert_eq!(retrieved.node_id, node2_id);
}

#[tokio::test]
async fn test_cluster_info_prune() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 8000);

    let cluster_info = Arc::new(ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_millis(100),
        1000,
    ));

    let peer_id = NodeId::random();
    let peer_info = create_test_contact_info(peer_id, 8001);
    cluster_info.insert(peer_info);

    assert_eq!(cluster_info.size(), 1);

    sleep(Duration::from_millis(200)).await;

    let pruned = cluster_info.prune_stale_nodes();
    assert_eq!(pruned, 1);
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
