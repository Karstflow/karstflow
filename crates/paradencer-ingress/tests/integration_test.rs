use paradencer_ingress::{
    ClusterInfo, ContactInfo, GossipConfig, GossipService, InMemoryShredStore, NodeId,
    RepairServerConfig, RepairService, RepairServiceConfig, ShredData,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn create_test_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

#[tokio::test]
async fn test_gossip_service_lifecycle() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 0);

    let mut config = GossipConfig::default();
    config.bind_addr = "127.0.0.1:0".parse().unwrap();

    let mut service = GossipService::new(node_id, contact_info, config)
        .await
        .expect("Failed to create gossip service");

    service
        .start()
        .await
        .expect("Failed to start gossip service");

    assert!(service.local_addr().is_ok());

    service.stop().await;
}

#[tokio::test]
async fn test_repair_service_lifecycle() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 0);

    let cluster_info = Arc::new(ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_secs(30),
        1000,
    ));

    let shred_store = Arc::new(InMemoryShredStore::new());

    let mut config = RepairServiceConfig::default();
    config.requester_bind_addr = "127.0.0.1:0".parse().unwrap();
    config.server_config.bind_addr = "127.0.0.1:0".parse().unwrap();

    let mut service = RepairService::new(node_id, cluster_info, config, shred_store)
        .await
        .expect("Failed to create repair service");

    service
        .start()
        .await
        .expect("Failed to start repair service");

    assert_eq!(service.node_id(), node_id);
}

#[tokio::test]
async fn test_cluster_info_operations() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id, 8000);

    let cluster_info = ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_secs(30),
        1000,
    );

    let peer_id = NodeId::random();
    let peer_info = create_test_contact_info(peer_id, 8001);

    assert!(cluster_info.insert(peer_info.clone()));
    assert_eq!(cluster_info.size(), 1);

    let retrieved = cluster_info.get(&peer_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().node_id, peer_id);

    let all_nodes = cluster_info.get_all();
    assert_eq!(all_nodes.len(), 1);
}

#[tokio::test]
async fn test_shred_store_operations() {
    let store = InMemoryShredStore::new();

    for slot in 100..110 {
        for index in 0..5 {
            let shred = ShredData::new(slot, index, vec![slot as u8, index as u8], false);
            store.insert(shred);
        }
    }

    let shred = store.get_shred(105, 3);
    assert!(shred.is_some());

    let highest = store.get_highest_shred_index(105);
    assert_eq!(highest, Some(4));

    let range_shreds = store.get_shreds_in_range(105, 107);
    assert!(!range_shreds.is_empty());
}

#[tokio::test]
async fn test_two_node_gossip() {
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

    let mut node2_contact = node2_info.clone();
    node2_contact.gossip_addr = service2.local_addr().unwrap();

    service1.cluster_info().insert(node2_contact);

    tokio::time::sleep(Duration::from_millis(100)).await;

    service1.stop().await;
    service2.stop().await;
}
