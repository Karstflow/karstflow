use super::*;
use crate::gossip::{ClusterInfo, ContactInfo, NodeId};
use crate::repair::protocol::{RepairRequest, ShredData};
use crate::repair::server::{InMemoryShredStore, RepairServer, RepairServerConfig};
use crate::repair::wire::convert;
use crate::repair::wire::protocol::WireRepairProtocol;
use crate::repair::wire::response;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn create_test_contact_info(node_id: NodeId) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

#[tokio::test]
async fn test_shred_store_basic() {
    let store = InMemoryShredStore::new();

    let shred1 = ShredData::new(100, 0, vec![1, 2, 3], false);
    let shred2 = ShredData::new(100, 1, vec![4, 5, 6], false);

    store.insert(shred1.clone());
    store.insert(shred2.clone());

    let retrieved = store.get_shred(100, 0).unwrap();
    assert_eq!(retrieved.data, vec![1, 2, 3]);

    let highest = store.get_highest_shred_index(100).unwrap();
    assert_eq!(highest, 1);
}

#[tokio::test]
async fn test_shred_store_range() {
    let store = InMemoryShredStore::new();

    for slot in 100..105 {
        for index in 0..3 {
            let shred = ShredData::new(slot, index, vec![slot as u8, index as u8], false);
            store.insert(shred);
        }
    }

    let shreds = store.get_shreds_in_range(102, 103);
    assert!(!shreds.is_empty());

    let all_in_range = shreds.iter().all(|s| s.slot >= 102 && s.slot <= 103);
    assert!(all_in_range);
}

#[tokio::test]
async fn test_shred_store_ancestors() {
    let store = InMemoryShredStore::new();

    for slot in 95..105 {
        let shred = ShredData::new(slot, 0, vec![slot as u8], false);
        store.insert(shred);
    }

    let ancestors = store.get_ancestors(104, 5);
    assert!(!ancestors.is_empty());
    assert!(ancestors.iter().all(|s| s.slot >= 99 && s.slot < 104));
}

#[tokio::test]
async fn test_repair_server_creation() {
    let node_id = NodeId::random();
    let config = RepairServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..RepairServerConfig::default()
    };

    let store = Arc::new(InMemoryShredStore::new());
    let server = RepairServer::new(node_id, config, store).await;

    assert!(server.is_ok());
}

#[tokio::test]
async fn test_wire_repair_request_encode_decode() {
    let (secret, pubkey) = karstflow_crypto::generate_keypair();
    let (_, recipient) = karstflow_crypto::generate_keypair();
    let request = RepairRequest::Shred {
        requester: NodeId::new(pubkey),
        slot: 100,
        index: 5,
        nonce: 12345,
    };

    let mut wire = convert::request_to_wire(&request, recipient).unwrap();
    wire.sign(&secret);

    let encoded = wire.encode().unwrap();
    let decoded = WireRepairProtocol::decode(&encoded).unwrap();
    assert!(decoded.verify());
    assert_eq!(decoded.discriminant(), 8); // WindowIndex

    let internal = convert::wire_to_request(&decoded).unwrap();
    assert_eq!(internal.requester().0, pubkey);
}

#[tokio::test]
async fn test_wire_shred_response_encode_decode() {
    let shred_data = vec![1, 2, 3, 4, 5];
    let nonce = 12345u32;

    let encoded = response::encode_shred_response(&shred_data, nonce);
    let (payload, decoded_nonce) = response::decode_shred_response(&encoded).unwrap();

    assert_eq!(payload, &shred_data[..]);
    assert_eq!(decoded_nonce, nonce);
}

#[tokio::test]
async fn test_repair_service_creation() {
    let node_id = NodeId::random();
    let contact_info = create_test_contact_info(node_id);
    let cluster_info = Arc::new(ClusterInfo::new(
        node_id,
        contact_info,
        Duration::from_secs(30),
        1000,
    ));

    let config = RepairServiceConfig {
        requester_bind_addr: "127.0.0.1:0".parse().unwrap(),
        server_config: RepairServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..RepairServerConfig::default()
        },
    };

    let store = Arc::new(InMemoryShredStore::new());
    let service = RepairService::new(node_id, cluster_info, config, store).await;

    assert!(service.is_ok());
}

#[tokio::test]
async fn test_repair_stats() {
    let stats = RepairServerStats::new();

    stats
        .requests_received
        .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
    stats
        .responses_sent
        .fetch_add(8, std::sync::atomic::Ordering::Relaxed);

    assert_eq!(
        stats
            .requests_received
            .load(std::sync::atomic::Ordering::Relaxed),
        10
    );
    assert_eq!(
        stats
            .responses_sent
            .load(std::sync::atomic::Ordering::Relaxed),
        8
    );
}
