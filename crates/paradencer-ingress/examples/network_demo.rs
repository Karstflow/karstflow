use paradencer_ingress::{
    ContactInfo, GossipConfig, GossipService, InMemoryShredStore, NodeId, RepairServerConfig,
    RepairService, RepairServiceConfig, ShredData,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Paradencer Network Demo: Gossip + Repair Protocols");
    println!("===================================================\n");

    // Create two validator nodes
    let node1_id = NodeId::random();
    let node2_id = NodeId::random();

    println!("Node 1 ID: {}", node1_id);
    println!("Node 2 ID: {}\n", node2_id);

    // Setup Node 1
    let node1_gossip_addr = "127.0.0.1:9001".parse().unwrap();
    let node1_tpu_addr = "127.0.0.1:9002".parse().unwrap();
    let node1_repair_addr = "127.0.0.1:9003".parse().unwrap();

    let node1_contact_info = ContactInfo::new(
        node1_id,
        node1_gossip_addr,
        node1_tpu_addr,
        node1_tpu_addr,
        node1_repair_addr,
        1,
    );

    // Setup Node 2
    let node2_gossip_addr = "127.0.0.1:9011".parse().unwrap();
    let node2_tpu_addr = "127.0.0.1:9012".parse().unwrap();
    let node2_repair_addr = "127.0.0.1:9013".parse().unwrap();

    let node2_contact_info = ContactInfo::new(
        node2_id,
        node2_gossip_addr,
        node2_tpu_addr,
        node2_tpu_addr,
        node2_repair_addr,
        1,
    );

    println!("Starting Gossip Services...");

    // Start gossip service for Node 1
    let gossip_config1 = GossipConfig {
        bind_addr: node1_gossip_addr,
        push_interval: Duration::from_millis(500),
        ..GossipConfig::default()
    };

    let mut gossip1 = GossipService::new(node1_id, node1_contact_info.clone(), gossip_config1)
        .await
        .unwrap();
    gossip1.start().await.unwrap();

    // Start gossip service for Node 2
    let gossip_config2 = GossipConfig {
        bind_addr: node2_gossip_addr,
        push_interval: Duration::from_millis(500),
        ..GossipConfig::default()
    };

    let mut gossip2 = GossipService::new(node2_id, node2_contact_info.clone(), gossip_config2)
        .await
        .unwrap();
    gossip2.start().await.unwrap();

    println!("Gossip services started\n");

    // Bootstrap: Node 1 knows about Node 2
    println!("Bootstrapping cluster info...");
    gossip1.cluster_info().insert(node2_contact_info.clone());

    // Wait for gossip to propagate
    sleep(Duration::from_secs(2)).await;

    println!("Node 1 cluster size: {}", gossip1.cluster_info().size());
    println!("Node 2 cluster size: {}\n", gossip2.cluster_info().size());

    // Display gossip stats
    let stats1 = gossip1.stats();
    println!("Node 1 Gossip Stats:");
    println!(
        "  Push messages sent: {}",
        stats1
            .push_messages_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Pull requests sent: {}",
        stats1
            .pull_requests_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Nodes discovered: {}\n",
        stats1
            .nodes_discovered
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    println!("Starting Repair Services...");

    // Setup repair service for Node 1
    let node1_shred_store = Arc::new(InMemoryShredStore::new());

    // Populate Node 1 with some shreds
    for slot in 100..110 {
        for index in 0..5 {
            let shred = ShredData::new(slot, index, vec![slot as u8, index as u8], false);
            node1_shred_store.insert(shred);
        }
    }

    let repair_config1 = RepairServiceConfig {
        requester_bind_addr: "127.0.0.1:0".parse().unwrap(),
        server_config: RepairServerConfig {
            bind_addr: node1_repair_addr,
            ..RepairServerConfig::default()
        },
    };

    let mut repair1 = RepairService::new(
        node1_id,
        gossip1.cluster_info(),
        repair_config1,
        node1_shred_store.clone(),
    )
    .await
    .unwrap();
    repair1.start().await.unwrap();

    // Setup repair service for Node 2
    let node2_shred_store = Arc::new(InMemoryShredStore::new());

    let repair_config2 = RepairServiceConfig {
        requester_bind_addr: "127.0.0.1:0".parse().unwrap(),
        server_config: RepairServerConfig {
            bind_addr: node2_repair_addr,
            ..RepairServerConfig::default()
        },
    };

    let mut repair2 = RepairService::new(
        node2_id,
        gossip2.cluster_info(),
        repair_config2,
        node2_shred_store.clone(),
    )
    .await
    .unwrap();
    repair2.start().await.unwrap();

    println!("Repair services started\n");

    // Wait for services to be ready
    sleep(Duration::from_millis(500)).await;

    // Node 2 requests shred from Node 1
    println!("Node 2 requesting shred (slot=105, index=3) from Node 1...");
    match repair2
        .requester()
        .request_shred(node1_repair_addr, 105, 3)
        .await
    {
        Ok(Some(shred)) => {
            println!(
                "Received shred: slot={}, index={}, size={} bytes",
                shred.slot,
                shred.index,
                shred.size()
            );
        }
        Ok(None) => {
            println!("Shred not found");
        }
        Err(e) => {
            println!("Request error: {}", e);
        }
    }

    // Node 2 requests highest shred for a slot
    println!("\nNode 2 requesting highest shred index for slot 107...");
    match repair2
        .requester()
        .request_highest_shred(node1_repair_addr, 107)
        .await
    {
        Ok(Some(index)) => {
            println!("Highest shred index: {}", index);
        }
        Ok(None) => {
            println!("No shreds found for slot");
        }
        Err(e) => {
            println!("Request error: {}", e);
        }
    }

    // Display repair stats
    println!("\nNode 1 Repair Stats:");
    let repair1_stats = repair1.server().stats();
    println!(
        "  Requests received: {}",
        repair1_stats
            .requests_received
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Responses sent: {}",
        repair1_stats
            .responses_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Shreds served: {}",
        repair1_stats
            .shreds_served
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    println!("\nNode 2 Repair Stats:");
    let repair2_stats = repair2.requester().stats();
    println!(
        "  Requests sent: {}",
        repair2_stats
            .requests_sent
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Responses received: {}",
        repair2_stats
            .responses_received
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    println!(
        "  Shreds received: {}",
        repair2_stats
            .shreds_received
            .load(std::sync::atomic::Ordering::Relaxed)
    );

    println!("\nDemo complete!");

    // Cleanup
    gossip1.stop().await;
    gossip2.stop().await;

    Ok(())
}
