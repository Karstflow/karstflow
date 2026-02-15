/// Turbine block propagation protocol demonstration
///
/// This example demonstrates how to use the Turbine protocol for efficient
/// block propagation in a distributed network using stake-weighted tree construction.
use paradencer_ingress::{
    BroadcastStats, ContactInfo, NodeId, QuicConfig, QuicEndpoint, QuicEndpointStats,
    RetransmitService, RetransmitStats, ShredBroadcaster, TurbineConfig, TurbineStats, TurbineTree,
    TurbineTreeBuilder, ValidatorInfo,
};
use paradencer_types::shred::{
    DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

fn create_node_id(byte: u8) -> NodeId {
    NodeId::new([byte; 32])
}

fn create_contact_info(node_id: NodeId, base_port: u16) -> ContactInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), base_port);
    ContactInfo::new(node_id, addr, addr, addr, addr, 1)
}

fn create_validator(node_id: NodeId, stake: u64, base_port: u16) -> ValidatorInfo {
    let contact = create_contact_info(node_id, base_port);
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Turbine Block Propagation Demo ===\n");

    // Step 1: Configure Turbine
    println!("Step 1: Configuring Turbine protocol");
    let turbine_config = TurbineConfig::with_fanout(200)
        .with_neighborhood_size(50)
        .with_stake_weighting(true)
        .with_neighborhood_optimization(true)
        .with_retransmit_batch_size(64);

    println!("  Fanout: {}", turbine_config.fanout);
    println!("  Layer2 Fanout: {}", turbine_config.layer2_fanout);
    println!(
        "  Max reachable nodes: {}",
        turbine_config.max_reachable_nodes()
    );
    println!(
        "  Propagation hops: {}\n",
        turbine_config.propagation_hops()
    );

    // Step 2: Create validators with varying stakes
    println!("Step 2: Creating validator set");
    let mut validators = Vec::new();

    // Large validators
    for i in 0..10 {
        let node_id = create_node_id(i + 1);
        validators.push(create_validator(node_id, 100_000_000, 9000 + i as u16));
    }

    // Medium validators
    for i in 0..50 {
        let node_id = create_node_id(i + 11);
        validators.push(create_validator(node_id, 10_000_000, 10000 + i as u16));
    }

    // Small validators
    for i in 0..100 {
        let node_id = create_node_id(i + 61);
        validators.push(create_validator(node_id, 1_000_000, 11000 + i as u16));
    }

    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    println!("  Total validators: {}", validators.len());
    println!("  Total stake: {}\n", total_stake);

    // Step 3: Build turbine tree
    println!("Step 3: Building stake-weighted turbine tree");
    let root_id = create_node_id(0);
    let root_contact = create_contact_info(root_id, 8000);
    let slot = 100;

    let tree_builder = TurbineTreeBuilder::new(turbine_config.clone());
    let tree = tree_builder.build(root_id, root_contact, validators, slot);

    println!("  Root: {}", tree.root());
    println!("  Slot: {}", tree.slot());
    println!("  Total nodes in tree: {}", tree.total_nodes());
    println!("  Layer 1 nodes: {}", tree.layer1_nodes().len());
    println!("  Layer 2 nodes: {}\n", tree.layer2_nodes().len());

    // Step 4: Display tree structure
    println!("Step 4: Tree structure");
    println!("  Root -> Layer 1 peers:");
    for (i, layer1_id) in tree.layer1_nodes().iter().take(5).enumerate() {
        if let Some(node) = tree.get_node(layer1_id) {
            println!(
                "    [{}] Node {} (stake: {})",
                i + 1,
                node.node_id,
                node.stake
            );
        }
    }
    println!(
        "    ... and {} more",
        tree.layer1_nodes().len().saturating_sub(5)
    );

    if let Some(first_layer1) = tree.layer1_nodes().first() {
        let children = tree.get_children(first_layer1);
        println!("\n  Layer 1 peer {} -> Layer 2 peers:", first_layer1);
        for (i, child_id) in children.iter().take(5).enumerate() {
            if let Some(node) = tree.get_node(child_id) {
                println!(
                    "    [{}] Node {} (stake: {})",
                    i + 1,
                    node.node_id,
                    node.stake
                );
            }
        }
        if children.len() > 5 {
            println!("    ... and {} more", children.len() - 5);
        }
    }
    println!();

    // Step 5: Setup broadcast infrastructure
    println!("Step 5: Setting up broadcast infrastructure");
    let quic_config = QuicConfig::default();
    let endpoint_stats = Arc::new(QuicEndpointStats::default());
    let endpoint = Arc::new(QuicEndpoint::new(quic_config, endpoint_stats)?);

    let turbine_stats = Arc::new(TurbineStats::new());
    let broadcast_stats = BroadcastStats::new(Arc::clone(&turbine_stats));
    let runtime = tokio::runtime::Handle::current();

    let broadcaster = ShredBroadcaster::new(endpoint.clone(), broadcast_stats, runtime.clone());
    broadcaster.update_tree(tree.clone());

    println!("  QUIC endpoint created");
    println!("  Broadcaster initialized");
    println!("  Tree loaded into broadcaster\n");

    // Step 6: Setup retransmit service
    println!("Step 6: Setting up retransmit service");
    let retransmit_stats = RetransmitStats::new(Arc::clone(&turbine_stats));
    let retransmit_service = RetransmitService::new(
        root_id,
        endpoint,
        turbine_config.clone(),
        retransmit_stats,
        runtime,
    );
    retransmit_service.update_tree(tree);

    println!("  Retransmit service initialized\n");

    // Step 7: Simulate shred broadcast
    println!("Step 7: Simulating shred broadcast");
    let shreds_per_slot = 100;

    for i in 0..shreds_per_slot {
        let shred = create_test_shred(slot, i);
        let _ = broadcaster.broadcast_shred(shred, 2); // Target both layers
    }

    println!("  Queued {} shreds for broadcast", shreds_per_slot);
    println!("  Target: Layer 1 + Layer 2 peers\n");

    // Step 8: Display statistics
    println!("Step 8: Broadcast statistics");
    println!(
        "  Shreds broadcast: {}",
        turbine_stats.total_shreds_broadcast()
    );
    println!(
        "  Bytes transmitted: {}",
        turbine_stats.total_bytes_transmitted()
    );
    println!(
        "  Success count: {}",
        turbine_stats.broadcast_success_count()
    );
    println!(
        "  Failure count: {}",
        turbine_stats.broadcast_failure_count()
    );
    println!("  Layer 1 peers: {}", turbine_stats.layer1_peer_count());
    println!("  Layer 2 peers: {}\n", turbine_stats.layer2_peer_count());

    // Step 9: Tree analysis
    println!("Step 9: Tree efficiency analysis");
    let coverage_ratio = tree.total_nodes() as f64 / 160.0; // Total validators
    println!("  Network coverage: {:.1}%", coverage_ratio * 100.0);
    println!(
        "  Propagation depth: {} hops",
        turbine_config.propagation_hops()
    );

    let theoretical_fanout = turbine_config.fanout * turbine_config.layer2_fanout;
    println!(
        "  Theoretical max fanout: {} peers/layer",
        theoretical_fanout
    );

    println!("\n=== Demo Complete ===");
    println!("\nKey Features Demonstrated:");
    println!("  ✓ Stake-weighted tree construction");
    println!("  ✓ Multi-layer peer selection (Layer 1 + Layer 2)");
    println!("  ✓ QUIC-based broadcast infrastructure");
    println!("  ✓ Retransmit service for reliability");
    println!("  ✓ Network proximity optimization");
    println!("  ✓ Performance metrics collection");

    Ok(())
}
