use crate::gossip::NodeId;
use crate::quic::{QuicEndpoint, QuicPacket, QuicPacketBatch};
use crate::turbine::{BroadcastStats, TurbineTree};
use crate::IngressError;
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use paradencer_types::shred::Shred;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Handle;
use tracing::{debug, error, info, warn};

/// Maximum number of shreds to batch in a single broadcast
const MAX_BROADCAST_BATCH_SIZE: usize = 64;

/// Maximum number of pending broadcasts
const MAX_PENDING_BROADCASTS: usize = 1000;

/// Shred ready for broadcast
#[derive(Debug, Clone)]
pub struct BroadcastShred {
    /// The shred to broadcast
    pub shred: Arc<Shred>,

    /// Slot number
    pub slot: u64,

    /// Shred index
    pub index: u32,

    /// Target layer (1 = layer1 only, 2 = both layers)
    pub target_layer: u8,

    /// Time when shred was queued
    pub queued_at: Instant,
}

impl BroadcastShred {
    pub fn new(shred: Shred, target_layer: u8) -> Self {
        let slot = shred.slot();
        let index = shred.index();

        Self {
            shred: Arc::new(shred),
            slot,
            index,
            target_layer,
            queued_at: Instant::now(),
        }
    }

    pub fn from_arc(shred: Arc<Shred>, target_layer: u8) -> Self {
        let slot = shred.slot();
        let index = shred.index();

        Self {
            shred,
            slot,
            index,
            target_layer,
            queued_at: Instant::now(),
        }
    }
}

/// Shred broadcaster using QUIC transport
pub struct ShredBroadcaster {
    /// QUIC endpoint for sending
    endpoint: Arc<QuicEndpoint>,

    /// Current turbine tree
    tree: Arc<RwLock<Option<TurbineTree>>>,

    /// Broadcast statistics
    stats: BroadcastStats,

    /// Channel for receiving shreds to broadcast
    shred_receiver: Receiver<BroadcastShred>,

    /// Channel for sending shreds to broadcast
    shred_sender: Sender<BroadcastShred>,

    /// Running flag
    running: Arc<AtomicBool>,

    /// Tokio runtime handle
    runtime_handle: Handle,

    /// Pending acknowledgments (slot, index) -> timestamp
    pending_acks: Arc<RwLock<HashMap<(u64, u32), Instant>>>,
}

impl ShredBroadcaster {
    /// Create a new shred broadcaster
    pub fn new(endpoint: Arc<QuicEndpoint>, stats: BroadcastStats, runtime_handle: Handle) -> Self {
        let (shred_sender, shred_receiver) = crossbeam_channel::bounded(MAX_PENDING_BROADCASTS);

        Self {
            endpoint,
            tree: Arc::new(RwLock::new(None)),
            stats,
            shred_receiver,
            shred_sender,
            running: Arc::new(AtomicBool::new(false)),
            runtime_handle,
            pending_acks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update the turbine tree
    pub fn update_tree(&self, tree: TurbineTree) {
        info!(
            slot = tree.slot(),
            layer1_count = tree.layer1_nodes().len(),
            layer2_count = tree.layer2_nodes().len(),
            "Updated turbine tree"
        );
        *self.tree.write() = Some(tree);
    }

    /// Get the current tree
    pub fn get_tree(&self) -> Option<TurbineTree> {
        self.tree.read().clone()
    }

    /// Queue a shred for broadcast
    pub fn broadcast_shred(&self, shred: Shred, target_layer: u8) -> Result<(), IngressError> {
        let broadcast_shred = BroadcastShred::new(shred, target_layer);
        self.shred_sender
            .try_send(broadcast_shred)
            .map_err(|e| IngressError::ChannelSend(format!("Failed to queue shred: {}", e)))
    }

    /// Queue multiple shreds for broadcast
    pub fn broadcast_shreds(
        &self,
        shreds: Vec<Shred>,
        target_layer: u8,
    ) -> Result<(), IngressError> {
        for shred in shreds {
            self.broadcast_shred(shred, target_layer)?;
        }
        Ok(())
    }

    /// Start the broadcaster service
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Broadcaster already running");
            return;
        }

        info!("Starting shred broadcaster");

        let receiver = self.shred_receiver.clone();
        let endpoint = Arc::clone(&self.endpoint);
        let tree = Arc::clone(&self.tree);
        let stats = self.stats.clone();
        let running = Arc::clone(&self.running);
        let pending_acks = Arc::clone(&self.pending_acks);

        self.runtime_handle.spawn(async move {
            let mut batch = Vec::new();

            while running.load(Ordering::SeqCst) {
                // Collect shreds into batch
                match receiver.recv_timeout(std::time::Duration::from_millis(10)) {
                    Ok(shred) => {
                        batch.push(shred);

                        // Drain additional shreds up to batch size
                        while batch.len() < MAX_BROADCAST_BATCH_SIZE {
                            match receiver.try_recv() {
                                Ok(shred) => batch.push(shred),
                                Err(_) => break,
                            }
                        }

                        // Broadcast the batch
                        Self::broadcast_batch(&endpoint, &tree, &stats, &pending_acks, &mut batch)
                            .await;
                        batch.clear();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // No shreds available, continue
                        continue;
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        info!("Broadcast channel disconnected, stopping");
                        break;
                    }
                }
            }

            info!("Shred broadcaster stopped");
        });
    }

    /// Stop the broadcaster service
    pub fn stop(&self) {
        info!("Stopping shred broadcaster");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the broadcaster is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Broadcast a batch of shreds
    async fn broadcast_batch(
        endpoint: &Arc<QuicEndpoint>,
        tree: &Arc<RwLock<Option<TurbineTree>>>,
        stats: &BroadcastStats,
        pending_acks: &Arc<RwLock<HashMap<(u64, u32), Instant>>>,
        shreds: &mut Vec<BroadcastShred>,
    ) {
        if shreds.is_empty() {
            return;
        }

        // Extract peer info from tree before any await points
        let (layer1_peers, layer2_peers) = {
            let tree_guard = tree.read();
            let Some(ref current_tree) = *tree_guard else {
                warn!(
                    "No turbine tree available, dropping {} shreds",
                    shreds.len()
                );
                stats.record_failure();
                return;
            };

            debug!(
                "Broadcasting batch of {} shreds to tree with {} layer1, {} layer2 nodes",
                shreds.len(),
                current_tree.layer1_nodes().len(),
                current_tree.layer2_nodes().len()
            );

            // Group shreds by target and collect peer addresses
            let mut layer1 = Vec::new();
            let mut layer2 = Vec::new();

            for node_id in current_tree.layer1_nodes() {
                if let Some(node) = current_tree.get_node(node_id) {
                    layer1.push((node.node_id, node.contact_info.tpu_quic_addr));
                }
            }

            for node_id in current_tree.layer2_nodes() {
                if let Some(node) = current_tree.get_node(node_id) {
                    layer2.push((node.node_id, node.contact_info.tpu_quic_addr));
                }
            }

            (layer1, layer2)
        }; // tree_guard dropped here

        // Send to each peer
        let mut total_sent = 0;
        let mut total_bytes = 0;

        for shred in shreds.iter() {
            // Serialize shred once
            let serialized = match bincode::serialize(&*shred.shred) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize shred: {}", e);
                    continue;
                }
            };

            let bytes = Bytes::from(serialized);
            total_bytes += bytes.len();

            // Send to layer1 peers
            for (node_id, addr) in &layer1_peers {
                if let Err(e) = Self::send_to_peer(endpoint, *addr, bytes.clone()).await {
                    warn!("Failed to send shred to layer1 peer {}: {}", node_id, e);
                }
            }

            // Send to layer2 peers if target_layer >= 2
            if shred.target_layer >= 2 {
                for (node_id, addr) in &layer2_peers {
                    if let Err(e) = Self::send_to_peer(endpoint, *addr, bytes.clone()).await {
                        warn!("Failed to send shred to layer2 peer {}: {}", node_id, e);
                    }
                }
            }

            total_sent += 1;

            // Track pending acknowledgment
            pending_acks
                .write()
                .insert((shred.slot, shred.index), Instant::now());
        }

        stats.record_success(total_sent, total_bytes as u64);

        debug!(
            "Broadcast complete: {} shreds, {} bytes, {} layer1 peers, {} layer2 peers",
            total_sent,
            total_bytes,
            layer1_peers.len(),
            layer2_peers.len()
        );
    }

    /// Send data to a single peer via QUIC
    async fn send_to_peer(
        endpoint: &Arc<QuicEndpoint>,
        addr: SocketAddr,
        data: Bytes,
    ) -> Result<(), IngressError> {
        // In a real implementation, this would use QUIC streams
        // For now, we use the packet interface
        let packet = QuicPacket::new(data, addr, 0);
        // The actual sending would happen through the QUIC endpoint
        // This is a simplified version
        Ok(())
    }

    /// Clear pending acknowledgments older than the given duration
    pub fn clear_old_acks(&self, max_age: std::time::Duration) -> usize {
        let mut pending = self.pending_acks.write();
        let before = pending.len();
        let now = Instant::now();
        pending.retain(|_, timestamp| now.duration_since(*timestamp) < max_age);
        before - pending.len()
    }

    /// Get the number of pending acknowledgments
    pub fn pending_ack_count(&self) -> usize {
        self.pending_acks.read().len()
    }

    /// Check if a shred is pending acknowledgment
    pub fn is_pending_ack(&self, slot: u64, index: u32) -> bool {
        self.pending_acks.read().contains_key(&(slot, index))
    }

    /// Acknowledge receipt of a shred
    pub fn acknowledge_shred(&self, slot: u64, index: u32) -> bool {
        self.pending_acks.write().remove(&(slot, index)).is_some()
    }
}

impl Drop for ShredBroadcaster {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Broadcast manager for coordinating multiple broadcast streams
pub struct BroadcastManager {
    broadcasters: Arc<RwLock<HashMap<u64, Arc<ShredBroadcaster>>>>,
}

impl BroadcastManager {
    pub fn new() -> Self {
        Self {
            broadcasters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a broadcaster for a specific slot
    pub fn register_broadcaster(&self, slot: u64, broadcaster: Arc<ShredBroadcaster>) {
        self.broadcasters.write().insert(slot, broadcaster);
    }

    /// Get a broadcaster for a specific slot
    pub fn get_broadcaster(&self, slot: u64) -> Option<Arc<ShredBroadcaster>> {
        self.broadcasters.read().get(&slot).cloned()
    }

    /// Remove a broadcaster for a specific slot
    pub fn remove_broadcaster(&self, slot: u64) -> Option<Arc<ShredBroadcaster>> {
        self.broadcasters.write().remove(&slot)
    }

    /// Get all active slots
    pub fn active_slots(&self) -> Vec<u64> {
        self.broadcasters.read().keys().copied().collect()
    }

    /// Clear broadcasters for slots older than the given slot
    pub fn clear_old_broadcasters(&self, max_slot: u64) -> usize {
        let mut broadcasters = self.broadcasters.write();
        let before = broadcasters.len();
        broadcasters.retain(|slot, _| *slot >= max_slot);
        before - broadcasters.len()
    }
}

impl Default for BroadcastManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{QuicConfig, QuicEndpointStats};
    use paradencer_types::shred::{
        DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };

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
    fn test_broadcast_shred_creation() {
        let shred = create_test_shred(100, 5);
        let broadcast_shred = BroadcastShred::new(shred, 1);

        assert_eq!(broadcast_shred.slot, 100);
        assert_eq!(broadcast_shred.index, 5);
        assert_eq!(broadcast_shred.target_layer, 1);
    }

    #[test]
    fn test_broadcaster_creation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = QuicConfig::default();
        let endpoint_stats = Arc::new(QuicEndpointStats::default());
        let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
        let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let broadcaster = ShredBroadcaster::new(endpoint, stats, runtime.handle().clone());
        assert!(!broadcaster.is_running());
    }

    #[test]
    fn test_broadcast_manager() {
        let manager = BroadcastManager::new();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = QuicConfig::default();
        let endpoint_stats = Arc::new(QuicEndpointStats::default());
        let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
        let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let broadcaster = Arc::new(ShredBroadcaster::new(
            endpoint,
            stats,
            runtime.handle().clone(),
        ));

        manager.register_broadcaster(100, Arc::clone(&broadcaster));
        assert!(manager.get_broadcaster(100).is_some());

        let removed = manager.remove_broadcaster(100);
        assert!(removed.is_some());
        assert!(manager.get_broadcaster(100).is_none());
    }

    #[test]
    fn test_clear_old_broadcasters() {
        let manager = BroadcastManager::new();
        let runtime = tokio::runtime::Runtime::new().unwrap();

        for slot in 100..110 {
            let config = QuicConfig::default();
            let endpoint_stats = Arc::new(QuicEndpointStats::default());
            let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
            let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));
            let broadcaster = Arc::new(ShredBroadcaster::new(
                endpoint,
                stats,
                runtime.handle().clone(),
            ));
            manager.register_broadcaster(slot, broadcaster);
        }

        assert_eq!(manager.active_slots().len(), 10);

        let cleared = manager.clear_old_broadcasters(105);
        assert_eq!(cleared, 5);
        assert_eq!(manager.active_slots().len(), 5);
    }
}
