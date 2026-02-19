use crate::turbine::transport::ShredTransport;
use crate::turbine::{BroadcastStats, TurbineTree};
use crate::IngressError;
use crossbeam_channel::{Receiver, Sender};
use paradencer_types::shred::Shred;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
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

/// Shred broadcaster using pluggable transport
pub struct ShredBroadcaster {
    /// Transport for sending packets
    transport: Arc<dyn ShredTransport>,

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

    /// Pending acknowledgments (slot, index) -> timestamp
    pending_acks: Arc<RwLock<HashMap<(u64, u32), Instant>>>,
}

impl ShredBroadcaster {
    /// Create a new shred broadcaster with the given transport
    pub fn new(transport: Arc<dyn ShredTransport>, stats: BroadcastStats) -> Self {
        let (shred_sender, shred_receiver) = crossbeam_channel::bounded(MAX_PENDING_BROADCASTS);

        Self {
            transport,
            tree: Arc::new(RwLock::new(None)),
            stats,
            shred_receiver,
            shred_sender,
            running: Arc::new(AtomicBool::new(false)),
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

    /// Start the broadcaster service (poll-driven)
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Broadcaster already running");
            return;
        }
        info!("Starting shred broadcaster");
    }

    /// Poll for pending shreds and broadcast them.
    /// Call this from a service loop.
    pub fn service(&self) {
        let mut batch = Vec::new();

        // Drain available shreds
        while batch.len() < MAX_BROADCAST_BATCH_SIZE {
            match self.shred_receiver.try_recv() {
                Ok(shred) => batch.push(shred),
                Err(_) => break,
            }
        }

        if !batch.is_empty() {
            self.broadcast_batch(&batch);
        }
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
    fn broadcast_batch(&self, shreds: &[BroadcastShred]) {
        if shreds.is_empty() {
            return;
        }

        let tree_guard = self.tree.read();
        let Some(ref current_tree) = *tree_guard else {
            warn!(
                "No turbine tree available, dropping {} shreds",
                shreds.len()
            );
            self.stats.record_failure();
            return;
        };

        // Collect peer addresses
        let mut layer1_peers: Vec<(_, SocketAddr)> = Vec::new();
        let mut layer2_peers: Vec<(_, SocketAddr)> = Vec::new();

        for node_id in current_tree.layer1_nodes() {
            if let Some(node) = current_tree.get_node(node_id) {
                layer1_peers.push((node.node_id, node.contact_info.tpu_quic_addr));
            }
        }

        for node_id in current_tree.layer2_nodes() {
            if let Some(node) = current_tree.get_node(node_id) {
                layer2_peers.push((node.node_id, node.contact_info.tpu_quic_addr));
            }
        }

        drop(tree_guard);

        let mut total_sent = 0;
        let mut total_bytes = 0;

        for shred in shreds {
            let serialized = match bincode::serialize(&*shred.shred) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize shred: {}", e);
                    continue;
                }
            };

            total_bytes += serialized.len();

            // Send to layer1 peers
            for (node_id, addr) in &layer1_peers {
                if let Err(e) = self.transport.send_to(&serialized, *addr) {
                    warn!("Failed to send shred to layer1 peer {}: {}", node_id, e);
                }
            }

            // Send to layer2 peers if target_layer >= 2
            if shred.target_layer >= 2 {
                for (node_id, addr) in &layer2_peers {
                    if let Err(e) = self.transport.send_to(&serialized, *addr) {
                        warn!("Failed to send shred to layer2 peer {}: {}", node_id, e);
                    }
                }
            }

            total_sent += 1;

            // Track pending acknowledgment
            self.pending_acks
                .write()
                .insert((shred.slot, shred.index), Instant::now());
        }

        self.stats.record_success(total_sent, total_bytes as u64);

        debug!(
            "Broadcast complete: {} shreds, {} bytes, {} layer1 peers, {} layer2 peers",
            total_sent,
            total_bytes,
            layer1_peers.len(),
            layer2_peers.len()
        );
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
    use crate::turbine::transport::NullTransport;
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
        let transport: Arc<dyn ShredTransport> = Arc::new(NullTransport);
        let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));
        let broadcaster = ShredBroadcaster::new(transport, stats);
        assert!(!broadcaster.is_running());
    }

    #[test]
    fn test_broadcast_manager() {
        let manager = BroadcastManager::new();

        let transport: Arc<dyn ShredTransport> = Arc::new(NullTransport);
        let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));
        let broadcaster = Arc::new(ShredBroadcaster::new(transport, stats));

        manager.register_broadcaster(100, Arc::clone(&broadcaster));
        assert!(manager.get_broadcaster(100).is_some());

        let removed = manager.remove_broadcaster(100);
        assert!(removed.is_some());
        assert!(manager.get_broadcaster(100).is_none());
    }

    #[test]
    fn test_clear_old_broadcasters() {
        let manager = BroadcastManager::new();

        for slot in 100..110 {
            let transport: Arc<dyn ShredTransport> = Arc::new(NullTransport);
            let stats = BroadcastStats::new(Arc::new(crate::turbine::TurbineStats::new()));
            let broadcaster = Arc::new(ShredBroadcaster::new(transport, stats));
            manager.register_broadcaster(slot, broadcaster);
        }

        assert_eq!(manager.active_slots().len(), 10);

        let cleared = manager.clear_old_broadcasters(105);
        assert_eq!(cleared, 5);
        assert_eq!(manager.active_slots().len(), 5);
    }
}
