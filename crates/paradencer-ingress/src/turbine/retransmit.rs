use crate::gossip::NodeId;
use crate::quic::QuicEndpoint;
use crate::turbine::{RetransmitStats, TurbineConfig, TurbineTree};
use crate::IngressError;
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use paradencer_types::shred::Shred;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tracing::{debug, error, info, warn};

/// Cache of shreds indexed by (slot, index)
type ShredCache = Arc<RwLock<HashMap<(u64, u32), Arc<Shred>>>>;

/// Retransmit request for a missing shred
#[derive(Debug, Clone)]
pub struct RetransmitRequest {
    /// Slot number
    pub slot: u64,

    /// Shred index
    pub index: u32,

    /// Time when request was created
    pub requested_at: Instant,

    /// Number of retry attempts
    pub retry_count: usize,

    /// Peers to request from (in priority order)
    pub target_peers: Vec<NodeId>,
}

impl RetransmitRequest {
    pub fn new(slot: u64, index: u32, target_peers: Vec<NodeId>) -> Self {
        Self {
            slot,
            index,
            requested_at: Instant::now(),
            retry_count: 0,
            target_peers,
        }
    }

    /// Check if this request has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.requested_at.elapsed() > timeout
    }

    /// Increment retry count
    pub fn retry(&mut self) {
        self.retry_count += 1;
        self.requested_at = Instant::now();
    }
}

/// Shred received for retransmission
#[derive(Debug, Clone)]
pub struct RetransmitShred {
    /// The shred to retransmit
    pub shred: Arc<Shred>,

    /// Time when shred was received
    pub received_at: Instant,

    /// Node that sent us this shred (our parent in the tree)
    pub received_from: NodeId,
}

impl RetransmitShred {
    pub fn new(shred: Arc<Shred>, received_from: NodeId) -> Self {
        Self {
            shred,
            received_at: Instant::now(),
            received_from,
        }
    }
}

/// Retransmit service for propagating shreds down the turbine tree
pub struct RetransmitService {
    /// QUIC endpoint for sending
    endpoint: Arc<QuicEndpoint>,

    /// Current turbine tree
    tree: Arc<RwLock<Option<TurbineTree>>>,

    /// Our node ID
    node_id: NodeId,

    /// Configuration
    config: TurbineConfig,

    /// Statistics
    stats: RetransmitStats,

    /// Channel for receiving shreds to retransmit
    shred_receiver: Receiver<RetransmitShred>,

    /// Channel for sending shreds to retransmit
    shred_sender: Sender<RetransmitShred>,

    /// Channel for receiving retransmit requests
    request_receiver: Receiver<RetransmitRequest>,

    /// Channel for sending retransmit requests
    request_sender: Sender<RetransmitRequest>,

    /// Running flag
    running: Arc<AtomicBool>,

    /// Tokio runtime handle
    runtime_handle: Handle,

    /// Recently retransmitted shreds (to avoid duplicates)
    recent_retransmits: Arc<RwLock<HashMap<(u64, u32), Instant>>>,

    /// Pending retransmit requests
    pending_requests: Arc<RwLock<HashMap<(u64, u32), RetransmitRequest>>>,

    /// Shred cache for fulfilling retransmit requests
    pub shred_cache: ShredCache,
}

impl RetransmitService {
    /// Create a new retransmit service
    pub fn new(
        node_id: NodeId,
        endpoint: Arc<QuicEndpoint>,
        config: TurbineConfig,
        stats: RetransmitStats,
        runtime_handle: Handle,
    ) -> Self {
        let (shred_sender, shred_receiver) = crossbeam_channel::unbounded();
        let (request_sender, request_receiver) = crossbeam_channel::unbounded();

        Self {
            endpoint,
            tree: Arc::new(RwLock::new(None)),
            node_id,
            config,
            stats,
            shred_receiver,
            shred_sender,
            request_receiver,
            request_sender,
            running: Arc::new(AtomicBool::new(false)),
            runtime_handle,
            recent_retransmits: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            shred_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update the turbine tree
    pub fn update_tree(&self, tree: TurbineTree) {
        *self.tree.write() = Some(tree);
    }

    /// Submit a shred for retransmission
    pub fn retransmit_shred(
        &self,
        shred: Arc<Shred>,
        received_from: NodeId,
    ) -> Result<(), IngressError> {
        let retransmit_shred = RetransmitShred::new(shred, received_from);
        self.shred_sender
            .send(retransmit_shred)
            .map_err(|e| IngressError::ChannelSend(format!("Failed to queue retransmit: {}", e)))
    }

    /// Request retransmission of a missing shred
    pub fn request_retransmit(
        &self,
        slot: u64,
        index: u32,
        target_peers: Vec<NodeId>,
    ) -> Result<(), IngressError> {
        let request = RetransmitRequest::new(slot, index, target_peers);
        self.request_sender
            .send(request)
            .map_err(|e| IngressError::ChannelSend(format!("Failed to queue request: {}", e)))
    }

    /// Start the retransmit service
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Retransmit service already running");
            return;
        }

        info!("Starting retransmit service for node {}", self.node_id);

        self.start_retransmit_worker();
        self.start_request_worker();
        self.start_cleanup_worker();
    }

    /// Start the retransmit worker
    fn start_retransmit_worker(&self) {
        let receiver = self.shred_receiver.clone();
        let endpoint = Arc::clone(&self.endpoint);
        let tree = Arc::clone(&self.tree);
        let node_id = self.node_id;
        let config = self.config.clone();
        let stats = self.stats.clone();
        let running = Arc::clone(&self.running);
        let recent_retransmits = Arc::clone(&self.recent_retransmits);
        let shred_cache = Arc::clone(&self.shred_cache);

        self.runtime_handle.spawn(async move {
            let mut batch = Vec::new();

            while running.load(Ordering::SeqCst) {
                match receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(retransmit_shred) => {
                        batch.push(retransmit_shred);

                        // Collect more shreds up to batch size
                        while batch.len() < config.retransmit_batch_size {
                            match receiver.try_recv() {
                                Ok(shred) => batch.push(shred),
                                Err(_) => break,
                            }
                        }

                        // Process the batch
                        Self::process_retransmit_batch(
                            &endpoint,
                            &tree,
                            node_id,
                            &stats,
                            &recent_retransmits,
                            &shred_cache,
                            &mut batch,
                        )
                        .await;
                        batch.clear();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        info!("Retransmit channel disconnected");
                        break;
                    }
                }
            }
        });
    }

    /// Start the request worker
    fn start_request_worker(&self) {
        let receiver = self.request_receiver.clone();
        let endpoint = Arc::clone(&self.endpoint);
        let tree = Arc::clone(&self.tree);
        let _config = self.config.clone();
        let running = Arc::clone(&self.running);
        let pending_requests = Arc::clone(&self.pending_requests);

        self.runtime_handle.spawn(async move {
            while running.load(Ordering::SeqCst) {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(request) => {
                        let key = (request.slot, request.index);
                        pending_requests.write().insert(key, request.clone());

                        // Send retransmit request
                        Self::send_retransmit_request(&endpoint, &tree, &request).await;
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        info!("Request channel disconnected");
                        break;
                    }
                }
            }
        });
    }

    /// Start the cleanup worker
    fn start_cleanup_worker(&self) {
        let running = Arc::clone(&self.running);
        let recent_retransmits = Arc::clone(&self.recent_retransmits);
        let pending_requests = Arc::clone(&self.pending_requests);
        let shred_cache = Arc::clone(&self.shred_cache);
        let config = self.config.clone();
        let stats = self.stats.clone();

        self.runtime_handle.spawn(async move {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Clean up old retransmit records
                let now = Instant::now();
                recent_retransmits
                    .write()
                    .retain(|_, timestamp| now.duration_since(*timestamp) < Duration::from_secs(5));

                // Check for timed out requests
                let timeout = Duration::from_millis(config.ack_timeout_ms);
                let mut timed_out = Vec::new();

                {
                    let requests = pending_requests.read();
                    for (key, request) in requests.iter() {
                        if request.is_timed_out(timeout) {
                            if request.retry_count < config.max_retransmit_attempts {
                                timed_out.push((*key, request.clone()));
                            } else {
                                stats.record_timeout();
                            }
                        }
                    }
                }

                // Retry timed out requests
                for (key, mut request) in timed_out {
                    request.retry();
                    pending_requests.write().insert(key, request);
                }

                // Clean up old shred cache entries (keep last 1000 slots)
                let mut cache = shred_cache.write();
                if cache.len() > 10000 {
                    let min_slot = cache.keys().map(|(slot, _)| *slot).min().unwrap_or(0);
                    cache.retain(|(slot, _), _| *slot > min_slot);
                }
            }
        });
    }

    /// Process a batch of shreds for retransmission
    async fn process_retransmit_batch(
        endpoint: &Arc<QuicEndpoint>,
        tree: &Arc<RwLock<Option<TurbineTree>>>,
        node_id: NodeId,
        stats: &RetransmitStats,
        recent_retransmits: &Arc<RwLock<HashMap<(u64, u32), Instant>>>,
        shred_cache: &ShredCache,
        batch: &mut [RetransmitShred],
    ) {
        if batch.is_empty() {
            return;
        }

        // Extract child addresses before any await points
        let child_addrs = {
            let tree_guard = tree.read();
            let Some(ref current_tree) = *tree_guard else {
                debug!("No turbine tree available for retransmit");
                return;
            };

            // Find our children in the tree
            let children = current_tree.get_children(&node_id);
            if children.is_empty() {
                // We're a leaf node, no retransmit needed
                return;
            }

            // Collect child addresses
            let mut addrs = Vec::new();
            for child_id in &children {
                if let Some(node) = current_tree.get_node(child_id) {
                    addrs.push((*child_id, node.contact_info.tpu_quic_addr));
                }
            }

            addrs
        }; // tree_guard dropped here

        let mut total_sent = 0;
        let mut total_bytes = 0;

        for retransmit in batch.iter() {
            let key = (retransmit.shred.slot(), retransmit.shred.index());

            // Check if we recently retransmitted this shred
            if recent_retransmits.read().contains_key(&key) {
                continue;
            }

            // Serialize shred
            let serialized = match bincode::serialize(&*retransmit.shred) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize shred: {}", e);
                    continue;
                }
            };

            let bytes = Bytes::from(serialized);
            total_bytes += bytes.len();

            // Send to all children
            for (child_id, addr) in &child_addrs {
                if let Err(e) = Self::send_to_peer(endpoint, *addr, bytes.clone()).await {
                    warn!("Failed to retransmit to child {}: {}", child_id, e);
                }
            }

            total_sent += 1;

            // Record retransmit
            recent_retransmits.write().insert(key, Instant::now());

            // Cache the shred
            shred_cache
                .write()
                .insert(key, Arc::clone(&retransmit.shred));
        }

        if total_sent > 0 {
            stats.record_retransmit(total_sent, total_bytes as u64);
            debug!(
                "Retransmitted {} shreds ({} bytes) to {} children",
                total_sent,
                total_bytes,
                child_addrs.len()
            );
        }
    }

    /// Send a retransmit request to peers
    async fn send_retransmit_request(
        _endpoint: &Arc<QuicEndpoint>,
        _tree: &Arc<RwLock<Option<TurbineTree>>>,
        request: &RetransmitRequest,
    ) {
        // In a real implementation, this would send a repair request
        // For now, we'll just log it
        debug!(
            "Requesting retransmit for slot {} index {} from {} peers",
            request.slot,
            request.index,
            request.target_peers.len()
        );
    }

    /// Send data to a peer
    async fn send_to_peer(
        _endpoint: &Arc<QuicEndpoint>,
        _addr: SocketAddr,
        _data: Bytes,
    ) -> Result<(), IngressError> {
        // Simplified send implementation
        // In production, this would use QUIC streams
        Ok(())
    }

    /// Stop the retransmit service
    pub fn stop(&self) {
        info!("Stopping retransmit service");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the service is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get a cached shred
    pub fn get_cached_shred(&self, slot: u64, index: u32) -> Option<Arc<Shred>> {
        self.shred_cache.read().get(&(slot, index)).cloned()
    }

    /// Clear old cache entries for slots before the given slot
    pub fn clear_cache_before_slot(&self, slot: u64) -> usize {
        let mut cache = self.shred_cache.write();
        let before = cache.len();
        cache.retain(|(s, _), _| *s >= slot);
        before - cache.len()
    }

    /// Get pending request count
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.read().len()
    }

    /// Clear a pending request (called when shred is received)
    pub fn clear_pending_request(&self, slot: u64, index: u32) -> bool {
        self.pending_requests
            .write()
            .remove(&(slot, index))
            .is_some()
    }
}

impl Drop for RetransmitService {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{QuicConfig, QuicEndpointStats};
    use paradencer_types::shred::{
        DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };

    fn create_node_id(byte: u8) -> NodeId {
        NodeId::new([byte; 32])
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
    fn test_retransmit_request_creation() {
        let peers = vec![create_node_id(1), create_node_id(2)];
        let request = RetransmitRequest::new(100, 5, peers.clone());

        assert_eq!(request.slot, 100);
        assert_eq!(request.index, 5);
        assert_eq!(request.retry_count, 0);
        assert_eq!(request.target_peers.len(), 2);
    }

    #[test]
    fn test_retransmit_request_timeout() {
        let request = RetransmitRequest::new(100, 5, vec![]);
        assert!(!request.is_timed_out(Duration::from_secs(1)));

        std::thread::sleep(Duration::from_millis(100));
        assert!(request.is_timed_out(Duration::from_millis(50)));
    }

    #[test]
    fn test_retransmit_shred_creation() {
        let shred = Arc::new(create_test_shred(100, 5));
        let sender = create_node_id(1);
        let retransmit = RetransmitShred::new(shred, sender);

        assert_eq!(retransmit.shred.slot(), 100);
        assert_eq!(retransmit.shred.index(), 5);
        assert_eq!(retransmit.received_from, sender);
    }

    #[test]
    fn test_retransmit_service_creation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node_id = create_node_id(0);
        let config = QuicConfig::default();
        let endpoint_stats = Arc::new(QuicEndpointStats::default());
        let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
        let turbine_config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(
            node_id,
            endpoint,
            turbine_config,
            stats,
            runtime.handle().clone(),
        );

        assert!(!service.is_running());
        assert_eq!(service.pending_request_count(), 0);
    }

    #[test]
    fn test_shred_cache() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node_id = create_node_id(0);
        let config = QuicConfig::default();
        let endpoint_stats = Arc::new(QuicEndpointStats::default());
        let endpoint = Arc::new(QuicEndpoint::new(config, endpoint_stats).unwrap());
        let turbine_config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(
            node_id,
            endpoint,
            turbine_config,
            stats,
            runtime.handle().clone(),
        );

        let shred = Arc::new(create_test_shred(100, 5));
        service.shred_cache.write().insert((100, 5), shred);

        assert!(service.get_cached_shred(100, 5).is_some());
        assert!(service.get_cached_shred(100, 6).is_none());

        let cleared = service.clear_cache_before_slot(101);
        assert_eq!(cleared, 1);
        assert!(service.get_cached_shred(100, 5).is_none());
    }
}
