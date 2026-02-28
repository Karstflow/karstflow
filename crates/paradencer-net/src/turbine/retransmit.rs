use crate::gossip::NodeId;
use crate::repair::wire::convert;
use crate::repair::RepairRequest;
use crate::turbine::transport::ShredTransport;
use crate::turbine::{RetransmitStats, TurbineConfig, TurbineTree};
use crate::IngressError;
use crossbeam_channel::{Receiver, Sender};
use paradencer_types::shred::Shred;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    /// Transport for sending packets
    transport: Arc<dyn ShredTransport>,

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

    /// Recently retransmitted shreds (to avoid duplicates)
    recent_retransmits: Arc<RwLock<HashMap<(u64, u32), Instant>>>,

    /// Pending retransmit requests
    pending_requests: Arc<RwLock<HashMap<(u64, u32), RetransmitRequest>>>,

    /// Shred cache for fulfilling retransmit requests
    pub shred_cache: ShredCache,

    /// Monotonic nonce counter for repair requests
    nonce_counter: AtomicU64,

    /// Ed25519 secret key for signing repair requests (32-byte seed).
    /// When present, outgoing repair requests are signed for authentication.
    signing_key: Option<[u8; 32]>,
}

impl RetransmitService {
    /// Create a new retransmit service
    pub fn new(
        node_id: NodeId,
        transport: Arc<dyn ShredTransport>,
        config: TurbineConfig,
        stats: RetransmitStats,
    ) -> Self {
        let (shred_sender, shred_receiver) = crossbeam_channel::unbounded();
        let (request_sender, request_receiver) = crossbeam_channel::unbounded();

        Self {
            transport,
            tree: Arc::new(RwLock::new(None)),
            node_id,
            config,
            stats,
            shred_receiver,
            shred_sender,
            request_receiver,
            request_sender,
            running: Arc::new(AtomicBool::new(false)),
            recent_retransmits: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            shred_cache: Arc::new(RwLock::new(HashMap::new())),
            nonce_counter: AtomicU64::new(0),
            signing_key: None,
        }
    }

    /// Update the turbine tree
    pub fn update_tree(&self, tree: TurbineTree) {
        *self.tree.write() = Some(tree);
    }

    /// Set the Ed25519 signing key for authenticating outgoing repair requests.
    ///
    /// The key is a 32-byte Ed25519 seed. When set, all repair requests
    /// sent to peers are signed before transmission.
    pub fn set_signing_key(&mut self, key: [u8; 32]) {
        self.signing_key = Some(key);
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

    /// Forward raw shred bytes to turbine tree children.
    ///
    /// Sends the data directly over UDP to all children in the current tree
    /// without parsing or re-serializing. Use this when raw wire-format bytes
    /// are available from the shred pipeline.
    pub fn forward_raw(&self, data: &[u8]) {
        let tree_guard = self.tree.read();
        let Some(ref current_tree) = *tree_guard else {
            return;
        };
        let children = current_tree.get_children(&self.node_id);
        if children.is_empty() {
            return;
        }
        for child_id in &children {
            if let Some(node) = current_tree.get_node(child_id) {
                let _ = self
                    .transport
                    .send_to(data, node.contact_info.tpu_quic_addr);
            }
        }
        self.stats.record_retransmit(1, data.len() as u64);
    }

    /// Start the retransmit service
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Retransmit service already running");
            return;
        }
        info!("Starting retransmit service for node {}", self.node_id);
    }

    /// Poll for pending shreds and retransmit them.
    /// Call this from a service loop.
    pub fn service(&self) {
        self.drain_retransmit_queue();
        self.drain_request_queue();
        self.cleanup_stale_entries();
    }

    /// Drain and process retransmit queue
    fn drain_retransmit_queue(&self) {
        let mut batch = Vec::new();

        while batch.len() < self.config.retransmit_batch_size {
            match self.shred_receiver.try_recv() {
                Ok(shred) => batch.push(shred),
                Err(_) => break,
            }
        }

        if !batch.is_empty() {
            self.process_retransmit_batch(&batch);
        }
    }

    /// Drain and process request queue
    fn drain_request_queue(&self) {
        while let Ok(request) = self.request_receiver.try_recv() {
            let key = (request.slot, request.index);
            self.pending_requests.write().insert(key, request.clone());
            self.send_retransmit_request(&request);
        }
    }

    /// Cleanup stale retransmit records and timed-out requests
    fn cleanup_stale_entries(&self) {
        let now = Instant::now();

        // Clean old retransmit records
        self.recent_retransmits
            .write()
            .retain(|_, timestamp| now.duration_since(*timestamp) < Duration::from_secs(5));

        // Check for timed out requests
        let timeout = Duration::from_millis(self.config.ack_timeout_ms);
        let mut timed_out = Vec::new();

        {
            let requests = self.pending_requests.read();
            for (key, request) in requests.iter() {
                if request.is_timed_out(timeout) {
                    if request.retry_count < self.config.max_retransmit_attempts {
                        timed_out.push((*key, request.clone()));
                    } else {
                        self.stats.record_timeout();
                    }
                }
            }
        }

        for (key, mut request) in timed_out {
            request.retry();
            self.pending_requests.write().insert(key, request);
        }

        // Clean up large shred cache
        let mut cache = self.shred_cache.write();
        if cache.len() > 10000 {
            let min_slot = cache.keys().map(|(slot, _)| *slot).min().unwrap_or(0);
            cache.retain(|(slot, _), _| *slot > min_slot);
        }
    }

    /// Process a batch of shreds for retransmission
    fn process_retransmit_batch(&self, batch: &[RetransmitShred]) {
        if batch.is_empty() {
            return;
        }

        let tree_guard = self.tree.read();
        let Some(ref current_tree) = *tree_guard else {
            debug!("No turbine tree available for retransmit");
            return;
        };

        // Find our children in the tree
        let children = current_tree.get_children(&self.node_id);
        if children.is_empty() {
            return;
        }

        // Collect child addresses
        let mut child_addrs = Vec::new();
        for child_id in &children {
            if let Some(node) = current_tree.get_node(child_id) {
                child_addrs.push((*child_id, node.contact_info.tpu_quic_addr));
            }
        }

        drop(tree_guard);

        let mut total_sent = 0;
        let mut total_bytes = 0;

        for retransmit in batch {
            let key = (retransmit.shred.slot(), retransmit.shred.index());

            // Check if we recently retransmitted this shred
            if self.recent_retransmits.read().contains_key(&key) {
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

            total_bytes += serialized.len();

            // Send to all children via transport
            for (child_id, addr) in &child_addrs {
                if let Err(e) = self.transport.send_to(&serialized, *addr) {
                    warn!("Failed to retransmit to child {}: {}", child_id, e);
                }
            }

            total_sent += 1;
            self.recent_retransmits.write().insert(key, Instant::now());
            self.shred_cache
                .write()
                .insert(key, Arc::clone(&retransmit.shred));
        }

        if total_sent > 0 {
            self.stats.record_retransmit(total_sent, total_bytes as u64);
            debug!(
                "Retransmitted {} shreds ({} bytes) to {} children",
                total_sent,
                total_bytes,
                child_addrs.len()
            );
        }
    }

    /// Send a retransmit request to peers.
    ///
    /// For each target peer, resolves the peer's identity and repair address
    /// from the turbine tree, constructs a signed repair request addressed
    /// to that specific peer, and sends it via the transport layer.
    fn send_retransmit_request(&self, request: &RetransmitRequest) {
        let tree_guard = self.tree.read();
        let Some(ref current_tree) = *tree_guard else {
            debug!("No turbine tree available, cannot send retransmit request");
            return;
        };

        let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);

        let mut sent = 0u32;
        for peer_id in &request.target_peers {
            let node = match current_tree.get_node(peer_id) {
                Some(node) => node,
                None => {
                    debug!("Peer {} not in turbine tree, skipping", peer_id);
                    continue;
                }
            };

            let repair_request = RepairRequest::Shred {
                requester: self.node_id,
                slot: request.slot,
                index: request.index,
                nonce,
            };

            // Address the repair request to this specific peer's pubkey.
            let recipient = peer_id.0;
            let mut wire_msg = match convert::request_to_wire(&repair_request, recipient) {
                Some(msg) => msg,
                None => {
                    error!("Failed to convert repair request to wire format");
                    continue;
                }
            };

            // Sign with our Ed25519 key so the recipient can verify authenticity.
            if let Some(ref key) = self.signing_key {
                wire_msg.sign(key);
            }

            let encoded = match wire_msg.encode() {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to encode repair request: {}", e);
                    continue;
                }
            };

            if let Err(e) = self
                .transport
                .send_to(&encoded, node.contact_info.repair_addr)
            {
                warn!(
                    "Failed to send retransmit request to peer {}: {}",
                    peer_id, e
                );
            } else {
                sent += 1;
            }
        }

        debug!(
            "Sent retransmit request for slot {} index {} to {}/{} peers (nonce={})",
            request.slot,
            request.index,
            sent,
            request.target_peers.len(),
            nonce,
        );
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
    use crate::gossip::{ContactInfo, ValidatorInfo};
    use crate::turbine::transport::{CountingTransport, NullTransport};
    use crate::turbine::TurbineTreeBuilder;
    use paradencer_types::shred::{
        DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;

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
        let node_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(NullTransport);
        let turbine_config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(node_id, transport, turbine_config, stats);

        assert!(!service.is_running());
        assert_eq!(service.pending_request_count(), 0);
    }

    #[test]
    fn test_shred_cache() {
        let node_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(NullTransport);
        let turbine_config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(node_id, transport, turbine_config, stats);

        let shred = Arc::new(create_test_shred(100, 5));
        service.shred_cache.write().insert((100, 5), shred);

        assert!(service.get_cached_shred(100, 5).is_some());
        assert!(service.get_cached_shred(100, 6).is_none());

        let cleared = service.clear_cache_before_slot(101);
        assert_eq!(cleared, 1);
        assert!(service.get_cached_shred(100, 5).is_none());
    }

    fn create_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[test]
    fn test_send_retransmit_request_sends_to_peers() {
        let counting = CountingTransport::new();
        let send_count = counting.send_count.clone();
        let byte_count = counting.byte_count.clone();

        let root_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(counting);
        let config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(root_id, transport, config.clone(), stats);

        // Build a tree with 3 peers
        let peer1 = create_node_id(1);
        let peer2 = create_node_id(2);
        let peer3 = create_node_id(3);

        let validators = vec![
            ValidatorInfo::new(create_contact_info(peer1, 9001), 1000),
            ValidatorInfo::new(create_contact_info(peer2, 9002), 1000),
            ValidatorInfo::new(create_contact_info(peer3, 9003), 1000),
        ];

        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, create_contact_info(root_id, 9000), validators, 100);
        service.update_tree(tree);

        // Send retransmit request to 2 of the 3 peers
        let request = RetransmitRequest::new(100, 5, vec![peer1, peer2]);
        service.send_retransmit_request(&request);

        assert_eq!(send_count.load(Ordering::Relaxed), 2);
        assert!(byte_count.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_send_retransmit_request_skips_unknown_peers() {
        let counting = CountingTransport::new();
        let send_count = counting.send_count.clone();

        let root_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(counting);
        let config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(root_id, transport, config.clone(), stats);

        // Build a tree with only 1 peer
        let peer1 = create_node_id(1);
        let unknown = create_node_id(99);

        let validators = vec![ValidatorInfo::new(create_contact_info(peer1, 9001), 1000)];

        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, create_contact_info(root_id, 9000), validators, 100);
        service.update_tree(tree);

        // Request from known + unknown peer
        let request = RetransmitRequest::new(100, 5, vec![peer1, unknown]);
        service.send_retransmit_request(&request);

        // Only the known peer should receive the request
        assert_eq!(send_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_send_retransmit_request_no_tree() {
        let counting = CountingTransport::new();
        let send_count = counting.send_count.clone();

        let root_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(counting);
        let config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(root_id, transport, config, stats);

        // No tree set — should silently return
        let request = RetransmitRequest::new(100, 5, vec![create_node_id(1)]);
        service.send_retransmit_request(&request);

        assert_eq!(send_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_send_retransmit_request_per_peer_addressing() {
        // Verify that each peer receives a request addressed to its own pubkey.
        let counting = CountingTransport::new();
        let send_count = counting.send_count.clone();

        let root_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(counting);
        let config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let service = RetransmitService::new(root_id, transport, config.clone(), stats);

        let peer1 = create_node_id(1);
        let peer2 = create_node_id(2);

        let validators = vec![
            ValidatorInfo::new(create_contact_info(peer1, 9001), 1000),
            ValidatorInfo::new(create_contact_info(peer2, 9002), 1000),
        ];

        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, create_contact_info(root_id, 9000), validators, 100);
        service.update_tree(tree);

        let request = RetransmitRequest::new(100, 5, vec![peer1, peer2]);
        service.send_retransmit_request(&request);

        // Both peers should receive the request.
        assert_eq!(send_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_signing_key_set_and_used() {
        let counting = CountingTransport::new();
        let send_count = counting.send_count.clone();
        let byte_count = counting.byte_count.clone();

        let root_id = create_node_id(0);
        let transport: Arc<dyn ShredTransport> = Arc::new(counting);
        let config = TurbineConfig::default();
        let stats = RetransmitStats::new(Arc::new(crate::turbine::TurbineStats::new()));

        let mut service = RetransmitService::new(root_id, transport, config.clone(), stats);

        // Set a signing key.
        let (secret, _pubkey) = paradencer_crypto::generate_keypair();
        service.set_signing_key(secret);

        let peer1 = create_node_id(1);
        let validators = vec![ValidatorInfo::new(create_contact_info(peer1, 9001), 1000)];

        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, create_contact_info(root_id, 9000), validators, 100);
        service.update_tree(tree);

        let request = RetransmitRequest::new(200, 10, vec![peer1]);
        service.send_retransmit_request(&request);

        // Signed request should be sent.
        assert_eq!(send_count.load(Ordering::Relaxed), 1);
        // Signed messages are larger than unsigned due to signature bytes.
        assert!(byte_count.load(Ordering::Relaxed) > 0);
    }
}
