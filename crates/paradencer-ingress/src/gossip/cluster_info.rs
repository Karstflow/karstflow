use super::*;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_CLUSTER_SIZE: usize = 5000;
pub const CRDT_UPDATE_INTERVAL_MS: u64 = 100;
pub const GOSSIP_PRUNE_TIMEOUT_MS: u64 = 30_000;

/// Unique identifier for a node in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut hasher = Sha256::new();
        hasher.update(count.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() != 32 {
            return Err(bs58::decode::Error::BufferTooSmall);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_base58()[..8])
    }
}

/// Contact information for a validator node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactInfo {
    pub node_id: NodeId,
    pub gossip_addr: SocketAddr,
    pub tpu_addr: SocketAddr,
    pub tpu_quic_addr: SocketAddr,
    pub repair_addr: SocketAddr,
    pub rpc_addr: Option<SocketAddr>,
    pub version: u64,
    pub wallclock: u64,
    pub shred_version: u16,
}

impl ContactInfo {
    pub fn new(
        node_id: NodeId,
        gossip_addr: SocketAddr,
        tpu_addr: SocketAddr,
        tpu_quic_addr: SocketAddr,
        repair_addr: SocketAddr,
        shred_version: u16,
    ) -> Self {
        Self {
            node_id,
            gossip_addr,
            tpu_addr,
            tpu_quic_addr,
            repair_addr,
            rpc_addr: None,
            version: 0,
            wallclock: current_timestamp_ms(),
            shred_version,
        }
    }

    pub fn with_rpc_addr(mut self, rpc_addr: SocketAddr) -> Self {
        self.rpc_addr = Some(rpc_addr);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.wallclock > 0 && self.version > 0
    }

    pub fn increment_version(&mut self) {
        self.version += 1;
        self.wallclock = current_timestamp_ms();
    }
}

/// Validator information with stake and performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub contact_info: ContactInfo,
    pub stake: u64,
    #[serde(skip, default = "Instant::now")]
    pub last_seen: Instant,
    pub is_active: bool,
}

impl ValidatorInfo {
    pub fn new(contact_info: ContactInfo, stake: u64) -> Self {
        Self {
            contact_info,
            stake,
            last_seen: Instant::now(),
            is_active: true,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Gossip node with routing information
#[derive(Debug, Clone)]
pub struct GossipNode {
    pub info: ValidatorInfo,
    pub failed_pushes: u64,
    pub last_push_attempt: Instant,
}

impl GossipNode {
    pub fn new(info: ValidatorInfo) -> Self {
        Self {
            info,
            failed_pushes: 0,
            last_push_attempt: Instant::now(),
        }
    }

    pub fn record_push_success(&mut self) {
        self.failed_pushes = 0;
        self.last_push_attempt = Instant::now();
    }

    pub fn record_push_failure(&mut self) {
        self.failed_pushes += 1;
        self.last_push_attempt = Instant::now();
    }

    pub fn should_retry(&self, backoff: Duration) -> bool {
        self.last_push_attempt.elapsed() > backoff
    }
}

/// Cluster information storage with CRDT semantics
pub struct ClusterInfo {
    node_id: NodeId,
    self_contact_info: Arc<RwLock<ContactInfo>>,
    nodes: Arc<RwLock<HashMap<NodeId, GossipNode>>>,
    prune_timeout: Duration,
    max_nodes: usize,
}

impl ClusterInfo {
    pub fn new(
        node_id: NodeId,
        contact_info: ContactInfo,
        prune_timeout: Duration,
        max_nodes: usize,
    ) -> Self {
        Self {
            node_id,
            self_contact_info: Arc::new(RwLock::new(contact_info)),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            prune_timeout,
            max_nodes,
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn self_contact_info(&self) -> ContactInfo {
        self.self_contact_info.read().clone()
    }

    pub fn update_self_contact_info<F>(&self, update_fn: F)
    where
        F: FnOnce(&mut ContactInfo),
    {
        let mut info = self.self_contact_info.write();
        update_fn(&mut info);
        info.increment_version();
    }

    /// Insert or update contact info using CRDT merge logic
    pub fn insert(&self, contact_info: ContactInfo) -> bool {
        if contact_info.node_id == self.node_id {
            return false;
        }

        let mut nodes = self.nodes.write();

        // Check size limit
        if nodes.len() >= self.max_nodes && !nodes.contains_key(&contact_info.node_id) {
            return false;
        }

        let should_insert = match nodes.get(&contact_info.node_id) {
            Some(existing) => {
                // CRDT merge: higher version or wallclock wins
                if contact_info.version > existing.info.contact_info.version {
                    true
                } else if contact_info.version == existing.info.contact_info.version {
                    contact_info.wallclock > existing.info.contact_info.wallclock
                } else {
                    false
                }
            }
            None => true,
        };

        if should_insert {
            let validator_info = ValidatorInfo::new(contact_info, 0);
            nodes.insert(
                validator_info.contact_info.node_id,
                GossipNode::new(validator_info),
            );
            true
        } else {
            false
        }
    }

    /// Insert multiple contact infos (batch operation)
    pub fn insert_batch(&self, infos: Vec<ContactInfo>) -> usize {
        let mut count = 0;
        for info in infos {
            if self.insert(info) {
                count += 1;
            }
        }
        count
    }

    /// Get a contact info by node ID
    pub fn get(&self, node_id: &NodeId) -> Option<ContactInfo> {
        self.nodes
            .read()
            .get(node_id)
            .map(|node| node.info.contact_info.clone())
    }

    /// Get all contact infos
    pub fn get_all(&self) -> Vec<ContactInfo> {
        self.nodes
            .read()
            .values()
            .map(|node| node.info.contact_info.clone())
            .collect()
    }

    /// Get random subset of nodes for push gossip
    pub fn get_random_nodes(&self, count: usize, exclude: &HashSet<NodeId>) -> Vec<ContactInfo> {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let nodes = self.nodes.read();
        let mut candidates: Vec<_> = nodes
            .values()
            .filter(|node| {
                !exclude.contains(&node.info.contact_info.node_id)
                    && node.info.is_active
                    && !node.info.is_stale(self.prune_timeout)
            })
            .map(|node| node.info.contact_info.clone())
            .collect();

        candidates.shuffle(&mut thread_rng());
        candidates.truncate(count);
        candidates
    }

    /// Get all active nodes
    pub fn get_active_nodes(&self) -> Vec<ContactInfo> {
        self.nodes
            .read()
            .values()
            .filter(|node| node.info.is_active && !node.info.is_stale(self.prune_timeout))
            .map(|node| node.info.contact_info.clone())
            .collect()
    }

    /// Prune stale nodes
    pub fn prune_stale_nodes(&self) -> usize {
        let mut nodes = self.nodes.write();
        let before_count = nodes.len();

        nodes.retain(|_, node| !node.info.is_stale(self.prune_timeout));

        before_count - nodes.len()
    }

    /// Update node last seen time
    pub fn update_last_seen(&self, node_id: &NodeId) {
        if let Some(node) = self.nodes.write().get_mut(node_id) {
            node.info.update_last_seen();
        }
    }

    /// Record push success for a node
    pub fn record_push_success(&self, node_id: &NodeId) {
        if let Some(node) = self.nodes.write().get_mut(node_id) {
            node.record_push_success();
        }
    }

    /// Record push failure for a node
    pub fn record_push_failure(&self, node_id: &NodeId) {
        if let Some(node) = self.nodes.write().get_mut(node_id) {
            node.record_push_failure();
        }
    }

    /// Get cluster size
    pub fn size(&self) -> usize {
        self.nodes.read().len()
    }

    /// Clear all nodes
    pub fn clear(&self) {
        self.nodes.write().clear();
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    #[test]
    fn test_node_id_creation() {
        let bytes = [1u8; 32];
        let node_id = NodeId::new(bytes);
        assert_eq!(node_id.as_bytes(), &bytes);
    }

    #[test]
    fn test_node_id_base58() {
        let node_id = NodeId::new([0u8; 32]);
        let base58 = node_id.to_base58();
        let decoded = NodeId::from_base58(&base58).unwrap();
        assert_eq!(node_id, decoded);
    }

    #[test]
    fn test_contact_info_creation() {
        let node_id = NodeId::new([1u8; 32]);
        let info = create_test_contact_info(node_id, 8000);
        assert_eq!(info.node_id, node_id);
        assert_eq!(info.version, 0);
        assert!(info.wallclock > 0);
    }

    #[test]
    fn test_cluster_info_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let peer_node_id = NodeId::new([1u8; 32]);
        let peer_info = create_test_contact_info(peer_node_id, 8001);
        assert!(cluster.insert(peer_info.clone()));
        assert_eq!(cluster.size(), 1);

        let retrieved = cluster.get(&peer_node_id).unwrap();
        assert_eq!(retrieved.node_id, peer_node_id);
    }

    #[test]
    fn test_cluster_info_crdt_merge() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let peer_node_id = NodeId::new([1u8; 32]);
        let mut peer_info_v1 = create_test_contact_info(peer_node_id, 8001);
        peer_info_v1.version = 1;
        assert!(cluster.insert(peer_info_v1));

        let mut peer_info_v2 = create_test_contact_info(peer_node_id, 8002);
        peer_info_v2.version = 2;
        assert!(cluster.insert(peer_info_v2.clone()));

        let retrieved = cluster.get(&peer_node_id).unwrap();
        assert_eq!(retrieved.gossip_addr.port(), 8002);
        assert_eq!(retrieved.version, 2);
    }

    #[test]
    fn test_cluster_info_no_self_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info.clone(),
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        assert!(!cluster.insert(self_info));
        assert_eq!(cluster.size(), 0);
    }

    #[test]
    fn test_cluster_info_batch_insert() {
        let self_node_id = NodeId::new([0u8; 32]);
        let self_info = create_test_contact_info(self_node_id, 8000);
        let cluster = ClusterInfo::new(
            self_node_id,
            self_info,
            Duration::from_secs(30),
            MAX_CLUSTER_SIZE,
        );

        let infos: Vec<_> = (1..=10)
            .map(|i| {
                let node_id = NodeId::new([i as u8; 32]);
                create_test_contact_info(node_id, 8000 + i)
            })
            .collect();

        let count = cluster.insert_batch(infos);
        assert_eq!(count, 10);
        assert_eq!(cluster.size(), 10);
    }
}
