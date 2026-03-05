use super::*;
use crate::gossip::NodeId;
use crate::repair::protocol::{RepairRequest, ShredData};
use crate::repair::wire::convert;
use crate::repair::wire::protocol::WireRepairProtocol;
use crate::repair::wire::response;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

const DEFAULT_RATE_LIMIT_PER_PEER: u64 = 100; // requests per second
const RATE_LIMIT_WINDOW_MS: u64 = 1000;

/// Configuration for repair server
#[derive(Debug, Clone)]
pub struct RepairServerConfig {
    pub bind_addr: SocketAddr,
    pub rate_limit_per_peer: u64,
    pub rate_limit_window: Duration,
    pub max_response_size: usize,
}

impl Default for RepairServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8002".parse().expect("valid socket addr literal"),
            rate_limit_per_peer: DEFAULT_RATE_LIMIT_PER_PEER,
            rate_limit_window: Duration::from_millis(RATE_LIMIT_WINDOW_MS),
            max_response_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

/// Statistics for repair server
#[derive(Debug, Clone)]
pub struct RepairServerStats {
    pub requests_received: Arc<AtomicU64>,
    pub responses_sent: Arc<AtomicU64>,
    pub errors_sent: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    pub shreds_served: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub signature_failures: Arc<AtomicU64>,
    pub timestamp_failures: Arc<AtomicU64>,
}

impl RepairServerStats {
    pub fn new() -> Self {
        Self {
            requests_received: Arc::new(AtomicU64::new(0)),
            responses_sent: Arc::new(AtomicU64::new(0)),
            errors_sent: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            shreds_served: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            signature_failures: Arc::new(AtomicU64::new(0)),
            timestamp_failures: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for RepairServerStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for repair requests
struct RateLimiter {
    requests: HashMap<SocketAddr, (u64, Instant)>,
    limit: u64,
    window: Duration,
}

impl RateLimiter {
    fn new(limit: u64, window: Duration) -> Self {
        Self {
            requests: HashMap::new(),
            limit,
            window,
        }
    }

    fn check_and_increment(&mut self, addr: &SocketAddr) -> bool {
        let now = Instant::now();

        let entry = self.requests.entry(*addr).or_insert((0, now));

        if now.duration_since(entry.1) > self.window {
            *entry = (1, now);
            true
        } else if entry.0 < self.limit {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.requests
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) <= self.window);
    }
}

/// Trait for providing shred data to the repair server.
///
/// Implementations back different storage strategies: in-memory for testing,
/// blockstore-backed for production. The `get_ancestor_hashes` method enables
/// proper AncestorHashes responses with real bank hashes.
pub trait ShredProvider: Send + Sync {
    fn get_shred(&self, slot: Slot, index: ShredIndex) -> Option<ShredData>;
    fn get_highest_shred_index(&self, slot: Slot) -> Option<ShredIndex>;
    fn get_shreds_in_range(&self, start_slot: Slot, end_slot: Slot) -> Vec<ShredData>;
    fn get_ancestors(&self, slot: Slot, count: u64) -> Vec<ShredData>;

    /// Get ancestor slot hashes for the AncestorHashes repair protocol.
    ///
    /// Returns up to `count` ancestor (slot, bank_hash) pairs starting from
    /// the parent of `slot`. Production implementations should return real
    /// bank hashes from the committed ledger.
    ///
    /// Default: derives placeholder hashes from ancestor shred data.
    fn get_ancestor_hashes(&self, slot: Slot, count: u64) -> Vec<(Slot, [u8; 32])> {
        let ancestors = self.get_ancestors(slot, count);
        ancestors
            .iter()
            .map(|s| {
                let mut hash = [0u8; 32];
                let copy_len = s.data.len().min(32);
                hash[..copy_len].copy_from_slice(&s.data[..copy_len]);
                (s.slot, hash)
            })
            .collect()
    }
}

/// Simple in-memory shred store for testing
pub struct InMemoryShredStore {
    shreds: Arc<RwLock<HashMap<(Slot, ShredIndex), ShredData>>>,
    highest_indices: Arc<RwLock<HashMap<Slot, ShredIndex>>>,
}

impl InMemoryShredStore {
    pub fn new() -> Self {
        Self {
            shreds: Arc::new(RwLock::new(HashMap::new())),
            highest_indices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, shred: ShredData) {
        let key = (shred.slot, shred.index);
        self.shreds.write().insert(key, shred.clone());

        let mut indices = self.highest_indices.write();
        let current = indices.entry(shred.slot).or_insert(0);
        if shred.index > *current {
            *current = shred.index;
        }
    }
}

impl Default for InMemoryShredStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ShredProvider for InMemoryShredStore {
    fn get_shred(&self, slot: Slot, index: ShredIndex) -> Option<ShredData> {
        self.shreds.read().get(&(slot, index)).cloned()
    }

    fn get_highest_shred_index(&self, slot: Slot) -> Option<ShredIndex> {
        self.highest_indices.read().get(&slot).copied()
    }

    fn get_shreds_in_range(&self, start_slot: Slot, end_slot: Slot) -> Vec<ShredData> {
        let shreds = self.shreds.read();
        shreds
            .iter()
            .filter(|((slot, _), _)| *slot >= start_slot && *slot <= end_slot)
            .map(|(_, shred)| shred.clone())
            .collect()
    }

    fn get_ancestors(&self, slot: Slot, count: u64) -> Vec<ShredData> {
        let shreds = self.shreds.read();
        let mut result = Vec::new();

        for ancestor_slot in (slot.saturating_sub(count)..slot).rev() {
            let ancestor_shreds: Vec<_> = shreds
                .iter()
                .filter(|((s, _), _)| *s == ancestor_slot)
                .map(|(_, shred)| shred.clone())
                .collect();
            result.extend(ancestor_shreds);
        }

        result
    }
}

/// Repair server for serving repair requests.
///
/// Decodes wire-format repair requests, verifies Ed25519 signatures and
/// timestamp freshness, then serves shred data in wire-compatible format
/// (raw shred bytes + u32 nonce appended).
pub struct RepairServer {
    node_id: NodeId,
    #[allow(dead_code)]
    config: RepairServerConfig,
    stats: RepairServerStats,
    socket: Arc<UdpSocket>,
    shred_provider: Arc<dyn ShredProvider>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

impl RepairServer {
    pub async fn new(
        node_id: NodeId,
        config: RepairServerConfig,
        shred_provider: Arc<dyn ShredProvider>,
    ) -> RepairResult<Self> {
        let socket = UdpSocket::bind(config.bind_addr).await.map_err(|e| {
            IngressError::QuicEndpointBind {
                detail: format!("failed to bind repair server socket: {}", e),
            }
        })?;

        let rate_limiter = RateLimiter::new(config.rate_limit_per_peer, config.rate_limit_window);

        Ok(Self {
            node_id,
            config,
            stats: RepairServerStats::new(),
            socket: Arc::new(socket),
            shred_provider,
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
        })
    }

    pub fn stats(&self) -> &RepairServerStats {
        &self.stats
    }

    pub fn local_addr(&self) -> RepairResult<SocketAddr> {
        self.socket.local_addr().map_err(|e| IngressError::QuicIo {
            detail: format!("failed to get local addr: {}", e),
        })
    }

    /// Start the repair server
    pub async fn start(&self) {
        let socket = Arc::clone(&self.socket);
        let stats = self.stats.clone();
        let shred_provider = Arc::clone(&self.shred_provider);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let node_id = self.node_id;

        tokio::spawn(async move {
            Self::serve_loop(socket, node_id, stats, shred_provider, rate_limiter).await;
        });

        let cleanup_rate_limiter = Arc::clone(&self.rate_limiter);
        tokio::spawn(async move {
            Self::cleanup_loop(cleanup_rate_limiter).await;
        });
    }

    async fn serve_loop(
        socket: Arc<UdpSocket>,
        node_id: NodeId,
        stats: RepairServerStats,
        shred_provider: Arc<dyn ShredProvider>,
        rate_limiter: Arc<RwLock<RateLimiter>>,
    ) {
        let mut buf = vec![0u8; 65536];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    stats
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    if !rate_limiter.write().check_and_increment(&src_addr) {
                        stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let data = &buf[..len];

                    // Decode wire-format repair request
                    let wire_msg = match WireRepairProtocol::decode(data) {
                        Ok(msg) => msg,
                        Err(_) => continue,
                    };

                    // Verify signature on modern (signed) variants
                    if wire_msg.sender().is_some() && !wire_msg.verify() {
                        stats.signature_failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Check timestamp freshness
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    if !wire_msg.is_timestamp_valid(now_ms) {
                        stats.timestamp_failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Extract nonce for response
                    let nonce = wire_msg.nonce().unwrap_or(0);

                    // Handle Pong separately (no response needed)
                    if let WireRepairProtocol::Pong(ref pong) = wire_msg {
                        if pong.verify() {
                            tracing::debug!("received valid repair pong from {:?}", src_addr);
                        }
                        continue;
                    }

                    // Convert to internal request
                    let request = match convert::wire_to_request(&wire_msg) {
                        Some(req) => req,
                        None => continue,
                    };

                    stats.requests_received.fetch_add(1, Ordering::Relaxed);

                    // Handle request and encode wire response
                    let response_bytes =
                        Self::handle_request_wire(node_id, request, &shred_provider, &stats, nonce);

                    if let Some(bytes) = response_bytes {
                        let _ = socket.send_to(&bytes, src_addr).await;
                        stats
                            .bytes_sent
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        stats.responses_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Handle a repair request and return wire-format response bytes.
    fn handle_request_wire(
        _node_id: NodeId,
        request: RepairRequest,
        shred_provider: &Arc<dyn ShredProvider>,
        stats: &RepairServerStats,
        nonce: u32,
    ) -> Option<Vec<u8>> {
        match request {
            RepairRequest::Shred { slot, index, .. } => {
                if let Some(shred) = shred_provider.get_shred(slot, index) {
                    stats.shreds_served.fetch_add(1, Ordering::Relaxed);
                    Some(response::encode_shred_response(&shred.data, nonce))
                } else {
                    None // No response for missing shreds
                }
            }
            RepairRequest::HighestShred { slot, .. } => {
                // Return the highest shred for this slot
                if let Some(highest_index) = shred_provider.get_highest_shred_index(slot) {
                    if let Some(shred) = shred_provider.get_shred(slot, highest_index) {
                        stats.shreds_served.fetch_add(1, Ordering::Relaxed);
                        return Some(response::encode_shred_response(&shred.data, nonce));
                    }
                }
                None
            }
            RepairRequest::Orphan { slot, .. } => {
                // Return ancestor shreds (up to MAX_ORPHAN_REPAIR_RESPONSES)
                let ancestors = shred_provider.get_ancestors(
                    slot,
                    paradencer_constants::repair::MAX_ORPHAN_REPAIR_RESPONSES as u64,
                );
                if let Some(first) = ancestors.first() {
                    stats.shreds_served.fetch_add(1, Ordering::Relaxed);
                    Some(response::encode_shred_response(&first.data, nonce))
                } else {
                    None
                }
            }
            RepairRequest::Ancestor { slot, .. } => {
                // AncestorHashes: return Vec<(Slot, Hash)>.
                // Production implementations return real bank hashes.
                let hashes = shred_provider.get_ancestor_hashes(
                    slot,
                    paradencer_constants::repair::MAX_ANCESTOR_HASHES_RESPONSE as u64,
                );
                let resp = response::WireAncestorHashesResponse::Hashes(hashes);
                Some(response::encode_ancestor_response(&resp, nonce))
            }
            RepairRequest::SlotRange { .. } => {
                // SlotRange has no Solana wire equivalent
                stats.errors_sent.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    async fn cleanup_loop(rate_limiter: Arc<RwLock<RateLimiter>>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            rate_limiter.write().cleanup_stale();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10, Duration::from_secs(1));
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        for _ in 0..10 {
            assert!(limiter.check_and_increment(&addr));
        }

        assert!(!limiter.check_and_increment(&addr));
    }

    #[test]
    fn test_in_memory_shred_store() {
        let store = InMemoryShredStore::new();
        let shred = ShredData::new(100, 5, vec![1, 2, 3], false);

        store.insert(shred.clone());

        let retrieved = store.get_shred(100, 5);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, vec![1, 2, 3]);

        let highest = store.get_highest_shred_index(100);
        assert_eq!(highest, Some(5));
    }

    #[test]
    fn test_shred_provider_range() {
        let store = InMemoryShredStore::new();

        for slot in 100..110 {
            for index in 0..5 {
                let shred = ShredData::new(slot, index, vec![slot as u8, index as u8], false);
                store.insert(shred);
            }
        }

        let shreds = store.get_shreds_in_range(105, 107);
        assert!(!shreds.is_empty());
        assert!(shreds.iter().all(|s| s.slot >= 105 && s.slot <= 107));
    }

    #[test]
    fn test_handle_shred_request_wire() {
        let store = Arc::new(InMemoryShredStore::new());
        store.insert(ShredData::new(100, 5, vec![0xAB; 64], false));

        let node_id = NodeId::new([1u8; 32]);
        let stats = RepairServerStats::new();

        let request = RepairRequest::Shred {
            requester: NodeId::new([2u8; 32]),
            slot: 100,
            index: 5,
            nonce: 42,
        };

        let response_bytes = RepairServer::handle_request_wire(
            node_id,
            request,
            &(store as Arc<dyn ShredProvider>),
            &stats,
            42,
        );

        let bytes = response_bytes.expect("should have response");
        let (payload, nonce) = response::decode_shred_response(&bytes).unwrap();
        assert_eq!(payload, &[0xAB; 64]);
        assert_eq!(nonce, 42);
        assert_eq!(stats.shreds_served.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_handle_missing_shred_returns_none() {
        let store = Arc::new(InMemoryShredStore::new());
        let node_id = NodeId::new([1u8; 32]);
        let stats = RepairServerStats::new();

        let request = RepairRequest::Shred {
            requester: NodeId::new([2u8; 32]),
            slot: 999,
            index: 0,
            nonce: 1,
        };

        let response_bytes = RepairServer::handle_request_wire(
            node_id,
            request,
            &(store as Arc<dyn ShredProvider>),
            &stats,
            1,
        );
        assert!(response_bytes.is_none());
    }

    #[test]
    fn test_handle_highest_shred_wire() {
        let store = Arc::new(InMemoryShredStore::new());
        store.insert(ShredData::new(100, 3, vec![0x11; 32], false));
        store.insert(ShredData::new(100, 7, vec![0x22; 32], false));
        store.insert(ShredData::new(100, 5, vec![0x33; 32], false));

        let node_id = NodeId::new([1u8; 32]);
        let stats = RepairServerStats::new();

        let request = RepairRequest::HighestShred {
            requester: NodeId::new([2u8; 32]),
            slot: 100,
            nonce: 99,
        };

        let response_bytes = RepairServer::handle_request_wire(
            node_id,
            request,
            &(store as Arc<dyn ShredProvider>),
            &stats,
            99,
        );

        let bytes = response_bytes.expect("should have response");
        let (payload, nonce) = response::decode_shred_response(&bytes).unwrap();
        assert_eq!(payload, &[0x22; 32]); // highest index = 7, data = 0x22
        assert_eq!(nonce, 99);
    }

    #[test]
    fn test_handle_ancestor_hashes_wire() {
        let store = Arc::new(InMemoryShredStore::new());
        store.insert(ShredData::new(99, 0, vec![0xAA; 32], false));
        store.insert(ShredData::new(98, 0, vec![0xBB; 32], false));

        let node_id = NodeId::new([1u8; 32]);
        let stats = RepairServerStats::new();

        let request = RepairRequest::Ancestor {
            requester: NodeId::new([2u8; 32]),
            slot: 100,
            ancestors: 5,
            nonce: 7,
        };

        let response_bytes = RepairServer::handle_request_wire(
            node_id,
            request,
            &(store as Arc<dyn ShredProvider>),
            &stats,
            7,
        );

        let bytes = response_bytes.expect("should have response");
        let (resp, nonce) = response::decode_ancestor_response(&bytes).unwrap();
        assert_eq!(nonce, 7);

        if let response::WireAncestorHashesResponse::Hashes(hashes) = resp {
            assert!(!hashes.is_empty());
        } else {
            panic!("expected Hashes variant");
        }
    }

    #[test]
    fn test_get_ancestor_hashes_default() {
        let store = InMemoryShredStore::new();
        store.insert(ShredData::new(99, 0, vec![0xAA; 32], false));
        store.insert(ShredData::new(98, 0, vec![0xBB; 32], false));

        let hashes = store.get_ancestor_hashes(100, 5);
        assert!(!hashes.is_empty());

        // Each hash should be derived from the shred's first 32 bytes.
        for (slot, hash) in &hashes {
            assert!(*slot == 99 || *slot == 98);
            if *slot == 99 {
                assert_eq!(hash, &[0xAA; 32]);
            } else {
                assert_eq!(hash, &[0xBB; 32]);
            }
        }
    }

    #[test]
    fn test_ancestor_hashes_custom_provider() {
        /// A custom provider that returns real bank hashes.
        struct CustomProvider;

        impl ShredProvider for CustomProvider {
            fn get_shred(&self, _slot: Slot, _index: ShredIndex) -> Option<ShredData> {
                None
            }
            fn get_highest_shred_index(&self, _slot: Slot) -> Option<ShredIndex> {
                None
            }
            fn get_shreds_in_range(&self, _start: Slot, _end: Slot) -> Vec<ShredData> {
                vec![]
            }
            fn get_ancestors(&self, _slot: Slot, _count: u64) -> Vec<ShredData> {
                vec![]
            }
            fn get_ancestor_hashes(&self, slot: Slot, count: u64) -> Vec<(Slot, [u8; 32])> {
                (1..=count.min(3))
                    .map(|i| {
                        let ancestor = slot.saturating_sub(i);
                        let mut hash = [0u8; 32];
                        hash[0] = ancestor as u8;
                        (ancestor, hash)
                    })
                    .collect()
            }
        }

        let provider = CustomProvider;
        let hashes = provider.get_ancestor_hashes(100, 3);
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0].0, 99);
        assert_eq!(hashes[0].1[0], 99);
        assert_eq!(hashes[1].0, 98);
        assert_eq!(hashes[2].0, 97);
    }
}
