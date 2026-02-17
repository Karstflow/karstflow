use super::*;
use crate::gossip::NodeId;
use crate::repair::protocol::{RepairMessage, RepairRequest, RepairResponse, ShredData};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
            bind_addr: "0.0.0.0:8002".parse().unwrap(),
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

/// Trait for providing shred data to the repair server
pub trait ShredProvider: Send + Sync {
    fn get_shred(&self, slot: Slot, index: ShredIndex) -> Option<ShredData>;
    fn get_highest_shred_index(&self, slot: Slot) -> Option<ShredIndex>;
    fn get_shreds_in_range(&self, start_slot: Slot, end_slot: Slot) -> Vec<ShredData>;
    fn get_ancestors(&self, slot: Slot, count: u64) -> Vec<ShredData>;
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

/// Repair server for serving repair requests
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

                    let data = bytes::Bytes::copy_from_slice(&buf[..len]);
                    if let Ok(RepairMessage::Request(request)) = RepairMessage::decode(data) {
                        stats.requests_received.fetch_add(1, Ordering::Relaxed);

                        let response =
                            Self::handle_request(node_id, request, &shred_provider, &stats);

                        if let Ok(encoded) = RepairMessage::Response(response).encode() {
                            let _ = socket.send_to(&encoded, src_addr).await;
                            stats
                                .bytes_sent
                                .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    fn handle_request(
        node_id: NodeId,
        request: RepairRequest,
        shred_provider: &Arc<dyn ShredProvider>,
        stats: &RepairServerStats,
    ) -> RepairResponse {
        match request {
            RepairRequest::Shred {
                slot, index, nonce, ..
            } => {
                let shred = shred_provider.get_shred(slot, index);
                if shred.is_some() {
                    stats.shreds_served.fetch_add(1, Ordering::Relaxed);
                    stats.responses_sent.fetch_add(1, Ordering::Relaxed);
                }
                RepairResponse::Shred {
                    responder: node_id,
                    shred,
                    nonce,
                }
            }
            RepairRequest::HighestShred { slot, nonce, .. } => {
                let index = shred_provider.get_highest_shred_index(slot);
                stats.responses_sent.fetch_add(1, Ordering::Relaxed);
                RepairResponse::HighestShred {
                    responder: node_id,
                    slot,
                    index,
                    nonce,
                }
            }
            RepairRequest::SlotRange {
                start_slot,
                end_slot,
                nonce,
                ..
            } => {
                let shreds = shred_provider.get_shreds_in_range(start_slot, end_slot);
                stats
                    .shreds_served
                    .fetch_add(shreds.len() as u64, Ordering::Relaxed);
                stats.responses_sent.fetch_add(1, Ordering::Relaxed);
                RepairResponse::Shreds {
                    responder: node_id,
                    shreds,
                    nonce,
                }
            }
            RepairRequest::Ancestor {
                slot,
                ancestors,
                nonce,
                ..
            } => {
                let shreds = shred_provider.get_ancestors(slot, ancestors);
                stats
                    .shreds_served
                    .fetch_add(shreds.len() as u64, Ordering::Relaxed);
                stats.responses_sent.fetch_add(1, Ordering::Relaxed);
                RepairResponse::Shreds {
                    responder: node_id,
                    shreds,
                    nonce,
                }
            }
            RepairRequest::Orphan { nonce, .. } => {
                stats.errors_sent.fetch_add(1, Ordering::Relaxed);
                RepairResponse::Error {
                    responder: node_id,
                    error_code: 501,
                    message: "orphan repair not implemented".to_string(),
                    nonce,
                }
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
}
