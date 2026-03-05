/// Peer selection and request deduplication for the repair protocol.
///
/// Implements latency-aware round-robin peer selection: peers are classified
/// as fast (< threshold) or slow, and requests rotate through them in a
/// balanced DFS pattern (1/7 stages to slow peers, 6/7 to fast).
///
/// Also provides a request dedup cache that prevents re-requesting the same
/// (slot, shred_idx) pair within a configurable timeout window.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{ShredIndex, Slot};

/// Identifier for a repair peer (validator pubkey).
pub type PeerId = [u8; 32];

/// Per-peer metrics and performance tracking.
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    /// Requests sent to this peer.
    pub requests_sent: u64,
    /// Responses received from this peer.
    pub responses_received: u64,
    /// Total round-trip latency observed (for averaging).
    pub total_latency: Duration,
    /// Timestamp of first request sent to peer.
    pub first_request: Option<Instant>,
    /// Timestamp of most recent response from peer.
    pub last_response: Option<Instant>,
    /// Peer's reported stake weight (0 if unknown).
    pub stake: u64,
    /// Whether this peer has been validated via ping/pong.
    pub validated: bool,
}

impl PeerMetrics {
    pub fn new(stake: u64) -> Self {
        Self {
            requests_sent: 0,
            responses_received: 0,
            total_latency: Duration::ZERO,
            first_request: None,
            last_response: None,
            stake,
            validated: false,
        }
    }

    /// Average response latency in milliseconds.
    pub fn average_latency_ms(&self) -> u64 {
        if self.responses_received == 0 {
            return u64::MAX;
        }
        self.total_latency.as_millis() as u64 / self.responses_received
    }

    /// Whether this peer is considered "fast" (below latency threshold).
    pub fn is_fast(&self, threshold_ms: u64) -> bool {
        if self.responses_received == 0 {
            // Untested peers are optimistically treated as fast.
            return true;
        }
        self.average_latency_ms() < threshold_ms
    }
}

/// Peer selection policy with latency-aware round-robin.
pub struct PeerSelector {
    /// All known peers and their metrics.
    peers: HashMap<PeerId, PeerMetrics>,
    /// Ordered list of peer IDs for round-robin traversal.
    fast_peers: Vec<PeerId>,
    /// Slow peers (above latency threshold).
    slow_peers: Vec<PeerId>,
    /// Current index in fast peer rotation.
    fast_index: usize,
    /// Current index in slow peer rotation.
    slow_index: usize,
    /// Current stage in the round-robin cycle (0..PEER_SELECTION_STAGES).
    stage: usize,
    /// Latency threshold for fast/slow classification (ms).
    latency_threshold_ms: u64,
    /// Whether peer lists need re-sorting.
    dirty: bool,
}

impl Default for PeerSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerSelector {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            fast_peers: Vec::new(),
            slow_peers: Vec::new(),
            fast_index: 0,
            slow_index: 0,
            stage: 0,
            latency_threshold_ms: karstflow_constants::repair::FAST_PEER_LATENCY_MS,
            dirty: false,
        }
    }

    /// Register a peer with its stake weight.
    pub fn add_peer(&mut self, id: PeerId, stake: u64) {
        self.peers
            .entry(id)
            .or_insert_with(|| PeerMetrics::new(stake));
        self.dirty = true;
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, id: &PeerId) {
        self.peers.remove(id);
        self.dirty = true;
    }

    /// Mark a peer as validated (ping/pong completed).
    pub fn validate_peer(&mut self, id: &PeerId) {
        if let Some(metrics) = self.peers.get_mut(id) {
            metrics.validated = true;
        }
    }

    /// Record that a request was sent to a peer.
    pub fn record_request(&mut self, id: &PeerId) {
        if let Some(metrics) = self.peers.get_mut(id) {
            metrics.requests_sent += 1;
            if metrics.first_request.is_none() {
                metrics.first_request = Some(Instant::now());
            }
        }
    }

    /// Record a response from a peer with observed latency.
    pub fn record_response(&mut self, id: &PeerId, latency: Duration) {
        if let Some(metrics) = self.peers.get_mut(id) {
            metrics.responses_received += 1;
            metrics.total_latency += latency;
            metrics.last_response = Some(Instant::now());
            self.dirty = true; // Latency changed, may affect fast/slow classification.
        }
    }

    /// Get metrics for a peer.
    pub fn peer_metrics(&self, id: &PeerId) -> Option<&PeerMetrics> {
        self.peers.get(id)
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Select the next peer for a repair request.
    ///
    /// Uses round-robin with slow/fast bias: 1 out of every
    /// PEER_SELECTION_STAGES requests goes to a slow peer, the rest to fast.
    /// Returns None if no peers are available.
    pub fn select_peer(&mut self) -> Option<PeerId> {
        if self.dirty {
            self.reclassify_peers();
        }

        if self.fast_peers.is_empty() && self.slow_peers.is_empty() {
            return None;
        }

        let use_slow = self.stage < karstflow_constants::repair::SLOW_PEER_STAGE_FRACTION
            && !self.slow_peers.is_empty();

        let peer = if use_slow {
            let id = self.slow_peers[self.slow_index % self.slow_peers.len()];
            self.slow_index = self.slow_index.wrapping_add(1);
            id
        } else if !self.fast_peers.is_empty() {
            let id = self.fast_peers[self.fast_index % self.fast_peers.len()];
            self.fast_index = self.fast_index.wrapping_add(1);
            id
        } else {
            // No fast peers, fall back to slow.
            let id = self.slow_peers[self.slow_index % self.slow_peers.len()];
            self.slow_index = self.slow_index.wrapping_add(1);
            id
        };

        self.stage = (self.stage + 1) % karstflow_constants::repair::PEER_SELECTION_STAGES;

        Some(peer)
    }

    /// Re-classify peers into fast/slow lists based on current latency data.
    fn reclassify_peers(&mut self) {
        self.fast_peers.clear();
        self.slow_peers.clear();

        for (&id, metrics) in &self.peers {
            if metrics.is_fast(self.latency_threshold_ms) {
                self.fast_peers.push(id);
            } else {
                self.slow_peers.push(id);
            }
        }

        // Sort by stake (higher stake first) for deterministic ordering.
        let peers = &self.peers;
        self.fast_peers.sort_by(|a, b| {
            let sa = peers.get(a).map_or(0, |m| m.stake);
            let sb = peers.get(b).map_or(0, |m| m.stake);
            sb.cmp(&sa)
        });
        self.slow_peers.sort_by(|a, b| {
            let sa = peers.get(a).map_or(0, |m| m.stake);
            let sb = peers.get(b).map_or(0, |m| m.stake);
            sb.cmp(&sa)
        });

        self.dirty = false;
    }
}

/// Key for the dedup cache: (slot, shred_index, request_kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DedupKey {
    slot: Slot,
    index: ShredIndex,
    kind: DedupKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DedupKind {
    Shred,
    HighestShred,
    Orphan,
}

/// Request deduplication cache.
///
/// Prevents sending duplicate repair requests for the same (slot, shred_idx)
/// within a configurable timeout window. This reduces network overhead and
/// prevents hammering peers with redundant requests.
pub struct RequestDedup {
    /// Recent requests with timestamps.
    cache: HashMap<DedupKey, Instant>,
    /// Minimum interval before re-requesting the same target.
    dedup_interval: Duration,
    /// Maximum cache entries before forced cleanup.
    max_entries: usize,
}

impl Default for RequestDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestDedup {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dedup_interval: Duration::from_millis(
                karstflow_constants::repair::REQUEST_DEDUP_INTERVAL_MS,
            ),
            max_entries: karstflow_constants::repair::MAX_INFLIGHT_REQUESTS,
        }
    }

    /// Check if a shred request should be sent (not a duplicate).
    /// Returns true if the request is allowed, false if it's too recent.
    pub fn allow_shred_request(&mut self, slot: Slot, index: ShredIndex) -> bool {
        self.allow_request(DedupKey {
            slot,
            index,
            kind: DedupKind::Shred,
        })
    }

    /// Check if a highest-shred request should be sent.
    pub fn allow_highest_request(&mut self, slot: Slot) -> bool {
        self.allow_request(DedupKey {
            slot,
            index: 0,
            kind: DedupKind::HighestShred,
        })
    }

    /// Check if an orphan request should be sent.
    pub fn allow_orphan_request(&mut self, slot: Slot) -> bool {
        self.allow_request(DedupKey {
            slot,
            index: 0,
            kind: DedupKind::Orphan,
        })
    }

    /// Remove expired entries from the cache.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, ts| now.duration_since(*ts) < self.dedup_interval);
    }

    /// Number of entries in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    fn allow_request(&mut self, key: DedupKey) -> bool {
        let now = Instant::now();

        // Periodic cleanup when cache grows large.
        if self.cache.len() > self.max_entries {
            self.cleanup();
        }

        if let Some(last_request) = self.cache.get(&key) {
            if now.duration_since(*last_request) < self.dedup_interval {
                return false; // Too recent, skip.
            }
        }

        self.cache.insert(key, now);
        true
    }
}

/// Tracks in-flight repair requests awaiting responses.
pub struct InflightTracker {
    /// Nonce → (slot, shred_idx, peer, send_time).
    pending: HashMap<u64, InflightEntry>,
    /// Maximum entries before evicting oldest.
    max_entries: usize,
    /// Keyed nonce generator for time-bucketed nonce computation.
    nonce_gen: super::nonce::RepairNonceGenerator,
    /// Request timeout duration.
    timeout: Duration,
}

/// A single in-flight request.
#[derive(Debug, Clone)]
pub struct InflightEntry {
    pub nonce: u64,
    pub slot: Slot,
    pub shred_index: ShredIndex,
    pub peer: PeerId,
    pub sent_at: Instant,
}

impl Default for InflightTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl InflightTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            max_entries: karstflow_constants::repair::MAX_INFLIGHT_REQUESTS,
            nonce_gen: crate::repair::RepairNonceGenerator::new(),
            timeout: Duration::from_millis(karstflow_constants::repair::REQUEST_TIMEOUT_MS),
        }
    }

    /// Register a new in-flight request. Returns the assigned nonce.
    ///
    /// The nonce is computed from a keyed hash of (slot, shred_index, time)
    /// using a per-session secret. This ties the nonce to the request
    /// parameters and prevents peers from forging response nonces.
    pub fn register(&mut self, slot: Slot, shred_index: ShredIndex, peer: PeerId) -> u64 {
        let time_ns = super::nonce::current_time_ns();
        let nonce = self
            .nonce_gen
            .compute_shred_nonce(slot, shred_index, time_ns) as u64;

        // Evict oldest if at capacity.
        if self.pending.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.pending.insert(
            nonce,
            InflightEntry {
                nonce,
                slot,
                shred_index,
                peer,
                sent_at: Instant::now(),
            },
        );

        nonce
    }

    /// Complete an in-flight request by nonce. Returns the entry if found.
    pub fn complete(&mut self, nonce: u64) -> Option<InflightEntry> {
        self.pending.remove(&nonce)
    }

    /// Complete an in-flight request, validating that the nonce matches
    /// the expected (slot, shred_index). Returns the entry only if both
    /// the nonce exists and the parameters match.
    pub fn complete_validated(
        &mut self,
        nonce: u64,
        slot: Slot,
        shred_index: ShredIndex,
    ) -> Option<InflightEntry> {
        if let Some(entry) = self.pending.get(&nonce) {
            if entry.slot == slot && entry.shred_index == shred_index {
                return self.pending.remove(&nonce);
            }
        }
        None
    }

    /// Remove and return all timed-out requests.
    pub fn drain_timed_out(&mut self) -> Vec<InflightEntry> {
        let now = Instant::now();
        let timed_out: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.sent_at) >= self.timeout)
            .map(|(&nonce, _)| nonce)
            .collect();

        let mut result = Vec::with_capacity(timed_out.len());
        for nonce in timed_out {
            if let Some(entry) = self.pending.remove(&nonce) {
                result.push(entry);
            }
        }
        result
    }

    /// Number of in-flight requests.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether there are no in-flight requests.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Get an entry by nonce without removing it.
    pub fn get(&self, nonce: u64) -> Option<&InflightEntry> {
        self.pending.get(&nonce)
    }

    /// Evict the oldest entry.
    fn evict_oldest(&mut self) {
        if let Some((&oldest_nonce, _)) = self.pending.iter().min_by_key(|(_, entry)| entry.sent_at)
        {
            self.pending.remove(&oldest_nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id(n: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    // --- PeerSelector tests ---

    #[test]
    fn empty_selector_returns_none() {
        let mut selector = PeerSelector::new();
        assert_eq!(selector.select_peer(), None);
    }

    #[test]
    fn single_peer_always_selected() {
        let mut selector = PeerSelector::new();
        selector.add_peer(peer_id(1), 1000);

        for _ in 0..10 {
            assert_eq!(selector.select_peer(), Some(peer_id(1)));
        }
    }

    #[test]
    fn round_robin_across_peers() {
        let mut selector = PeerSelector::new();
        selector.add_peer(peer_id(1), 1000);
        selector.add_peer(peer_id(2), 1000);
        selector.add_peer(peer_id(3), 1000);

        let mut seen = HashMap::new();
        for _ in 0..21 {
            if let Some(id) = selector.select_peer() {
                *seen.entry(id).or_insert(0u32) += 1;
            }
        }

        // All peers should be selected at least once.
        assert_eq!(seen.len(), 3);
        for &count in seen.values() {
            assert!(count >= 5, "each peer should be selected ~7 times");
        }
    }

    #[test]
    fn fast_peers_preferred() {
        let mut selector = PeerSelector::new();
        selector.add_peer(peer_id(1), 1000); // fast (no latency data → optimistic)
        selector.add_peer(peer_id(2), 1000);

        // Record high latency for peer 2 → slow.
        selector.record_response(&peer_id(2), Duration::from_millis(200));
        selector.record_response(&peer_id(2), Duration::from_millis(200));

        let mut fast_count = 0u32;
        let mut slow_count = 0u32;
        for _ in 0..70 {
            if let Some(id) = selector.select_peer() {
                if id == peer_id(1) {
                    fast_count += 1;
                } else {
                    slow_count += 1;
                }
            }
        }

        // Fast peer should be selected significantly more often.
        assert!(
            fast_count > slow_count * 3,
            "fast peer should be 6x more likely than slow: fast={fast_count}, slow={slow_count}"
        );
    }

    #[test]
    fn peer_metrics_tracking() {
        let mut selector = PeerSelector::new();
        selector.add_peer(peer_id(1), 5000);

        selector.record_request(&peer_id(1));
        selector.record_request(&peer_id(1));
        selector.record_response(&peer_id(1), Duration::from_millis(50));

        let metrics = selector.peer_metrics(&peer_id(1)).unwrap();
        assert_eq!(metrics.requests_sent, 2);
        assert_eq!(metrics.responses_received, 1);
        assert_eq!(metrics.average_latency_ms(), 50);
        assert!(metrics.is_fast(80));
    }

    #[test]
    fn remove_peer() {
        let mut selector = PeerSelector::new();
        selector.add_peer(peer_id(1), 1000);
        selector.add_peer(peer_id(2), 1000);

        selector.remove_peer(&peer_id(1));
        assert_eq!(selector.peer_count(), 1);

        // Should only return peer 2.
        for _ in 0..5 {
            assert_eq!(selector.select_peer(), Some(peer_id(2)));
        }
    }

    // --- RequestDedup tests ---

    #[test]
    fn dedup_blocks_recent_duplicate() {
        let mut dedup = RequestDedup::new();

        assert!(dedup.allow_shred_request(100, 5));
        assert!(!dedup.allow_shred_request(100, 5)); // duplicate blocked
        assert!(dedup.allow_shred_request(100, 6)); // different index OK
        assert!(dedup.allow_shred_request(101, 5)); // different slot OK
    }

    #[test]
    fn dedup_allows_after_timeout() {
        let mut dedup = RequestDedup {
            cache: HashMap::new(),
            dedup_interval: Duration::from_millis(10),
            max_entries: 1000,
        };

        assert!(dedup.allow_shred_request(100, 5));
        assert!(!dedup.allow_shred_request(100, 5));

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(15));
        assert!(dedup.allow_shred_request(100, 5)); // allowed again
    }

    #[test]
    fn dedup_separate_kinds() {
        let mut dedup = RequestDedup::new();

        assert!(dedup.allow_shred_request(100, 0));
        assert!(dedup.allow_highest_request(100)); // different kind OK
        assert!(dedup.allow_orphan_request(100)); // different kind OK
    }

    #[test]
    fn dedup_cleanup() {
        let mut dedup = RequestDedup {
            cache: HashMap::new(),
            dedup_interval: Duration::from_millis(10),
            max_entries: 1000,
        };

        dedup.allow_shred_request(100, 0);
        dedup.allow_shred_request(101, 0);
        assert_eq!(dedup.len(), 2);

        std::thread::sleep(Duration::from_millis(15));
        dedup.cleanup();
        assert_eq!(dedup.len(), 0);
    }

    // --- InflightTracker tests ---

    #[test]
    fn inflight_register_and_complete() {
        let mut tracker = InflightTracker::new();

        let nonce = tracker.register(100, 5, peer_id(1));
        assert_eq!(tracker.len(), 1);

        let entry = tracker.complete(nonce).unwrap();
        assert_eq!(entry.slot, 100);
        assert_eq!(entry.shred_index, 5);
        assert_eq!(entry.peer, peer_id(1));
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn inflight_nonce_is_nonzero() {
        let mut tracker = InflightTracker::new();
        let nonce = tracker.register(100, 0, peer_id(1));
        assert!(nonce > 0, "keyed nonce should be nonzero");
    }

    #[test]
    fn inflight_different_params_different_nonces() {
        let mut tracker = InflightTracker::new();
        let n1 = tracker.register(100, 0, peer_id(1));
        let n2 = tracker.register(101, 0, peer_id(1));
        // Different slots should produce different nonces (with high probability).
        // They could collide in theory but this is extremely unlikely.
        assert_ne!(
            n1, n2,
            "different request params should produce different nonces"
        );
    }

    #[test]
    fn inflight_complete_validated_matches() {
        let mut tracker = InflightTracker::new();
        let nonce = tracker.register(100, 5, peer_id(1));

        // Correct slot/index should succeed.
        let entry = tracker.complete_validated(nonce, 100, 5).unwrap();
        assert_eq!(entry.slot, 100);
        assert_eq!(entry.shred_index, 5);
    }

    #[test]
    fn inflight_complete_validated_wrong_slot_fails() {
        let mut tracker = InflightTracker::new();
        let nonce = tracker.register(100, 5, peer_id(1));

        // Wrong slot should fail.
        assert!(tracker.complete_validated(nonce, 999, 5).is_none());
        // Entry should still be pending.
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn inflight_timeout_drain() {
        let mut tracker = InflightTracker {
            pending: HashMap::new(),
            max_entries: 1000,
            nonce_gen: crate::repair::RepairNonceGenerator::new(),
            timeout: Duration::from_millis(10),
        };

        tracker.register(100, 0, peer_id(1));
        tracker.register(101, 0, peer_id(2));

        std::thread::sleep(Duration::from_millis(15));

        let timed_out = tracker.drain_timed_out();
        assert_eq!(timed_out.len(), 2);
        assert!(tracker.is_empty());
    }

    #[test]
    fn inflight_evicts_oldest_at_capacity() {
        let mut tracker = InflightTracker {
            pending: HashMap::new(),
            max_entries: 2,
            nonce_gen: crate::repair::RepairNonceGenerator::new(),
            timeout: Duration::from_secs(60),
        };

        let n1 = tracker.register(100, 0, peer_id(1));
        let _n2 = tracker.register(101, 0, peer_id(2));

        // At capacity, next register should evict oldest (n1).
        let _n3 = tracker.register(102, 0, peer_id(3));
        assert_eq!(tracker.len(), 2);
        assert!(tracker.get(n1).is_none(), "oldest should be evicted");
    }
}
