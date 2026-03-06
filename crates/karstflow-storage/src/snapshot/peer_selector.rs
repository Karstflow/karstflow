/// Peer selection for remote snapshot download.
///
/// Selects and manages peers for downloading snapshots during bootstrap.
/// Implements health checking, retry logic, and peer scoring based on
/// download speed and reliability.
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A peer that can serve snapshots.
#[derive(Debug, Clone)]
pub struct SnapshotPeer {
    /// Peer identity (e.g., IP:port or node pubkey).
    pub id: String,
    /// The snapshot slot this peer advertises.
    pub snapshot_slot: u64,
    /// Hash of the snapshot this peer advertises.
    pub snapshot_hash: [u8; 32],
    /// Whether this peer supports incremental snapshots.
    pub supports_incremental: bool,
}

/// Health status of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealth {
    /// Peer is healthy and available.
    Healthy,
    /// Peer has had recent failures; in cooldown.
    Degraded,
    /// Peer is blacklisted after too many failures.
    Blacklisted,
}

/// Internal tracking state for a peer.
struct PeerState {
    peer: SnapshotPeer,
    health: PeerHealth,
    /// Number of consecutive failures.
    consecutive_failures: u32,
    /// Total bytes downloaded from this peer.
    bytes_downloaded: u64,
    /// Total download time for throughput estimation.
    download_duration: Duration,
    /// Last attempt timestamp.
    last_attempt: Option<Instant>,
    /// Cooldown until (for degraded peers).
    cooldown_until: Option<Instant>,
}

/// Configuration for peer selection.
#[derive(Debug, Clone)]
pub struct PeerSelectorConfig {
    /// Maximum consecutive failures before blacklisting.
    pub max_failures: u32,
    /// Cooldown duration after a failure.
    pub cooldown: Duration,
    /// Maximum number of tracked peers.
    pub max_peers: usize,
}

impl Default for PeerSelectorConfig {
    fn default() -> Self {
        Self {
            max_failures: 3,
            cooldown: Duration::from_secs(30),
            max_peers: 64,
        }
    }
}

/// Selects and manages peers for snapshot downloads.
pub struct PeerSelector {
    config: PeerSelectorConfig,
    peers: HashMap<String, PeerState>,
}

impl PeerSelector {
    /// Create a new peer selector.
    pub fn new(config: PeerSelectorConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Register a new peer. Overwrites existing entry for the same ID.
    pub fn add_peer(&mut self, peer: SnapshotPeer) {
        if self.peers.len() >= self.config.max_peers && !self.peers.contains_key(&peer.id) {
            return;
        }
        let id = peer.id.clone();
        self.peers.insert(
            id,
            PeerState {
                peer,
                health: PeerHealth::Healthy,
                consecutive_failures: 0,
                bytes_downloaded: 0,
                download_duration: Duration::ZERO,
                last_attempt: None,
                cooldown_until: None,
            },
        );
    }

    /// Select the best available peer for the given slot.
    ///
    /// Prefers:
    /// 1. Healthy peers over degraded
    /// 2. Higher throughput peers
    /// 3. Peers with the requested snapshot slot
    pub fn select_peer(&self, target_slot: u64) -> Option<&SnapshotPeer> {
        let now = Instant::now();
        let mut best: Option<&PeerState> = None;
        let mut best_score: f64 = -1.0;

        for state in self.peers.values() {
            if state.health == PeerHealth::Blacklisted {
                continue;
            }
            if state.health == PeerHealth::Degraded {
                if let Some(until) = state.cooldown_until {
                    if now < until {
                        continue;
                    }
                }
            }

            let mut score = 0.0;
            // Prefer peers with the exact slot.
            if state.peer.snapshot_slot == target_slot {
                score += 100.0;
            }
            // Throughput bonus (bytes per second).
            if state.download_duration.as_secs_f64() > 0.0 {
                score += state.bytes_downloaded as f64
                    / state.download_duration.as_secs_f64()
                    / 1_000_000.0;
            }
            // Healthy bonus.
            if state.health == PeerHealth::Healthy {
                score += 50.0;
            }

            if score > best_score {
                best_score = score;
                best = Some(state);
            }
        }

        best.map(|s| &s.peer)
    }

    /// Report a successful download from a peer.
    pub fn report_success(&mut self, peer_id: &str, bytes: u64, duration: Duration) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.consecutive_failures = 0;
            state.health = PeerHealth::Healthy;
            state.bytes_downloaded += bytes;
            state.download_duration += duration;
            state.last_attempt = Some(Instant::now());
            state.cooldown_until = None;
        }
    }

    /// Report a failed download from a peer.
    pub fn report_failure(&mut self, peer_id: &str) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.consecutive_failures += 1;
            state.last_attempt = Some(Instant::now());

            if state.consecutive_failures >= self.config.max_failures {
                state.health = PeerHealth::Blacklisted;
            } else {
                state.health = PeerHealth::Degraded;
                state.cooldown_until = Some(Instant::now() + self.config.cooldown);
            }
        }
    }

    /// Get the health status of a peer.
    pub fn peer_health(&self, peer_id: &str) -> Option<PeerHealth> {
        self.peers.get(peer_id).map(|s| s.health)
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of healthy (available) peers.
    pub fn healthy_peer_count(&self) -> usize {
        self.peers
            .values()
            .filter(|s| s.health == PeerHealth::Healthy)
            .count()
    }

    /// Remove blacklisted peers from tracking.
    pub fn prune_blacklisted(&mut self) {
        self.peers
            .retain(|_, state| state.health != PeerHealth::Blacklisted);
    }

    /// Clear all peer state.
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: &str, slot: u64) -> SnapshotPeer {
        SnapshotPeer {
            id: id.to_string(),
            snapshot_slot: slot,
            snapshot_hash: [0u8; 32],
            supports_incremental: false,
        }
    }

    #[test]
    fn add_and_select_peer() {
        let mut selector = PeerSelector::new(PeerSelectorConfig::default());
        selector.add_peer(make_peer("peer1", 100));

        let selected = selector.select_peer(100);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().id, "peer1");
    }

    #[test]
    fn prefers_matching_slot() {
        let mut selector = PeerSelector::new(PeerSelectorConfig::default());
        selector.add_peer(make_peer("peer1", 100));
        selector.add_peer(make_peer("peer2", 200));

        let selected = selector.select_peer(200).unwrap();
        assert_eq!(selected.id, "peer2");
    }

    #[test]
    fn failure_degrades_peer() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_failures: 3,
            cooldown: Duration::from_secs(3600), // long cooldown
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));

        selector.report_failure("peer1");
        assert_eq!(selector.peer_health("peer1"), Some(PeerHealth::Degraded));
    }

    #[test]
    fn multiple_failures_blacklist() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_failures: 2,
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));

        selector.report_failure("peer1");
        selector.report_failure("peer1");
        assert_eq!(selector.peer_health("peer1"), Some(PeerHealth::Blacklisted));
    }

    #[test]
    fn blacklisted_peer_not_selected() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_failures: 1,
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));
        selector.report_failure("peer1");

        assert!(selector.select_peer(100).is_none());
    }

    #[test]
    fn success_resets_health() {
        let mut selector = PeerSelector::new(PeerSelectorConfig::default());
        selector.add_peer(make_peer("peer1", 100));

        selector.report_failure("peer1");
        assert_eq!(selector.peer_health("peer1"), Some(PeerHealth::Degraded));

        selector.report_success("peer1", 1_000_000, Duration::from_secs(1));
        assert_eq!(selector.peer_health("peer1"), Some(PeerHealth::Healthy));
    }

    #[test]
    fn prune_removes_blacklisted() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_failures: 1,
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));
        selector.add_peer(make_peer("peer2", 100));

        selector.report_failure("peer1");
        assert_eq!(selector.peer_count(), 2);

        selector.prune_blacklisted();
        assert_eq!(selector.peer_count(), 1);
    }

    #[test]
    fn max_peers_enforced() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_peers: 2,
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));
        selector.add_peer(make_peer("peer2", 100));
        selector.add_peer(make_peer("peer3", 100)); // should be rejected

        assert_eq!(selector.peer_count(), 2);
    }

    #[test]
    fn healthy_peer_count() {
        let mut selector = PeerSelector::new(PeerSelectorConfig {
            max_failures: 1,
            ..Default::default()
        });
        selector.add_peer(make_peer("peer1", 100));
        selector.add_peer(make_peer("peer2", 100));
        selector.add_peer(make_peer("peer3", 100));

        assert_eq!(selector.healthy_peer_count(), 3);

        selector.report_failure("peer1");
        assert_eq!(selector.healthy_peer_count(), 2);
    }
}
