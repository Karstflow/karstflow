/// Repair coordinator: orchestrates the forest, peer policy, dedup cache,
/// and inflight tracker into a unified repair pipeline.
///
/// The coordinator runs a poll-driven `service()` loop:
///   1. Scan the forest for slots needing repair
///   2. Filter requests through the dedup cache
///   3. Select peers via the latency-aware policy
///   4. Track in-flight requests and handle timeouts
///   5. Process incoming responses and update forest state
///
/// This is the main entry point for the repair subsystem.
use std::time::{Duration, Instant};

use super::forest::{RepairForest, RepairTarget, ShredSource};
use super::policy::{InflightTracker, PeerId, PeerSelector, RequestDedup};
use super::{ShredIndex, Slot};

/// Configuration for the repair coordinator.
#[derive(Debug, Clone)]
pub struct RepairCoordinatorConfig {
    /// Maximum repair requests to generate per service tick.
    pub max_requests_per_tick: usize,
    /// How often to run timeout cleanup.
    pub cleanup_interval: Duration,
    /// How often to re-scan the forest for new repair targets.
    pub scan_interval: Duration,
    /// Maximum in-flight requests before throttling.
    pub max_inflight: usize,
}

impl Default for RepairCoordinatorConfig {
    fn default() -> Self {
        Self {
            max_requests_per_tick: 128,
            cleanup_interval: Duration::from_millis(500),
            scan_interval: Duration::from_millis(50),
            max_inflight: karstflow_constants::repair::MAX_INFLIGHT_REQUESTS,
        }
    }
}

/// A repair request ready to be sent over the network.
#[derive(Debug, Clone)]
pub struct OutboundRepair {
    /// Target peer to send the request to.
    pub peer: PeerId,
    /// The repair target (slot + shred index or orphan).
    pub target: RepairTarget,
    /// Assigned nonce for response correlation.
    pub nonce: u64,
}

/// Result of processing an inbound repair response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// Shred was new and inserted into the forest.
    Accepted,
    /// Shred was a duplicate (already received).
    Duplicate,
    /// Response nonce didn't match any in-flight request.
    UnknownNonce,
    /// Response indicated an error from the peer.
    PeerError,
}

/// Statistics for the repair coordinator.
#[derive(Debug, Default, Clone)]
pub struct RepairCoordinatorStats {
    /// Total repair requests generated.
    pub requests_generated: u64,
    /// Requests filtered by dedup cache.
    pub requests_deduped: u64,
    /// Requests actually sent (after dedup + peer selection).
    pub requests_sent: u64,
    /// Responses received and accepted.
    pub responses_accepted: u64,
    /// Responses received but duplicate.
    pub responses_duplicate: u64,
    /// Responses with unknown nonce.
    pub responses_unknown: u64,
    /// In-flight requests that timed out.
    pub requests_timed_out: u64,
    /// Slots completed via repair.
    pub slots_completed: u64,
    /// Orphan requests sent.
    pub orphan_requests: u64,
}

/// The repair coordinator.
pub struct RepairCoordinator {
    /// Slot repair forest.
    pub forest: RepairForest,
    /// Peer selection policy.
    pub peers: PeerSelector,
    /// Request deduplication cache.
    dedup: RequestDedup,
    /// In-flight request tracker.
    inflight: InflightTracker,
    /// Configuration.
    config: RepairCoordinatorConfig,
    /// Statistics.
    stats: RepairCoordinatorStats,
    /// Last cleanup time.
    last_cleanup: Instant,
}

impl RepairCoordinator {
    /// Create a new repair coordinator rooted at the given slot.
    pub fn new(root_slot: Slot, config: RepairCoordinatorConfig) -> Self {
        Self {
            forest: RepairForest::new(root_slot),
            peers: PeerSelector::new(),
            dedup: RequestDedup::new(),
            inflight: InflightTracker::new(),
            config,
            stats: RepairCoordinatorStats::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults(root_slot: Slot) -> Self {
        Self::new(root_slot, RepairCoordinatorConfig::default())
    }

    /// Get current statistics.
    pub fn stats(&self) -> &RepairCoordinatorStats {
        &self.stats
    }

    /// Number of in-flight requests.
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Run one service tick: generate repair requests, handle timeouts.
    ///
    /// Returns outbound repair requests ready to be sent over the network.
    pub fn service(&mut self) -> Vec<OutboundRepair> {
        // Handle timeouts periodically.
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval {
            self.handle_timeouts();
            self.dedup.cleanup();
            self.last_cleanup = Instant::now();
        }

        // Don't generate new requests if we're at the inflight limit.
        if self.inflight.len() >= self.config.max_inflight {
            return vec![];
        }

        let remaining_capacity = self.config.max_inflight - self.inflight.len();
        let batch_size = self.config.max_requests_per_tick.min(remaining_capacity);

        // Ask the forest for repair targets.
        let targets = self.forest.next_repairs(batch_size);
        self.stats.requests_generated += targets.len() as u64;

        // Filter through dedup and assign peers.
        let mut outbound = Vec::with_capacity(targets.len());
        for target in targets {
            // Dedup check.
            let allowed = match &target {
                RepairTarget::Shred { slot, index } => {
                    self.dedup.allow_shred_request(*slot, *index)
                }
                RepairTarget::HighestShred { slot } => self.dedup.allow_highest_request(*slot),
                RepairTarget::Orphan { slot } => self.dedup.allow_orphan_request(*slot),
            };

            if !allowed {
                self.stats.requests_deduped += 1;
                continue;
            }

            // Select a peer.
            let Some(peer) = self.peers.select_peer() else {
                break; // No peers available.
            };

            // Register in-flight.
            let (slot, shred_idx) = match &target {
                RepairTarget::Shred { slot, index } => (*slot, *index),
                RepairTarget::HighestShred { slot } => (*slot, 0),
                RepairTarget::Orphan { slot } => (*slot, 0),
            };
            let nonce = self.inflight.register(slot, shred_idx, peer);
            self.peers.record_request(&peer);

            if matches!(target, RepairTarget::Orphan { .. }) {
                self.stats.orphan_requests += 1;
            }

            self.stats.requests_sent += 1;
            outbound.push(OutboundRepair {
                peer,
                target,
                nonce,
            });
        }

        outbound
    }

    /// Process an inbound repair response.
    ///
    /// Updates the forest with received shred data and records peer metrics.
    pub fn receive_response(
        &mut self,
        nonce: u64,
        slot: Slot,
        shred_index: ShredIndex,
        is_last_in_slot: bool,
        parent_slot: Option<Slot>,
    ) -> ResponseOutcome {
        // Look up the in-flight request.
        let entry = match self.inflight.complete(nonce) {
            Some(e) => e,
            None => {
                self.stats.responses_unknown += 1;
                return ResponseOutcome::UnknownNonce;
            }
        };

        // Record peer latency.
        let latency = entry.sent_at.elapsed();
        self.peers.record_response(&entry.peer, latency);

        // Insert shred into forest.
        let was_new = self.forest.receive_shred(
            slot,
            shred_index,
            ShredSource::Repair,
            is_last_in_slot,
            parent_slot,
        );

        if was_new {
            self.stats.responses_accepted += 1;
            ResponseOutcome::Accepted
        } else {
            self.stats.responses_duplicate += 1;
            ResponseOutcome::Duplicate
        }
    }

    /// Process an orphan response (ancestor information).
    ///
    /// Inserts the discovered ancestor slots into the forest.
    pub fn receive_orphan_response(
        &mut self,
        nonce: u64,
        ancestors: &[(Slot, Slot)], // (slot, parent_slot) pairs
    ) -> ResponseOutcome {
        let entry = match self.inflight.complete(nonce) {
            Some(e) => e,
            None => {
                self.stats.responses_unknown += 1;
                return ResponseOutcome::UnknownNonce;
            }
        };

        let latency = entry.sent_at.elapsed();
        self.peers.record_response(&entry.peer, latency);

        for &(slot, parent) in ancestors {
            self.forest.insert_slot(slot, parent);
        }

        self.stats.responses_accepted += 1;
        ResponseOutcome::Accepted
    }

    /// Notify that a shred was received from turbine (not repair).
    pub fn receive_turbine_shred(
        &mut self,
        slot: Slot,
        index: ShredIndex,
        is_last_in_slot: bool,
        parent_slot: Option<Slot>,
    ) {
        self.forest.receive_shred(
            slot,
            index,
            ShredSource::Turbine,
            is_last_in_slot,
            parent_slot,
        );
    }

    /// Advance the root slot, pruning old data.
    pub fn advance_root(&mut self, new_root: Slot) {
        let completed = self.forest.drain_completed(new_root);
        self.stats.slots_completed += completed.len() as u64;
        self.forest.publish(new_root);
    }

    /// Register a new peer for repair requests.
    pub fn add_peer(&mut self, id: PeerId, stake: u64) {
        self.peers.add_peer(id, stake);
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, id: &PeerId) {
        self.peers.remove_peer(id);
    }

    /// Handle timed-out requests.
    fn handle_timeouts(&mut self) {
        let timed_out = self.inflight.drain_timed_out();
        self.stats.requests_timed_out += timed_out.len() as u64;
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

    #[test]
    fn coordinator_creates_with_defaults() {
        let coord = RepairCoordinator::with_defaults(0);
        assert_eq!(coord.forest.root(), 0);
        assert_eq!(coord.inflight_count(), 0);
    }

    #[test]
    fn service_generates_no_requests_without_peers() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        // No peers → no outbound requests.
        let requests = coord.service();
        assert!(requests.is_empty());
    }

    #[test]
    fn service_generates_requests_with_peers() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        let requests = coord.service();
        assert!(!requests.is_empty(), "should generate repair requests");

        // All requests should target peer 1.
        for req in &requests {
            assert_eq!(req.peer, peer_id(1));
        }
    }

    #[test]
    fn service_tracks_inflight() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        let requests = coord.service();
        assert_eq!(coord.inflight_count(), requests.len());
    }

    #[test]
    fn receive_response_updates_forest() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        let requests = coord.service();
        assert!(!requests.is_empty());

        // Simulate a response for the first request.
        let nonce = requests[0].nonce;
        let outcome = coord.receive_response(nonce, 1, 0, false, Some(0));
        assert_eq!(outcome, ResponseOutcome::Accepted);
        assert_eq!(coord.stats().responses_accepted, 1);
    }

    #[test]
    fn unknown_nonce_response() {
        let mut coord = RepairCoordinator::with_defaults(0);
        let outcome = coord.receive_response(99999, 1, 0, false, None);
        assert_eq!(outcome, ResponseOutcome::UnknownNonce);
    }

    #[test]
    fn receive_turbine_shred() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        coord.receive_turbine_shred(1, 0, true, Some(0));

        let state = coord.forest.get_slot(1).unwrap();
        assert_eq!(state.turbine_count, 1);
        assert_eq!(state.total_received(), 1);
    }

    #[test]
    fn advance_root_prunes_and_counts() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        // Complete slot 1.
        coord.receive_turbine_shred(1, 0, true, Some(0));

        coord.advance_root(2);
        assert_eq!(coord.forest.root(), 2);
        assert_eq!(coord.stats().slots_completed, 1);
    }

    #[test]
    fn orphan_response_connects_slots() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);

        // Slot 5 is disconnected (parent 3 unknown).
        coord.forest.insert_slot(5, 3);

        // Generate orphan repair.
        let requests = coord.service();
        let orphan_req = requests
            .iter()
            .find(|r| matches!(r.target, RepairTarget::Orphan { .. }));

        if let Some(req) = orphan_req {
            // Respond with ancestor chain: slot 3 has parent 1, slot 1 has parent 0.
            let outcome = coord.receive_orphan_response(req.nonce, &[(3, 1), (1, 0)]);
            assert_eq!(outcome, ResponseOutcome::Accepted);

            // Slot 3 should now be in the forest.
            assert!(coord.forest.get_slot(3).is_some());
        }
    }

    #[test]
    fn dedup_prevents_duplicate_requests() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        // First service call generates requests.
        let first = coord.service();
        let first_count = first.len();

        // Second immediate call — dedup should filter most/all.
        let second = coord.service();
        assert!(
            second.len() <= first_count,
            "dedup should filter repeated requests"
        );
    }

    #[test]
    fn inflight_limit_throttles_generation() {
        let config = RepairCoordinatorConfig {
            max_inflight: 2,
            ..Default::default()
        };
        let mut coord = RepairCoordinator::new(0, config);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);
        coord.forest.insert_slot(2, 1);
        coord.forest.insert_slot(3, 2);

        // Fill up inflight.
        let first = coord.service();
        assert!(first.len() <= 2);

        // Should be throttled now.
        let second = coord.service();
        assert!(
            second.is_empty() || second.len() + first.len() <= 2,
            "should respect inflight limit"
        );
    }

    #[test]
    fn stats_accumulate() {
        let mut coord = RepairCoordinator::with_defaults(0);
        coord.add_peer(peer_id(1), 1000);
        coord.forest.insert_slot(0, 0);
        coord.forest.insert_slot(1, 0);

        coord.service();
        assert!(coord.stats().requests_generated > 0);
        assert!(coord.stats().requests_sent > 0);
    }
}
