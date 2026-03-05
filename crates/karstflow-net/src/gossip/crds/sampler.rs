//! Weighted peer sampler for gossip push and pull target selection.
//!
//! Uses cumulative weight arrays for O(log n) weighted random sampling.
//! Each sampler tracks a set of peers with their weights (stake + base),
//! and allows random selection proportional to weight.

/// Weighted peer sampler using cumulative weight binary search.
///
/// Peers are stored with cumulative weights. Sampling selects a random
/// value in [0, total_weight) and binary-searches to find the peer.
/// Peers can be enabled/disabled without rebuilding the sampler.
#[derive(Debug, Clone)]
pub struct WeightedPeerSampler {
    /// Peer entries: (peer_index, individual_weight).
    peers: Vec<PeerWeight>,
    /// Cumulative weight at each position (for binary search).
    cumulative_weights: Vec<u64>,
    /// Total weight of enabled peers.
    total_weight: u64,
    /// Bitset: 1 = peer enabled for sampling.
    enabled: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PeerWeight {
    /// Index into the CRDS contact info array.
    peer_index: usize,
    /// Individual weight for this peer.
    weight: u64,
}

impl WeightedPeerSampler {
    /// Create a new empty sampler.
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            cumulative_weights: Vec::new(),
            total_weight: 0,
            enabled: Vec::new(),
        }
    }

    /// Create a sampler with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let enabled_words = capacity.div_ceil(64);
        Self {
            peers: Vec::with_capacity(capacity),
            cumulative_weights: Vec::with_capacity(capacity),
            total_weight: 0,
            enabled: vec![0u64; enabled_words],
        }
    }

    /// Number of peers in the sampler.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the sampler is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Total weight of all enabled peers.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Add a peer with the given weight.
    pub fn add(&mut self, peer_index: usize, weight: u64) {
        let idx = self.peers.len();
        self.peers.push(PeerWeight { peer_index, weight });

        // Ensure enabled bitset has enough capacity
        let word_idx = idx / 64;
        while self.enabled.len() <= word_idx {
            self.enabled.push(0);
        }

        // Enable by default
        self.enabled[word_idx] |= 1u64 << (idx % 64);

        self.rebuild_cumulative();
    }

    /// Update the weight of a peer at the given sampler position.
    pub fn update_weight(&mut self, sampler_position: usize, new_weight: u64) {
        if sampler_position < self.peers.len() {
            self.peers[sampler_position].weight = new_weight;
            self.rebuild_cumulative();
        }
    }

    /// Enable a peer for sampling.
    pub fn enable(&mut self, sampler_position: usize) {
        if sampler_position < self.peers.len() {
            let word_idx = sampler_position / 64;
            let bit_idx = sampler_position % 64;
            if word_idx < self.enabled.len() {
                self.enabled[word_idx] |= 1u64 << bit_idx;
                self.rebuild_cumulative();
            }
        }
    }

    /// Disable a peer from sampling (weight treated as 0).
    pub fn disable(&mut self, sampler_position: usize) {
        if sampler_position < self.peers.len() {
            let word_idx = sampler_position / 64;
            let bit_idx = sampler_position % 64;
            if word_idx < self.enabled.len() {
                self.enabled[word_idx] &= !(1u64 << bit_idx);
                self.rebuild_cumulative();
            }
        }
    }

    /// Check if a peer is enabled.
    pub fn is_enabled(&self, sampler_position: usize) -> bool {
        if sampler_position >= self.peers.len() {
            return false;
        }
        let word_idx = sampler_position / 64;
        let bit_idx = sampler_position % 64;
        if word_idx >= self.enabled.len() {
            return false;
        }
        (self.enabled[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Sample a random peer index, weighted by stake.
    ///
    /// Returns `None` if no enabled peers or total weight is zero.
    /// The `random_value` should be a uniform random u64.
    pub fn sample(&self, random_value: u64) -> Option<usize> {
        if self.total_weight == 0 || self.cumulative_weights.is_empty() {
            return None;
        }

        let target = random_value % self.total_weight;

        // Binary search for the first cumulative weight > target
        let pos = self.cumulative_weights.partition_point(|&w| w <= target);

        if pos < self.peers.len() {
            Some(self.peers[pos].peer_index)
        } else {
            // Edge case: return last peer
            self.peers.last().map(|p| p.peer_index)
        }
    }

    /// Remove a peer from the sampler by its peer_index.
    ///
    /// Returns true if the peer was found and removed.
    pub fn remove(&mut self, peer_index: usize) -> bool {
        if let Some(pos) = self.peers.iter().position(|p| p.peer_index == peer_index) {
            self.peers.remove(pos);
            // Rebuild enabled bitset (shift bits after removed position)
            self.rebuild_enabled_after_remove(pos);
            self.rebuild_cumulative();
            true
        } else {
            false
        }
    }

    /// Clear all peers.
    pub fn clear(&mut self) {
        self.peers.clear();
        self.cumulative_weights.clear();
        self.enabled.fill(0);
        self.total_weight = 0;
    }

    /// Rebuild cumulative weights from scratch.
    fn rebuild_cumulative(&mut self) {
        self.cumulative_weights.clear();
        self.cumulative_weights.reserve(self.peers.len());
        self.total_weight = 0;

        for (i, peer) in self.peers.iter().enumerate() {
            let effective_weight = if self.is_enabled(i) { peer.weight } else { 0 };
            self.total_weight = self.total_weight.saturating_add(effective_weight);
            self.cumulative_weights.push(self.total_weight);
        }
    }

    /// Rebuild enabled bitset after removing a peer at position.
    fn rebuild_enabled_after_remove(&mut self, removed_pos: usize) {
        // Simple approach: rebuild from scratch based on current peers count
        let peer_count = self.peers.len();
        let needed_words = peer_count.div_ceil(64);
        let mut new_enabled = vec![0u64; needed_words.max(1)];

        // Copy bits, shifting down after removed position
        for i in 0..peer_count {
            let old_i = if i < removed_pos { i } else { i + 1 };
            let old_word = old_i / 64;
            let old_bit = old_i % 64;

            let was_enabled = if old_word < self.enabled.len() {
                (self.enabled[old_word] & (1u64 << old_bit)) != 0
            } else {
                false
            };

            if was_enabled {
                let new_word = i / 64;
                let new_bit = i % 64;
                if new_word < new_enabled.len() {
                    new_enabled[new_word] |= 1u64 << new_bit;
                }
            }
        }

        self.enabled = new_enabled;
    }
}

impl Default for WeightedPeerSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampler_empty() {
        let sampler = WeightedPeerSampler::new();
        assert!(sampler.is_empty());
        assert_eq!(sampler.total_weight(), 0);
        assert_eq!(sampler.sample(42), None);
    }

    #[test]
    fn test_sampler_single_peer() {
        let mut sampler = WeightedPeerSampler::new();
        sampler.add(0, 100);

        assert_eq!(sampler.len(), 1);
        assert_eq!(sampler.total_weight(), 100);

        // Always returns the only peer
        assert_eq!(sampler.sample(0), Some(0));
        assert_eq!(sampler.sample(50), Some(0));
        assert_eq!(sampler.sample(99), Some(0));
    }

    #[test]
    fn test_sampler_weighted_distribution() {
        let mut sampler = WeightedPeerSampler::new();
        // Peer 0: weight 100, peer 1: weight 900
        sampler.add(0, 100);
        sampler.add(1, 900);

        assert_eq!(sampler.total_weight(), 1000);

        // Values 0..99 should map to peer 0
        assert_eq!(sampler.sample(0), Some(0));
        assert_eq!(sampler.sample(99), Some(0));

        // Values 100..999 should map to peer 1
        assert_eq!(sampler.sample(100), Some(1));
        assert_eq!(sampler.sample(999), Some(1));
    }

    #[test]
    fn test_sampler_disable_enable() {
        let mut sampler = WeightedPeerSampler::new();
        sampler.add(0, 100);
        sampler.add(1, 200);

        assert_eq!(sampler.total_weight(), 300);
        assert!(sampler.is_enabled(0));

        sampler.disable(0);
        assert!(!sampler.is_enabled(0));
        assert_eq!(sampler.total_weight(), 200);

        // All samples should go to peer 1
        assert_eq!(sampler.sample(0), Some(1));
        assert_eq!(sampler.sample(100), Some(1));

        sampler.enable(0);
        assert_eq!(sampler.total_weight(), 300);
    }

    #[test]
    fn test_sampler_remove() {
        let mut sampler = WeightedPeerSampler::new();
        sampler.add(10, 100);
        sampler.add(20, 200);
        sampler.add(30, 300);

        assert_eq!(sampler.len(), 3);
        assert!(sampler.remove(20));
        assert_eq!(sampler.len(), 2);
        assert_eq!(sampler.total_weight(), 400);

        // Removed peer should not be returned
        let mut found_peers = std::collections::HashSet::new();
        for i in 0..1000 {
            if let Some(peer) = sampler.sample(i) {
                found_peers.insert(peer);
            }
        }
        assert!(found_peers.contains(&10));
        assert!(found_peers.contains(&30));
        assert!(!found_peers.contains(&20));
    }

    #[test]
    fn test_sampler_update_weight() {
        let mut sampler = WeightedPeerSampler::new();
        sampler.add(0, 100);
        sampler.add(1, 100);
        assert_eq!(sampler.total_weight(), 200);

        sampler.update_weight(0, 900);
        assert_eq!(sampler.total_weight(), 1000);
    }

    #[test]
    fn test_sampler_clear() {
        let mut sampler = WeightedPeerSampler::new();
        sampler.add(0, 100);
        sampler.add(1, 200);
        sampler.clear();

        assert!(sampler.is_empty());
        assert_eq!(sampler.total_weight(), 0);
        assert_eq!(sampler.sample(42), None);
    }

    #[test]
    fn test_sampler_statistical_distribution() {
        let mut sampler = WeightedPeerSampler::new();
        // Equal weights: should be roughly 50/50
        sampler.add(0, 500);
        sampler.add(1, 500);

        let mut counts = [0u32; 2];
        let samples = 10_000;
        for i in 0u64..samples {
            // Use a simple hash-like distribution
            let rand = i
                .wrapping_mul(0x9E3779B97F4A7C15)
                .wrapping_add(0x123456789ABCDEF0);
            if let Some(peer) = sampler.sample(rand) {
                if peer < 2 {
                    counts[peer] += 1;
                }
            }
        }

        // Each peer should get roughly 50% of samples (within 10% margin)
        let expected = samples as u32 / 2;
        let margin = expected / 10;
        assert!(
            counts[0] > expected - margin && counts[0] < expected + margin,
            "peer 0 got {} samples, expected ~{}",
            counts[0],
            expected
        );
    }
}
