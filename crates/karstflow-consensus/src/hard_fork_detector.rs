/// Hard fork detection via bank hash divergence tracking.
///
/// Monitors votes from the network to detect when our validator has
/// produced a different bank hash than the supermajority for the same
/// block. This indicates a consensus bug that caused divergence.
///
/// Detection criteria (52% threshold):
/// - 52% of stake voted on a block_id with a bank_hash different from ours.
/// - 52% of stake voted on a block_id we marked as dead (failed execution).
///
/// Each vote account's last `max_live_slots` votes are tracked in a ring
/// buffer to bound memory. This makes detection heuristic — if validators
/// are far apart in slot progress, old votes may be evicted before reaching
/// the threshold.
use karstflow_storage::Pubkey;
use std::collections::{HashMap, VecDeque};

/// Threshold percentage for hard fork detection.
const HARD_FORK_THRESHOLD_PCT: f64 = 52.0;

/// Default maximum votes tracked per vote account.
const DEFAULT_MAX_VOTES_PER_ACCOUNT: usize = 400;

/// A vote observed from the network (gossip or replay).
#[derive(Debug, Clone)]
struct TrackedVote {
    /// Block identifier (shred merkle root).
    block_id: [u8; 32],
    /// Bank hash after executing the block.
    bank_hash: [u8; 32],
    /// Slot number.
    slot: u64,
    /// Stake weight of the voter at time of vote.
    stake: u64,
}

/// Candidate for hard fork detection — aggregates stake for a
/// (block_id, bank_hash) pair.
#[derive(Debug, Clone)]
struct Candidate {
    slot: u64,
    stake: u64,
    count: u64,
    checked: bool,
}

/// Our own replay result for a block.
#[derive(Debug, Clone)]
struct OurBlock {
    /// Whether we marked this block dead during replay.
    dead: bool,
    /// Whether we have finished replaying this block.
    replayed: bool,
    /// Our bank hash (valid only if replayed && !dead).
    our_bank_hash: [u8; 32],
    /// Set of bank hashes observed from the network for this block_id.
    observed_bank_hashes: Vec<[u8; 32]>,
    /// Whether multiple different bank hashes have been seen (a fork).
    forked: bool,
}

/// Hard fork detection event.
#[derive(Debug, Clone)]
pub struct HardForkEvent {
    /// The slot where divergence was detected.
    pub slot: u64,
    /// The block identifier.
    pub block_id: [u8; 32],
    /// Our bank hash (if we replayed the block).
    pub our_bank_hash: Option<[u8; 32]>,
    /// The divergent bank hash from the network supermajority.
    pub network_bank_hash: [u8; 32],
    /// Number of validators that voted for the divergent hash.
    pub voter_count: u64,
    /// Percentage of stake that voted for the divergent hash.
    pub stake_pct: f64,
    /// Whether we marked the block dead.
    pub we_marked_dead: bool,
}

/// Metrics for hard fork detection.
#[derive(Debug, Clone, Default)]
pub struct HardForkMetrics {
    /// Total hard forks seen.
    pub seen: u64,
    /// Currently active divergent blocks.
    pub active: u64,
    /// Divergent blocks that were pruned (evicted from tracking).
    pub pruned: u64,
    /// Maximum number of different bank hashes for any single block_id.
    pub max_width: u64,
}

/// Detects bank hash divergence indicating hard forks.
#[derive(Debug)]
pub struct HardForkDetector {
    /// Per vote-account ring buffer of recent votes.
    voter_history: HashMap<Pubkey, VecDeque<TrackedVote>>,
    /// Aggregate stake per (block_id, bank_hash) pair.
    candidates: HashMap<([u8; 32], [u8; 32]), Candidate>,
    /// Our replay state per block_id.
    our_blocks: HashMap<[u8; 32], OurBlock>,
    /// Maximum votes per account before eviction.
    max_votes_per_account: usize,
    /// Whether detection is fatal (abort) or warning-only.
    fatal: bool,
    /// Metrics.
    pub metrics: HardForkMetrics,
}

impl HardForkDetector {
    /// Create a new hard fork detector.
    ///
    /// If `fatal` is true, hard fork events will be treated as critical
    /// errors (useful for testing). If false, they are warnings only.
    pub fn new(fatal: bool) -> Self {
        Self {
            voter_history: HashMap::new(),
            candidates: HashMap::new(),
            our_blocks: HashMap::new(),
            max_votes_per_account: DEFAULT_MAX_VOTES_PER_ACCOUNT,
            fatal,
            metrics: HardForkMetrics::default(),
        }
    }

    /// Create with a custom vote history depth per account.
    pub fn with_history_depth(max_votes_per_account: usize, fatal: bool) -> Self {
        Self {
            max_votes_per_account,
            ..Self::new(fatal)
        }
    }

    /// Whether hard fork events are fatal.
    pub fn is_fatal(&self) -> bool {
        self.fatal
    }

    /// Count a vote from a validator.
    ///
    /// Returns `Some(HardForkEvent)` if this vote causes a hard fork
    /// to be detected (our bank hash differs from the network supermajority).
    pub fn count_vote(
        &mut self,
        vote_account: &Pubkey,
        block_id: &[u8; 32],
        bank_hash: &[u8; 32],
        slot: u64,
        stake: u64,
        total_stake: u64,
    ) -> Option<HardForkEvent> {
        // Only process newer votes from this voter.
        let history = self
            .voter_history
            .entry(vote_account.clone())
            .or_insert_with(|| VecDeque::with_capacity(self.max_votes_per_account));

        if let Some(last) = history.back() {
            if last.slot >= slot {
                return None;
            }
        }

        // Evict oldest vote if at capacity.
        if history.len() >= self.max_votes_per_account {
            if let Some(old) = history.pop_front() {
                let key = (old.block_id, old.bank_hash);
                if let Some(candidate) = self.candidates.get_mut(&key) {
                    candidate.stake = candidate.stake.saturating_sub(old.stake);
                    candidate.count = candidate.count.saturating_sub(1);
                    if candidate.count == 0 {
                        self.candidates.remove(&key);
                        // Clean up block tracking.
                        if let Some(block) = self.our_blocks.get_mut(&old.block_id) {
                            block
                                .observed_bank_hashes
                                .retain(|h| h != &old.bank_hash);
                            if block.observed_bank_hashes.is_empty() {
                                if block.forked {
                                    self.metrics.active =
                                        self.metrics.active.saturating_sub(1);
                                    self.metrics.pruned += 1;
                                }
                                self.our_blocks.remove(&old.block_id);
                            }
                        }
                    }
                }
            }
        }

        // Push the new vote.
        history.push_back(TrackedVote {
            block_id: *block_id,
            bank_hash: *bank_hash,
            slot,
            stake,
        });

        // Update candidate aggregate.
        let key = (*block_id, *bank_hash);
        let candidate = self.candidates.entry(key).or_insert(Candidate {
            slot,
            stake: 0,
            count: 0,
            checked: false,
        });
        candidate.count += 1;
        candidate.stake += stake;

        // Track observed bank hashes for this block_id.
        let block = self.our_blocks.entry(*block_id).or_insert(OurBlock {
            dead: false,
            replayed: false,
            our_bank_hash: [0u8; 32],
            observed_bank_hashes: Vec::new(),
            forked: false,
        });
        if !block.observed_bank_hashes.contains(bank_hash) {
            if !block.observed_bank_hashes.is_empty() {
                block.forked = true;
                self.metrics.seen += 1;
                self.metrics.active += 1;
            }
            block.observed_bank_hashes.push(*bank_hash);
        }
        let width = block.observed_bank_hashes.len() as u64;
        if width > self.metrics.max_width {
            self.metrics.max_width = width;
        }

        // Check for hard fork if we have replayed this block.
        if block.replayed {
            self.check_divergence(block_id, bank_hash, total_stake)
        } else {
            None
        }
    }

    /// Record our own bank hash for a block after replay.
    ///
    /// If `bank_hash` is `None`, the block was marked dead.
    /// Returns any hard fork events detected against already-counted votes.
    pub fn record_our_bank_hash(
        &mut self,
        block_id: &[u8; 32],
        bank_hash: Option<&[u8; 32]>,
        total_stake: u64,
    ) -> Vec<HardForkEvent> {
        let block = self.our_blocks.entry(*block_id).or_insert(OurBlock {
            dead: false,
            replayed: false,
            our_bank_hash: [0u8; 32],
            observed_bank_hashes: Vec::new(),
            forked: false,
        });

        match bank_hash {
            Some(hash) => {
                block.dead = false;
                block.replayed = true;
                block.our_bank_hash = *hash;
            }
            None => {
                block.dead = true;
                block.replayed = true;
            }
        }

        // Check all existing candidates for this block_id.
        let mut events = Vec::new();
        let observed: Vec<[u8; 32]> = block.observed_bank_hashes.clone();
        for bh in &observed {
            if let Some(event) = self.check_divergence(block_id, bh, total_stake) {
                events.push(event);
            }
        }
        events
    }

    /// Advance the root slot, pruning old tracking data.
    pub fn publish_root(&mut self, root_slot: u64) {
        // Remove candidates for slots older than root.
        self.candidates
            .retain(|_, c| c.slot >= root_slot);

        // Remove old blocks.
        self.our_blocks.retain(|_, b| {
            // Keep blocks that might still be relevant.
            // We don't track slot per block, so just keep all for now.
            // In practice, old blocks get cleaned up via vote eviction.
            let _ = b;
            true
        });

        // Trim old votes from voter history.
        for history in self.voter_history.values_mut() {
            while let Some(front) = history.front() {
                if front.slot < root_slot {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }

        // Remove empty voter histories.
        self.voter_history.retain(|_, h| !h.is_empty());
    }

    /// Check if a (block_id, bank_hash) pair diverges from our replay.
    fn check_divergence(
        &self,
        block_id: &[u8; 32],
        bank_hash: &[u8; 32],
        total_stake: u64,
    ) -> Option<HardForkEvent> {
        let key = (*block_id, *bank_hash);
        let candidate = self.candidates.get(&key)?;

        if candidate.checked {
            return None;
        }

        if total_stake == 0 {
            return None;
        }

        let pct = (candidate.stake as f64) * 100.0 / (total_stake as f64);
        if pct < HARD_FORK_THRESHOLD_PCT {
            return None;
        }

        let block = self.our_blocks.get(block_id)?;

        if block.dead {
            // We marked it dead but supermajority voted on it.
            Some(HardForkEvent {
                slot: candidate.slot,
                block_id: *block_id,
                our_bank_hash: None,
                network_bank_hash: *bank_hash,
                voter_count: candidate.count,
                stake_pct: pct,
                we_marked_dead: true,
            })
        } else if block.our_bank_hash != *bank_hash {
            // Our bank hash differs from the network supermajority.
            Some(HardForkEvent {
                slot: candidate.slot,
                block_id: *block_id,
                our_bank_hash: Some(block.our_bank_hash),
                network_bank_hash: *bank_hash,
                voter_count: candidate.count,
                stake_pct: pct,
                we_marked_dead: false,
            })
        } else {
            // Our hash matches — no divergence.
            None
        }
    }

    /// Mark a candidate as checked so it doesn't re-fire.
    pub fn mark_checked(&mut self, block_id: &[u8; 32], bank_hash: &[u8; 32]) {
        let key = (*block_id, *bank_hash);
        if let Some(candidate) = self.candidates.get_mut(&key) {
            candidate.checked = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    fn hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn no_divergence_when_hashes_match() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let bank_hash = hash(2);

        // Record our bank hash first.
        det.record_our_bank_hash(&block_id, Some(&bank_hash), 100);

        // Votes with same bank hash should not trigger.
        let result = det.count_vote(&pk(1), &block_id, &bank_hash, 10, 60, 100);
        assert!(result.is_none());
    }

    #[test]
    fn detects_divergence_at_threshold() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let our_hash = hash(2);
        let their_hash = hash(3);

        det.record_our_bank_hash(&block_id, Some(&our_hash), 100);

        // Below threshold: no detection.
        let result = det.count_vote(&pk(1), &block_id, &their_hash, 10, 51, 100);
        assert!(result.is_none());

        // At threshold: detect.
        let result = det.count_vote(&pk(2), &block_id, &their_hash, 11, 1, 100);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.slot, 10);
        assert_eq!(event.our_bank_hash, Some(our_hash));
        assert_eq!(event.network_bank_hash, their_hash);
        assert!(!event.we_marked_dead);
        assert!(event.stake_pct >= 52.0);
    }

    #[test]
    fn detects_dead_block_divergence() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let their_hash = hash(3);

        // We marked the block dead.
        det.record_our_bank_hash(&block_id, None, 100);

        // Network voted on it with enough stake.
        let result = det.count_vote(&pk(1), &block_id, &their_hash, 10, 53, 100);
        assert!(result.is_some());
        let event = result.unwrap();
        assert!(event.we_marked_dead);
        assert_eq!(event.our_bank_hash, None);
    }

    #[test]
    fn retroactive_detection_on_replay() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let our_hash = hash(2);
        let their_hash = hash(3);

        // Votes come in before we replay.
        det.count_vote(&pk(1), &block_id, &their_hash, 10, 30, 100);
        det.count_vote(&pk(2), &block_id, &their_hash, 11, 25, 100);

        // Now we replay and discover divergence.
        let events = det.record_our_bank_hash(&block_id, Some(&our_hash), 100);
        assert_eq!(events.len(), 1);
        assert!(events[0].stake_pct >= 52.0);
    }

    #[test]
    fn ignores_old_votes_from_same_voter() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let bank_hash = hash(2);

        det.count_vote(&pk(1), &block_id, &bank_hash, 10, 60, 100);
        // Older slot from same voter — should be ignored.
        let result = det.count_vote(&pk(1), &block_id, &bank_hash, 9, 60, 100);
        assert!(result.is_none());
    }

    #[test]
    fn mark_checked_prevents_re_fire() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let our_hash = hash(2);
        let their_hash = hash(3);

        det.record_our_bank_hash(&block_id, Some(&our_hash), 100);
        let result = det.count_vote(&pk(1), &block_id, &their_hash, 10, 53, 100);
        assert!(result.is_some());

        det.mark_checked(&block_id, &their_hash);

        // Additional votes should not re-trigger.
        let result = det.count_vote(&pk(2), &block_id, &their_hash, 11, 10, 100);
        assert!(result.is_none());
    }

    #[test]
    fn tracks_fork_metrics() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let hash_a = hash(2);
        let hash_b = hash(3);

        det.count_vote(&pk(1), &block_id, &hash_a, 10, 30, 100);
        assert_eq!(det.metrics.seen, 0);

        // Second different bank hash for same block_id triggers fork metric.
        det.count_vote(&pk(2), &block_id, &hash_b, 11, 30, 100);
        assert_eq!(det.metrics.seen, 1);
        assert_eq!(det.metrics.active, 1);
        assert_eq!(det.metrics.max_width, 2);
    }

    #[test]
    fn publish_root_prunes_old_data() {
        let mut det = HardForkDetector::new(false);
        let block_id = hash(1);
        let bank_hash = hash(2);

        det.count_vote(&pk(1), &block_id, &bank_hash, 5, 30, 100);
        det.count_vote(&pk(2), &block_id, &bank_hash, 6, 30, 100);

        assert!(!det.voter_history.is_empty());

        det.publish_root(10);

        // Old votes should be pruned.
        for history in det.voter_history.values() {
            for vote in history {
                assert!(vote.slot >= 10);
            }
        }
    }
}
