/// Partitioned epoch rewards distribution.
///
/// After epoch rewards are calculated, they must be distributed to individual
/// stake and vote accounts. To avoid blocking the validator for an extended
/// period, distribution is spread across multiple consecutive slots.
///
/// The `RewardsDistributor` splits the pending rewards into partitions and
/// provides the subset that should be applied during each slot.
use crate::epoch_processing::RewardType;
use paradencer_constants::economics::MAX_REWARDS_PER_SLOT;
use paradencer_storage::Pubkey;

/// A single pending reward waiting to be credited to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReward {
    /// Target account (stake or vote account)
    pub account: Pubkey,
    /// Lamports to credit
    pub amount: u64,
    /// Classification of the reward
    pub reward_type: RewardType,
}

/// Tracks the state of a single distribution partition.
#[derive(Debug, Clone, PartialEq)]
struct Partition {
    /// Index of the first reward in this partition (into the rewards vec)
    start_index: usize,
    /// Number of rewards in this partition
    count: usize,
    /// Whether this partition has already been distributed
    distributed: bool,
}

/// Distributes epoch rewards across multiple slots.
///
/// Rewards are divided into partitions of at most `MAX_REWARDS_PER_SLOT` entries.
/// Each partition is assigned to a consecutive slot starting from `start_slot`.
/// The caller invokes `rewards_for_slot` once per slot and credits the returned
/// accounts, then calls `mark_slot_distributed` to record progress.
#[derive(Debug, Clone, PartialEq)]
pub struct RewardsDistributor {
    /// All pending rewards (ordered for deterministic distribution)
    pending_rewards: Vec<PendingReward>,
    /// Partition metadata (maps partition index -> slice of pending_rewards)
    partitions: Vec<Partition>,
    /// Total number of distribution partitions
    total_partitions: u64,
    /// First slot in the distribution window
    start_slot: u64,
    /// Number of partitions that have been distributed so far
    distributed_count: u64,
}

impl RewardsDistributor {
    /// Create a new distributor that spreads `rewards` over `total_partitions` slots.
    ///
    /// If `total_partitions` is 0, all rewards will be placed into a single partition.
    /// The actual number of partitions is capped by the number of rewards divided
    /// by `MAX_REWARDS_PER_SLOT` (i.e., we never create more partitions than needed).
    pub fn new(rewards: Vec<PendingReward>, total_partitions: u64, start_slot: u64) -> Self {
        let total_partitions = total_partitions.max(1);
        let reward_count = rewards.len();

        // Build partitions: distribute rewards as evenly as possible
        let mut partitions = Vec::new();
        if reward_count > 0 {
            let per_partition = (reward_count as u64)
                .checked_div(total_partitions)
                .unwrap_or(reward_count as u64)
                .max(1) as usize;

            let capped_per_partition = per_partition.min(MAX_REWARDS_PER_SLOT);

            let mut offset = 0;
            while offset < reward_count {
                let count = capped_per_partition.min(reward_count - offset);
                partitions.push(Partition {
                    start_index: offset,
                    count,
                    distributed: false,
                });
                offset += count;
            }
        }

        let effective_partitions = partitions.len() as u64;

        Self {
            pending_rewards: rewards,
            partitions,
            total_partitions: effective_partitions,
            start_slot,
            distributed_count: 0,
        }
    }

    /// Get the rewards that should be distributed during `slot`.
    ///
    /// Returns an empty slice if the slot falls outside the distribution window
    /// or the corresponding partition has already been distributed.
    pub fn rewards_for_slot(&self, slot: u64) -> &[PendingReward] {
        if slot < self.start_slot {
            return &[];
        }

        let partition_index = (slot - self.start_slot) as usize;
        if partition_index >= self.partitions.len() {
            return &[];
        }

        let partition = &self.partitions[partition_index];
        if partition.distributed {
            return &[];
        }

        let start = partition.start_index;
        let end = start + partition.count;
        &self.pending_rewards[start..end]
    }

    /// Mark the partition for `slot` as distributed.
    ///
    /// This is idempotent: calling it on an already-distributed slot is a no-op.
    pub fn mark_slot_distributed(&mut self, slot: u64) {
        if slot < self.start_slot {
            return;
        }

        let partition_index = (slot - self.start_slot) as usize;
        if partition_index >= self.partitions.len() {
            return;
        }

        if !self.partitions[partition_index].distributed {
            self.partitions[partition_index].distributed = true;
            self.distributed_count += 1;
        }
    }

    /// Check whether all partitions have been distributed.
    pub fn is_complete(&self) -> bool {
        self.distributed_count >= self.total_partitions
    }

    /// Number of partitions remaining.
    pub fn remaining_partitions(&self) -> u64 {
        self.total_partitions.saturating_sub(self.distributed_count)
    }

    /// Total number of pending reward entries.
    pub fn total_rewards_count(&self) -> usize {
        self.pending_rewards.len()
    }

    /// Total lamports pending distribution.
    pub fn total_pending_lamports(&self) -> u64 {
        self.pending_rewards.iter().map(|r| r.amount).sum()
    }

    /// The first slot of the distribution window.
    pub fn start_slot(&self) -> u64 {
        self.start_slot
    }

    /// The last slot of the distribution window (inclusive).
    pub fn end_slot(&self) -> u64 {
        self.start_slot
            .saturating_add(self.total_partitions.saturating_sub(1))
    }

    /// Total number of distribution partitions.
    pub fn partition_count(&self) -> u64 {
        self.total_partitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rewards(count: usize) -> Vec<PendingReward> {
        (0..count)
            .map(|_| PendingReward {
                account: Pubkey::new_unique(),
                amount: 1_000,
                reward_type: RewardType::Staking,
            })
            .collect()
    }

    #[test]
    fn distributor_with_empty_rewards() {
        let dist = RewardsDistributor::new(Vec::new(), 10, 100);
        assert!(dist.is_complete());
        assert_eq!(dist.total_rewards_count(), 0);
        assert_eq!(dist.total_pending_lamports(), 0);
    }

    #[test]
    fn distributor_single_partition() {
        let rewards = make_rewards(5);
        let dist = RewardsDistributor::new(rewards, 1, 100);

        assert_eq!(dist.partition_count(), 1);
        assert!(!dist.is_complete());
        assert_eq!(dist.remaining_partitions(), 1);
        assert_eq!(dist.rewards_for_slot(100).len(), 5);
        assert_eq!(dist.total_pending_lamports(), 5_000);
    }

    #[test]
    fn distributor_distributes_across_slots() {
        // 10 rewards, request 5 partitions => 2 per partition
        let rewards = make_rewards(10);
        let mut dist = RewardsDistributor::new(rewards, 5, 100);

        assert!(!dist.is_complete());

        let mut total_distributed = 0;
        for slot in 100..110 {
            let batch = dist.rewards_for_slot(slot);
            total_distributed += batch.len();
            dist.mark_slot_distributed(slot);
        }

        assert_eq!(total_distributed, 10);
        assert!(dist.is_complete());
    }

    #[test]
    fn distributor_returns_empty_for_out_of_range_slot() {
        let rewards = make_rewards(5);
        let dist = RewardsDistributor::new(rewards, 2, 100);

        // Before start
        assert!(dist.rewards_for_slot(99).is_empty());
        // After end
        assert!(dist.rewards_for_slot(200).is_empty());
    }

    #[test]
    fn distributor_idempotent_mark() {
        let rewards = make_rewards(5);
        let mut dist = RewardsDistributor::new(rewards, 1, 100);

        dist.mark_slot_distributed(100);
        assert!(dist.is_complete());

        // Second call is a no-op
        dist.mark_slot_distributed(100);
        assert!(dist.is_complete());
        assert_eq!(dist.remaining_partitions(), 0);
    }

    #[test]
    fn distributor_already_distributed_returns_empty() {
        let rewards = make_rewards(5);
        let mut dist = RewardsDistributor::new(rewards, 1, 100);

        assert_eq!(dist.rewards_for_slot(100).len(), 5);
        dist.mark_slot_distributed(100);
        assert!(dist.rewards_for_slot(100).is_empty());
    }

    #[test]
    fn distributor_tracks_start_and_end_slot() {
        let rewards = make_rewards(20);
        let dist = RewardsDistributor::new(rewards, 5, 50);

        assert_eq!(dist.start_slot(), 50);
        // End slot is start + partition_count - 1
        let expected_end = 50 + dist.partition_count() - 1;
        assert_eq!(dist.end_slot(), expected_end);
    }

    #[test]
    fn distributor_caps_partition_size_at_max() {
        // Create more rewards than MAX_REWARDS_PER_SLOT * partitions
        let rewards = make_rewards(MAX_REWARDS_PER_SLOT * 3);
        let dist = RewardsDistributor::new(rewards, 1, 0);

        // Should create multiple partitions even though we requested 1
        assert!(dist.partition_count() >= 3);

        // Each partition should have at most MAX_REWARDS_PER_SLOT entries
        for slot in 0..dist.partition_count() {
            let batch = dist.rewards_for_slot(slot);
            assert!(batch.len() <= MAX_REWARDS_PER_SLOT);
        }
    }

    #[test]
    fn distributor_large_partition_request() {
        // 10 rewards with 100 requested partitions -- should create ~10 partitions
        let rewards = make_rewards(10);
        let dist = RewardsDistributor::new(rewards, 100, 0);

        assert!(dist.partition_count() <= 10);
        assert_eq!(dist.total_rewards_count(), 10);
    }

    #[test]
    fn distributor_mark_out_of_range_is_noop() {
        let rewards = make_rewards(5);
        let mut dist = RewardsDistributor::new(rewards, 1, 100);

        dist.mark_slot_distributed(50); // before start
        dist.mark_slot_distributed(200); // after end
        assert!(!dist.is_complete());
    }
}
