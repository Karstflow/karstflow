/// Bounded cache of vote account metadata for epoch processing.
///
/// Maintains per-vote-account summaries (commission, node identity,
/// last vote slot, timestamps) and three epochs of stake snapshots
/// used by leader schedule generation, clock calculation, and tower
/// consensus. Updated post-transaction when vote accounts change and
/// rotated at epoch boundaries.
use paradencer_types::Pubkey;
use std::collections::HashMap;

/// Cached summary of a single vote account's state.
///
/// Stores the subset of vote-account fields that other subsystems
/// (leader schedule, rewards, tower) need without deserializing the
/// full vote state on every access.
#[derive(Debug, Clone)]
pub struct VoteAccountEntry {
    /// Validator node identity that owns this vote account.
    pub node_pubkey: Pubkey,
    /// Commission rate (0-100) for reward distribution.
    pub commission: u8,
    /// Most recently voted slot.
    pub last_vote_slot: u64,
    /// Timestamp attached to the last vote.
    pub last_vote_timestamp: i64,
    /// Effective stake for the current epoch.
    pub stake: u64,
    /// Effective stake at the end of the previous epoch (E-1).
    pub stake_prev: u64,
    /// Effective stake at the end of two epochs ago (E-2).
    ///
    /// Used by tower consensus for threshold and switch checks.
    pub stake_prev_prev: u64,
}

impl VoteAccountEntry {
    /// Create a new entry with only current-epoch data.
    pub fn new(
        node_pubkey: Pubkey,
        commission: u8,
        last_vote_slot: u64,
        last_vote_timestamp: i64,
    ) -> Self {
        Self {
            node_pubkey,
            commission,
            last_vote_slot,
            last_vote_timestamp,
            stake: 0,
            stake_prev: 0,
            stake_prev_prev: 0,
        }
    }
}

/// Cache of all known vote account summaries.
///
/// Keyed by vote account pubkey. The cache is populated from snapshot
/// data at startup and updated incrementally as vote transactions
/// modify vote account state.
#[derive(Debug, Clone)]
pub struct VoteAccountCache {
    entries: HashMap<Pubkey, VoteAccountEntry>,
    /// Total epoch stake across all entries (current epoch).
    total_epoch_stake: u64,
}

impl VoteAccountCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            total_epoch_stake: 0,
        }
    }

    /// Create a cache pre-allocated for the expected number of vote accounts.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            total_epoch_stake: 0,
        }
    }

    /// Get a reference to an entry.
    pub fn get(&self, vote_account: &Pubkey) -> Option<&VoteAccountEntry> {
        self.entries.get(vote_account)
    }

    /// Number of cached vote accounts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total epoch stake summed across all vote accounts.
    pub fn total_epoch_stake(&self) -> u64 {
        self.total_epoch_stake
    }

    /// Insert or update a vote account entry from parsed vote state.
    ///
    /// Called after a transaction modifies a vote account. Updates the
    /// cached metadata (commission, node identity, last vote, timestamp)
    /// while preserving existing stake values.
    pub fn update_from_vote_state(
        &mut self,
        vote_account: Pubkey,
        node_pubkey: Pubkey,
        commission: u8,
        last_vote_slot: u64,
        last_vote_timestamp: i64,
    ) {
        let entry = self
            .entries
            .entry(vote_account)
            .or_insert_with(|| VoteAccountEntry::new(node_pubkey, commission, 0, 0));

        entry.node_pubkey = node_pubkey;
        entry.commission = commission;
        entry.last_vote_slot = last_vote_slot;
        entry.last_vote_timestamp = last_vote_timestamp;
    }

    /// Remove a vote account (e.g., when lamports drop to zero).
    pub fn remove(&mut self, vote_account: &Pubkey) {
        if let Some(removed) = self.entries.remove(vote_account) {
            self.total_epoch_stake = self.total_epoch_stake.saturating_sub(removed.stake);
        }
    }

    /// Set the current epoch stake for a vote account.
    ///
    /// Called during epoch refresh when recalculating effective stakes
    /// from stake delegations.
    pub fn set_stake(&mut self, vote_account: &Pubkey, stake: u64) {
        if let Some(entry) = self.entries.get_mut(vote_account) {
            self.total_epoch_stake = self
                .total_epoch_stake
                .saturating_sub(entry.stake)
                .saturating_add(stake);
            entry.stake = stake;
        }
    }

    /// Rotate epoch stakes: current → prev → prev_prev.
    ///
    /// Called at the epoch boundary before recalculating new stakes.
    /// After rotation, all current stakes are zero until refreshed.
    pub fn rotate_epoch(&mut self) {
        for entry in self.entries.values_mut() {
            entry.stake_prev_prev = entry.stake_prev;
            entry.stake_prev = entry.stake;
            entry.stake = 0;
        }
        self.total_epoch_stake = 0;
    }

    /// Reset all current epoch stakes to zero (before recalculation).
    pub fn reset_stakes(&mut self) {
        for entry in self.entries.values_mut() {
            entry.stake = 0;
        }
        self.total_epoch_stake = 0;
    }

    /// Iterate over all cached entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Pubkey, &VoteAccountEntry)> {
        self.entries.iter()
    }

    /// Get all vote accounts with nonzero current stake, sorted by
    /// descending stake (useful for leader schedule generation).
    pub fn staked_vote_accounts(&self) -> Vec<(&Pubkey, &VoteAccountEntry)> {
        let mut staked: Vec<_> = self.entries.iter().filter(|(_, e)| e.stake > 0).collect();
        staked.sort_by(|a, b| b.1.stake.cmp(&a.1.stake));
        staked
    }

    /// Get node pubkey for a vote account.
    pub fn node_pubkey(&self, vote_account: &Pubkey) -> Option<&Pubkey> {
        self.entries.get(vote_account).map(|e| &e.node_pubkey)
    }

    /// Get commission for a vote account.
    pub fn commission(&self, vote_account: &Pubkey) -> Option<u8> {
        self.entries.get(vote_account).map(|e| e.commission)
    }
}

impl Default for VoteAccountCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pubkey(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    #[test]
    fn empty_cache_defaults() {
        let cache = VoteAccountCache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert_eq!(cache.total_epoch_stake(), 0);
        assert!(cache.get(&make_pubkey(1)).is_none());
    }

    #[test]
    fn insert_and_retrieve() {
        let mut cache = VoteAccountCache::new();
        let vote = make_pubkey(1);
        let node = make_pubkey(2);

        cache.update_from_vote_state(vote, node, 10, 100, 1_700_000_000);

        let entry = cache.get(&vote).unwrap();
        assert_eq!(entry.node_pubkey, node);
        assert_eq!(entry.commission, 10);
        assert_eq!(entry.last_vote_slot, 100);
        assert_eq!(entry.last_vote_timestamp, 1_700_000_000);
        assert_eq!(entry.stake, 0); // Not yet set
    }

    #[test]
    fn update_preserves_stake() {
        let mut cache = VoteAccountCache::new();
        let vote = make_pubkey(1);
        let node = make_pubkey(2);

        cache.update_from_vote_state(vote, node, 10, 50, 0);
        cache.set_stake(&vote, 1000);
        assert_eq!(cache.get(&vote).unwrap().stake, 1000);

        // Update from vote state preserves existing stake
        cache.update_from_vote_state(vote, node, 15, 100, 1);
        assert_eq!(cache.get(&vote).unwrap().commission, 15);
        assert_eq!(cache.get(&vote).unwrap().last_vote_slot, 100);
        assert_eq!(cache.get(&vote).unwrap().stake, 1000);
    }

    #[test]
    fn set_stake_updates_total() {
        let mut cache = VoteAccountCache::new();
        let v1 = make_pubkey(1);
        let v2 = make_pubkey(2);
        let node = make_pubkey(10);

        cache.update_from_vote_state(v1, node, 5, 0, 0);
        cache.update_from_vote_state(v2, node, 5, 0, 0);

        cache.set_stake(&v1, 3000);
        cache.set_stake(&v2, 7000);
        assert_eq!(cache.total_epoch_stake(), 10_000);

        // Update v1 stake
        cache.set_stake(&v1, 5000);
        assert_eq!(cache.total_epoch_stake(), 12_000);
    }

    #[test]
    fn remove_decrements_total_stake() {
        let mut cache = VoteAccountCache::new();
        let vote = make_pubkey(1);
        let node = make_pubkey(2);

        cache.update_from_vote_state(vote, node, 5, 0, 0);
        cache.set_stake(&vote, 5000);
        assert_eq!(cache.total_epoch_stake(), 5000);

        cache.remove(&vote);
        assert_eq!(cache.total_epoch_stake(), 0);
        assert!(cache.get(&vote).is_none());
    }

    #[test]
    fn rotate_epoch_shifts_stakes() {
        let mut cache = VoteAccountCache::new();
        let vote = make_pubkey(1);
        let node = make_pubkey(2);

        cache.update_from_vote_state(vote, node, 5, 0, 0);
        cache.set_stake(&vote, 1000);

        // First rotation: current → prev, prev → prev_prev
        cache.rotate_epoch();
        let entry = cache.get(&vote).unwrap();
        assert_eq!(entry.stake, 0);
        assert_eq!(entry.stake_prev, 1000);
        assert_eq!(entry.stake_prev_prev, 0);
        assert_eq!(cache.total_epoch_stake(), 0);

        // Set new stake after rotation
        cache.set_stake(&vote, 2000);

        // Second rotation
        cache.rotate_epoch();
        let entry = cache.get(&vote).unwrap();
        assert_eq!(entry.stake, 0);
        assert_eq!(entry.stake_prev, 2000);
        assert_eq!(entry.stake_prev_prev, 1000);
    }

    #[test]
    fn staked_vote_accounts_sorted_descending() {
        let mut cache = VoteAccountCache::new();
        let v1 = make_pubkey(1);
        let v2 = make_pubkey(2);
        let v3 = make_pubkey(3);
        let node = make_pubkey(10);

        cache.update_from_vote_state(v1, node, 5, 0, 0);
        cache.update_from_vote_state(v2, node, 5, 0, 0);
        cache.update_from_vote_state(v3, node, 5, 0, 0);

        cache.set_stake(&v1, 100);
        cache.set_stake(&v2, 300);
        cache.set_stake(&v3, 200);

        let staked = cache.staked_vote_accounts();
        assert_eq!(staked.len(), 3);
        assert_eq!(*staked[0].0, v2); // 300
        assert_eq!(*staked[1].0, v3); // 200
        assert_eq!(*staked[2].0, v1); // 100
    }

    #[test]
    fn staked_vote_accounts_excludes_zero_stake() {
        let mut cache = VoteAccountCache::new();
        let v1 = make_pubkey(1);
        let v2 = make_pubkey(2);
        let node = make_pubkey(10);

        cache.update_from_vote_state(v1, node, 5, 0, 0);
        cache.update_from_vote_state(v2, node, 5, 0, 0);
        cache.set_stake(&v1, 100);
        // v2 has stake=0

        let staked = cache.staked_vote_accounts();
        assert_eq!(staked.len(), 1);
        assert_eq!(*staked[0].0, v1);
    }

    #[test]
    fn reset_stakes_zeros_current_only() {
        let mut cache = VoteAccountCache::new();
        let vote = make_pubkey(1);
        let node = make_pubkey(2);

        cache.update_from_vote_state(vote, node, 5, 0, 0);
        cache.set_stake(&vote, 1000);
        cache.rotate_epoch();
        cache.set_stake(&vote, 2000);

        cache.reset_stakes();
        let entry = cache.get(&vote).unwrap();
        assert_eq!(entry.stake, 0);
        assert_eq!(entry.stake_prev, 1000); // Preserved
        assert_eq!(cache.total_epoch_stake(), 0);
    }
}
