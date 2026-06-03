/// Network-wide stake delegation tracking.
///
/// Aggregates all stake delegations across the network for consensus weight
/// calculation and leader schedule generation. Maintains a mapping from
/// stake accounts to their delegations with epoch-aware effective stake.
///
/// Also maintains a vote account cache for fast lookups during consensus
/// and leader schedule computation.
use crate::stake::delegation::Delegation;
use karstflow_storage::Pubkey;
use std::collections::HashMap;

/// Cached vote account info for fast consensus lookups.
#[derive(Debug, Clone)]
pub struct VoteAccountEntry {
    /// Node identity pubkey of the validator running this vote account.
    pub node_pubkey: Pubkey,
    /// Commission percentage (0-100).
    pub commission: u8,
    /// Last vote slot (used for delinquency detection).
    pub last_vote_slot: u64,
    /// Total active stake delegated to this vote account (cached).
    pub activated_stake: u64,
}

/// Tracks all stake delegations across the network.
#[derive(Debug, Clone)]
pub struct StakeTracker {
    /// Map of stake account pubkey to delegation
    delegations: HashMap<Pubkey, Delegation>,
    /// Current epoch for warmup/cooldown calculations
    current_epoch: u64,
    /// Vote account cache: vote_pubkey -> VoteAccountEntry
    vote_accounts: HashMap<Pubkey, VoteAccountEntry>,
}

impl StakeTracker {
    pub fn new(current_epoch: u64) -> Self {
        Self {
            delegations: HashMap::new(),
            current_epoch,
            vote_accounts: HashMap::new(),
        }
    }

    /// Register a new stake delegation.
    pub fn add_delegation(&mut self, stake_account: Pubkey, delegation: Delegation) {
        self.delegations.insert(stake_account, delegation);
    }

    /// Remove a stake delegation.
    pub fn remove_delegation(&mut self, stake_account: &Pubkey) {
        self.delegations.remove(stake_account);
    }

    /// Get delegation for a stake account.
    pub fn get_delegation(&self, stake_account: &Pubkey) -> Option<&Delegation> {
        self.delegations.get(stake_account)
    }

    /// Update current epoch for warmup/cooldown calculations.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Calculate total effective stake delegated to a vote account.
    ///
    /// Uses simplified warmup/cooldown (no history-based calculation).
    pub fn total_stake_for_voter(&self, voter: &Pubkey) -> u64 {
        self.delegations
            .values()
            .filter(|d| &d.voter_pubkey == voter)
            .map(|d| d.effective_stake(self.current_epoch, None, None))
            .sum()
    }

    /// Get all vote accounts with their total effective stake.
    ///
    /// Returns map of vote_pubkey -> total_effective_stake.
    pub fn stake_by_vote_account(&self) -> HashMap<Pubkey, u64> {
        let mut result = HashMap::new();

        for delegation in self.delegations.values() {
            let effective = delegation.effective_stake(self.current_epoch, None, None);
            *result.entry(delegation.voter_pubkey).or_insert(0) += effective;
        }

        result
    }

    /// Calculate total stake across all delegations.
    pub fn total_stake(&self) -> u64 {
        self.delegations
            .values()
            .map(|d| d.effective_stake(self.current_epoch, None, None))
            .sum()
    }

    /// Get number of stake accounts.
    pub fn delegation_count(&self) -> usize {
        self.delegations.len()
    }

    /// Get all stake accounts delegating to a specific voter.
    pub fn delegations_for_voter(&self, voter: &Pubkey) -> Vec<(Pubkey, &Delegation)> {
        self.delegations
            .iter()
            .filter(|(_, d)| &d.voter_pubkey == voter)
            .map(|(k, v)| (*k, v))
            .collect()
    }

    // --- Vote account cache ---

    /// Register or update a vote account in the cache.
    pub fn set_vote_account(&mut self, vote_pubkey: Pubkey, entry: VoteAccountEntry) {
        self.vote_accounts.insert(vote_pubkey, entry);
    }

    /// Get cached vote account info.
    pub fn get_vote_account(&self, vote_pubkey: &Pubkey) -> Option<&VoteAccountEntry> {
        self.vote_accounts.get(vote_pubkey)
    }

    /// Remove a vote account from cache.
    pub fn remove_vote_account(&mut self, vote_pubkey: &Pubkey) {
        self.vote_accounts.remove(vote_pubkey);
    }

    /// Number of cached vote accounts.
    pub fn vote_account_count(&self) -> usize {
        self.vote_accounts.len()
    }

    /// Refresh vote account stake totals from current delegations.
    ///
    /// Recalculates `activated_stake` for each cached vote account
    /// based on effective stake from all delegations. This should be
    /// called after loading from snapshot or at epoch boundaries.
    pub fn refresh_vote_account_stakes(&mut self) {
        // Reset all stakes to zero
        for entry in self.vote_accounts.values_mut() {
            entry.activated_stake = 0;
        }

        // Accumulate effective stake from delegations
        for delegation in self.delegations.values() {
            let effective = delegation.effective_stake(self.current_epoch, None, None);
            if let Some(entry) = self.vote_accounts.get_mut(&delegation.voter_pubkey) {
                entry.activated_stake += effective;
            }
        }
    }

    /// Post-snapshot refresh: validate delegations and remove invalid entries.
    ///
    /// Removes delegations whose vote account is not in the vote account cache.
    /// Returns the number of removed delegations.
    pub fn refresh_after_snapshot(&mut self) -> usize {
        let vote_keys: std::collections::HashSet<Pubkey> =
            self.vote_accounts.keys().copied().collect();
        let before = self.delegations.len();
        self.delegations
            .retain(|_, d| vote_keys.contains(&d.voter_pubkey));
        let removed = before - self.delegations.len();

        // Refresh stake totals
        self.refresh_vote_account_stakes();
        removed
    }

    /// Get all vote accounts sorted by stake (descending).
    pub fn vote_accounts_by_stake(&self) -> Vec<(Pubkey, &VoteAccountEntry)> {
        let mut entries: Vec<_> = self.vote_accounts.iter().map(|(k, v)| (*k, v)).collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.1.activated_stake));
        entries
    }

    /// Iterate over all vote accounts.
    pub fn vote_accounts_iter(&self) -> impl Iterator<Item = (&Pubkey, &VoteAccountEntry)> {
        self.vote_accounts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter_a() -> Pubkey {
        Pubkey::new([1u8; 32])
    }
    fn voter_b() -> Pubkey {
        Pubkey::new([2u8; 32])
    }
    fn stake_key(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn delegation_to(voter: Pubkey, amount: u64, epoch: u64) -> Delegation {
        Delegation::new(voter, amount, epoch)
    }

    #[test]
    fn new_tracker_is_empty() {
        let tracker = StakeTracker::new(0);
        assert_eq!(tracker.delegation_count(), 0);
        assert_eq!(tracker.total_stake(), 0);
    }

    #[test]
    fn add_and_get_delegation() {
        let mut tracker = StakeTracker::new(10);
        let key = stake_key(10);
        let d = delegation_to(voter_a(), 1000, 5);
        tracker.add_delegation(key, d.clone());

        assert_eq!(tracker.delegation_count(), 1);
        let got = tracker.get_delegation(&key).unwrap();
        assert_eq!(got.voter_pubkey, voter_a());
        assert_eq!(got.stake_amount, 1000);
    }

    #[test]
    fn remove_delegation() {
        let mut tracker = StakeTracker::new(10);
        let key = stake_key(10);
        tracker.add_delegation(key, delegation_to(voter_a(), 1000, 5));
        tracker.remove_delegation(&key);
        assert_eq!(tracker.delegation_count(), 0);
        assert!(tracker.get_delegation(&key).is_none());
    }

    #[test]
    fn total_stake_for_voter() {
        let mut tracker = StakeTracker::new(10);
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_a(), 2000, 5));
        tracker.add_delegation(stake_key(12), delegation_to(voter_b(), 500, 5));

        assert_eq!(tracker.total_stake_for_voter(&voter_a()), 3000);
        assert_eq!(tracker.total_stake_for_voter(&voter_b()), 500);
    }

    #[test]
    fn total_stake() {
        let mut tracker = StakeTracker::new(10);
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_b(), 2000, 5));

        assert_eq!(tracker.total_stake(), 3000);
    }

    #[test]
    fn stake_by_vote_account() {
        let mut tracker = StakeTracker::new(10);
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_a(), 2000, 5));
        tracker.add_delegation(stake_key(12), delegation_to(voter_b(), 500, 5));

        let by_voter = tracker.stake_by_vote_account();
        assert_eq!(by_voter.len(), 2);
        assert_eq!(*by_voter.get(&voter_a()).unwrap(), 3000);
        assert_eq!(*by_voter.get(&voter_b()).unwrap(), 500);
    }

    #[test]
    fn delegations_for_voter() {
        let mut tracker = StakeTracker::new(10);
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_a(), 2000, 5));
        tracker.add_delegation(stake_key(12), delegation_to(voter_b(), 500, 5));

        let voter_a_delegations = tracker.delegations_for_voter(&voter_a());
        assert_eq!(voter_a_delegations.len(), 2);

        let voter_b_delegations = tracker.delegations_for_voter(&voter_b());
        assert_eq!(voter_b_delegations.len(), 1);
    }

    #[test]
    fn set_epoch_affects_effective_stake() {
        let mut tracker = StakeTracker::new(5);
        // At epoch 5 (activation epoch), effective stake is 0
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        assert_eq!(tracker.total_stake(), 0);

        // After activation epoch, without history it's fully activated
        tracker.set_epoch(6);
        assert_eq!(tracker.total_stake(), 1000);
    }

    #[test]
    fn unknown_voter_returns_zero_stake() {
        let tracker = StakeTracker::new(10);
        let unknown = Pubkey::new([99u8; 32]);
        assert_eq!(tracker.total_stake_for_voter(&unknown), 0);
    }

    #[test]
    fn overwrite_delegation() {
        let mut tracker = StakeTracker::new(10);
        let key = stake_key(10);
        tracker.add_delegation(key, delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(key, delegation_to(voter_b(), 2000, 5));

        assert_eq!(tracker.delegation_count(), 1);
        let got = tracker.get_delegation(&key).unwrap();
        assert_eq!(got.voter_pubkey, voter_b());
        assert_eq!(got.stake_amount, 2000);
    }

    fn make_vote_entry(node_id: u8, commission: u8) -> VoteAccountEntry {
        VoteAccountEntry {
            node_pubkey: Pubkey::new([node_id; 32]),
            commission,
            last_vote_slot: 0,
            activated_stake: 0,
        }
    }

    #[test]
    fn vote_account_cache_basic() {
        let mut tracker = StakeTracker::new(10);
        tracker.set_vote_account(voter_a(), make_vote_entry(10, 5));
        assert_eq!(tracker.vote_account_count(), 1);
        assert!(tracker.get_vote_account(&voter_a()).is_some());
        assert!(tracker.get_vote_account(&voter_b()).is_none());
    }

    #[test]
    fn vote_account_remove() {
        let mut tracker = StakeTracker::new(10);
        tracker.set_vote_account(voter_a(), make_vote_entry(10, 5));
        tracker.remove_vote_account(&voter_a());
        assert_eq!(tracker.vote_account_count(), 0);
    }

    #[test]
    fn refresh_vote_account_stakes() {
        let mut tracker = StakeTracker::new(10);
        tracker.set_vote_account(voter_a(), make_vote_entry(10, 5));
        tracker.set_vote_account(voter_b(), make_vote_entry(20, 10));
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_a(), 2000, 5));
        tracker.add_delegation(stake_key(12), delegation_to(voter_b(), 500, 5));

        tracker.refresh_vote_account_stakes();
        assert_eq!(
            tracker
                .get_vote_account(&voter_a())
                .unwrap()
                .activated_stake,
            3000
        );
        assert_eq!(
            tracker
                .get_vote_account(&voter_b())
                .unwrap()
                .activated_stake,
            500
        );
    }

    #[test]
    fn refresh_after_snapshot_removes_orphans() {
        let mut tracker = StakeTracker::new(10);
        tracker.set_vote_account(voter_a(), make_vote_entry(10, 5));
        // voter_b NOT in vote account cache
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 1000, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_b(), 2000, 5));

        let removed = tracker.refresh_after_snapshot();
        assert_eq!(removed, 1); // voter_b delegation removed
        assert_eq!(tracker.delegation_count(), 1);
        assert_eq!(
            tracker
                .get_vote_account(&voter_a())
                .unwrap()
                .activated_stake,
            1000
        );
    }

    #[test]
    fn vote_accounts_by_stake_sorted() {
        let mut tracker = StakeTracker::new(10);
        tracker.set_vote_account(voter_a(), make_vote_entry(10, 5));
        tracker.set_vote_account(voter_b(), make_vote_entry(20, 10));
        tracker.add_delegation(stake_key(10), delegation_to(voter_a(), 100, 5));
        tracker.add_delegation(stake_key(11), delegation_to(voter_b(), 5000, 5));
        tracker.refresh_vote_account_stakes();

        let sorted = tracker.vote_accounts_by_stake();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].0, voter_b()); // higher stake first
        assert_eq!(sorted[0].1.activated_stake, 5000);
        assert_eq!(sorted[1].0, voter_a());
        assert_eq!(sorted[1].1.activated_stake, 100);
    }
}
