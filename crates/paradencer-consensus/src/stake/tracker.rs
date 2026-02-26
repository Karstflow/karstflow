/// Network-wide stake delegation tracking.
///
/// Aggregates all stake delegations across the network for consensus weight
/// calculation and leader schedule generation. Maintains a mapping from
/// stake accounts to their delegations with epoch-aware effective stake.
use crate::stake::delegation::Delegation;
use paradencer_storage::Pubkey;
use std::collections::HashMap;

/// Tracks all stake delegations across the network.
#[derive(Debug, Clone)]
pub struct StakeTracker {
    /// Map of stake account pubkey to delegation
    delegations: HashMap<Pubkey, Delegation>,
    /// Current epoch for warmup/cooldown calculations
    current_epoch: u64,
}

impl StakeTracker {
    pub fn new(current_epoch: u64) -> Self {
        Self {
            delegations: HashMap::new(),
            current_epoch,
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
}
