/// Stake delegation tracking and management.
///
/// Tracks validator stake delegations for consensus weight calculation
/// and rewards distribution. Each stake account delegates tokens to a
/// vote account (validator), contributing to that validator's weight.
use paradencer_storage::Pubkey;
use std::collections::HashMap;

/// Delegation of stake to a validator's vote account.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    /// Vote account this stake is delegated to
    pub voter_pubkey: Pubkey,
    /// Amount of lamports staked
    pub stake_amount: u64,
    /// Epoch when stake becomes active
    pub activation_epoch: u64,
    /// Epoch when stake begins deactivating (u64::MAX if not deactivating)
    pub deactivation_epoch: u64,
    /// Rate at which stake warms up or cools down
    pub warmup_cooldown_rate: f64,
}

impl Delegation {
    pub fn new(voter_pubkey: Pubkey, stake_amount: u64, activation_epoch: u64) -> Self {
        Self {
            voter_pubkey,
            stake_amount,
            activation_epoch,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: 0.25, // 25% per epoch by default
        }
    }

    /// Calculate effective stake for a given epoch during warmup/cooldown.
    pub fn effective_stake(&self, current_epoch: u64) -> u64 {
        // If not yet activated
        if current_epoch < self.activation_epoch {
            return 0;
        }

        // If deactivating
        if current_epoch >= self.deactivation_epoch {
            let epochs_deactivating = current_epoch.saturating_sub(self.deactivation_epoch) + 1;
            let cooldown_progress = (epochs_deactivating as f64) * self.warmup_cooldown_rate;
            let remaining_ratio = (1.0 - cooldown_progress).max(0.0);
            return (self.stake_amount as f64 * remaining_ratio) as u64;
        }

        // If still warming up
        let epochs_active = current_epoch.saturating_sub(self.activation_epoch) + 1;

        // Calculate warmup progress
        let warmup_progress = (epochs_active as f64) * self.warmup_cooldown_rate;
        if warmup_progress >= 1.0 {
            // Fully warmed up
            self.stake_amount
        } else {
            (self.stake_amount as f64 * warmup_progress) as u64
        }
    }

    /// Begin deactivation of this delegation.
    pub fn deactivate(&mut self, deactivation_epoch: u64) {
        self.deactivation_epoch = deactivation_epoch;
    }

    /// Check if this delegation is fully active (no warmup/cooldown).
    pub fn is_fully_active(&self, current_epoch: u64) -> bool {
        if current_epoch < self.activation_epoch {
            return false;
        }

        if current_epoch >= self.deactivation_epoch {
            return false;
        }

        let epochs_active = current_epoch.saturating_sub(self.activation_epoch) + 1;
        let warmup_progress = (epochs_active as f64) * self.warmup_cooldown_rate;
        warmup_progress >= 1.0
    }
}

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
    pub fn total_stake_for_voter(&self, voter: &Pubkey) -> u64 {
        self.delegations
            .values()
            .filter(|d| &d.voter_pubkey == voter)
            .map(|d| d.effective_stake(self.current_epoch))
            .sum()
    }

    /// Get all vote accounts with their total effective stake.
    ///
    /// Returns map of vote_pubkey -> total_effective_stake.
    pub fn stake_by_vote_account(&self) -> HashMap<Pubkey, u64> {
        let mut result = HashMap::new();

        for delegation in self.delegations.values() {
            let effective = delegation.effective_stake(self.current_epoch);
            *result.entry(delegation.voter_pubkey).or_insert(0) += effective;
        }

        result
    }

    /// Calculate total stake across all delegations.
    pub fn total_stake(&self) -> u64 {
        self.delegations
            .values()
            .map(|d| d.effective_stake(self.current_epoch))
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

    #[test]
    fn delegation_calculates_effective_stake_during_warmup() {
        let voter = Pubkey::new_unique();
        let delegation = Delegation::new(voter, 1000, 10);

        // Before activation
        assert_eq!(delegation.effective_stake(9), 0);

        // First epoch of activation (25% warmup)
        assert_eq!(delegation.effective_stake(10), 250);

        // Second epoch (50%)
        assert_eq!(delegation.effective_stake(11), 500);

        // Third epoch (75%)
        assert_eq!(delegation.effective_stake(12), 750);

        // Fourth epoch and beyond (100%)
        assert_eq!(delegation.effective_stake(13), 1000);
        assert_eq!(delegation.effective_stake(100), 1000);
    }

    #[test]
    fn delegation_calculates_effective_stake_during_cooldown() {
        let voter = Pubkey::new_unique();
        let mut delegation = Delegation::new(voter, 1000, 0);

        // Fully active first
        assert_eq!(delegation.effective_stake(10), 1000);

        // Begin deactivation at epoch 10
        delegation.deactivate(10);

        // First epoch of deactivation (75% remaining)
        assert_eq!(delegation.effective_stake(10), 750);

        // Second epoch (50%)
        assert_eq!(delegation.effective_stake(11), 500);

        // Third epoch (25%)
        assert_eq!(delegation.effective_stake(12), 250);

        // Fully deactivated
        assert_eq!(delegation.effective_stake(13), 0);
    }

    #[test]
    fn delegation_checks_fully_active_status() {
        let voter = Pubkey::new_unique();
        let delegation = Delegation::new(voter, 1000, 10);

        assert!(!delegation.is_fully_active(9));
        assert!(!delegation.is_fully_active(10));
        assert!(!delegation.is_fully_active(11));
        assert!(!delegation.is_fully_active(12));
        assert!(delegation.is_fully_active(13));
        assert!(delegation.is_fully_active(100));
    }

    #[test]
    fn stake_tracker_aggregates_stake_by_voter() {
        let mut tracker = StakeTracker::new(10);

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        // Two stakes delegated to voter1
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 1000, 0));
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 500, 0));

        // One stake delegated to voter2
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter2, 800, 0));

        assert_eq!(tracker.total_stake_for_voter(&voter1), 1500);
        assert_eq!(tracker.total_stake_for_voter(&voter2), 800);
        assert_eq!(tracker.total_stake(), 2300);
    }

    #[test]
    fn stake_tracker_respects_warmup_cooldown() {
        let mut tracker = StakeTracker::new(5);

        let voter = Pubkey::new_unique();

        // Stake activating at epoch 5
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter, 1000, 5));

        // At epoch 5, only 25% active
        assert_eq!(tracker.total_stake_for_voter(&voter), 250);

        // Advance to epoch 6 (50% active)
        tracker.set_epoch(6);
        assert_eq!(tracker.total_stake_for_voter(&voter), 500);

        // Advance to epoch 8 (100% active)
        tracker.set_epoch(8);
        assert_eq!(tracker.total_stake_for_voter(&voter), 1000);
    }

    #[test]
    fn stake_tracker_provides_stake_by_vote_account_map() {
        let mut tracker = StakeTracker::new(10);

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 1000, 0));
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 500, 0));
        tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter2, 800, 0));

        let stakes = tracker.stake_by_vote_account();
        assert_eq!(stakes.get(&voter1), Some(&1500));
        assert_eq!(stakes.get(&voter2), Some(&800));
    }

    #[test]
    fn stake_tracker_lists_delegations_for_voter() {
        let mut tracker = StakeTracker::new(10);

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();
        let stake1 = Pubkey::new_unique();
        let stake2 = Pubkey::new_unique();
        let stake3 = Pubkey::new_unique();

        tracker.add_delegation(stake1, Delegation::new(voter1, 1000, 0));
        tracker.add_delegation(stake2, Delegation::new(voter1, 500, 0));
        tracker.add_delegation(stake3, Delegation::new(voter2, 800, 0));

        let voter1_delegations = tracker.delegations_for_voter(&voter1);
        assert_eq!(voter1_delegations.len(), 2);

        let voter2_delegations = tracker.delegations_for_voter(&voter2);
        assert_eq!(voter2_delegations.len(), 1);
    }
}
