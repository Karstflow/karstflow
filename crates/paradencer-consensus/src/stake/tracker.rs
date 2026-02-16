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
