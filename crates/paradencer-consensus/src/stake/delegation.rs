use crate::stake::warmup_cooldown::warmup_cooldown_rate;
/// Stake delegation tracking and effective stake calculation.
///
/// A delegation represents tokens staked to a validator's vote account.
/// Delegations have warmup/cooldown periods where effective stake gradually
/// increases or decreases over multiple epochs.
use crate::stake_history::{StakeHistory, StakeHistoryEntry};
use paradencer_constants::stake_program as constants;
use paradencer_storage::Pubkey;

/// Active delegation to a validator's vote account.
///
/// Contains the delegation parameters and tracks credits observed
/// for reward calculation.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    /// Vote account this stake is delegated to
    pub voter_pubkey: Pubkey,
    /// Amount of lamports staked (excluding rent-exempt reserve)
    pub stake_amount: u64,
    /// Epoch when this delegation was activated
    pub activation_epoch: u64,
    /// Epoch when deactivation was requested (u64::MAX if still active)
    pub deactivation_epoch: u64,
    /// Deprecated warmup/cooldown rate field (kept for serialization compat)
    #[deprecated(note = "Use warmup_cooldown_rate() function instead")]
    pub warmup_cooldown_rate: f64,
}

#[allow(deprecated)]
impl Delegation {
    pub fn new(voter_pubkey: Pubkey, stake_amount: u64, activation_epoch: u64) -> Self {
        Self {
            voter_pubkey,
            stake_amount,
            activation_epoch,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: constants::DEFAULT_WARMUP_COOLDOWN_RATE,
        }
    }

    /// Calculate the effective, activating, and deactivating stake at a target epoch.
    ///
    /// Uses the stake history to determine how much of this delegation's stake
    /// is actually effective, still warming up, or cooling down.
    pub fn activation_status(
        &self,
        target_epoch: u64,
        history: Option<&StakeHistory>,
        new_rate_activation_epoch: Option<u64>,
    ) -> StakeHistoryEntry {
        let (effective, activating) =
            self.effective_and_activating(target_epoch, history, new_rate_activation_epoch);

        if target_epoch < self.deactivation_epoch {
            return if activating == 0 {
                StakeHistoryEntry::new(effective, 0, 0)
            } else {
                StakeHistoryEntry::new(effective, activating, 0)
            };
        }

        if target_epoch == self.deactivation_epoch {
            return StakeHistoryEntry::new(effective, 0, effective);
        }

        // Target is past deactivation - calculate cooldown
        if let Some(history) = history {
            if let Some(cluster_stake) = history.get(self.deactivation_epoch) {
                let mut prev_epoch = self.deactivation_epoch;
                let mut prev_cluster_stake = *cluster_stake;
                let mut current_effective = effective;

                loop {
                    let current_epoch = prev_epoch + 1;
                    if prev_cluster_stake.deactivating == 0 {
                        break;
                    }

                    let weight = current_effective as f64 / prev_cluster_stake.deactivating as f64;
                    let rate = warmup_cooldown_rate(current_epoch, new_rate_activation_epoch);

                    let newly_ineffective_cluster = prev_cluster_stake.effective as f64 * rate;
                    let newly_ineffective = (weight * newly_ineffective_cluster) as u64;
                    let newly_ineffective = newly_ineffective.max(1);

                    current_effective = current_effective.saturating_sub(newly_ineffective);
                    if current_effective == 0 {
                        break;
                    }

                    if current_epoch >= target_epoch {
                        break;
                    }

                    if let Some(entry) = history.get(current_epoch) {
                        prev_epoch = current_epoch;
                        prev_cluster_stake = *entry;
                    } else {
                        break;
                    }
                }

                return StakeHistoryEntry::new(current_effective, 0, current_effective);
            }
        }

        // No history available after deactivation - assume fully deactivated
        StakeHistoryEntry::new(0, 0, 0)
    }

    /// Calculate effective and activating stake amounts.
    ///
    /// Returns (effective_stake, still_activating_stake).
    fn effective_and_activating(
        &self,
        target_epoch: u64,
        history: Option<&StakeHistory>,
        new_rate_activation_epoch: Option<u64>,
    ) -> (u64, u64) {
        // Bootstrap delegation (activation_epoch == MAX)
        if self.activation_epoch == u64::MAX {
            return (self.stake_amount, 0);
        }

        // Activated and deactivated in the same epoch
        if self.activation_epoch == self.deactivation_epoch {
            return (0, 0);
        }

        // Target is the activation epoch itself
        if target_epoch == self.activation_epoch {
            return (0, self.stake_amount);
        }

        // Target is before activation
        if target_epoch < self.activation_epoch {
            return (0, 0);
        }

        // Use history to calculate warmup progress
        if let Some(history) = history {
            if let Some(cluster_stake_at_activation) = history.get(self.activation_epoch) {
                let mut prev_epoch = self.activation_epoch;
                let mut prev_cluster_stake = *cluster_stake_at_activation;
                let mut current_effective: u64 = 0;

                loop {
                    let current_epoch = prev_epoch + 1;
                    if prev_cluster_stake.activating == 0 {
                        break;
                    }

                    let remaining_activating = self.stake_amount.saturating_sub(current_effective);
                    let weight = remaining_activating as f64 / prev_cluster_stake.activating as f64;
                    let rate = warmup_cooldown_rate(current_epoch, new_rate_activation_epoch);

                    let newly_effective_cluster = prev_cluster_stake.effective as f64 * rate;
                    let newly_effective = (weight * newly_effective_cluster) as u64;
                    let newly_effective = newly_effective.max(1);

                    current_effective = current_effective.saturating_add(newly_effective);
                    if current_effective >= self.stake_amount {
                        current_effective = self.stake_amount;
                        break;
                    }

                    if current_epoch >= target_epoch || current_epoch >= self.deactivation_epoch {
                        break;
                    }

                    if let Some(entry) = history.get(current_epoch) {
                        prev_epoch = current_epoch;
                        prev_cluster_stake = *entry;
                    } else {
                        break;
                    }
                }

                return (
                    current_effective,
                    self.stake_amount.saturating_sub(current_effective),
                );
            }
        }

        // No history or no entry found for activation epoch - assume fully activated
        (self.stake_amount, 0)
    }

    /// Get the effective stake for a given epoch (convenience method).
    pub fn effective_stake(
        &self,
        epoch: u64,
        history: Option<&StakeHistory>,
        new_rate_activation_epoch: Option<u64>,
    ) -> u64 {
        self.activation_status(epoch, history, new_rate_activation_epoch)
            .effective
    }

    /// Begin deactivation at the specified epoch.
    pub fn deactivate(&mut self, deactivation_epoch: u64) {
        self.deactivation_epoch = deactivation_epoch;
    }

    /// Check if this delegation is currently deactivating or fully deactivated.
    pub fn is_deactivated(&self) -> bool {
        self.deactivation_epoch != u64::MAX
    }

    /// Check if this delegation is a bootstrap stake (pre-genesis).
    pub fn is_bootstrap(&self) -> bool {
        self.activation_epoch == u64::MAX
    }
}

/// A complete stake account with delegation and credits tracking.
///
/// Contains the delegation parameters plus the last observed vote credits
/// for calculating rewards.
#[derive(Debug, Clone, PartialEq)]
pub struct StakeAccount {
    /// The delegation details
    pub delegation: Delegation,
    /// Vote account credits last observed when rewards were calculated
    pub credits_observed: u64,
}

impl StakeAccount {
    pub fn new(delegation: Delegation, credits_observed: u64) -> Self {
        Self {
            delegation,
            credits_observed,
        }
    }

    /// Split this stake account, reducing delegation proportionally.
    ///
    /// Returns a new StakeAccount with the split portion, or an error if
    /// the remaining delegation would be too small.
    pub fn split(
        &mut self,
        remaining_stake_delta: u64,
        split_stake_amount: u64,
    ) -> Result<StakeAccount, super::StakeError> {
        if remaining_stake_delta > self.delegation.stake_amount {
            return Err(super::StakeError::InsufficientStake);
        }
        self.delegation.stake_amount -= remaining_stake_delta;

        let mut new = self.clone();
        new.delegation.stake_amount = split_stake_amount;
        Ok(new)
    }

    /// Merge another stake account into this one.
    ///
    /// Both must be delegated to the same voter and have compatible states.
    pub fn merge(&mut self, other: &StakeAccount) -> Result<(), super::StakeError> {
        if self.delegation.voter_pubkey != other.delegation.voter_pubkey {
            return Err(super::StakeError::MergeMismatch);
        }
        self.delegation.stake_amount = self
            .delegation
            .stake_amount
            .saturating_add(other.delegation.stake_amount);
        self.credits_observed = self.credits_observed.max(other.credits_observed);
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    fn voter() -> Pubkey {
        Pubkey::new_unique()
    }

    // --- Delegation tests ---

    #[test]
    fn new_delegation_is_active() {
        let d = Delegation::new(voter(), 1000, 5);
        assert_eq!(d.stake_amount, 1000);
        assert_eq!(d.activation_epoch, 5);
        assert_eq!(d.deactivation_epoch, u64::MAX);
        assert!(!d.is_deactivated());
        assert!(!d.is_bootstrap());
    }

    #[test]
    fn bootstrap_delegation() {
        let d = Delegation {
            voter_pubkey: voter(),
            stake_amount: 5000,
            activation_epoch: u64::MAX,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: 0.25,
        };
        assert!(d.is_bootstrap());
    }

    #[test]
    fn deactivate_marks_delegation() {
        let mut d = Delegation::new(voter(), 1000, 5);
        d.deactivate(10);
        assert!(d.is_deactivated());
        assert_eq!(d.deactivation_epoch, 10);
    }

    #[test]
    fn bootstrap_delegation_fully_effective_at_any_epoch() {
        let d = Delegation {
            voter_pubkey: voter(),
            stake_amount: 5000,
            activation_epoch: u64::MAX,
            deactivation_epoch: u64::MAX,
            warmup_cooldown_rate: 0.25,
        };
        let status = d.activation_status(100, None, None);
        assert_eq!(status.effective, 5000);
        assert_eq!(status.activating, 0);
    }

    #[test]
    fn activation_epoch_shows_all_activating() {
        let d = Delegation::new(voter(), 1000, 5);
        let status = d.activation_status(5, None, None);
        assert_eq!(status.effective, 0);
        assert_eq!(status.activating, 1000);
    }

    #[test]
    fn before_activation_shows_zero() {
        let d = Delegation::new(voter(), 1000, 5);
        let status = d.activation_status(3, None, None);
        assert_eq!(status.effective, 0);
        assert_eq!(status.activating, 0);
    }

    #[test]
    fn same_epoch_activate_deactivate_shows_zero() {
        let mut d = Delegation::new(voter(), 1000, 5);
        d.deactivate(5);
        let status = d.activation_status(5, None, None);
        assert_eq!(status.effective, 0);
        assert_eq!(status.activating, 0);
    }

    #[test]
    fn fully_activated_without_history() {
        let d = Delegation::new(voter(), 1000, 5);
        // No history provided => assume fully activated after activation epoch
        let status = d.activation_status(10, None, None);
        assert_eq!(status.effective, 1000);
        assert_eq!(status.activating, 0);
    }

    #[test]
    fn warmup_with_history() {
        // Large stake relative to cluster so it cannot fully activate in one epoch
        let d = Delegation::new(voter(), 100_000, 5);
        let mut history = StakeHistory::new();
        // Epoch 5: small cluster, large activating pool
        history.add(5, StakeHistoryEntry::new(1_000, 100_000, 0));

        let status = d.activation_status(6, Some(&history), None);
        // Should have warmed up some but not fully (25% of 1000 effective = 250 capacity)
        assert!(status.effective > 0);
        assert!(status.effective < 100_000);
    }

    #[test]
    fn deactivation_epoch_shows_effective_as_deactivating() {
        let mut d = Delegation::new(voter(), 1000, 5);
        d.deactivate(10);

        // Without history, assume fully effective at deactivation
        let status = d.activation_status(10, None, None);
        assert_eq!(status.effective, 1000);
        assert_eq!(status.deactivating, 1000);
    }

    #[test]
    fn effective_stake_convenience() {
        let d = Delegation::new(voter(), 1000, 5);
        let effective = d.effective_stake(10, None, None);
        assert_eq!(effective, 1000);
    }

    // --- StakeAccount tests ---

    #[test]
    fn split_reduces_original() {
        let d = Delegation::new(voter(), 1000, 5);
        let mut account = StakeAccount::new(d, 0);

        let split = account.split(400, 400).unwrap();
        assert_eq!(account.delegation.stake_amount, 600);
        assert_eq!(split.delegation.stake_amount, 400);
    }

    #[test]
    fn split_fails_when_insufficient() {
        let d = Delegation::new(voter(), 1000, 5);
        let mut account = StakeAccount::new(d, 0);

        let result = account.split(1500, 400);
        assert!(result.is_err());
    }

    #[test]
    fn merge_combines_stakes() {
        let v = voter();
        let d1 = Delegation::new(v, 1000, 5);
        let d2 = Delegation::new(v, 500, 5);
        let mut a1 = StakeAccount::new(d1, 100);
        let a2 = StakeAccount::new(d2, 200);

        a1.merge(&a2).unwrap();
        assert_eq!(a1.delegation.stake_amount, 1500);
        assert_eq!(a1.credits_observed, 200); // max of 100, 200
    }

    #[test]
    fn merge_rejects_different_voters() {
        let d1 = Delegation::new(Pubkey::new_unique(), 1000, 5);
        let d2 = Delegation::new(Pubkey::new_unique(), 500, 5);
        let mut a1 = StakeAccount::new(d1, 0);
        let a2 = StakeAccount::new(d2, 0);

        let result = a1.merge(&a2);
        assert!(result.is_err());
    }
}
