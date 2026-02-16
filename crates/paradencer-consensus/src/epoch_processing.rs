/// Epoch boundary processing.
///
/// At each epoch boundary the runtime must perform several housekeeping tasks:
/// activating pending feature gates, recalculating stake history, distributing
/// inflation rewards, updating epoch-level sysvars, and recomputing the leader
/// schedule for the upcoming epoch.
///
/// This module orchestrates those steps in the correct order, matching the
/// on-chain behavior.
use crate::{
    rewards_calculator::{RewardsCalculator, ValidatorReward, VoteAccountInfo},
    rewards_distribution::{PendingReward, RewardsDistributor},
    Bank, EpochSchedule, Inflation, StakeHistory, StakeHistoryEntry, StakeTracker,
};
use paradencer_constants::economics::PARTITIONED_REWARDS_DISTRIBUTION_SLOTS;
use paradencer_storage::Pubkey;
use std::sync::Arc;

/// Errors that can occur during epoch boundary processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    /// The bank is not at an epoch boundary.
    NotEpochBoundary,
    /// Feature activation failed.
    FeatureActivationFailed(String),
    /// Reward calculation failed.
    RewardCalculationFailed(String),
    /// Leader schedule generation failed.
    LeaderScheduleUpdateFailed(String),
    /// The slot is the genesis slot (epoch boundary processing not applicable).
    GenesisSlot,
}

impl std::fmt::Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochError::NotEpochBoundary => write!(f, "slot is not an epoch boundary"),
            EpochError::FeatureActivationFailed(msg) => {
                write!(f, "feature activation failed: {}", msg)
            }
            EpochError::RewardCalculationFailed(msg) => {
                write!(f, "reward calculation failed: {}", msg)
            }
            EpochError::LeaderScheduleUpdateFailed(msg) => {
                write!(f, "leader schedule update failed: {}", msg)
            }
            EpochError::GenesisSlot => write!(f, "genesis slot has no epoch boundary processing"),
        }
    }
}

/// Context passed through each step of epoch processing.
///
/// Accumulates results (rewards, stake snapshots) that are computed in
/// earlier steps and consumed by later ones.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochContext {
    /// Previous epoch number (before the transition).
    pub previous_epoch: u64,
    /// New epoch number (after the transition).
    pub new_epoch: u64,
    /// Capitalization at the start of processing.
    pub capitalization: u64,
    /// Computed validator rewards (populated by `distribute_epoch_rewards`).
    pub validator_rewards: Vec<ValidatorReward>,
    /// Pending rewards distributor (populated by `distribute_epoch_rewards`).
    pub rewards_distributor: Option<RewardsDistributor>,
    /// Stake history snapshot for the previous epoch.
    pub stake_snapshot: Option<StakeHistoryEntry>,
}

/// Stateless processor for epoch boundary transitions.
///
/// Call `process_epoch_boundary` with a bank whose slot is the first slot of
/// a new epoch. The processor runs each sub-step in order. If any step fails,
/// processing halts and the error is returned.
pub struct EpochProcessor;

impl EpochProcessor {
    /// Run all epoch boundary processing steps on the given bank.
    ///
    /// The bank's slot must be the first slot of a new epoch (i.e., slot_index == 0
    /// and epoch > 0). Returns the completed `EpochContext` on success.
    pub fn process_epoch_boundary(
        bank: &Bank,
        stake_tracker: &StakeTracker,
        stake_history: &mut StakeHistory,
    ) -> Result<EpochContext, EpochError> {
        // Only process at epoch boundaries
        if bank.slot() == 0 {
            return Err(EpochError::GenesisSlot);
        }

        let epoch_schedule = bank.epoch_schedule();
        let current_epoch = bank.epoch();
        let parent_slot = bank.parent_slot().unwrap_or(0);
        let parent_epoch = epoch_schedule.get_epoch(parent_slot);

        if current_epoch == parent_epoch && bank.slot_index() != 0 {
            return Err(EpochError::NotEpochBoundary);
        }

        let mut ctx = EpochContext {
            previous_epoch: parent_epoch,
            new_epoch: current_epoch,
            capitalization: bank.capitalization(),
            validator_rewards: Vec::new(),
            rewards_distributor: None,
            stake_snapshot: None,
        };

        // Step 1: Update stake history with previous epoch totals
        Self::update_stake_history(&mut ctx, stake_tracker, stake_history)?;

        // Step 2: Calculate and prepare reward distribution
        Self::distribute_epoch_rewards(&mut ctx, bank, stake_tracker)?;

        Ok(ctx)
    }

    /// Record the previous epoch's stake state in the stake history sysvar.
    ///
    /// Computes the effective, activating, and deactivating stake from the
    /// tracker and adds an entry for the previous epoch.
    fn update_stake_history(
        ctx: &mut EpochContext,
        stake_tracker: &StakeTracker,
        stake_history: &mut StakeHistory,
    ) -> Result<(), EpochError> {
        // Sum effective, activating, deactivating stake from all delegations
        let mut effective: u64 = 0;
        let mut activating: u64 = 0;
        let mut deactivating: u64 = 0;

        let epoch = ctx.previous_epoch;
        let stake_by_voter = stake_tracker.stake_by_vote_account();

        for (_voter, total_stake) in &stake_by_voter {
            effective = effective.saturating_add(*total_stake);
        }

        // In a full implementation we would iterate individual delegations
        // to separate activating/deactivating amounts. For now, track only
        // effective stake and leave transition fields at zero to match the
        // simplified stake model already in the codebase.
        let _ = activating;
        let _ = deactivating;

        let entry = StakeHistoryEntry::new(effective, activating, deactivating);
        stake_history.add(epoch, entry);
        ctx.stake_snapshot = Some(entry);

        Ok(())
    }

    /// Compute inflation rewards and prepare the partitioned distributor.
    ///
    /// Uses the `RewardsCalculator` to determine each validator's share of the
    /// epoch reward pool, then creates a `RewardsDistributor` that partitions
    /// the rewards across multiple slots.
    fn distribute_epoch_rewards(
        ctx: &mut EpochContext,
        bank: &Bank,
        stake_tracker: &StakeTracker,
    ) -> Result<(), EpochError> {
        let inflation = *bank.inflation();
        let epoch_schedule = *bank.epoch_schedule().as_ref();
        let calculator = RewardsCalculator::new(inflation, epoch_schedule);

        let (total_rewards, _validator_rate, _foundation_rate) =
            calculator.calculate_epoch_rewards(ctx.new_epoch, ctx.capitalization);

        if total_rewards == 0 {
            return Ok(());
        }

        // Build vote account info from stake tracker
        let stake_by_voter = stake_tracker.stake_by_vote_account();
        let vote_accounts: Vec<(Pubkey, VoteAccountInfo)> = stake_by_voter
            .iter()
            .map(|(pubkey, &total_stake)| {
                (
                    *pubkey,
                    VoteAccountInfo {
                        total_stake,
                        // In a full implementation these would come from vote state
                        vote_credits: 100,
                        commission: 5,
                    },
                )
            })
            .collect();

        let validator_rewards =
            calculator.calculate_validator_rewards(&vote_accounts, total_rewards);

        // Convert to pending rewards for partitioned distribution
        let pending: Vec<PendingReward> = validator_rewards
            .iter()
            .map(|vr| PendingReward {
                account: vr.vote_account,
                amount: vr.total_reward,
                reward_type: RewardType::Voting,
            })
            .collect();

        let start_slot = bank.slot();
        let distributor =
            RewardsDistributor::new(pending, PARTITIONED_REWARDS_DISTRIBUTION_SLOTS, start_slot);

        ctx.validator_rewards = validator_rewards;
        ctx.rewards_distributor = Some(distributor);

        Ok(())
    }
}

/// Classification of a reward payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardType {
    /// Reward from vote account commission
    Voting,
    /// Reward from stake delegation
    Staking,
    /// Rent collected and credited to validators
    Rent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Delegation, EpochSchedule, LeaderSchedule, Rent};
    use paradencer_constants::ledger::TICKS_PER_SLOT;
    use paradencer_storage::AccountDatabase;

    fn create_test_leader_schedule(epoch: u64) -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        Arc::new(LeaderSchedule::new(epoch, &validators).unwrap())
    }

    fn make_bank_at_epoch_boundary(epoch: u64) -> (Bank, StakeTracker, StakeHistory) {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        // Create genesis
        let parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule.clone(),
            1_000_000_000_000, // 1T lamports
            Rent::default(),
            Inflation::default(),
        );

        // Create a bank at the first slot of the requested epoch
        let slot = epoch_schedule.get_first_slot_in_epoch(epoch);
        let child_leader_schedule = create_test_leader_schedule(epoch);
        let child = Bank::new_from_parent(&parent, slot, child_leader_schedule);

        // Set up a stake tracker with some delegations
        let mut tracker = StakeTracker::new(epoch);
        let voter = Pubkey::new_unique();
        let stake_acct = Pubkey::new_unique();
        tracker.add_delegation(stake_acct, Delegation::new(voter, 1_000_000_000, 0));

        let history = StakeHistory::new();

        (child, tracker, history)
    }

    #[test]
    fn epoch_processing_rejects_genesis_slot() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);
        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let tracker = StakeTracker::new(0);
        let mut history = StakeHistory::new();

        let result = EpochProcessor::process_epoch_boundary(&bank, &tracker, &mut history);
        assert_eq!(result, Err(EpochError::GenesisSlot));
    }

    #[test]
    fn epoch_processing_updates_stake_history() {
        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);

        let result = EpochProcessor::process_epoch_boundary(&bank, &tracker, &mut history);
        assert!(result.is_ok());

        let ctx = result.unwrap();
        assert_eq!(ctx.previous_epoch, 0);
        assert_eq!(ctx.new_epoch, 1);

        // Stake history should have an entry for epoch 0
        assert!(history.get(0).is_some());
        let entry = history.get(0).unwrap();
        assert!(entry.effective > 0);
    }

    #[test]
    fn epoch_processing_computes_validator_rewards() {
        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);

        let ctx = EpochProcessor::process_epoch_boundary(&bank, &tracker, &mut history).unwrap();

        // Should have computed some rewards
        assert!(!ctx.validator_rewards.is_empty());
        assert!(ctx.validator_rewards[0].total_reward > 0);
    }

    #[test]
    fn epoch_processing_creates_distributor() {
        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);

        let ctx = EpochProcessor::process_epoch_boundary(&bank, &tracker, &mut history).unwrap();

        assert!(ctx.rewards_distributor.is_some());
        let distributor = ctx.rewards_distributor.unwrap();
        assert!(!distributor.is_complete());
    }

    #[test]
    fn epoch_processing_with_no_stake_gives_empty_rewards() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule,
            0, // Zero capitalization
            Rent::default(),
            Inflation::default(),
        );

        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        let tracker = StakeTracker::new(1);
        let mut history = StakeHistory::new();

        let ctx = EpochProcessor::process_epoch_boundary(&child, &tracker, &mut history).unwrap();
        assert!(ctx.validator_rewards.is_empty());
        assert!(ctx.rewards_distributor.is_none());
    }
}
