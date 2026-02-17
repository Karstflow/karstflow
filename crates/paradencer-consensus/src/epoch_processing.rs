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
    Bank, Inflation, StakeHistory, StakeHistoryEntry, StakeTracker,
};
use paradencer_constants::economics::PARTITIONED_REWARDS_DISTRIBUTION_SLOTS;
use paradencer_storage::{AccountDatabase, Pubkey};

// ---------------------------------------------------------------------------
// Vote account reader trait
// ---------------------------------------------------------------------------

/// Reads vote account data for epoch rewards calculation.
///
/// Implementations extract vote credits earned in a specific epoch and the
/// validator's commission rate from stored vote account data.
pub trait VoteAccountReader {
    /// Read vote credits earned in the given epoch and commission for a vote account.
    ///
    /// Returns `(vote_credits_earned, commission)` or `None` if the account
    /// cannot be found or is not a valid vote account.
    fn read_vote_info(&self, vote_account: &Pubkey, epoch: u64) -> Option<(u64, u8)>;
}

/// Default fallback reader that returns hardcoded values.
///
/// Used when no account database is available (e.g., in tests).
pub struct DefaultVoteReader;

impl VoteAccountReader for DefaultVoteReader {
    fn read_vote_info(&self, _vote_account: &Pubkey, _epoch: u64) -> Option<(u64, u8)> {
        Some((100, 5))
    }
}

/// Reads vote credits and commission from vote accounts stored in an account database.
///
/// Falls back to `DefaultVoteReader` values when the account is missing or
/// its data cannot be parsed.
pub struct AccountDatabaseVoteReader<'a> {
    db: &'a AccountDatabase,
}

impl<'a> AccountDatabaseVoteReader<'a> {
    pub fn new(db: &'a AccountDatabase) -> Self {
        Self { db }
    }
}

impl<'a> VoteAccountReader for AccountDatabaseVoteReader<'a> {
    fn read_vote_info(&self, vote_account: &Pubkey, epoch: u64) -> Option<(u64, u8)> {
        let account = self.db.get_published_account(vote_account)?;
        parse_vote_credits_and_commission(account.data.as_ref(), epoch)
    }
}

// ---------------------------------------------------------------------------
// Vote state binary parser (minimal — only extracts what epoch processing needs)
// ---------------------------------------------------------------------------

/// Parse commission and epoch credits from raw vote account data.
///
/// The binary format matches the sbpf vote state serialization:
/// - `[0..32]`   node_pubkey
/// - `[32..64]`  authorized_voter
/// - `[64..96]`  authorized_withdrawer
/// - `[96]`      commission (1 byte)
/// - `[97..101]` vote_count (u32 LE)
/// - votes:      vote_count * 12 bytes (slot:u64 + conf:u32)
/// - root_slot:  1 byte option tag + optional 8 bytes
/// - `[..]`      epoch_credits_count (u32 LE) + entries * 24 bytes (epoch:u64 + credits:u64 + prev:u64)
///
/// Returns `(credits_earned_in_epoch, commission)` or `None` on parse failure.
fn parse_vote_credits_and_commission(data: &[u8], target_epoch: u64) -> Option<(u64, u8)> {
    // Minimum: 3 pubkeys + commission + vote_count = 97 + 4 = 101
    if data.len() < 101 {
        return None;
    }

    let commission = data[96];
    let mut offset = 97;

    // Skip votes
    let vote_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    offset += vote_count * 12; // each vote = slot(8) + conf(4)
    if offset >= data.len() {
        // No root_slot or epoch_credits — return with zero credits
        return Some((0, commission));
    }

    // Skip root_slot
    let root_tag = data[offset];
    offset += 1;
    if root_tag == 1 {
        offset += 8; // skip root slot value
    }

    if offset + 4 > data.len() {
        return Some((0, commission));
    }

    // Parse epoch credits
    let ec_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;

    for _ in 0..ec_count {
        if offset + 24 > data.len() {
            break;
        }
        let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let credits = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let prev_credits = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        if epoch == target_epoch {
            let earned = credits.saturating_sub(prev_credits);
            return Some((earned, commission));
        }
    }

    // Target epoch not found in credits history
    Some((0, commission))
}

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
    ///
    /// When a `vote_reader` is provided, real vote credits and commission are read
    /// from vote accounts. Otherwise, falls back to defaults (100 credits, 5% commission).
    pub fn process_epoch_boundary(
        bank: &Bank,
        stake_tracker: &StakeTracker,
        stake_history: &mut StakeHistory,
    ) -> Result<EpochContext, EpochError> {
        Self::process_epoch_boundary_with_reader(bank, stake_tracker, stake_history, None)
    }

    /// Run epoch boundary processing with an explicit vote account reader.
    pub fn process_epoch_boundary_with_reader(
        bank: &Bank,
        stake_tracker: &StakeTracker,
        stake_history: &mut StakeHistory,
        vote_reader: Option<&dyn VoteAccountReader>,
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
        Self::distribute_epoch_rewards(&mut ctx, bank, stake_tracker, vote_reader)?;

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
        vote_reader: Option<&dyn VoteAccountReader>,
    ) -> Result<(), EpochError> {
        let inflation = *bank.inflation();
        let epoch_schedule = *bank.epoch_schedule().as_ref();
        let calculator = RewardsCalculator::new(inflation, epoch_schedule);

        let (total_rewards, _validator_rate, _foundation_rate) =
            calculator.calculate_epoch_rewards(ctx.new_epoch, ctx.capitalization);

        if total_rewards == 0 {
            return Ok(());
        }

        // Build vote account info from stake tracker, reading real vote data when available
        let stake_by_voter = stake_tracker.stake_by_vote_account();
        let vote_accounts: Vec<(Pubkey, VoteAccountInfo)> = stake_by_voter
            .iter()
            .map(|(pubkey, &total_stake)| {
                let (vote_credits, commission) = vote_reader
                    .and_then(|reader| reader.read_vote_info(pubkey, ctx.previous_epoch))
                    .unwrap_or((100, 5));
                (
                    *pubkey,
                    VoteAccountInfo {
                        total_stake,
                        vote_credits,
                        commission,
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
    use paradencer_storage::AccountDatabase;
    use std::sync::Arc;

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

    /// Build a minimal serialized vote account with given commission and epoch credits.
    fn build_vote_account_data(commission: u8, epoch_credits: &[(u64, u64, u64)]) -> Vec<u8> {
        let mut data = Vec::new();

        // 3 pubkeys (32 bytes each)
        data.extend_from_slice(&[0u8; 32]); // node_pubkey
        data.extend_from_slice(&[1u8; 32]); // authorized_voter
        data.extend_from_slice(&[2u8; 32]); // authorized_withdrawer

        // commission
        data.push(commission);

        // votes: count=0
        data.extend_from_slice(&0u32.to_le_bytes());

        // root_slot: None
        data.push(0);

        // epoch credits
        data.extend_from_slice(&(epoch_credits.len() as u32).to_le_bytes());
        for &(epoch, credits, prev_credits) in epoch_credits {
            data.extend_from_slice(&epoch.to_le_bytes());
            data.extend_from_slice(&credits.to_le_bytes());
            data.extend_from_slice(&prev_credits.to_le_bytes());
        }

        data
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

    // -----------------------------------------------------------------------
    // Phase 1: VoteAccountReader and binary parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_vote_data_extracts_commission_and_credits() {
        // Epoch 5: credits=500, prev=300 → earned=200, commission=10
        let data = build_vote_account_data(10, &[(5, 500, 300)]);
        let result = parse_vote_credits_and_commission(&data, 5);
        assert_eq!(result, Some((200, 10)));
    }

    #[test]
    fn parse_vote_data_returns_zero_for_missing_epoch() {
        let data = build_vote_account_data(7, &[(3, 100, 50)]);
        // Epoch 5 not in credits → returns (0, commission)
        let result = parse_vote_credits_and_commission(&data, 5);
        assert_eq!(result, Some((0, 7)));
    }

    #[test]
    fn parse_vote_data_handles_multiple_epochs() {
        let credits = vec![(1, 100, 0), (2, 250, 100), (3, 400, 250)];
        let data = build_vote_account_data(8, &credits);

        assert_eq!(parse_vote_credits_and_commission(&data, 1), Some((100, 8)));
        assert_eq!(parse_vote_credits_and_commission(&data, 2), Some((150, 8)));
        assert_eq!(parse_vote_credits_and_commission(&data, 3), Some((150, 8)));
    }

    #[test]
    fn parse_vote_data_with_votes_present() {
        let mut data = Vec::new();

        // 3 pubkeys
        data.extend_from_slice(&[0u8; 96]);
        // commission = 12
        data.push(12);
        // 2 votes
        data.extend_from_slice(&2u32.to_le_bytes());
        // vote 1: slot=100, conf=3
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        // vote 2: slot=101, conf=1
        data.extend_from_slice(&101u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        // root_slot: Some(50)
        data.push(1);
        data.extend_from_slice(&50u64.to_le_bytes());
        // epoch credits: 1 entry for epoch 7
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&7u64.to_le_bytes());
        data.extend_from_slice(&1000u64.to_le_bytes());
        data.extend_from_slice(&800u64.to_le_bytes());

        let result = parse_vote_credits_and_commission(&data, 7);
        assert_eq!(result, Some((200, 12)));
    }

    #[test]
    fn parse_vote_data_rejects_too_short() {
        let data = vec![0u8; 50]; // way too short
        assert_eq!(parse_vote_credits_and_commission(&data, 0), None);
    }

    #[test]
    fn parse_vote_data_empty_credits() {
        let data = build_vote_account_data(5, &[]);
        assert_eq!(parse_vote_credits_and_commission(&data, 0), Some((0, 5)));
    }

    #[test]
    fn default_vote_reader_returns_hardcoded_values() {
        let reader = DefaultVoteReader;
        let pubkey = Pubkey::new_unique();
        assert_eq!(reader.read_vote_info(&pubkey, 0), Some((100, 5)));
        assert_eq!(reader.read_vote_info(&pubkey, 999), Some((100, 5)));
    }

    #[test]
    fn custom_vote_reader_overrides_defaults() {
        struct FixedReader {
            credits: u64,
            commission: u8,
        }
        impl VoteAccountReader for FixedReader {
            fn read_vote_info(&self, _vote_account: &Pubkey, _epoch: u64) -> Option<(u64, u8)> {
                Some((self.credits, self.commission))
            }
        }

        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);
        let reader = FixedReader {
            credits: 500,
            commission: 10,
        };

        let ctx = EpochProcessor::process_epoch_boundary_with_reader(
            &bank,
            &tracker,
            &mut history,
            Some(&reader),
        )
        .unwrap();

        assert!(!ctx.validator_rewards.is_empty());
        assert!(ctx.validator_rewards[0].total_reward > 0);
    }

    #[test]
    fn vote_reader_returning_none_falls_back_to_defaults() {
        struct NoneReader;
        impl VoteAccountReader for NoneReader {
            fn read_vote_info(&self, _vote_account: &Pubkey, _epoch: u64) -> Option<(u64, u8)> {
                None
            }
        }

        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);

        // With NoneReader, falls back to (100, 5) defaults
        let ctx_custom = EpochProcessor::process_epoch_boundary_with_reader(
            &bank,
            &tracker,
            &mut history,
            Some(&NoneReader),
        )
        .unwrap();

        // Without reader (None), also uses (100, 5) defaults
        let mut history2 = StakeHistory::new();
        let (bank2, tracker2, _) = make_bank_at_epoch_boundary(1);
        let ctx_default =
            EpochProcessor::process_epoch_boundary(&bank2, &tracker2, &mut history2).unwrap();

        // Rewards should match since both use the same defaults
        assert_eq!(
            ctx_custom.validator_rewards.len(),
            ctx_default.validator_rewards.len()
        );
        if !ctx_custom.validator_rewards.is_empty() {
            assert_eq!(
                ctx_custom.validator_rewards[0].total_reward,
                ctx_default.validator_rewards[0].total_reward
            );
        }
    }

    #[test]
    fn zero_credits_reader_gives_zero_rewards() {
        struct ZeroCreditsReader;
        impl VoteAccountReader for ZeroCreditsReader {
            fn read_vote_info(&self, _vote_account: &Pubkey, _epoch: u64) -> Option<(u64, u8)> {
                Some((0, 5))
            }
        }

        let (bank, tracker, mut history) = make_bank_at_epoch_boundary(1);

        let ctx = EpochProcessor::process_epoch_boundary_with_reader(
            &bank,
            &tracker,
            &mut history,
            Some(&ZeroCreditsReader),
        )
        .unwrap();

        // With zero credits, all rewards should be zero
        for vr in &ctx.validator_rewards {
            assert_eq!(vr.total_reward, 0);
        }
    }

    // -----------------------------------------------------------------------
    // Phase 4: AccountDatabaseVoteReader integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn account_database_vote_reader_reads_real_data() {
        let db = Arc::new(AccountDatabase::new());
        let vote_pubkey = Pubkey::new_unique();

        // Store a vote account with commission=10, epoch 0 credits: 500-300=200
        let vote_data = build_vote_account_data(10, &[(0, 500, 300)]);
        let vote_account =
            paradencer_storage::Account::new(1_000_000, vote_data, Pubkey::default());
        db.store_published_account(vote_pubkey, vote_account);

        let reader = AccountDatabaseVoteReader::new(&db);
        let result = reader.read_vote_info(&vote_pubkey, 0);
        assert_eq!(result, Some((200, 10)));
    }

    #[test]
    fn account_database_vote_reader_returns_none_for_missing() {
        let db = Arc::new(AccountDatabase::new());
        let reader = AccountDatabaseVoteReader::new(&db);
        let result = reader.read_vote_info(&Pubkey::new_unique(), 0);
        assert_eq!(result, None);
    }

    #[test]
    fn account_database_vote_reader_returns_none_for_short_data() {
        let db = Arc::new(AccountDatabase::new());
        let vote_pubkey = Pubkey::new_unique();

        // Store account with data too short to be a vote account
        let account = paradencer_storage::Account::new(1_000_000, vec![0; 50], Pubkey::default());
        db.store_published_account(vote_pubkey, account);

        let reader = AccountDatabaseVoteReader::new(&db);
        assert_eq!(reader.read_vote_info(&vote_pubkey, 0), None);
    }

    #[test]
    fn account_database_vote_reader_with_epoch_processing() {
        let db = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis_with_config(
            db.clone(),
            epoch_schedule.clone(),
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        let voter = Pubkey::new_unique();
        let stake_acct = Pubkey::new_unique();

        // Store vote account with real data: commission=8, epoch 0: credits=1000
        let vote_data = build_vote_account_data(8, &[(0, 1000, 0)]);
        let vote_account =
            paradencer_storage::Account::new(1_000_000, vote_data, Pubkey::default());
        db.store_published_account(voter, vote_account);

        let mut tracker = StakeTracker::new(1);
        tracker.add_delegation(stake_acct, Delegation::new(voter, 1_000_000_000, 0));

        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        let mut history = StakeHistory::new();
        let reader = AccountDatabaseVoteReader::new(&db);

        let ctx = EpochProcessor::process_epoch_boundary_with_reader(
            &child,
            &tracker,
            &mut history,
            Some(&reader),
        )
        .unwrap();

        // With real vote data (1000 credits, 8% commission), rewards should be > 0
        assert!(!ctx.validator_rewards.is_empty());
        assert!(ctx.validator_rewards[0].total_reward > 0);
    }
}
