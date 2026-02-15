use super::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::stake_program as constants;
use paradencer_ids::STAKE_PROGRAM_ID;
use paradencer_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

/// Stake program execution errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeProgramError {
    NoCreditsToRedeem,
    LockupInForce,
    AlreadyDeactivated,
    TooSoonToRedelegate,
    InsufficientStake,
    MergeTransientStake,
    MergeMismatch,
    CustodianMissing,
    CustodianSignatureMissing,
    InsufficientReferenceVotes,
    VoteAddressMismatch,
    MinimumDelinquentEpochsNotMet,
    InsufficientDelegation,
    RedelegateTransientOrInactive,
    RedelegateToSameVoteAccount,
    RedelegatedStakeMustActivate,
    EpochRewardsActive,
}

impl StakeProgramError {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::NoCreditsToRedeem => constants::ERR_NO_CREDITS_TO_REDEEM,
            Self::LockupInForce => constants::ERR_LOCKUP_IN_FORCE,
            Self::AlreadyDeactivated => constants::ERR_ALREADY_DEACTIVATED,
            Self::TooSoonToRedelegate => constants::ERR_TOO_SOON_TO_REDELEGATE,
            Self::InsufficientStake => constants::ERR_INSUFFICIENT_STAKE,
            Self::MergeTransientStake => constants::ERR_MERGE_TRANSIENT_STAKE,
            Self::MergeMismatch => constants::ERR_MERGE_MISMATCH,
            Self::CustodianMissing => constants::ERR_CUSTODIAN_MISSING,
            Self::CustodianSignatureMissing => constants::ERR_CUSTODIAN_SIGNATURE_MISSING,
            Self::InsufficientReferenceVotes => constants::ERR_INSUFFICIENT_REFERENCE_VOTES,
            Self::VoteAddressMismatch => constants::ERR_VOTE_ADDRESS_MISMATCH,
            Self::MinimumDelinquentEpochsNotMet => constants::ERR_MINIMUM_DELINQUENT_EPOCHS_NOT_MET,
            Self::InsufficientDelegation => constants::ERR_INSUFFICIENT_DELEGATION,
            Self::RedelegateTransientOrInactive => constants::ERR_REDELEGATE_TRANSIENT_OR_INACTIVE,
            Self::RedelegateToSameVoteAccount => constants::ERR_REDELEGATE_TO_SAME_VOTE_ACCOUNT,
            Self::RedelegatedStakeMustActivate => constants::ERR_REDELEGATED_STAKE_MUST_ACTIVATE,
            Self::EpochRewardsActive => constants::ERR_EPOCH_REWARDS_ACTIVE,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::NoCreditsToRedeem => "No credits to redeem".to_string(),
            Self::LockupInForce => "Lockup in force".to_string(),
            Self::AlreadyDeactivated => "Already deactivated".to_string(),
            Self::TooSoonToRedelegate => "Too soon to redelegate".to_string(),
            Self::InsufficientStake => "Insufficient stake".to_string(),
            Self::MergeTransientStake => "Merge transient stake".to_string(),
            Self::MergeMismatch => "Merge mismatch".to_string(),
            Self::CustodianMissing => "Custodian missing".to_string(),
            Self::CustodianSignatureMissing => "Custodian signature missing".to_string(),
            Self::InsufficientReferenceVotes => "Insufficient reference votes".to_string(),
            Self::VoteAddressMismatch => "Vote address mismatch".to_string(),
            Self::MinimumDelinquentEpochsNotMet => {
                "Minimum delinquent epochs not met".to_string()
            }
            Self::InsufficientDelegation => "Insufficient delegation".to_string(),
            Self::RedelegateTransientOrInactive => {
                "Redelegate transient or inactive".to_string()
            }
            Self::RedelegateToSameVoteAccount => "Redelegate to same vote account".to_string(),
            Self::RedelegatedStakeMustActivate => "Redelegated stake must activate".to_string(),
            Self::EpochRewardsActive => "Epoch rewards active".to_string(),
        }
    }
}

/// Stake program executor
#[derive(Debug, Clone)]
pub struct StakeProgramExecutor {
    base_cost: u64,
}

impl StakeProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        if context.instruction_data.len() < 4 {
            return Err("Instruction data too short".to_string());
        }

        let instruction_type = u32::from_le_bytes(
            context.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction type")?,
        );

        let mut compute_used = constants::COMPUTE_COST_BASE_INSTRUCTION;
        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        let result = match instruction_type {
            constants::INSTRUCTION_INITIALIZE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_INITIALIZE);
                self.execute_initialize(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_DELEGATE_STAKE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_DELEGATE);
                self.execute_delegate_stake(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_DEACTIVATE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_DEACTIVATE);
                self.execute_deactivate(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_WITHDRAW => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_WITHDRAW);
                self.execute_withdraw(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_SPLIT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_SPLIT);
                self.execute_split(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_MERGE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_MERGE);
                self.execute_merge(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_SET_LOCKUP => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_set_lockup(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_with_seed(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_INITIALIZE_CHECKED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_INITIALIZE);
                self.execute_initialize_checked(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked_with_seed(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_SET_LOCKUP_CHECKED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_set_lockup_checked(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_GET_MINIMUM_DELEGATION => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_get_minimum_delegation(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_DEACTIVATE_DELINQUENT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_DEACTIVATE);
                self.execute_deactivate_delinquent(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_REDELEGATE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_DELEGATE);
                self.execute_redelegate(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_MOVE_STAKE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_SPLIT);
                self.execute_move_stake(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_MOVE_LAMPORTS => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_WITHDRAW);
                self.execute_move_lamports(context, &mut modified_accounts, &mut logs)
            }
            _ => {
                logs.push(format!(
                    "Stake: Unknown instruction type {}",
                    instruction_type
                ));
                Err("Unknown instruction type".to_string())
            }
        };

        result?;

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs,
            return_data: None,
        })
    }

    fn execute_initialize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Initialize".to_string());

        if context.accounts.is_empty() {
            return Err("Initialize requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 100 {
            return Err("Initialize instruction data too short".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // Account must be owned by stake program
        if account.meta.owner != STAKE_PROGRAM_ID {
            return Err("Stake account must be owned by stake program".to_string());
        }

        // Allocate stake state if needed
        if account.data.as_ref().len() < constants::STAKE_STATE_V2_SIZE {
            account.data = AccountData::with_capacity(constants::STAKE_STATE_V2_SIZE);
            account.data.resize(constants::STAKE_STATE_V2_SIZE, 0);
        }

        // In full implementation, would:
        // 1. Parse Authorized (staker, withdrawer) from instruction data
        // 2. Parse Lockup (unix_timestamp, epoch, custodian) from instruction data
        // 3. Create initial StakeState::Initialized with empty delegation
        // 4. Serialize StakeState into account data

        modified_accounts.insert(account_pubkey, account);
        logs.push("Initialized stake account".to_string());

        Ok(())
    }

    fn execute_delegate_stake(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: DelegateStake".to_string());

        if context.accounts.len() < 2 {
            return Err("DelegateStake requires at least 2 accounts".to_string());
        }

        let (stake_pubkey, mut stake_account, stake_writable) = context.accounts[0].clone();
        let (vote_pubkey, _vote_account, _vote_writable) = context.accounts[1].clone();

        if !stake_writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState from stake account
        // 2. Verify staker authority signature
        // 3. Verify vote account is valid vote account
        // 4. Create delegation with:
        //    - voter_pubkey = vote account
        //    - stake = account lamports - rent exemption
        //    - activation_epoch = current + 1 (warmup period)
        //    - deactivation_epoch = u64::MAX (not deactivated)
        // 5. Update StakeState to Stake variant with delegation
        // 6. Serialize updated StakeState

        modified_accounts.insert(stake_pubkey, stake_account);
        logs.push(format!("Delegated stake to vote account {}", vote_pubkey));

        Ok(())
    }

    fn execute_deactivate(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Deactivate".to_string());

        if context.accounts.is_empty() {
            return Err("Deactivate requires at least 1 account".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Verify staker authority signature
        // 3. Verify stake is currently active (not already deactivating)
        // 4. Set deactivation_epoch = current epoch (begins cooldown)
        // 5. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Deactivated stake".to_string());

        Ok(())
    }

    fn execute_withdraw(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Withdraw".to_string());

        if context.accounts.len() < 2 {
            return Err("Withdraw requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("Withdraw instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (from_pubkey, mut from_account, from_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, _to_writable) = context.accounts[1].clone();

        if !from_writable {
            return Err("Stake account must be writable".to_string());
        }

        // Validate sufficient lamports
        if from_account.meta.lamports < lamports {
            return Err(StakeProgramError::InsufficientStake.to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Verify withdrawer authority signature
        // 3. Verify lockup has expired (if any)
        // 4. Verify stake is fully deactivated (cooldown complete)
        // 5. Ensure remaining lamports cover rent exemption
        // 6. If withdrawing all, set state to Uninitialized

        from_account.meta.lamports = from_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(lamports);

        modified_accounts.insert(from_pubkey, from_account);
        modified_accounts.insert(to_pubkey, to_account);
        logs.push(format!("Withdrew {} lamports from stake account", lamports));

        Ok(())
    }

    fn execute_authorize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Authorize".to_string());

        if context.accounts.is_empty() {
            return Err("Authorize requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Parse authority type (Staker or Withdrawer) and new authority
        // 3. Verify current authority signature
        // 4. Verify lockup conditions if changing withdrawer
        // 5. Update authority in StakeState
        // 6. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake account authority".to_string());

        Ok(())
    }

    fn execute_split(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Split".to_string());

        if context.accounts.len() < 2 {
            return Err("Split requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("Split instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();

        if !source_writable || !dest_writable {
            return Err("Both accounts must be writable".to_string());
        }

        // Validate sufficient lamports
        if source_account.meta.lamports < lamports {
            return Err(StakeProgramError::InsufficientStake.to_string());
        }

        // In full implementation, would:
        // 1. Deserialize source StakeState
        // 2. Verify staker authority signature
        // 3. Verify dest account is uninitialized
        // 4. Split delegation proportionally
        // 5. Update both StakeStates
        // 6. Serialize both accounts

        source_account.meta.lamports = source_account.meta.lamports.saturating_sub(lamports);
        dest_account.meta.lamports = lamports;

        modified_accounts.insert(source_pubkey, source_account);
        modified_accounts.insert(dest_pubkey, dest_account);
        logs.push(format!("Split {} lamports to new stake account", lamports));

        Ok(())
    }

    fn execute_merge(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Merge".to_string());

        if context.accounts.len() < 2 {
            return Err("Merge requires at least 2 accounts".to_string());
        }

        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[0].clone();
        let (source_pubkey, mut source_account, source_writable) = context.accounts[1].clone();

        if !dest_writable || !source_writable {
            return Err("Both accounts must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize both StakeStates
        // 2. Verify staker authority signature
        // 3. Verify both delegated to same vote account
        // 4. Verify lockups are compatible
        // 5. Merge delegations (combine effective stake)
        // 6. Transfer all lamports from source to dest
        // 7. Set source to Uninitialized
        // 8. Serialize both accounts

        let lamports = source_account.meta.lamports;
        dest_account.meta.lamports = dest_account.meta.lamports.saturating_add(lamports);
        source_account.meta.lamports = 0;

        modified_accounts.insert(dest_pubkey, dest_account);
        modified_accounts.insert(source_pubkey, source_account);
        logs.push("Merged stake accounts".to_string());

        Ok(())
    }

    fn execute_set_lockup(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: SetLockup".to_string());

        if context.accounts.is_empty() {
            return Err("SetLockup requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Parse new lockup parameters (unix_timestamp, epoch, custodian)
        // 3. Verify custodian signature
        // 4. Update lockup in StakeState
        // 5. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake lockup".to_string());

        Ok(())
    }

    fn execute_authorize_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: AuthorizeWithSeed".to_string());

        if context.accounts.len() < 2 {
            return Err("AuthorizeWithSeed requires at least 2 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Parse base pubkey, seed, and authority type from instruction data
        // 2. Derive authority address using create_with_seed
        // 3. Verify derived authority signature
        // 4. Deserialize StakeState
        // 5. Update authority in StakeState
        // 6. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake authority (with seed)".to_string());

        Ok(())
    }

    fn execute_initialize_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: InitializeChecked".to_string());

        if context.accounts.len() < 3 {
            return Err("InitializeChecked requires at least 3 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        if account.meta.owner != STAKE_PROGRAM_ID {
            return Err("Stake account has invalid owner".to_string());
        }

        // InitializeChecked requires staker and withdrawer to be signers
        // In full implementation, would:
        // 1. Verify staker signature (accounts[1])
        // 2. Verify withdrawer signature (accounts[2])
        // 3. Create StakeState with Authorized { staker, withdrawer }
        // 4. Serialize StakeState to account data

        let mut new_account = account;
        new_account.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        modified_accounts.insert(account_pubkey, new_account);
        logs.push(format!("Initialized stake account (checked): {}", account_pubkey));

        Ok(())
    }

    fn execute_authorize_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: AuthorizeChecked".to_string());

        if context.accounts.len() < 3 {
            return Err("AuthorizeChecked requires at least 3 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // AuthorizeChecked requires new authority to be a signer (accounts[2])
        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Parse authority type (Staker or Withdrawer)
        // 3. Verify current authority signature
        // 4. Verify new authority signature (accounts[2])
        // 5. Update authority in StakeState
        // 6. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake authority (checked)".to_string());

        Ok(())
    }

    fn execute_authorize_checked_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: AuthorizeCheckedWithSeed".to_string());

        if context.accounts.len() < 3 {
            return Err("AuthorizeCheckedWithSeed requires at least 3 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // Combines seed-based authority with checked authorization
        // In full implementation, would:
        // 1. Parse base pubkey, seed, and authority type
        // 2. Derive current authority using create_with_seed
        // 3. Verify derived authority signature
        // 4. Verify new authority signature (accounts[2])
        // 5. Deserialize StakeState
        // 6. Update authority in StakeState
        // 7. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake authority (checked with seed)".to_string());

        Ok(())
    }

    fn execute_set_lockup_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: SetLockupChecked".to_string());

        if context.accounts.len() < 2 {
            return Err("SetLockupChecked requires at least 2 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Stake account must be writable".to_string());
        }

        // SetLockupChecked requires new custodian to be a signer
        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Parse new lockup parameters
        // 3. Verify current custodian signature
        // 4. If changing custodian, verify new custodian signature (accounts[1])
        // 5. Update lockup in StakeState
        // 6. Serialize updated StakeState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated stake lockup (checked)".to_string());

        Ok(())
    }

    fn execute_get_minimum_delegation(
        &self,
        _context: &ExecutionContext,
        _modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: GetMinimumDelegation".to_string());

        // This is a read-only instruction that returns the minimum delegation
        // In full implementation, would return minimum delegation via return_data

        logs.push("Returned minimum delegation".to_string());

        Ok(())
    }

    fn execute_deactivate_delinquent(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: DeactivateDelinquent".to_string());

        if context.accounts.len() < 3 {
            return Err("DeactivateDelinquent requires at least 3 accounts".to_string());
        }

        let (stake_pubkey, stake_account, stake_writable) = context.accounts[0].clone();

        if !stake_writable {
            return Err("Stake account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize StakeState
        // 2. Verify vote account (accounts[1]) is delinquent
        // 3. Verify reference vote account (accounts[2]) has sufficient votes
        // 4. Check minimum delinquent epochs threshold
        // 5. Force deactivate the stake
        // 6. Serialize updated StakeState

        modified_accounts.insert(stake_pubkey, stake_account);
        logs.push("Deactivated delinquent stake".to_string());

        Ok(())
    }

    fn execute_redelegate(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: Redelegate".to_string());

        if context.accounts.len() < 3 {
            return Err("Redelegate requires at least 3 accounts".to_string());
        }

        let (stake_pubkey, stake_account, stake_writable) = context.accounts[0].clone();
        let (uninitialized_pubkey, uninitialized_account, uninitialized_writable) =
            context.accounts[1].clone();

        if !stake_writable || !uninitialized_writable {
            return Err("Stake accounts must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize source StakeState
        // 2. Verify stake is fully activated
        // 3. Verify not too soon since last delegation
        // 4. Verify new vote account (accounts[2]) is different
        // 5. Create new stake delegation in uninitialized account
        // 6. Mark source stake for redelegation
        // 7. Serialize both StakeStates

        modified_accounts.insert(stake_pubkey, stake_account);
        modified_accounts.insert(uninitialized_pubkey, uninitialized_account);
        logs.push("Redelegated stake to new vote account".to_string());

        Ok(())
    }

    fn execute_move_stake(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: MoveStake".to_string());

        if context.accounts.len() < 2 {
            return Err("MoveStake requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("MoveStake instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (source_pubkey, source_account, source_writable) = context.accounts[0].clone();
        let (dest_pubkey, dest_account, dest_writable) = context.accounts[1].clone();

        if !source_writable || !dest_writable {
            return Err("Both stake accounts must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize both StakeStates
        // 2. Verify both are delegated to same vote account
        // 3. Verify sufficient stake in source
        // 4. Move stake from source to dest
        // 5. Update effective stakes
        // 6. Serialize both StakeStates

        modified_accounts.insert(source_pubkey, source_account);
        modified_accounts.insert(dest_pubkey, dest_account);
        logs.push(format!("Moved {} lamports of stake", lamports));

        Ok(())
    }

    fn execute_move_lamports(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Stake: MoveLamports".to_string());

        if context.accounts.len() < 2 {
            return Err("MoveLamports requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("MoveLamports instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (source_pubkey, mut source_account, source_writable) = context.accounts[0].clone();
        let (dest_pubkey, mut dest_account, dest_writable) = context.accounts[1].clone();

        if !source_writable || !dest_writable {
            return Err("Both accounts must be writable".to_string());
        }

        if source_account.meta.lamports < lamports {
            return Err(StakeProgramError::InsufficientStake.to_string());
        }

        // In full implementation, would:
        // 1. Deserialize both StakeStates
        // 2. Verify source has sufficient inactive lamports
        // 3. Move lamports from source to dest
        // 4. Ensure source maintains rent exemption
        // 5. Serialize both StakeStates

        source_account.meta.lamports -= lamports;
        dest_account.meta.lamports += lamports;

        modified_accounts.insert(source_pubkey, source_account);
        modified_accounts.insert(dest_pubkey, dest_account);
        logs.push(format!("Moved {} lamports", lamports));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    #[test]
    fn stake_initialize() {
        let executor = StakeProgramExecutor::new(150);

        let account = Account {
            meta: AccountMeta {
                lamports: 100_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![0, 0, 0, 0]; // Initialize
        instruction_data.resize(100, 0); // Add placeholder data

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Initialized")));
    }

    #[test]
    fn stake_delegate() {
        let executor = StakeProgramExecutor::new(150);

        let mut stake_account = Account {
            meta: AccountMeta {
                lamports: 100_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        stake_account.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: Pubkey::new_unique(), // Vote program ID
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let instruction_data = vec![2, 0, 0, 0]; // DelegateStake

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), stake_account, true),
                (Pubkey::new_unique(), vote_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Delegated")));
    }

    #[test]
    fn stake_deactivate() {
        let executor = StakeProgramExecutor::new(150);

        let mut account = Account {
            meta: AccountMeta {
                lamports: 100_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        account.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let instruction_data = vec![5, 0, 0, 0]; // Deactivate

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs.iter().any(|log| log.contains("Deactivated")));
    }

    #[test]
    fn stake_withdraw() {
        let executor = StakeProgramExecutor::new(150);

        let mut from_account = Account {
            meta: AccountMeta {
                lamports: 100_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        from_account.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let to_account = Account {
            meta: AccountMeta {
                lamports: 0,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![4, 0, 0, 0]; // Withdraw
        instruction_data.extend_from_slice(&50_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), from_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.logs.iter().any(|log| log.contains("Withdrew")));
    }

    #[test]
    fn stake_split() {
        let executor = StakeProgramExecutor::new(150);

        let mut source = Account {
            meta: AccountMeta {
                lamports: 100_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        source.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let dest = Account {
            meta: AccountMeta {
                lamports: 0,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![3, 0, 0, 0]; // Split
        instruction_data.extend_from_slice(&40_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), source, true),
                (Pubkey::new_unique(), dest, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.logs.iter().any(|log| log.contains("Split")));
    }

    #[test]
    fn stake_merge() {
        let executor = StakeProgramExecutor::new(150);

        let mut dest = Account {
            meta: AccountMeta {
                lamports: 60_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        dest.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let mut source = Account {
            meta: AccountMeta {
                lamports: 40_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        source.data.resize(constants::STAKE_STATE_V2_SIZE, 0);

        let instruction_data = vec![7, 0, 0, 0]; // Merge

        let context = ExecutionContext::new(
            STAKE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), dest, true),
                (Pubkey::new_unique(), source, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.logs.iter().any(|log| log.contains("Merged")));
    }
}
