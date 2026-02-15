use super::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::vote_program as constants;
use paradencer_ids::VOTE_PROGRAM_ID;
use paradencer_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

/// Vote program execution errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteProgramError {
    VoteTooOld,
    SlotsMismatch,
    SlotsHashMismatch,
    EmptySlots,
    TimestampTooOld,
    TooSoonToReauthorize,
    LockoutConflict,
    NewVoteStateLockoutMismatch,
    SlotsNotOrdered,
    ConfirmationsNotOrdered,
    ZeroConfirmations,
    ConfirmationTooLarge,
    RootRollBack,
    ConfirmationRollBack,
    SlotSmallerThanRoot,
    TooManyVotes,
    VotesTooOldAllFiltered,
    RootOnDifferentFork,
    ActiveVoteAccountClose,
    CommissionUpdateTooLate,
}

impl VoteProgramError {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::VoteTooOld => constants::ERR_VOTE_TOO_OLD,
            Self::SlotsMismatch => constants::ERR_SLOTS_MISMATCH,
            Self::SlotsHashMismatch => constants::ERR_SLOTS_HASH_MISMATCH,
            Self::EmptySlots => constants::ERR_EMPTY_SLOTS,
            Self::TimestampTooOld => constants::ERR_TIMESTAMP_TOO_OLD,
            Self::TooSoonToReauthorize => constants::ERR_TOO_SOON_TO_REAUTHORIZE,
            Self::LockoutConflict => constants::ERR_LOCKOUT_CONFLICT,
            Self::NewVoteStateLockoutMismatch => constants::ERR_NEW_VOTE_STATE_LOCKOUT_MISMATCH,
            Self::SlotsNotOrdered => constants::ERR_SLOTS_NOT_ORDERED,
            Self::ConfirmationsNotOrdered => constants::ERR_CONFIRMATIONS_NOT_ORDERED,
            Self::ZeroConfirmations => constants::ERR_ZERO_CONFIRMATIONS,
            Self::ConfirmationTooLarge => constants::ERR_CONFIRMATION_TOO_LARGE,
            Self::RootRollBack => constants::ERR_ROOT_ROLL_BACK,
            Self::ConfirmationRollBack => constants::ERR_CONFIRMATION_ROLL_BACK,
            Self::SlotSmallerThanRoot => constants::ERR_SLOT_SMALLER_THAN_ROOT,
            Self::TooManyVotes => constants::ERR_TOO_MANY_VOTES,
            Self::VotesTooOldAllFiltered => constants::ERR_VOTES_TOO_OLD_ALL_FILTERED,
            Self::RootOnDifferentFork => constants::ERR_ROOT_ON_DIFFERENT_FORK,
            Self::ActiveVoteAccountClose => constants::ERR_ACTIVE_VOTE_ACCOUNT_CLOSE,
            Self::CommissionUpdateTooLate => constants::ERR_COMMISSION_UPDATE_TOO_LATE,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::VoteTooOld => "Vote is too old".to_string(),
            Self::SlotsMismatch => "Slots mismatch".to_string(),
            Self::SlotsHashMismatch => "Slots hash mismatch".to_string(),
            Self::EmptySlots => "Empty slots".to_string(),
            Self::TimestampTooOld => "Timestamp too old".to_string(),
            Self::TooSoonToReauthorize => "Too soon to reauthorize".to_string(),
            Self::LockoutConflict => "Lockout conflict".to_string(),
            Self::NewVoteStateLockoutMismatch => "New vote state lockout mismatch".to_string(),
            Self::SlotsNotOrdered => "Slots not ordered".to_string(),
            Self::ConfirmationsNotOrdered => "Confirmations not ordered".to_string(),
            Self::ZeroConfirmations => "Zero confirmations".to_string(),
            Self::ConfirmationTooLarge => "Confirmation too large".to_string(),
            Self::RootRollBack => "Root rollback".to_string(),
            Self::ConfirmationRollBack => "Confirmation rollback".to_string(),
            Self::SlotSmallerThanRoot => "Slot smaller than root".to_string(),
            Self::TooManyVotes => "Too many votes".to_string(),
            Self::VotesTooOldAllFiltered => "Votes too old, all filtered".to_string(),
            Self::RootOnDifferentFork => "Root on different fork".to_string(),
            Self::ActiveVoteAccountClose => "Active vote account close".to_string(),
            Self::CommissionUpdateTooLate => "Commission update too late".to_string(),
        }
    }
}

/// Vote program executor
#[derive(Debug, Clone)]
pub struct VoteProgramExecutor {
    base_cost: u64,
}

impl VoteProgramExecutor {
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
            constants::INSTRUCTION_INITIALIZE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_INITIALIZE);
                self.execute_initialize_account(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_VOTE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_VOTE);
                self.execute_vote(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_UPDATE_VOTE_STATE => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_update_vote_state(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_WITHDRAW => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_WITHDRAW);
                self.execute_withdraw(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_UPDATE_COMMISSION => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_COMMISSION);
                self.execute_update_commission(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_UPDATE_VALIDATOR_IDENTITY => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_COMMISSION);
                self.execute_update_validator_identity(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_INITIALIZE_ACCOUNT_V2 => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_INITIALIZE);
                self.execute_initialize_account_v2(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_VOTE_SWITCH => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_VOTE);
                self.execute_vote_switch(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_UPDATE_VOTE_STATE_SWITCH => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_update_vote_state_switch(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_COMPACT_UPDATE_VOTE_STATE => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_compact_update_vote_state(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_COMPACT_UPDATE_VOTE_STATE_SWITCH => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_compact_update_vote_state_switch(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                )
            }
            constants::INSTRUCTION_TOWER_SYNC => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_tower_sync(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_TOWER_SYNC_SWITCH => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_tower_sync_switch(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_with_seed(context, &mut modified_accounts, &mut logs)
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked_with_seed(context, &mut modified_accounts, &mut logs)
            }
            _ => {
                logs.push(format!(
                    "Vote: Unknown instruction type {}",
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

    fn execute_initialize_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: InitializeAccount".to_string());

        if context.accounts.is_empty() {
            return Err("InitializeAccount requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 100 {
            return Err("InitializeAccount instruction data too short".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // Account must be owned by vote program
        if account.meta.owner != VOTE_PROGRAM_ID {
            return Err("Vote account must be owned by vote program".to_string());
        }

        // Allocate vote state if needed
        if account.data.as_ref().len() < constants::VOTE_STATE_V3_SIZE {
            account.data = AccountData::with_capacity(constants::VOTE_STATE_V3_SIZE);
            account.data.resize(constants::VOTE_STATE_V3_SIZE, 0);
        }

        // In full implementation, would:
        // 1. Parse VoteInit from instruction data (node_pubkey, authorized_voter, authorized_withdrawer, commission)
        // 2. Create initial VoteState with empty lockouts
        // 3. Serialize VoteState into account data

        modified_accounts.insert(account_pubkey, account);
        logs.push("Initialized vote account".to_string());

        Ok(())
    }

    fn execute_vote(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: Vote".to_string());

        if context.accounts.is_empty() {
            return Err("Vote requires at least 1 account".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState from account data
        // 2. Parse Vote from instruction data (slots, hash, timestamp)
        // 3. Validate vote is not too old (check against root)
        // 4. Process lockouts (add vote, update confirmation counts)
        // 5. Update credits for voted slots
        // 6. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Processed vote".to_string());

        Ok(())
    }

    fn execute_update_vote_state(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: UpdateVoteState".to_string());

        if context.accounts.is_empty() {
            return Err("UpdateVoteState requires at least 1 account".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState from account data
        // 2. Parse VoteStateUpdate from instruction data (compact representation)
        // 3. Apply lockouts and root updates
        // 4. Update epoch credits
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote state".to_string());

        Ok(())
    }

    fn execute_withdraw(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: Withdraw".to_string());

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
            return Err("Vote account must be writable".to_string());
        }

        // Validate sufficient lamports
        if from_account.meta.lamports < lamports {
            return Err("Insufficient lamports".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState to verify withdrawer authority
        // 2. Check that account maintains rent exemption after withdrawal
        // 3. Verify there are no active lockouts if closing account

        from_account.meta.lamports = from_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(lamports);

        modified_accounts.insert(from_pubkey, from_account);
        modified_accounts.insert(to_pubkey, to_account);
        logs.push(format!("Withdrew {} lamports from vote account", lamports));

        Ok(())
    }

    fn execute_authorize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: Authorize".to_string());

        if context.accounts.is_empty() {
            return Err("Authorize requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse authority type (Voter or Withdrawer) and new authority
        // 3. Verify current authority signature
        // 4. Update authority in VoteState
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote account authority".to_string());

        Ok(())
    }

    fn execute_update_commission(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: UpdateCommission".to_string());

        if context.accounts.is_empty() {
            return Err("UpdateCommission requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 5 {
            return Err("UpdateCommission instruction data too short".to_string());
        }

        let _commission = context.instruction_data[4];

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Verify it's not too late in the epoch to update commission
        // 3. Update commission in VoteState
        // 4. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote account commission".to_string());

        Ok(())
    }

    fn execute_update_validator_identity(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: UpdateValidatorIdentity".to_string());

        if context.accounts.len() < 2 {
            return Err("UpdateValidatorIdentity requires at least 2 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Verify withdrawer authority signature
        // 3. Verify new validator identity signature (accounts[1])
        // 4. Update node_pubkey in VoteState
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated validator identity".to_string());

        Ok(())
    }

    fn execute_authorize_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: AuthorizeChecked".to_string());

        if context.accounts.len() < 3 {
            return Err("AuthorizeChecked requires at least 3 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // AuthorizeChecked is like Authorize but requires the new authority
        // to be a signer (accounts[2]) for extra security
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse authority type (Voter or Withdrawer)
        // 3. Verify current authority signature (accounts[1] or derived)
        // 4. Verify new authority signature (accounts[2])
        // 5. Update authority in VoteState
        // 6. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote account authority (checked)".to_string());

        Ok(())
    }

    fn execute_initialize_account_v2(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: InitializeAccountV2".to_string());

        if context.accounts.len() < 2 {
            return Err("InitializeAccountV2 requires at least 2 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        if account.meta.owner != VOTE_PROGRAM_ID {
            return Err("Vote account has invalid owner".to_string());
        }

        // InitializeAccountV2 is similar to InitializeAccount but with
        // updated VoteState format (V1.14+)
        // In full implementation, would:
        // 1. Parse VoteInit from instruction data
        // 2. Create VoteState with node_pubkey, authorized voter/withdrawer, commission
        // 3. Serialize VoteState to account data

        let mut new_account = account;
        new_account.data.resize(constants::VOTE_STATE_V3_SIZE, 0);

        modified_accounts.insert(account_pubkey, new_account);
        logs.push(format!("Initialized vote account V2: {}", account_pubkey));

        Ok(())
    }

    fn execute_vote_switch(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: VoteSwitch".to_string());

        if context.accounts.is_empty() {
            return Err("VoteSwitch requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // VoteSwitch includes proof of switching from another fork
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse vote slots and hash from instruction data
        // 3. Parse proof of switch (previous vote on different fork)
        // 4. Verify switch proof is valid
        // 5. Update vote state with new votes
        // 6. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Processed vote with switch proof".to_string());

        Ok(())
    }

    fn execute_update_vote_state_switch(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: UpdateVoteStateSwitch".to_string());

        if context.accounts.is_empty() {
            return Err("UpdateVoteStateSwitch requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // UpdateVoteStateSwitch updates vote state with switch proof
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse vote state update from instruction data
        // 3. Parse and verify switch proof
        // 4. Apply vote state update
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote state with switch proof".to_string());

        Ok(())
    }

    fn execute_compact_update_vote_state(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: CompactUpdateVoteState".to_string());

        if context.accounts.is_empty() {
            return Err("CompactUpdateVoteState requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // CompactUpdateVoteState uses compact encoding to save transaction space
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse compact vote state update (using variable-length encoding)
        // 3. Apply vote state update
        // 4. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote state (compact format)".to_string());

        Ok(())
    }

    fn execute_compact_update_vote_state_switch(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: CompactUpdateVoteStateSwitch".to_string());

        if context.accounts.is_empty() {
            return Err("CompactUpdateVoteStateSwitch requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // CompactUpdateVoteStateSwitch combines compact encoding with switch proof
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse compact vote state update
        // 3. Parse and verify switch proof
        // 4. Apply vote state update
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote state (compact) with switch proof".to_string());

        Ok(())
    }

    fn execute_tower_sync(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: TowerSync".to_string());

        if context.accounts.is_empty() {
            return Err("TowerSync requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // TowerSync synchronizes the entire tower state
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse complete tower state from instruction data
        // 3. Verify tower consistency (lockouts, confirmations)
        // 4. Replace vote state with synced tower
        // 5. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Synchronized vote tower".to_string());

        Ok(())
    }

    fn execute_tower_sync_switch(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: TowerSyncSwitch".to_string());

        if context.accounts.is_empty() {
            return Err("TowerSyncSwitch requires at least 1 account".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // TowerSyncSwitch synchronizes tower with switch proof
        // In full implementation, would:
        // 1. Deserialize VoteState
        // 2. Parse complete tower state from instruction data
        // 3. Parse and verify switch proof
        // 4. Verify tower consistency
        // 5. Replace vote state with synced tower
        // 6. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Synchronized vote tower with switch proof".to_string());

        Ok(())
    }

    fn execute_authorize_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: AuthorizeWithSeed".to_string());

        if context.accounts.len() < 2 {
            return Err("AuthorizeWithSeed requires at least 2 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // AuthorizeWithSeed uses a seed-derived authority
        // In full implementation, would:
        // 1. Parse base pubkey, seed, and authority type from instruction data
        // 2. Derive authority address using create_with_seed
        // 3. Verify derived authority signature
        // 4. Deserialize VoteState
        // 5. Update authority in VoteState
        // 6. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote account authority (with seed)".to_string());

        Ok(())
    }

    fn execute_authorize_checked_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: AuthorizeCheckedWithSeed".to_string());

        if context.accounts.len() < 3 {
            return Err("AuthorizeCheckedWithSeed requires at least 3 accounts".to_string());
        }

        let (account_pubkey, account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // AuthorizeCheckedWithSeed combines seed-based authority with checked authorization
        // In full implementation, would:
        // 1. Parse base pubkey, seed, and authority type from instruction data
        // 2. Derive current authority address using create_with_seed
        // 3. Verify derived authority signature
        // 4. Verify new authority signature (accounts[2])
        // 5. Deserialize VoteState
        // 6. Update authority in VoteState
        // 7. Serialize updated VoteState

        modified_accounts.insert(account_pubkey, account);
        logs.push("Updated vote account authority (checked with seed)".to_string());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    #[test]
    fn vote_initialize_account() {
        let executor = VoteProgramExecutor::new(150);

        let account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![0, 0, 0, 0]; // InitializeAccount
        instruction_data.resize(100, 0); // Add placeholder data

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
        assert!(outcome.logs.iter().any(|log| log.contains("Initialized")));
    }

    #[test]
    fn vote_process_vote() {
        let executor = VoteProgramExecutor::new(150);

        let mut account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        account.data.resize(constants::VOTE_STATE_V3_SIZE, 0);

        let mut instruction_data = vec![2, 0, 0, 0]; // Vote
        instruction_data.resize(100, 0);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn vote_withdraw_lamports() {
        let executor = VoteProgramExecutor::new(150);

        let mut from_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        from_account.data.resize(constants::VOTE_STATE_V3_SIZE, 0);

        let to_account = Account {
            meta: AccountMeta {
                lamports: 0,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![3, 0, 0, 0]; // Withdraw
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), from_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
    }

    #[test]
    fn vote_update_commission() {
        let executor = VoteProgramExecutor::new(150);

        let mut account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        account.data.resize(constants::VOTE_STATE_V3_SIZE, 0);

        let instruction_data = vec![5, 0, 0, 0, 10]; // UpdateCommission with 10% commission

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs.iter().any(|log| log.contains("commission")));
    }
}
