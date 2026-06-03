/// Vote program executor implementing all vote instruction handlers.
///
/// Each instruction parses its data, validates signers and account ownership,
/// loads and modifies the vote state, serializes the result, and returns
/// modified accounts.
use super::state::{LandedVote, Lockout, VoteError, VoteState};
use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::vote_program::{
    self as constants, COMPUTE_COST_AUTHORIZE, COMPUTE_COST_BASE_INSTRUCTION,
    COMPUTE_COST_INITIALIZE, COMPUTE_COST_UPDATE_COMMISSION, COMPUTE_COST_UPDATE_VOTE_STATE,
    COMPUTE_COST_VOTE, COMPUTE_COST_WITHDRAW, VOTE_AUTHORIZE_VOTER, VOTE_AUTHORIZE_WITHDRAWER,
};
use karstflow_ids::features::{is_feature_active, DELAY_COMMISSION_UPDATES};
use karstflow_ids::VOTE_PROGRAM_ID;
use karstflow_types::{Account, AccountData, Pubkey};
use std::collections::HashMap;

/// Whether a vote-commission increase is allowed at the given slot.
///
/// Mirrors the reference implementation: increases are only permitted in the
/// first half of an epoch (relative_slot * 2 <= slots_per_epoch). With no
/// normal epoch schedule (slots_per_epoch == 0) updates are always allowed.
fn is_commission_update_allowed(slot: u64, first_normal_slot: u64, slots_per_epoch: u64) -> bool {
    if slots_per_epoch == 0 {
        return true;
    }
    let relative_slot = slot.saturating_sub(first_normal_slot) % slots_per_epoch;
    relative_slot.saturating_mul(2) <= slots_per_epoch
}

/// Vote program executor with configurable base compute cost.
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
            return Err("Vote instruction data is empty".to_string());
        }

        if context.instruction_data.len() < 4 {
            return Err("Vote instruction data too short for type discriminant".to_string());
        }

        let instruction_type = u32::from_le_bytes(
            context.instruction_data[0..4]
                .try_into()
                .map_err(|_| "Failed to parse instruction type")?,
        );

        let mut compute_used = self.base_cost.saturating_add(COMPUTE_COST_BASE_INSTRUCTION);
        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        match instruction_type {
            constants::INSTRUCTION_INITIALIZE_ACCOUNT => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_INITIALIZE);
                self.execute_initialize(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_INITIALIZE_ACCOUNT_V2 => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_INITIALIZE);
                // V2 is identical to V1 in behavior but for newer state format.
                // Since our VoteState already supports the latest format, delegate.
                self.execute_initialize(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_AUTHORIZE => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_AUTHORIZE);
                self.execute_authorize(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_VOTE => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_VOTE);
                self.execute_vote(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_VOTE_SWITCH => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_VOTE);
                // VoteSwitch is identical to Vote but includes a switch proof hash
                // that is verified at the consensus layer, not here.
                self.execute_vote(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_UPDATE_VOTE_STATE
            | constants::INSTRUCTION_COMPACT_UPDATE_VOTE_STATE
            | constants::INSTRUCTION_TOWER_SYNC => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_UPDATE_VOTE_STATE);
                self.execute_vote_state_update(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_UPDATE_VOTE_STATE_SWITCH
            | constants::INSTRUCTION_COMPACT_UPDATE_VOTE_STATE_SWITCH
            | constants::INSTRUCTION_TOWER_SYNC_SWITCH => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_UPDATE_VOTE_STATE);
                // Switch variants include a proof hash; behavior is otherwise identical.
                self.execute_vote_state_update(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_UPDATE_VALIDATOR_IDENTITY => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_AUTHORIZE);
                self.execute_update_validator_identity(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_UPDATE_COMMISSION => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_UPDATE_COMMISSION);
                self.execute_update_commission(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_WITHDRAW => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_WITHDRAW);
                self.execute_withdraw(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_AUTHORIZE_WITH_SEED => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_with_seed(context, &mut modified_accounts, &mut logs)?;
            }
            constants::INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED => {
                compute_used = compute_used.saturating_add(COMPUTE_COST_AUTHORIZE);
                self.execute_authorize_checked_with_seed(
                    context,
                    &mut modified_accounts,
                    &mut logs,
                )?;
            }
            constants::INSTRUCTION_UPDATE_COMMISSION_COLLECTOR
            | constants::INSTRUCTION_UPDATE_COMMISSION_BPS
            | constants::INSTRUCTION_DEPOSIT_DELEGATOR_REWARDS => {
                // Agave 4.0 stub instructions — feature-gated and not yet
                // activated on any network. Return an error matching the
                // reference implementation behavior.
                return Err(format!(
                    "Unimplemented vote instruction type {}",
                    instruction_type
                ));
            }
            _ => {
                return Err(format!(
                    "Unknown vote instruction type {}",
                    instruction_type
                ));
            }
        }

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs,
            return_data: None,
        })
    }

    // -----------------------------------------------------------------------
    // InitializeAccount
    // -----------------------------------------------------------------------

    /// Initialize a new vote account.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..36]   node_pubkey (32 bytes)
    ///   [36..68]  authorized_voter (32 bytes)
    ///   [68..100] authorized_withdrawer (32 bytes)
    ///   [100]     commission (1 byte)
    fn execute_initialize(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: InitializeAccount".to_string());

        if context.accounts.is_empty() {
            return Err("InitializeAccount requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 101 {
            return Err("InitializeAccount instruction data too short".to_string());
        }

        let node_pubkey = read_pubkey(&context.instruction_data, 4)?;
        let authorized_voter = read_pubkey(&context.instruction_data, 36)?;
        let authorized_withdrawer = read_pubkey(&context.instruction_data, 68)?;
        let commission = context.instruction_data[100];

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // Ensure account is owned by the vote program
        if vote_account.meta.owner != VOTE_PROGRAM_ID {
            return Err("Vote account not owned by vote program".to_string());
        }

        // Create and serialize vote state
        let vote_state = VoteState::new(
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
        );
        vote_account.data = AccountData::new(vote_state.serialize());

        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Authorize
    // -----------------------------------------------------------------------

    /// Change the authorized voter or withdrawer.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..36]  new_authority (32 bytes)
    ///   [36..40] authorize_type (u32 LE: 0=Voter, 1=Withdrawer)
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] clock sysvar
    ///   [2] current authority (signer)
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

        if context.instruction_data.len() < 40 {
            return Err("Authorize instruction data too short".to_string());
        }

        let new_authority = read_pubkey(&context.instruction_data, 4)?;
        let authorize_type = read_u32(&context.instruction_data, 36)?;

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        match authorize_type {
            VOTE_AUTHORIZE_VOTER => {
                vote_state.authorized_voter = new_authority;
            }
            VOTE_AUTHORIZE_WITHDRAWER => {
                vote_state.authorized_withdrawer = new_authority;
            }
            _ => {
                return Err(format!("Invalid authorize type: {}", authorize_type));
            }
        }

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // AuthorizeChecked
    // -----------------------------------------------------------------------

    /// Change authority with the new authority required as a signer.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..8] authorize_type (u32 LE: 0=Voter, 1=Withdrawer)
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] clock sysvar
    ///   [2] current authority (signer)
    ///   [3] new authority (signer) - the pubkey of the new authority
    fn execute_authorize_checked(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: AuthorizeChecked".to_string());

        if context.accounts.len() < 4 {
            return Err("AuthorizeChecked requires at least 4 accounts".to_string());
        }

        if context.instruction_data.len() < 8 {
            return Err("AuthorizeChecked instruction data too short".to_string());
        }

        let authorize_type = read_u32(&context.instruction_data, 4)?;

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        // The new authority pubkey comes from accounts[3]
        let (new_authority_pubkey, _, _) = &context.accounts[3];

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        match authorize_type {
            VOTE_AUTHORIZE_VOTER => {
                vote_state.authorized_voter = *new_authority_pubkey;
            }
            VOTE_AUTHORIZE_WITHDRAWER => {
                vote_state.authorized_withdrawer = *new_authority_pubkey;
            }
            _ => {
                return Err(format!("Invalid authorize type: {}", authorize_type));
            }
        }

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Vote (legacy) / VoteSwitch
    // -----------------------------------------------------------------------

    /// Process a legacy vote instruction.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..12]   slot count (u64 LE) -- number of slots voted on
    ///   [12..12+8*N] slots (u64 LE each)
    ///   [12+8*N..12+8*N+32] hash (32 bytes)
    ///
    /// For simplicity, we process the first slot and hash only (matching the
    /// most common usage pattern of voting on a single slot).
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] slot hashes sysvar
    ///   [2] clock sysvar
    ///   [3] vote authority (signer)
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

        if context.instruction_data.len() < 12 {
            return Err("Vote instruction data too short".to_string());
        }

        // Parse slot count
        let slot_count = read_u64(&context.instruction_data, 4)? as usize;

        if slot_count == 0 {
            return Err("Vote with zero slots".to_string());
        }

        let slots_data_end = 12 + slot_count * 8;
        let hash_end = slots_data_end + 32;

        if context.instruction_data.len() < hash_end {
            return Err("Vote instruction data too short for slots and hash".to_string());
        }

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        let hash: [u8; 32] = context.instruction_data[slots_data_end..hash_end]
            .try_into()
            .map_err(|_| "Failed to parse vote hash")?;

        // Process each voted slot
        for i in 0..slot_count {
            let offset = 12 + i * 8;
            let slot = read_u64(&context.instruction_data, offset)?;
            vote_state
                .process_vote(slot, hash)
                .map_err(|e| format!("Vote processing failed: {:?}", e))?;
        }

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Vote State Update (UpdateVoteState, CompactUpdateVoteState, TowerSync)
    // -----------------------------------------------------------------------

    /// Process a vote state update instruction.
    ///
    /// These instructions provide a complete new tower state. The instruction
    /// data layout after the 4-byte type discriminant:
    ///   [4..12]  root_slot option: 1 byte (0=None, 1=Some) + 8 bytes if Some
    ///   then:    vote_count (u32 LE)
    ///            for each vote: slot (u64 LE) + confirmation_count (u32 LE)
    ///            optional: has_timestamp (1 byte) + timestamp (i64 LE) if has=1
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] vote authority (signer)
    fn execute_vote_state_update(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: VoteStateUpdate".to_string());

        if context.accounts.is_empty() {
            return Err("VoteStateUpdate requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 5 {
            return Err("VoteStateUpdate instruction data too short".to_string());
        }

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        // Parse root slot option
        let mut offset = 4;
        let (new_root, new_offset) = parse_optional_slot(&context.instruction_data, offset)?;
        offset = new_offset;

        // Parse vote count
        if context.instruction_data.len() < offset + 4 {
            return Err("VoteStateUpdate data too short for vote count".to_string());
        }
        let vote_count = read_u32(&context.instruction_data, offset)? as usize;
        offset += 4;

        // Parse votes
        let mut new_votes = Vec::with_capacity(vote_count);
        for _ in 0..vote_count {
            if context.instruction_data.len() < offset + 12 {
                return Err("VoteStateUpdate data too short for vote entry".to_string());
            }
            let slot = read_u64(&context.instruction_data, offset)?;
            offset += 8;
            let confirmation_count = read_u32(&context.instruction_data, offset)?;
            offset += 4;
            new_votes.push(LandedVote::with_lockout(
                Lockout::with_confirmation_count(slot, confirmation_count),
                0,
            ));
        }

        // Parse optional timestamp
        let has_timestamp = if context.instruction_data.len() > offset {
            context.instruction_data[offset] == 1
        } else {
            false
        };
        let _timestamp = if has_timestamp && context.instruction_data.len() >= offset + 9 {
            offset += 1;
            let ts = read_i64(&context.instruction_data, offset)?;
            offset += 8;
            ts
        } else {
            if has_timestamp {
                offset += 1;
            }
            0
        };

        // Apply the vote state update
        // For the current slot, use the latest vote slot if available
        let current_slot = new_votes.last().map(|v| v.slot()).unwrap_or(0);

        vote_state
            .apply_vote_state_update(new_votes, new_root, 0, current_slot)
            .map_err(|e| format!("Vote state update failed: {:?}", e))?;

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // UpdateValidatorIdentity
    // -----------------------------------------------------------------------

    /// Update the validator node identity on the vote account.
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] new validator identity (signer)
    ///   [2] authorized withdrawer (signer)
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

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let (new_identity_pubkey, _, _) = &context.accounts[1];

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        vote_state.node_pubkey = *new_identity_pubkey;

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // UpdateCommission
    // -----------------------------------------------------------------------

    /// Update the commission rate on the vote account.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4] new_commission (1 byte)
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] authorized withdrawer (signer)
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

        let new_commission = context.instruction_data[4];

        if new_commission > 100 {
            return Err("Commission must be between 0 and 100".to_string());
        }

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        // The authorized withdrawer must sign a commission change.
        if !context.signers.is_empty() && !context.is_signer(&vote_state.authorized_withdrawer) {
            return Err("UpdateCommission: authorized withdrawer must sign".to_string());
        }

        // Commission increases are only allowed in the first half of an epoch,
        // unless the `delay_commission_updates` feature disables the rule.
        // Decreases are always allowed. Skipped when no sysvar snapshot is
        // available to evaluate the epoch position.
        if let Some(ref snap) = context.sysvar_snapshot {
            let rule_disabled = is_feature_active(&snap.active_features, &DELAY_COMMISSION_UPDATES);
            if !rule_disabled
                && new_commission > vote_state.commission
                && !is_commission_update_allowed(
                    snap.slot,
                    snap.first_normal_slot,
                    snap.slots_per_epoch,
                )
            {
                return Err("UpdateCommission: commission update too late in epoch".to_string());
            }
        }

        vote_state.commission = new_commission;

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Withdraw
    // -----------------------------------------------------------------------

    /// Withdraw lamports from a vote account.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..12] lamports (u64 LE)
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] recipient account (writable)
    ///   [2] authorized withdrawer (signer)
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

        let lamports = read_u64(&context.instruction_data, 4)?;

        let (vote_pubkey, mut vote_account, vote_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, to_writable) = context.accounts[1].clone();

        if !vote_writable || !to_writable {
            return Err("Both accounts must be writable".to_string());
        }

        // The authorized withdrawer must sign a withdrawal.
        let vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;
        if !context.signers.is_empty() && !context.is_signer(&vote_state.authorized_withdrawer) {
            return Err("Withdraw: authorized withdrawer must sign".to_string());
        }

        if vote_account.meta.lamports < lamports {
            return Err(format!(
                "Insufficient lamports in vote account: {} < {}",
                vote_account.meta.lamports, lamports
            ));
        }

        vote_account.meta.lamports = vote_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(lamports);

        modified_accounts.insert(vote_pubkey, vote_account);
        modified_accounts.insert(to_pubkey, to_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // AuthorizeWithSeed
    // -----------------------------------------------------------------------

    /// Authorize a new voter or withdrawer using a seed-derived address.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..8]   authorize_type (u32 LE: 0=Voter, 1=Withdrawer)
    ///   [8..40]  new_authority (32 bytes)
    ///   [40..44] seed_len (u32 LE)
    ///   [44..44+seed_len] seed bytes
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] clock sysvar
    ///   [2] base key of current authority (signer)
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

        if context.instruction_data.len() < 40 {
            return Err("AuthorizeWithSeed instruction data too short".to_string());
        }

        let authorize_type = read_u32(&context.instruction_data, 4)?;
        let new_authority = read_pubkey(&context.instruction_data, 8)?;

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        match authorize_type {
            VOTE_AUTHORIZE_VOTER => {
                vote_state.authorized_voter = new_authority;
            }
            VOTE_AUTHORIZE_WITHDRAWER => {
                vote_state.authorized_withdrawer = new_authority;
            }
            _ => {
                return Err(format!("Invalid authorize type: {}", authorize_type));
            }
        }

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // AuthorizeCheckedWithSeed
    // -----------------------------------------------------------------------

    /// Authorize with seed, requiring the new authority to also be a signer.
    ///
    /// Instruction data layout after the 4-byte type discriminant:
    ///   [4..8]   authorize_type (u32 LE: 0=Voter, 1=Withdrawer)
    ///   [8..12]  seed_len (u32 LE)
    ///   [12..12+seed_len] seed bytes
    ///
    /// Accounts:
    ///   [0] vote account (writable)
    ///   [1] clock sysvar
    ///   [2] base key of current authority (signer)
    ///   [3] new authority (signer) -- pubkey taken from accounts
    fn execute_authorize_checked_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("Vote: AuthorizeCheckedWithSeed".to_string());

        if context.accounts.len() < 4 {
            return Err("AuthorizeCheckedWithSeed requires at least 4 accounts".to_string());
        }

        if context.instruction_data.len() < 8 {
            return Err("AuthorizeCheckedWithSeed instruction data too short".to_string());
        }

        let authorize_type = read_u32(&context.instruction_data, 4)?;
        let (new_authority_pubkey, _, _) = &context.accounts[3];

        let (vote_pubkey, mut vote_account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Vote account must be writable".to_string());
        }

        let mut vote_state = VoteState::deserialize(vote_account.data.as_ref())
            .map_err(|e| format!("Failed to deserialize vote state: {:?}", e))?;

        match authorize_type {
            VOTE_AUTHORIZE_VOTER => {
                vote_state.authorized_voter = *new_authority_pubkey;
            }
            VOTE_AUTHORIZE_WITHDRAWER => {
                vote_state.authorized_withdrawer = *new_authority_pubkey;
            }
            _ => {
                return Err(format!("Invalid authorize type: {}", authorize_type));
            }
        }

        vote_account.data = AccountData::new(vote_state.serialize());
        modified_accounts.insert(vote_pubkey, vote_account);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn read_pubkey(data: &[u8], offset: usize) -> Result<Pubkey, String> {
    if data.len() < offset + 32 {
        return Err("Data too short for pubkey".to_string());
    }
    let bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .map_err(|_| "Failed to parse pubkey")?;
    Ok(Pubkey::new_from_array(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if data.len() < offset + 4 {
        return Err("Data too short for u32".to_string());
    }
    Ok(u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| "Failed to parse u32")?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if data.len() < offset + 8 {
        return Err("Data too short for u64".to_string());
    }
    Ok(u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| "Failed to parse u64")?,
    ))
}

fn read_i64(data: &[u8], offset: usize) -> Result<i64, String> {
    if data.len() < offset + 8 {
        return Err("Data too short for i64".to_string());
    }
    Ok(i64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| "Failed to parse i64")?,
    ))
}

/// Parse an optional slot (1 byte tag + 8 bytes if present).
/// Returns (Option<u64>, new_offset).
fn parse_optional_slot(data: &[u8], offset: usize) -> Result<(Option<u64>, usize), String> {
    if data.len() <= offset {
        return Err("Data too short for optional slot tag".to_string());
    }
    if data[offset] == 1 {
        let slot = read_u64(data, offset + 1)?;
        Ok((Some(slot), offset + 9))
    } else {
        Ok((None, offset + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::AccountMeta;

    fn make_vote_account(vote_state: &VoteState) -> Account {
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        }
    }

    fn make_empty_vote_account() -> Account {
        Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    fn make_initialize_data(
        node: &Pubkey,
        voter: &Pubkey,
        withdrawer: &Pubkey,
        commission: u8,
    ) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 0]; // INSTRUCTION_INITIALIZE_ACCOUNT = 0
        data.extend_from_slice(node.as_bytes());
        data.extend_from_slice(voter.as_bytes());
        data.extend_from_slice(withdrawer.as_bytes());
        data.push(commission);
        data
    }

    #[test]
    fn initialize_creates_vote_state() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let instruction_data = make_initialize_data(&node, &voter, &withdrawer, 10);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_empty_vote_account();

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let state = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(state.node_pubkey, node);
        assert_eq!(state.authorized_voter, voter);
        assert_eq!(state.authorized_withdrawer, withdrawer);
        assert_eq!(state.commission, 10);
    }

    #[test]
    fn initialize_rejects_non_vote_owned_account() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let instruction_data = make_initialize_data(&node, &voter, &withdrawer, 5);
        let account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: Pubkey::new_unique(), // NOT vote program
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not owned by vote program"));
    }

    #[test]
    fn vote_processes_single_slot() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        // Build vote instruction data: type(4) + slot_count(8) + slot(8) + hash(32)
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_VOTE.to_le_bytes());
        instruction_data.extend_from_slice(&1u64.to_le_bytes()); // 1 slot
        instruction_data.extend_from_slice(&100u64.to_le_bytes()); // slot 100
        instruction_data.extend_from_slice(&[42u8; 32]); // hash

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.votes.len(), 1);
        assert_eq!(updated.votes[0].slot(), 100);
    }

    #[test]
    fn vote_processes_multiple_slots() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        // 3 slots
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_VOTE.to_le_bytes());
        instruction_data.extend_from_slice(&3u64.to_le_bytes());
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(&101u64.to_le_bytes());
        instruction_data.extend_from_slice(&102u64.to_le_bytes());
        instruction_data.extend_from_slice(&[0u8; 32]); // hash

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.votes.len(), 3);
    }

    #[test]
    fn vote_rejects_non_sequential() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let mut vote_state = VoteState::new(node, voter, withdrawer, 5);
        vote_state.process_vote(100, [0; 32]).unwrap();

        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        // Try to vote on slot 50 (before 100)
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_VOTE.to_le_bytes());
        instruction_data.extend_from_slice(&1u64.to_le_bytes());
        instruction_data.extend_from_slice(&50u64.to_le_bytes());
        instruction_data.extend_from_slice(&[0u8; 32]);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Vote processing failed"));
    }

    #[test]
    fn withdraw_transfers_lamports() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let vote_account = make_vote_account(&vote_state);

        let to_pubkey = Pubkey::new_unique();
        let to_account = Account::zeroed();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_WITHDRAW.to_le_bytes());
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, vote_account, true),
                (to_pubkey, to_account, true),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let vote_modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        assert_eq!(vote_modified.meta.lamports, 5_000);

        let to_modified = outcome.modified_accounts.get(&to_pubkey).unwrap();
        assert_eq!(to_modified.meta.lamports, 5_000);
    }

    #[test]
    fn withdraw_rejects_insufficient_lamports() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vote_state.serialize()),
        };

        let to_account = Account::zeroed();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_WITHDRAW.to_le_bytes());
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), vote_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient lamports"));
    }

    #[test]
    fn update_commission_changes_value() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(25);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.commission, 25);
    }

    #[test]
    fn update_commission_accepts_when_withdrawer_signs() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(25);

        let mut signers = std::collections::HashSet::new();
        signers.insert(withdrawer);
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        )
        .with_signers(signers);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        assert_eq!(
            VoteState::deserialize(modified.data.as_ref())
                .unwrap()
                .commission,
            25
        );
    }

    #[test]
    fn update_commission_rejects_when_withdrawer_does_not_sign() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(25);

        // Some other account signs, but not the authorized withdrawer.
        let mut signers = std::collections::HashSet::new();
        signers.insert(Pubkey::new_unique());
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        )
        .with_signers(signers);

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("authorized withdrawer must sign"));
    }

    #[test]
    fn withdraw_rejects_when_withdrawer_does_not_sign() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let mut account = make_vote_account(&vote_state);
        account.meta.lamports = 1_000_000;
        let to_account = Account::zeroed();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_WITHDRAW.to_le_bytes());
        instruction_data.extend_from_slice(&500u64.to_le_bytes());

        let mut signers = std::collections::HashSet::new();
        signers.insert(Pubkey::new_unique()); // not the withdrawer
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        )
        .with_signers(signers);

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("authorized withdrawer must sign"));
    }

    fn commission_snapshot(slot: u64, feature_active: bool) -> crate::SysvarSnapshot {
        let mut snap = crate::SysvarSnapshot {
            slot,
            slots_per_epoch: 100,
            first_normal_slot: 0,
            ..Default::default()
        };
        if feature_active {
            snap.active_features
                .insert(*DELAY_COMMISSION_UPDATES.as_bytes());
        }
        snap
    }

    #[test]
    fn update_commission_increase_rejected_in_second_half_of_epoch() {
        let executor = VoteProgramExecutor::new(150);
        let withdrawer = Pubkey::new_unique();
        let vote_state = VoteState::new(Pubkey::new_unique(), Pubkey::new_unique(), withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(25); // increase 5 -> 25

        let mut signers = std::collections::HashSet::new();
        signers.insert(withdrawer);
        // slot 80 of a 100-slot epoch: 80*2 > 100 → second half → not allowed.
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        )
        .with_signers(signers)
        .with_sysvar_snapshot(commission_snapshot(80, false));

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too late in epoch"));
    }

    #[test]
    fn update_commission_decrease_allowed_in_second_half_of_epoch() {
        let executor = VoteProgramExecutor::new(150);
        let withdrawer = Pubkey::new_unique();
        let vote_state = VoteState::new(Pubkey::new_unique(), Pubkey::new_unique(), withdrawer, 50);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(10); // decrease 50 -> 10, always allowed

        let mut signers = std::collections::HashSet::new();
        signers.insert(withdrawer);
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        )
        .with_signers(signers)
        .with_sysvar_snapshot(commission_snapshot(80, false));

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn update_commission_increase_allowed_when_delay_feature_active() {
        let executor = VoteProgramExecutor::new(150);
        let withdrawer = Pubkey::new_unique();
        let vote_state = VoteState::new(Pubkey::new_unique(), Pubkey::new_unique(), withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(25);

        let mut signers = std::collections::HashSet::new();
        signers.insert(withdrawer);
        // Second half of epoch, but the feature disables the timing rule.
        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        )
        .with_signers(signers)
        .with_sysvar_snapshot(commission_snapshot(80, true));

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn commission_update_allowed_first_half_only() {
        // first half allowed
        assert!(is_commission_update_allowed(10, 0, 100));
        assert!(is_commission_update_allowed(50, 0, 100));
        // second half rejected
        assert!(!is_commission_update_allowed(51, 0, 100));
        assert!(!is_commission_update_allowed(99, 0, 100));
        // no normal schedule → always allowed
        assert!(is_commission_update_allowed(99, 0, 0));
    }

    #[test]
    fn update_commission_rejects_over_100() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let account = make_vote_account(&vote_state);

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_UPDATE_COMMISSION.to_le_bytes());
        instruction_data.push(101);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Commission must be between"));
    }

    #[test]
    fn authorize_changes_voter() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_voter = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_AUTHORIZE.to_le_bytes());
        instruction_data.extend_from_slice(new_voter.as_bytes());
        instruction_data.extend_from_slice(&VOTE_AUTHORIZE_VOTER.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.authorized_voter, new_voter);
    }

    #[test]
    fn authorize_changes_withdrawer() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_withdrawer = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_AUTHORIZE.to_le_bytes());
        instruction_data.extend_from_slice(new_withdrawer.as_bytes());
        instruction_data.extend_from_slice(&VOTE_AUTHORIZE_WITHDRAWER.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.authorized_withdrawer, new_withdrawer);
    }

    #[test]
    fn authorize_checked_changes_voter() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_voter = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_AUTHORIZE_CHECKED.to_le_bytes());
        instruction_data.extend_from_slice(&VOTE_AUTHORIZE_VOTER.to_le_bytes());

        let clock_account = Account::zeroed();
        let current_authority = Account::zeroed();
        let new_authority_account = Account::zeroed();

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, account, true),
                (Pubkey::new_unique(), clock_account, false),
                (voter, current_authority, false),
                (new_voter, new_authority_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.authorized_voter, new_voter);
    }

    #[test]
    fn update_validator_identity_changes_node() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_node = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data
            .extend_from_slice(&constants::INSTRUCTION_UPDATE_VALIDATOR_IDENTITY.to_le_bytes());

        let new_identity_account = Account::zeroed();

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, account, true),
                (new_node, new_identity_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.node_pubkey, new_node);
    }

    #[test]
    fn vote_state_update_applies_new_tower() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        // Build a TowerSync instruction with:
        //   root = Some(50)
        //   votes: [100/3, 101/2, 102/1]
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_TOWER_SYNC.to_le_bytes());
        // root = Some(50)
        instruction_data.push(1);
        instruction_data.extend_from_slice(&50u64.to_le_bytes());
        // vote_count = 3
        instruction_data.extend_from_slice(&3u32.to_le_bytes());
        // vote 1: slot=100, conf=3
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(&3u32.to_le_bytes());
        // vote 2: slot=101, conf=2
        instruction_data.extend_from_slice(&101u64.to_le_bytes());
        instruction_data.extend_from_slice(&2u32.to_le_bytes());
        // vote 3: slot=102, conf=1
        instruction_data.extend_from_slice(&102u64.to_le_bytes());
        instruction_data.extend_from_slice(&1u32.to_le_bytes());
        // no timestamp
        instruction_data.push(0);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(vote_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.votes.len(), 3);
        assert_eq!(updated.votes[0].slot(), 100);
        assert_eq!(updated.votes[0].lockout.confirmation_count, 3);
        assert_eq!(updated.votes[2].slot(), 102);
        assert_eq!(updated.votes[2].lockout.confirmation_count, 1);
    }

    #[test]
    fn vote_state_update_rejects_invalid_ordering() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let account = make_vote_account(&vote_state);

        // Build an update with unordered slots
        let mut instruction_data = Vec::new();
        instruction_data.extend_from_slice(&constants::INSTRUCTION_TOWER_SYNC.to_le_bytes());
        // no root
        instruction_data.push(0);
        // 2 votes with unordered slots
        instruction_data.extend_from_slice(&2u32.to_le_bytes());
        // vote 1: slot=200, conf=2
        instruction_data.extend_from_slice(&200u64.to_le_bytes());
        instruction_data.extend_from_slice(&2u32.to_le_bytes());
        // vote 2: slot=100, conf=1 -- out of order!
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(&1u32.to_le_bytes());

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Vote state update failed"));
    }

    #[test]
    fn unknown_instruction_returns_error() {
        let executor = VoteProgramExecutor::new(150);

        let instruction_data = vec![255, 0, 0, 0]; // Unknown type 255

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), Account::zeroed(), true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Unknown vote instruction type"));
    }

    #[test]
    fn empty_instruction_data_returns_error() {
        let executor = VoteProgramExecutor::new(150);

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![(Pubkey::new_unique(), Account::zeroed(), true)],
            Vec::new(),
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
    }

    #[test]
    fn authorize_with_seed_changes_voter() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_voter = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data
            .extend_from_slice(&constants::INSTRUCTION_AUTHORIZE_WITH_SEED.to_le_bytes());
        instruction_data.extend_from_slice(&VOTE_AUTHORIZE_VOTER.to_le_bytes());
        instruction_data.extend_from_slice(new_voter.as_bytes());
        // seed_len + seed (not parsed fully but data must be present)
        instruction_data.extend_from_slice(&0u32.to_le_bytes());

        let base_account = Account::zeroed();

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, account, true),
                (Pubkey::new_unique(), base_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.authorized_voter, new_voter);
    }

    #[test]
    fn authorize_checked_with_seed_changes_withdrawer() {
        let executor = VoteProgramExecutor::new(150);
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node, voter, withdrawer, 5);
        let vote_pubkey = Pubkey::new_unique();
        let account = make_vote_account(&vote_state);

        let new_withdrawer = Pubkey::new_unique();

        let mut instruction_data = Vec::new();
        instruction_data
            .extend_from_slice(&constants::INSTRUCTION_AUTHORIZE_CHECKED_WITH_SEED.to_le_bytes());
        instruction_data.extend_from_slice(&VOTE_AUTHORIZE_WITHDRAWER.to_le_bytes());
        // seed data
        instruction_data.extend_from_slice(&0u32.to_le_bytes());

        let clock_account = Account::zeroed();
        let base_account = Account::zeroed();
        let new_authority_account = Account::zeroed();

        let context = ExecutionContext::new(
            VOTE_PROGRAM_ID,
            vec![
                (vote_pubkey, account, true),
                (Pubkey::new_unique(), clock_account, false),
                (Pubkey::new_unique(), base_account, false),
                (new_withdrawer, new_authority_account, false),
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = outcome.modified_accounts.get(&vote_pubkey).unwrap();
        let updated = VoteState::deserialize(modified.data.as_ref()).unwrap();
        assert_eq!(updated.authorized_withdrawer, new_withdrawer);
    }
}
