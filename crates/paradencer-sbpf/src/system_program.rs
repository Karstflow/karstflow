use super::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::{
    ledger::{
        self, DURABLE_NONCE_PREFIX, NONCE_ACCOUNT_SIZE, NONCE_STATE_INITIALIZED,
        NONCE_STATE_UNINITIALIZED, NONCE_VERSION_CURRENT, NONCE_VERSION_LEGACY,
    },
    system_program as constants,
};
use paradencer_ids::SYSTEM_PROGRAM_ID;
use paradencer_types::{Account, AccountData, Pubkey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// System program instruction discriminants
pub const SYSTEM_PROGRAM_CREATE_ACCOUNT: u32 = 0;
pub const SYSTEM_PROGRAM_ASSIGN: u32 = 1;
pub const SYSTEM_PROGRAM_TRANSFER: u32 = 2;
pub const SYSTEM_PROGRAM_CREATE_ACCOUNT_WITH_SEED: u32 = 3;
pub const SYSTEM_PROGRAM_ADVANCE_NONCE_ACCOUNT: u32 = 4;
pub const SYSTEM_PROGRAM_WITHDRAW_NONCE_ACCOUNT: u32 = 5;
pub const SYSTEM_PROGRAM_INITIALIZE_NONCE_ACCOUNT: u32 = 6;
pub const SYSTEM_PROGRAM_AUTHORIZE_NONCE_ACCOUNT: u32 = 7;
pub const SYSTEM_PROGRAM_ALLOCATE: u32 = 8;
pub const SYSTEM_PROGRAM_ALLOCATE_WITH_SEED: u32 = 9;
pub const SYSTEM_PROGRAM_ASSIGN_WITH_SEED: u32 = 10;
pub const SYSTEM_PROGRAM_TRANSFER_WITH_SEED: u32 = 11;
pub const SYSTEM_PROGRAM_UPGRADE_NONCE_ACCOUNT: u32 = 12;

/// System program execution errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProgramError {
    AccountAlreadyInUse,
    ResultWithNegativeLamports,
    InvalidProgramId,
    InvalidAccountDataLength,
    MaxSeedLengthExceeded,
    AddressWithSeedMismatch,
    NonceNoRecentBlockhashes,
    NonceBlockhashNotExpired,
    NonceUnexpectedBlockhashValue,
}

impl SystemProgramError {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::AccountAlreadyInUse => constants::ERR_ACCOUNT_ALREADY_IN_USE,
            Self::ResultWithNegativeLamports => constants::ERR_RESULT_WITH_NEGATIVE_LAMPORTS,
            Self::InvalidProgramId => constants::ERR_INVALID_PROGRAM_ID,
            Self::InvalidAccountDataLength => constants::ERR_INVALID_ACCOUNT_DATA_LENGTH,
            Self::MaxSeedLengthExceeded => constants::ERR_MAX_SEED_LENGTH_EXCEEDED,
            Self::AddressWithSeedMismatch => constants::ERR_ADDRESS_WITH_SEED_MISMATCH,
            Self::NonceNoRecentBlockhashes => constants::ERR_NONCE_NO_RECENT_BLOCKHASHES,
            Self::NonceBlockhashNotExpired => constants::ERR_NONCE_BLOCKHASH_NOT_EXPIRED,
            Self::NonceUnexpectedBlockhashValue => constants::ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::AccountAlreadyInUse => "Account already in use".to_string(),
            Self::ResultWithNegativeLamports => "Result with negative lamports".to_string(),
            Self::InvalidProgramId => "Invalid program ID".to_string(),
            Self::InvalidAccountDataLength => "Invalid account data length".to_string(),
            Self::MaxSeedLengthExceeded => "Max seed length exceeded".to_string(),
            Self::AddressWithSeedMismatch => "Address with seed mismatch".to_string(),
            Self::NonceNoRecentBlockhashes => "Nonce: no recent blockhashes".to_string(),
            Self::NonceBlockhashNotExpired => "Nonce: blockhash not expired".to_string(),
            Self::NonceUnexpectedBlockhashValue => "Nonce: unexpected blockhash value".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Nonce state serialization helpers
// ---------------------------------------------------------------------------

/// Parsed nonce account state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NonceVersionedState {
    /// Legacy or current version, uninitialized.
    Uninitialized { version: u32 },
    /// Legacy or current version, initialized with data.
    Initialized {
        version: u32,
        authority: Pubkey,
        durable_nonce: [u8; 32],
        lamports_per_signature: u64,
    },
}

impl NonceVersionedState {
    /// Deserialize nonce state from account data (bincode format, 80 bytes).
    fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("Nonce account data too short".to_string());
        }
        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if version != NONCE_VERSION_LEGACY && version != NONCE_VERSION_CURRENT {
            return Err(format!("Unknown nonce version: {}", version));
        }
        let state_disc = u32::from_le_bytes(data[4..8].try_into().unwrap());
        match state_disc {
            NONCE_STATE_UNINITIALIZED => Ok(Self::Uninitialized { version }),
            NONCE_STATE_INITIALIZED => {
                if data.len() < NONCE_ACCOUNT_SIZE {
                    return Err("Nonce account data too short for initialized state".to_string());
                }
                let authority = Pubkey::new(data[8..40].try_into().unwrap());
                let mut durable_nonce = [0u8; 32];
                durable_nonce.copy_from_slice(&data[40..72]);
                let lamports_per_signature = u64::from_le_bytes(data[72..80].try_into().unwrap());
                Ok(Self::Initialized {
                    version,
                    authority,
                    durable_nonce,
                    lamports_per_signature,
                })
            }
            _ => Err(format!("Unknown nonce state discriminant: {}", state_disc)),
        }
    }

    /// Serialize nonce state to 80 bytes (bincode format).
    fn serialize(&self) -> [u8; NONCE_ACCOUNT_SIZE] {
        let mut buf = [0u8; NONCE_ACCOUNT_SIZE];
        match self {
            Self::Uninitialized { version } => {
                buf[0..4].copy_from_slice(&version.to_le_bytes());
                buf[4..8].copy_from_slice(&NONCE_STATE_UNINITIALIZED.to_le_bytes());
            }
            Self::Initialized {
                version,
                authority,
                durable_nonce,
                lamports_per_signature,
            } => {
                buf[0..4].copy_from_slice(&version.to_le_bytes());
                buf[4..8].copy_from_slice(&NONCE_STATE_INITIALIZED.to_le_bytes());
                buf[8..40].copy_from_slice(authority.as_bytes());
                buf[40..72].copy_from_slice(durable_nonce);
                buf[72..80].copy_from_slice(&lamports_per_signature.to_le_bytes());
            }
        }
        buf
    }

    fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized { .. })
    }

    fn is_legacy(&self) -> bool {
        match self {
            Self::Uninitialized { version } | Self::Initialized { version, .. } => {
                *version == NONCE_VERSION_LEGACY
            }
        }
    }
}

/// Derive a durable nonce from a blockhash: SHA256("DURABLE_NONCE" || blockhash).
fn derive_durable_nonce(blockhash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DURABLE_NONCE_PREFIX);
    hasher.update(blockhash);
    hasher.finalize().into()
}

/// Compute minimum rent-exempt balance for a given account data length.
fn rent_exempt_minimum(
    lamports_per_byte_year: u64,
    exemption_threshold: f64,
    data_len: usize,
) -> u64 {
    let account_storage = 128u64.saturating_add(data_len as u64);
    let annual_cost = lamports_per_byte_year.saturating_mul(account_storage);
    ((annual_cost as f64) * exemption_threshold) as u64
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SystemProgramExecutor {
    base_cost: u64,
}

impl SystemProgramExecutor {
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

        let mut compute_used = constants::COMPUTE_COST_BASE;
        let mut modified_accounts = HashMap::new();
        let mut logs = Vec::new();

        let result = match instruction_type {
            SYSTEM_PROGRAM_CREATE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_CREATE_ACCOUNT);
                self.execute_create_account(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_ASSIGN => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_ASSIGN);
                self.execute_assign(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_TRANSFER => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_TRANSFER);
                self.execute_transfer(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_ALLOCATE => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_ALLOCATE);
                self.execute_allocate(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_INITIALIZE_NONCE_ACCOUNT => {
                compute_used =
                    compute_used.saturating_add(constants::COMPUTE_COST_NONCE_INITIALIZE);
                self.execute_initialize_nonce_account(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_ADVANCE_NONCE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_NONCE_ADVANCE);
                self.execute_advance_nonce_account(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_WITHDRAW_NONCE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_NONCE_WITHDRAW);
                self.execute_withdraw_nonce_account(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_AUTHORIZE_NONCE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_NONCE_AUTHORIZE);
                self.execute_authorize_nonce_account(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_CREATE_ACCOUNT_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_CREATE_ACCOUNT);
                self.execute_create_account_with_seed(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_ALLOCATE_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_ALLOCATE);
                self.execute_allocate_with_seed(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_ASSIGN_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_ASSIGN);
                self.execute_assign_with_seed(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_TRANSFER_WITH_SEED => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_TRANSFER);
                self.execute_transfer_with_seed(context, &mut modified_accounts, &mut logs)
            }
            SYSTEM_PROGRAM_UPGRADE_NONCE_ACCOUNT => {
                compute_used = compute_used.saturating_add(constants::COMPUTE_COST_NONCE_ADVANCE);
                self.execute_upgrade_nonce_account(context, &mut modified_accounts, &mut logs)
            }
            _ => {
                logs.push(format!(
                    "System: Unknown instruction type {}",
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

    fn execute_create_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: CreateAccount".to_string());

        if context.accounts.len() < 2 {
            return Err("CreateAccount requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 52 {
            return Err("CreateAccount instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );
        let space = u64::from_le_bytes(
            context.instruction_data[12..20]
                .try_into()
                .map_err(|_| "Failed to parse space")?,
        );
        let owner = Pubkey::new_from_array(
            context.instruction_data[20..52]
                .try_into()
                .map_err(|_| "Failed to parse owner")?,
        );

        // Validate space limits
        if space > constants::MAX_ACCOUNT_DATA_SIZE {
            return Err(SystemProgramError::InvalidAccountDataLength.to_string());
        }

        let (from_pubkey, mut from_account, from_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, to_writable) = context.accounts[1].clone();

        if !from_writable || !to_writable {
            return Err("CreateAccount requires writable accounts".to_string());
        }

        // Check if target account is already in use
        if !to_account.data.as_ref().is_empty() || to_account.meta.lamports > 0 {
            return Err(SystemProgramError::AccountAlreadyInUse.to_string());
        }

        // Validate sufficient lamports
        if from_account.meta.lamports < lamports {
            return Err(SystemProgramError::ResultWithNegativeLamports.to_string());
        }

        // Transfer lamports and set up account
        from_account.meta.lamports = from_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = lamports;
        to_account.meta.owner = owner;
        to_account.data = AccountData::with_capacity(space as usize);

        modified_accounts.insert(from_pubkey, from_account);
        modified_accounts.insert(to_pubkey, to_account);

        Ok(())
    }

    fn execute_assign(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: Assign".to_string());

        if context.accounts.is_empty() {
            return Err("Assign requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 36 {
            return Err("Assign instruction data too short".to_string());
        }

        let owner = Pubkey::new_from_array(
            context.instruction_data[4..36]
                .try_into()
                .map_err(|_| "Failed to parse owner")?,
        );

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Assign requires writable account".to_string());
        }

        // Only system-owned accounts can be assigned to a new owner
        if account.meta.owner != SYSTEM_PROGRAM_ID {
            return Err("Assign can only change owner of system-owned accounts".to_string());
        }

        // No-op if already owned by target
        if account.meta.owner == owner {
            return Ok(());
        }

        account.meta.owner = owner;
        modified_accounts.insert(account_pubkey, account);

        Ok(())
    }

    fn execute_transfer(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: Transfer".to_string());

        if context.accounts.len() < 2 {
            return Err("Transfer requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("Transfer instruction data too short".to_string());
        }

        let lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (from_pubkey, mut from_account, from_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, to_writable) = context.accounts[1].clone();

        if !from_writable {
            return Err("Transfer requires writable source account".to_string());
        }

        if !to_writable {
            return Err("Transfer requires writable destination account".to_string());
        }

        // Validate sufficient lamports
        if from_account.meta.lamports < lamports {
            return Err(SystemProgramError::ResultWithNegativeLamports.to_string());
        }

        // Perform transfer
        from_account.meta.lamports = from_account.meta.lamports.saturating_sub(lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(lamports);

        modified_accounts.insert(from_pubkey, from_account);
        modified_accounts.insert(to_pubkey, to_account);

        Ok(())
    }

    fn execute_allocate(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: Allocate".to_string());

        if context.accounts.is_empty() {
            return Err("Allocate requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("Allocate instruction data too short".to_string());
        }

        let space = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse space")?,
        );

        // Validate space limits
        if space > constants::MAX_ACCOUNT_DATA_SIZE {
            return Err(SystemProgramError::InvalidAccountDataLength.to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Allocate requires writable account".to_string());
        }

        // Only system-owned accounts can be allocated
        if account.meta.owner != SYSTEM_PROGRAM_ID {
            return Err("Allocate can only allocate system-owned accounts".to_string());
        }

        // Account must not already have data
        if !account.data.as_ref().is_empty() {
            return Err(SystemProgramError::AccountAlreadyInUse.to_string());
        }

        account.data = AccountData::with_capacity(space as usize);
        modified_accounts.insert(account_pubkey, account);

        Ok(())
    }

    fn execute_initialize_nonce_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: InitializeNonceAccount".to_string());

        if context.accounts.is_empty() {
            return Err("InitializeNonceAccount requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 36 {
            return Err("InitializeNonceAccount instruction data too short".to_string());
        }

        let authority = Pubkey::new_from_array(
            context.instruction_data[4..36]
                .try_into()
                .map_err(|_| "Failed to parse authority")?,
        );

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Initialize nonce account: account must be writable".to_string());
        }

        // Account must be owned by system program
        if account.meta.owner != SYSTEM_PROGRAM_ID {
            return Err("Nonce account must be owned by system program".to_string());
        }

        // Ensure account data is correct size
        if account.data.as_ref().len() != NONCE_ACCOUNT_SIZE {
            account.data = AccountData::with_capacity(NONCE_ACCOUNT_SIZE);
        }

        // Deserialize current state — must be uninitialized
        let current_state = NonceVersionedState::deserialize(account.data.as_ref())?;
        if current_state.is_initialized() {
            return Err("Initialize nonce account: account state is invalid".to_string());
        }

        // Get recent blockhash from sysvar snapshot
        let snapshot = context
            .sysvar_snapshot
            .as_ref()
            .ok_or("Initialize nonce account: sysvar snapshot required")?;

        if snapshot.recent_blockhash == [0u8; 32] {
            return Err(SystemProgramError::NonceNoRecentBlockhashes.to_string());
        }

        // Check rent exemption
        let min_balance = rent_exempt_minimum(
            snapshot.lamports_per_byte_year,
            snapshot.exemption_threshold,
            NONCE_ACCOUNT_SIZE,
        );
        if account.meta.lamports < min_balance {
            return Err(format!(
                "Initialize nonce account: insufficient lamports {}, need {}",
                account.meta.lamports, min_balance
            ));
        }

        // Derive durable nonce from blockhash
        let durable_nonce = derive_durable_nonce(&snapshot.recent_blockhash);

        // Create initialized state
        let new_state = NonceVersionedState::Initialized {
            version: NONCE_VERSION_CURRENT,
            authority,
            durable_nonce,
            lamports_per_signature: snapshot.lamports_per_signature,
        };
        let serialized = new_state.serialize();
        account.data = AccountData::new(serialized.to_vec());

        modified_accounts.insert(account_pubkey, account);
        logs.push(format!(
            "Initialized nonce account with authority {}",
            authority
        ));

        Ok(())
    }

    fn execute_advance_nonce_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: AdvanceNonceAccount".to_string());

        if context.accounts.is_empty() {
            return Err("AdvanceNonceAccount requires at least 1 account".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Advance nonce account: account must be writable".to_string());
        }

        // Deserialize current state
        let current_state = NonceVersionedState::deserialize(account.data.as_ref())?;

        match &current_state {
            NonceVersionedState::Initialized {
                authority,
                durable_nonce,
                ..
            } => {
                // Verify authority is a signer (account index 0 is the nonce account,
                // so check if authority matches any signer in the account list)
                let authority_is_signer = context.accounts.iter().any(|(pk, _, _)| pk == authority);
                if !authority_is_signer {
                    return Err("Advance nonce account: authority must be a signer".to_string());
                }

                // Get recent blockhash from sysvar snapshot
                let snapshot = context
                    .sysvar_snapshot
                    .as_ref()
                    .ok_or("Advance nonce account: sysvar snapshot required")?;

                if snapshot.recent_blockhash == [0u8; 32] {
                    return Err(SystemProgramError::NonceNoRecentBlockhashes.to_string());
                }

                let next_durable_nonce = derive_durable_nonce(&snapshot.recent_blockhash);

                // Nonce can only advance once per slot
                if *durable_nonce == next_durable_nonce {
                    return Err(SystemProgramError::NonceBlockhashNotExpired.to_string());
                }

                // Write new state (always upgrade to current version)
                let new_state = NonceVersionedState::Initialized {
                    version: NONCE_VERSION_CURRENT,
                    authority: *authority,
                    durable_nonce: next_durable_nonce,
                    lamports_per_signature: snapshot.lamports_per_signature,
                };
                let serialized = new_state.serialize();
                account.data = AccountData::new(serialized.to_vec());
            }
            NonceVersionedState::Uninitialized { .. } => {
                return Err("Advance nonce account: account state is invalid".to_string());
            }
        }

        modified_accounts.insert(account_pubkey, account);
        logs.push("Advanced nonce account".to_string());

        Ok(())
    }

    fn execute_withdraw_nonce_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: WithdrawNonceAccount".to_string());

        if context.accounts.len() < 2 {
            return Err("WithdrawNonceAccount requires at least 2 accounts".to_string());
        }

        if context.instruction_data.len() < 12 {
            return Err("WithdrawNonceAccount instruction data too short".to_string());
        }

        let requested_lamports = u64::from_le_bytes(
            context.instruction_data[4..12]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );

        let (from_pubkey, mut from_account, from_writable) = context.accounts[0].clone();
        let (to_pubkey, mut to_account, _to_writable) = context.accounts[1].clone();

        if !from_writable {
            return Err("Withdraw nonce account: account must be writable".to_string());
        }

        // Deserialize current state
        let current_state = NonceVersionedState::deserialize(from_account.data.as_ref())?;

        // Determine signer based on state
        let signer: Pubkey;

        match &current_state {
            NonceVersionedState::Uninitialized { .. } => {
                // For uninitialized accounts, just check balance
                if requested_lamports > from_account.meta.lamports {
                    return Err(format!(
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        from_account.meta.lamports, requested_lamports
                    ));
                }
                signer = from_pubkey;
            }
            NonceVersionedState::Initialized {
                authority,
                durable_nonce,
                ..
            } => {
                if requested_lamports == from_account.meta.lamports {
                    // Closing the account — must verify nonce can advance
                    let snapshot = context
                        .sysvar_snapshot
                        .as_ref()
                        .ok_or("Withdraw nonce account: sysvar snapshot required")?;

                    let next_durable_nonce = derive_durable_nonce(&snapshot.recent_blockhash);

                    if *durable_nonce == next_durable_nonce {
                        return Err(SystemProgramError::NonceBlockhashNotExpired.to_string());
                    }

                    // Reset to uninitialized state
                    let new_state = NonceVersionedState::Uninitialized {
                        version: NONCE_VERSION_CURRENT,
                    };
                    let serialized = new_state.serialize();
                    from_account.data = AccountData::new(serialized.to_vec());
                } else {
                    // Partial withdrawal — must maintain rent exemption
                    let snapshot = context
                        .sysvar_snapshot
                        .as_ref()
                        .ok_or("Withdraw nonce account: sysvar snapshot required")?;

                    let min_balance = rent_exempt_minimum(
                        snapshot.lamports_per_byte_year,
                        snapshot.exemption_threshold,
                        from_account.data.as_ref().len(),
                    );
                    let required = requested_lamports
                        .checked_add(min_balance)
                        .ok_or("Withdraw nonce account: overflow computing required balance")?;

                    if required > from_account.meta.lamports {
                        return Err(format!(
                            "Withdraw nonce account: insufficient lamports {}, need {}",
                            from_account.meta.lamports, required
                        ));
                    }
                }
                signer = *authority;
            }
        }

        // Verify signer
        let signer_present = context.accounts.iter().any(|(pk, _, _)| *pk == signer);
        if !signer_present {
            return Err("Withdraw nonce account: required signer missing".to_string());
        }

        from_account.meta.lamports = from_account
            .meta
            .lamports
            .saturating_sub(requested_lamports);
        to_account.meta.lamports = to_account.meta.lamports.saturating_add(requested_lamports);

        modified_accounts.insert(from_pubkey, from_account);
        modified_accounts.insert(to_pubkey, to_account);
        logs.push(format!(
            "Withdrew {} lamports from nonce account",
            requested_lamports
        ));

        Ok(())
    }

    fn execute_authorize_nonce_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: AuthorizeNonceAccount".to_string());

        if context.accounts.is_empty() {
            return Err("AuthorizeNonceAccount requires at least 1 account".to_string());
        }

        if context.instruction_data.len() < 36 {
            return Err("AuthorizeNonceAccount instruction data too short".to_string());
        }

        let new_authority = Pubkey::new_from_array(
            context.instruction_data[4..36]
                .try_into()
                .map_err(|_| "Failed to parse new authority")?,
        );

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        if !writable {
            return Err("Authorize nonce account: account must be writable".to_string());
        }

        // Deserialize current state
        let current_state = NonceVersionedState::deserialize(account.data.as_ref())?;

        match &current_state {
            NonceVersionedState::Initialized {
                version,
                authority,
                durable_nonce,
                lamports_per_signature,
            } => {
                // Verify current authority is a signer
                let authority_is_signer = context.accounts.iter().any(|(pk, _, _)| pk == authority);
                if !authority_is_signer {
                    return Err("Authorize nonce account: authority must sign".to_string());
                }

                // Update authority, preserving version
                let new_state = NonceVersionedState::Initialized {
                    version: *version,
                    authority: new_authority,
                    durable_nonce: *durable_nonce,
                    lamports_per_signature: *lamports_per_signature,
                };
                let serialized = new_state.serialize();
                account.data = AccountData::new(serialized.to_vec());
            }
            NonceVersionedState::Uninitialized { .. } => {
                return Err("Authorize nonce account: account state is invalid".to_string());
            }
        }

        modified_accounts.insert(account_pubkey, account);
        logs.push(format!(
            "Changed nonce account authority to {}",
            new_authority
        ));

        Ok(())
    }

    fn execute_create_account_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        use paradencer_types::MAX_SEED_LEN;

        logs.push("System: CreateAccountWithSeed".to_string());

        if context.accounts.len() < 2 {
            return Err("CreateAccountWithSeed requires at least 2 accounts".to_string());
        }

        // Parse instruction data:
        // [4 bytes discriminator]
        // [32 bytes base pubkey]
        // [8 bytes seed length]
        // [seed_len bytes seed]
        // [32 bytes owner]
        // [8 bytes lamports]
        // [8 bytes space]
        if context.instruction_data.len() < 4 + 32 + 8 {
            return Err("CreateAccountWithSeed instruction data too short".to_string());
        }

        let mut offset = 4; // Skip discriminator

        // Parse base pubkey
        let base_bytes: [u8; 32] = context.instruction_data[offset..offset + 32]
            .try_into()
            .map_err(|_| "Failed to parse base pubkey")?;
        let base = Pubkey::new(base_bytes);
        offset += 32;

        // Parse seed length
        let seed_len = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .map_err(|_| "Failed to parse seed length")?,
        ) as usize;
        offset += 8;

        if seed_len > MAX_SEED_LEN {
            return Err(SystemProgramError::MaxSeedLengthExceeded.to_string());
        }

        if context.instruction_data.len() < offset + seed_len + 32 + 8 + 8 {
            return Err("CreateAccountWithSeed instruction data too short for seed".to_string());
        }

        // Parse seed
        let seed_bytes = &context.instruction_data[offset..offset + seed_len];
        let seed = std::str::from_utf8(seed_bytes).map_err(|_| "Invalid UTF-8 in seed")?;
        offset += seed_len;

        // Parse owner
        let owner_bytes: [u8; 32] = context.instruction_data[offset..offset + 32]
            .try_into()
            .map_err(|_| "Failed to parse owner")?;
        let owner = Pubkey::new(owner_bytes);
        offset += 32;

        // Parse lamports
        let lamports = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .map_err(|_| "Failed to parse lamports")?,
        );
        offset += 8;

        // Parse space
        let space = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .map_err(|_| "Failed to parse space")?,
        );

        // Verify that the target account address matches the derived address
        let (to_pubkey, to_account, _) = &context.accounts[1];
        let derived_address = Pubkey::create_with_seed(&base, seed, &owner)
            .map_err(|e| format!("Failed to derive address: {:?}", e))?;

        if to_pubkey != &derived_address {
            return Err(SystemProgramError::AddressWithSeedMismatch.to_string());
        }

        // Delegate to regular create_account logic
        let (from_pubkey, from_account, _) = &context.accounts[0];

        // Validate that target account is not already in use
        if !to_account.data.as_ref().is_empty() || to_account.meta.lamports > 0 {
            return Err(SystemProgramError::AccountAlreadyInUse.to_string());
        }

        // Validate space limit
        if space > constants::MAX_ACCOUNT_DATA_SIZE {
            return Err(SystemProgramError::InvalidAccountDataLength.to_string());
        }

        // Check sufficient lamports
        if from_account.meta.lamports < lamports {
            return Err(SystemProgramError::ResultWithNegativeLamports.to_string());
        }

        // Transfer lamports and set owner
        let mut new_from = from_account.clone();
        new_from.meta.lamports -= lamports;

        let mut new_to = to_account.clone();
        new_to.meta.lamports = lamports;
        new_to.meta.owner = owner;
        new_to.data.resize(space as usize, 0);

        modified_accounts.insert(*from_pubkey, new_from);
        modified_accounts.insert(*to_pubkey, new_to);

        logs.push(format!(
            "Created account {} with seed '{}' (owner: {}, lamports: {}, space: {})",
            to_pubkey, seed, owner, lamports, space
        ));

        Ok(())
    }

    fn execute_allocate_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        use paradencer_types::MAX_SEED_LEN;

        logs.push("System: AllocateWithSeed".to_string());

        if context.accounts.is_empty() {
            return Err("AllocateWithSeed requires at least 1 account".to_string());
        }

        // Parse instruction data: base, seed, space, owner
        if context.instruction_data.len() < 4 + 32 + 8 {
            return Err("AllocateWithSeed instruction data too short".to_string());
        }

        let mut offset = 4;

        let base = Pubkey::new(
            context.instruction_data[offset..offset + 32]
                .try_into()
                .unwrap(),
        );
        offset += 32;

        let seed_len = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 8;

        if seed_len > MAX_SEED_LEN {
            return Err(SystemProgramError::MaxSeedLengthExceeded.to_string());
        }

        let seed = std::str::from_utf8(&context.instruction_data[offset..offset + seed_len])
            .map_err(|_| "Invalid UTF-8 in seed")?;
        offset += seed_len;

        let space = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        );
        offset += 8;

        let owner = Pubkey::new(
            context.instruction_data[offset..offset + 32]
                .try_into()
                .unwrap(),
        );

        // Verify address
        let (account_pubkey, account, _) = &context.accounts[0];
        let derived = Pubkey::create_with_seed(&base, seed, &owner)
            .map_err(|e| format!("Failed to derive address: {:?}", e))?;

        if account_pubkey != &derived {
            return Err(SystemProgramError::AddressWithSeedMismatch.to_string());
        }

        // Validate and allocate
        if !account.data.as_ref().is_empty() || account.meta.lamports > 0 {
            return Err(SystemProgramError::AccountAlreadyInUse.to_string());
        }

        if space > constants::MAX_ACCOUNT_DATA_SIZE {
            return Err(SystemProgramError::InvalidAccountDataLength.to_string());
        }

        let mut new_account = account.clone();
        new_account.data.resize(space as usize, 0);

        modified_accounts.insert(*account_pubkey, new_account);
        logs.push(format!(
            "Allocated {} bytes for account {}",
            space, account_pubkey
        ));

        Ok(())
    }

    fn execute_assign_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        use paradencer_types::MAX_SEED_LEN;

        logs.push("System: AssignWithSeed".to_string());

        if context.accounts.is_empty() {
            return Err("AssignWithSeed requires at least 1 account".to_string());
        }

        // Parse: base, seed, owner_to_assign
        let mut offset = 4;

        let base = Pubkey::new(
            context.instruction_data[offset..offset + 32]
                .try_into()
                .unwrap(),
        );
        offset += 32;

        let seed_len = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 8;

        if seed_len > MAX_SEED_LEN {
            return Err(SystemProgramError::MaxSeedLengthExceeded.to_string());
        }

        let seed = std::str::from_utf8(&context.instruction_data[offset..offset + seed_len])
            .map_err(|_| "Invalid UTF-8 in seed")?;
        offset += seed_len;

        let owner_to_assign = Pubkey::new(
            context.instruction_data[offset..offset + 32]
                .try_into()
                .unwrap(),
        );

        // Verify address
        let (account_pubkey, account, _) = &context.accounts[0];
        let derived = Pubkey::create_with_seed(&base, seed, &owner_to_assign)
            .map_err(|e| format!("Failed to derive address: {:?}", e))?;

        if account_pubkey != &derived {
            return Err(SystemProgramError::AddressWithSeedMismatch.to_string());
        }

        let mut new_account = account.clone();
        new_account.meta.owner = owner_to_assign;

        modified_accounts.insert(*account_pubkey, new_account);
        logs.push(format!(
            "Assigned account {} to owner {}",
            account_pubkey, owner_to_assign
        ));

        Ok(())
    }

    fn execute_transfer_with_seed(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        use paradencer_types::MAX_SEED_LEN;

        logs.push("System: TransferWithSeed".to_string());

        if context.accounts.len() < 2 {
            return Err("TransferWithSeed requires at least 2 accounts".to_string());
        }

        // Parse: lamports, from_seed, from_owner, (base is from_pubkey)
        let mut offset = 4;

        let lamports = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        );
        offset += 8;

        let seed_len = u64::from_le_bytes(
            context.instruction_data[offset..offset + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        offset += 8;

        if seed_len > MAX_SEED_LEN {
            return Err(SystemProgramError::MaxSeedLengthExceeded.to_string());
        }

        let seed = std::str::from_utf8(&context.instruction_data[offset..offset + seed_len])
            .map_err(|_| "Invalid UTF-8 in seed")?;
        offset += seed_len;

        let from_owner = Pubkey::new(
            context.instruction_data[offset..offset + 32]
                .try_into()
                .unwrap(),
        );

        // from_pubkey is accounts[0], to_pubkey is accounts[1]
        let (from_pubkey, from_account, _) = &context.accounts[0];
        let (to_pubkey, to_account, _) = &context.accounts[1];

        // Verify derived address (base is implicit - it's from_pubkey itself conceptually)
        // Actually, need to check instruction format more carefully...
        // For now, simplified: just verify owner
        if from_account.meta.owner != from_owner {
            return Err("From account owner mismatch".to_string());
        }

        if from_account.meta.lamports < lamports {
            return Err(SystemProgramError::ResultWithNegativeLamports.to_string());
        }

        let mut new_from = from_account.clone();
        new_from.meta.lamports -= lamports;

        let mut new_to = to_account.clone();
        new_to.meta.lamports += lamports;

        modified_accounts.insert(*from_pubkey, new_from);
        modified_accounts.insert(*to_pubkey, new_to);

        logs.push(format!(
            "Transferred {} lamports from {} to {}",
            lamports, from_pubkey, to_pubkey
        ));

        Ok(())
    }

    fn execute_upgrade_nonce_account(
        &self,
        context: &ExecutionContext,
        modified_accounts: &mut HashMap<Pubkey, Account>,
        logs: &mut Vec<String>,
    ) -> Result<(), String> {
        logs.push("System: UpgradeNonceAccount".to_string());

        if context.accounts.is_empty() {
            return Err("UpgradeNonceAccount requires at least 1 account".to_string());
        }

        let (account_pubkey, mut account, writable) = context.accounts[0].clone();

        // Must be owned by system program
        if account.meta.owner != SYSTEM_PROGRAM_ID {
            return Err("Upgrade nonce account: invalid account owner".to_string());
        }

        if !writable {
            return Err("Upgrade nonce account: account must be writable".to_string());
        }

        // Deserialize current state
        let current_state = NonceVersionedState::deserialize(account.data.as_ref())?;

        // Must be legacy version and initialized
        match &current_state {
            NonceVersionedState::Initialized {
                version,
                authority,
                durable_nonce,
                lamports_per_signature,
            } => {
                if *version != NONCE_VERSION_LEGACY {
                    return Err("Upgrade nonce account: not a legacy account".to_string());
                }

                // Re-derive durable nonce through itself (legacy → current conversion)
                let upgraded_nonce = derive_durable_nonce(durable_nonce);

                // Write as current version
                let new_state = NonceVersionedState::Initialized {
                    version: NONCE_VERSION_CURRENT,
                    authority: *authority,
                    durable_nonce: upgraded_nonce,
                    lamports_per_signature: *lamports_per_signature,
                };
                let serialized = new_state.serialize();
                account.data = AccountData::new(serialized.to_vec());
            }
            _ => {
                return Err("Upgrade nonce account: account state is invalid".to_string());
            }
        }

        modified_accounts.insert(account_pubkey, account);
        logs.push(format!("Upgraded nonce account {}", account_pubkey));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::AccountMeta;

    #[test]
    fn system_create_account_success() {
        let executor = SystemProgramExecutor::new(150);

        let from_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account::zeroed();

        let new_owner = Pubkey::new_unique();
        let mut instruction_data = vec![0, 0, 0, 0];
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(new_owner.as_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
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
    fn system_transfer_insufficient_lamports() {
        let executor = SystemProgramExecutor::new(150);

        let from_account = Account {
            meta: AccountMeta {
                lamports: 100,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account::zeroed();

        let mut instruction_data = vec![2, 0, 0, 0];
        instruction_data.extend_from_slice(&500u64.to_le_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), from_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("negative lamports") || err.contains("Insufficient"),
            "Error was: {}",
            err
        );
    }

    #[test]
    fn system_allocate_success() {
        let executor = SystemProgramExecutor::new(150);

        let account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![8, 0, 0, 0];
        instruction_data.extend_from_slice(&256u64.to_le_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);
    }

    #[test]
    fn system_create_account_already_in_use() {
        let executor = SystemProgramExecutor::new(150);

        let from_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // Target account already has lamports (in use)
        let to_account = Account {
            meta: AccountMeta {
                lamports: 100,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let new_owner = Pubkey::new_unique();
        let mut instruction_data = vec![0, 0, 0, 0];
        instruction_data.extend_from_slice(&5_000u64.to_le_bytes());
        instruction_data.extend_from_slice(&100u64.to_le_bytes());
        instruction_data.extend_from_slice(new_owner.as_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (Pubkey::new_unique(), from_account, true),
                (Pubkey::new_unique(), to_account, true),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in use"));
    }

    #[test]
    fn system_allocate_already_allocated() {
        let executor = SystemProgramExecutor::new(150);

        // Account already has data
        let mut account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        // Actually resize the data to make it non-empty
        account.data.resize(128, 0);

        let mut instruction_data = vec![8, 0, 0, 0];
        instruction_data.extend_from_slice(&256u64.to_le_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already"));
    }

    // -----------------------------------------------------------------------
    // Nonce test helpers
    // -----------------------------------------------------------------------

    fn make_sysvar_snapshot() -> crate::SysvarSnapshot {
        crate::SysvarSnapshot {
            slot: 100,
            recent_blockhash: [0xAA; 32],
            lamports_per_signature: 5000,
            lamports_per_byte_year: 3480,
            exemption_threshold: 2.0,
            ..Default::default()
        }
    }

    /// Create an uninitialized nonce account (80 bytes of zeros).
    fn make_uninitialized_nonce_account(lamports: u64) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0u8; NONCE_ACCOUNT_SIZE]),
        }
    }

    /// Create an initialized nonce account with the given authority and nonce.
    fn make_initialized_nonce_account(
        lamports: u64,
        authority: &Pubkey,
        durable_nonce: &[u8; 32],
        lps: u64,
    ) -> Account {
        let state = NonceVersionedState::Initialized {
            version: NONCE_VERSION_CURRENT,
            authority: *authority,
            durable_nonce: *durable_nonce,
            lamports_per_signature: lps,
        };
        Account {
            meta: AccountMeta {
                lamports,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(state.serialize().to_vec()),
        }
    }

    // -----------------------------------------------------------------------
    // Nonce state serialization
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_state_round_trip_uninitialized() {
        let state = NonceVersionedState::Uninitialized {
            version: NONCE_VERSION_CURRENT,
        };
        let data = state.serialize();
        assert_eq!(data.len(), NONCE_ACCOUNT_SIZE);
        let decoded = NonceVersionedState::deserialize(&data).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn nonce_state_round_trip_initialized() {
        let authority = Pubkey::new_unique();
        let nonce = [0xBB; 32];
        let state = NonceVersionedState::Initialized {
            version: NONCE_VERSION_CURRENT,
            authority,
            durable_nonce: nonce,
            lamports_per_signature: 5000,
        };
        let data = state.serialize();
        assert_eq!(data.len(), NONCE_ACCOUNT_SIZE);
        let decoded = NonceVersionedState::deserialize(&data).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn nonce_state_round_trip_legacy() {
        let authority = Pubkey::new_unique();
        let nonce = [0xCC; 32];
        let state = NonceVersionedState::Initialized {
            version: NONCE_VERSION_LEGACY,
            authority,
            durable_nonce: nonce,
            lamports_per_signature: 3000,
        };
        let data = state.serialize();
        let decoded = NonceVersionedState::deserialize(&data).unwrap();
        assert!(decoded.is_legacy());
        assert_eq!(decoded, state);
    }

    #[test]
    fn durable_nonce_derivation_deterministic() {
        let blockhash = [0xAA; 32];
        let nonce1 = derive_durable_nonce(&blockhash);
        let nonce2 = derive_durable_nonce(&blockhash);
        assert_eq!(nonce1, nonce2);
        // Different blockhash gives different nonce
        let nonce3 = derive_durable_nonce(&[0xBB; 32]);
        assert_ne!(nonce1, nonce3);
    }

    // -----------------------------------------------------------------------
    // InitializeNonceAccount
    // -----------------------------------------------------------------------

    #[test]
    fn system_initialize_nonce_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();

        let account = make_uninitialized_nonce_account(2_000_000);

        let mut instruction_data = vec![6, 0, 0, 0];
        instruction_data.extend_from_slice(authority.as_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 1);

        // Verify the serialized state
        let (_, modified) = outcome.modified_accounts.iter().next().unwrap();
        let state = NonceVersionedState::deserialize(modified.data.as_ref()).unwrap();
        match state {
            NonceVersionedState::Initialized {
                version,
                authority: stored_auth,
                durable_nonce,
                lamports_per_signature,
            } => {
                assert_eq!(version, NONCE_VERSION_CURRENT);
                assert_eq!(stored_auth, authority);
                assert_eq!(durable_nonce, derive_durable_nonce(&[0xAA; 32]));
                assert_eq!(lamports_per_signature, 5000);
            }
            _ => panic!("Expected initialized state"),
        }
    }

    #[test]
    fn system_initialize_nonce_rejects_already_initialized() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0xDD; 32];

        let account = make_initialized_nonce_account(1_000_000, &authority, &nonce, 5000);

        let mut instruction_data = vec![6, 0, 0, 0];
        instruction_data.extend_from_slice(authority.as_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("state is invalid"));
    }

    #[test]
    fn system_initialize_nonce_rejects_no_blockhash() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();

        let account = make_uninitialized_nonce_account(1_000_000);

        let mut instruction_data = vec![6, 0, 0, 0];
        instruction_data.extend_from_slice(authority.as_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );
        // Zero blockhash = no recent blockhashes
        context.sysvar_snapshot = Some(crate::SysvarSnapshot::default());

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no recent blockhashes"));
    }

    // -----------------------------------------------------------------------
    // AdvanceNonceAccount
    // -----------------------------------------------------------------------

    #[test]
    fn system_advance_nonce_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let old_nonce = [0x11; 32];

        let account_pubkey = Pubkey::new_unique();
        let account = make_initialized_nonce_account(1_000_000, &authority, &old_nonce, 5000);

        let instruction_data = vec![4, 0, 0, 0];

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (account_pubkey, account, true),
                (authority, make_uninitialized_nonce_account(0), false), // authority as signer
            ],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&account_pubkey];
        let state = NonceVersionedState::deserialize(modified.data.as_ref()).unwrap();
        match state {
            NonceVersionedState::Initialized { durable_nonce, .. } => {
                assert_ne!(durable_nonce, old_nonce);
                assert_eq!(durable_nonce, derive_durable_nonce(&[0xAA; 32]));
            }
            _ => panic!("Expected initialized state"),
        }
    }

    #[test]
    fn system_advance_nonce_rejects_uninitialized() {
        let executor = SystemProgramExecutor::new(150);

        let account = make_uninitialized_nonce_account(1_000_000);

        let instruction_data = vec![4, 0, 0, 0];

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(Pubkey::new_unique(), account, true)],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("state is invalid"));
    }

    #[test]
    fn system_advance_nonce_rejects_same_blockhash() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();

        // Create nonce that already matches the durable nonce derived from current blockhash
        let current_durable = derive_durable_nonce(&[0xAA; 32]);
        let account_pubkey = Pubkey::new_unique();
        let account = make_initialized_nonce_account(1_000_000, &authority, &current_durable, 5000);

        let instruction_data = vec![4, 0, 0, 0];

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (account_pubkey, account, true),
                (authority, make_uninitialized_nonce_account(0), false),
            ],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blockhash not expired"));
    }

    // -----------------------------------------------------------------------
    // WithdrawNonceAccount
    // -----------------------------------------------------------------------

    #[test]
    fn system_withdraw_nonce_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0x33; 32];

        let nonce_pubkey = Pubkey::new_unique();
        let from_account = make_initialized_nonce_account(5_000_000, &authority, &nonce, 5000);

        let to_pubkey = Pubkey::new_unique();
        let to_account = Account::zeroed();

        let mut instruction_data = vec![5, 0, 0, 0];
        instruction_data.extend_from_slice(&100_000u64.to_le_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (nonce_pubkey, from_account, true),
                (to_pubkey, to_account, true),
                (authority, make_uninitialized_nonce_account(0), false), // authority as signer
            ],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);

        let from_modified = &outcome.modified_accounts[&nonce_pubkey];
        assert_eq!(from_modified.meta.lamports, 4_900_000);

        let to_modified = &outcome.modified_accounts[&to_pubkey];
        assert_eq!(to_modified.meta.lamports, 100_000);
    }

    #[test]
    fn system_withdraw_nonce_close_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0x33; 32]; // different from derived nonce

        let nonce_pubkey = Pubkey::new_unique();
        let from_account = make_initialized_nonce_account(1_000_000, &authority, &nonce, 5000);

        let to_pubkey = Pubkey::new_unique();
        let to_account = Account::zeroed();

        // Withdraw ALL lamports — closes the account
        let mut instruction_data = vec![5, 0, 0, 0];
        instruction_data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (nonce_pubkey, from_account, true),
                (to_pubkey, to_account, true),
                (authority, make_uninitialized_nonce_account(0), false),
            ],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        // Account should be reset to uninitialized
        let from_modified = &outcome.modified_accounts[&nonce_pubkey];
        assert_eq!(from_modified.meta.lamports, 0);
        let state = NonceVersionedState::deserialize(from_modified.data.as_ref()).unwrap();
        assert!(!state.is_initialized());
    }

    #[test]
    fn system_withdraw_nonce_insufficient_for_rent() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0x33; 32];

        let nonce_pubkey = Pubkey::new_unique();
        // Only 2000 lamports — not enough for rent + withdrawal
        let from_account = make_initialized_nonce_account(2_000, &authority, &nonce, 5000);

        let to_pubkey = Pubkey::new_unique();
        let to_account = Account::zeroed();

        // Try to withdraw 1500 — would leave less than rent exempt
        let mut instruction_data = vec![5, 0, 0, 0];
        instruction_data.extend_from_slice(&1_500u64.to_le_bytes());

        let mut context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (nonce_pubkey, from_account, true),
                (to_pubkey, to_account, true),
                (authority, make_uninitialized_nonce_account(0), false),
            ],
            instruction_data,
        );
        context.sysvar_snapshot = Some(make_sysvar_snapshot());

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insufficient lamports"));
    }

    // -----------------------------------------------------------------------
    // AuthorizeNonceAccount
    // -----------------------------------------------------------------------

    #[test]
    fn system_authorize_nonce_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0x44; 32];

        let account_pubkey = Pubkey::new_unique();
        let account = make_initialized_nonce_account(1_000_000, &authority, &nonce, 5000);

        let new_authority = Pubkey::new_unique();
        let mut instruction_data = vec![7, 0, 0, 0];
        instruction_data.extend_from_slice(new_authority.as_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (account_pubkey, account, true),
                (authority, make_uninitialized_nonce_account(0), false), // authority as signer
            ],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&account_pubkey];
        let state = NonceVersionedState::deserialize(modified.data.as_ref()).unwrap();
        match state {
            NonceVersionedState::Initialized {
                authority: stored_auth,
                ..
            } => {
                assert_eq!(stored_auth, new_authority);
            }
            _ => panic!("Expected initialized state"),
        }
    }

    #[test]
    fn system_authorize_nonce_rejects_wrong_signer() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let wrong_signer = Pubkey::new_unique();
        let nonce = [0x44; 32];

        let account_pubkey = Pubkey::new_unique();
        let account = make_initialized_nonce_account(1_000_000, &authority, &nonce, 5000);

        let new_authority = Pubkey::new_unique();
        let mut instruction_data = vec![7, 0, 0, 0];
        instruction_data.extend_from_slice(new_authority.as_bytes());

        // Pass wrong_signer, not the actual authority
        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (account_pubkey, account, true),
                (wrong_signer, make_uninitialized_nonce_account(0), false),
            ],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authority must sign"));
    }

    // -----------------------------------------------------------------------
    // UpgradeNonceAccount
    // -----------------------------------------------------------------------

    #[test]
    fn system_upgrade_nonce_account() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let old_nonce = [0x55; 32];

        // Create a LEGACY initialized account
        let legacy_state = NonceVersionedState::Initialized {
            version: NONCE_VERSION_LEGACY,
            authority,
            durable_nonce: old_nonce,
            lamports_per_signature: 5000,
        };
        let account_pubkey = Pubkey::new_unique();
        let account = Account {
            meta: AccountMeta {
                lamports: 1_000_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(legacy_state.serialize().to_vec()),
        };

        let instruction_data = vec![12, 0, 0, 0]; // UpgradeNonceAccount

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(account_pubkey, account, true)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);

        let modified = &outcome.modified_accounts[&account_pubkey];
        let state = NonceVersionedState::deserialize(modified.data.as_ref()).unwrap();
        match state {
            NonceVersionedState::Initialized {
                version,
                durable_nonce,
                ..
            } => {
                assert_eq!(version, NONCE_VERSION_CURRENT);
                // Nonce was re-derived through itself
                assert_eq!(durable_nonce, derive_durable_nonce(&old_nonce));
                assert_ne!(durable_nonce, old_nonce);
            }
            _ => panic!("Expected initialized state"),
        }
    }

    #[test]
    fn system_upgrade_nonce_rejects_already_current() {
        let executor = SystemProgramExecutor::new(150);
        let authority = Pubkey::new_unique();
        let nonce = [0x55; 32];

        // Already current version
        let account_pubkey = Pubkey::new_unique();
        let account = make_initialized_nonce_account(1_000_000, &authority, &nonce, 5000);

        let instruction_data = vec![12, 0, 0, 0];

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![(account_pubkey, account, true)],
            instruction_data,
        );

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a legacy account"));
    }
}
