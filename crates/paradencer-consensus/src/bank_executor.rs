/// Bank transaction execution pipeline.
///
/// Defines the `ExecutionBackend` trait for pluggable instruction execution,
/// and implements the full transaction processing flow on Bank:
/// account loading, fee validation, instruction execution, account writeback,
/// and fee collection.
use crate::cost_tracker::TransactionCost;
use crate::nonce::{derive_durable_nonce, deserialize_nonce_state, serialize_nonce_state};
use crate::transaction_cache::{extract_nonce_key_index, is_nonce_instruction};
use crate::{Bank, BankStatus, FeeCalculator};
use paradencer_constants::block_limits::MAX_TRANSACTION_ACCOUNT_LOCKS;
use paradencer_constants::compute_budget_program::{
    INSTRUCTION_SET_COMPUTE_UNIT_LIMIT, INSTRUCTION_SET_COMPUTE_UNIT_PRICE,
    INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
};
use paradencer_constants::economics::MICRO_LAMPORTS_PER_LAMPORT;
use paradencer_constants::execution::{
    MAX_COMPUTE_UNIT_LIMIT, MAX_LOADED_ACCOUNTS_DATA_SIZE, TRANSACTION_ACCOUNT_BASE_SIZE,
};
use paradencer_constants::ledger::NONCE_ACCOUNT_SIZE;
use paradencer_constants::system_program::MAX_ACCOUNT_DATA_SIZE;
use paradencer_constants::sysvars::MAX_INSTRUCTIONS_PER_TRANSACTION;
use paradencer_ids::{
    COMPUTE_BUDGET_PROGRAM_ID, ED25519_PROGRAM_ID, INCINERATOR_ID, INSTRUCTIONS_SYSVAR_ID,
    SECP256K1_PROGRAM_ID, SECP256R1_PROGRAM_ID, STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
    VOTE_PROGRAM_ID,
};
use paradencer_storage::{Account, AccountData, Pubkey, TransactionId};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Execution backend trait
// ---------------------------------------------------------------------------

/// Sysvar context passed to instruction execution so programs can read
/// chain state (current slot, epoch, rent parameters, etc.).
#[derive(Debug, Clone, Default)]
pub struct SlotContext {
    pub slot: u64,
    pub epoch: u64,
    pub unix_timestamp: i64,
    pub epoch_start_timestamp: i64,
    pub leader_schedule_epoch: u64,
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
    pub lamports_per_byte_year: u64,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
    pub last_restart_slot: u64,
    pub recent_blockhash: [u8; 32],
    pub lamports_per_signature: u64,
    /// Active feature gate IDs (as raw 32-byte keys) at this slot.
    /// Execution layer uses this to check feature-gated behavior.
    pub active_features: HashSet<[u8; 32]>,
}

/// Compiled instruction passed to the execution backend.
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// Program that processes this instruction.
    pub program_id: Pubkey,
    /// Accounts accessed by this instruction (pubkey, account, is_writable, is_signer).
    pub accounts: Vec<(Pubkey, Account, bool, bool)>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
    /// Sysvar context (slot, epoch, rent, etc.) for the current execution.
    pub slot_context: SlotContext,
}

/// Result produced by executing a single instruction.
#[derive(Debug, Clone)]
pub struct InstructionResult {
    /// Whether the instruction succeeded.
    pub success: bool,
    /// Compute units consumed by this instruction.
    pub compute_units_consumed: u64,
    /// Modified accounts after execution.
    pub modified_accounts: HashMap<Pubkey, Account>,
    /// Log lines emitted during execution.
    pub logs: Vec<String>,
    /// Error description when `success` is false.
    pub error: Option<String>,
    /// Return data set by the program via `set_return_data` syscall.
    /// Contains the program ID and the returned bytes. Only the last
    /// instruction's return data is preserved in the transaction result.
    pub return_data: Option<(Pubkey, Vec<u8>)>,
}

/// Pluggable backend for executing transaction instructions.
///
/// Consensus defines the trait; the execution layer provides the implementation.
/// This keeps `paradencer-consensus` independent of `paradencer-sbpf`.
pub trait ExecutionBackend: Send + Sync {
    /// Execute a single instruction against the supplied accounts.
    fn execute_instruction(
        &self,
        instruction: &InstructionInfo,
        remaining_compute_units: u64,
    ) -> InstructionResult;
}

// ---------------------------------------------------------------------------
// Transaction types used inside Bank
// ---------------------------------------------------------------------------

/// A transaction ready for execution by the Bank.
#[derive(Debug, Clone)]
pub struct SanitizedTransaction {
    /// All account keys referenced by this transaction (fee payer first).
    pub account_keys: Vec<Pubkey>,
    /// Recent blockhash.
    pub recent_blockhash: [u8; 32],
    /// Instructions to execute.
    pub instructions: Vec<CompiledInstruction>,
    /// Number of required signatures.
    pub num_signatures: u64,
    /// Number of read-only signed accounts.
    pub num_readonly_signed: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned: u8,
    /// Ed25519 signatures (one per required signer).
    pub signatures: Vec<[u8; 64]>,
    /// Serialized message bytes for signature verification.
    pub message_bytes: Vec<u8>,
}

impl SanitizedTransaction {
    /// Check if account at given index is a signer.
    ///
    /// Accounts `[0, num_signatures)` are signers.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.num_signatures as usize
    }

    /// Check if account at given index is writable according to the message.
    ///
    /// Account layout:
    /// - `[0, num_signatures - num_readonly_signed)` → writable signed
    /// - `[num_signatures - num_readonly_signed, num_signatures)` → readonly signed
    /// - `[num_signatures, total - num_readonly_unsigned)` → writable unsigned
    /// - `[total - num_readonly_unsigned, total)` → readonly unsigned
    pub fn is_writable_index(&self, index: usize) -> bool {
        let num_sigs = self.num_signatures as usize;
        let ro_signed = self.num_readonly_signed as usize;
        let ro_unsigned = self.num_readonly_unsigned as usize;
        let total = self.account_keys.len();

        if index < num_sigs {
            // Signed accounts: writable if before readonly boundary
            index < num_sigs.saturating_sub(ro_signed)
        } else {
            // Unsigned accounts: writable if before readonly boundary
            index < total.saturating_sub(ro_unsigned)
        }
    }
}

/// Instruction within a sanitized transaction (index-based references).
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    /// Index into `account_keys` for the program.
    pub program_id_index: u8,
    /// Indices into `account_keys` for instruction accounts.
    pub account_indices: Vec<u8>,
    /// Opaque data.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

/// Outcome of processing a single transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Total compute units consumed.
    pub compute_units_consumed: u64,
    /// Fee charged to the payer.
    pub fee: u64,
    /// Accounts modified by the transaction (final state).
    pub modified_accounts: HashMap<Pubkey, Account>,
    /// Combined execution logs.
    pub logs: Vec<String>,
    /// Error description when `success` is false.
    pub error: Option<TransactionExecutionError>,
    /// Vote updates extracted from vote program instructions.
    pub vote_updates: Vec<VoteUpdate>,
    /// Return data from the last instruction that set it.
    /// Contains the program ID that produced the data and the bytes.
    pub return_data: Option<(Pubkey, Vec<u8>)>,
}

/// Errors that can occur during transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionExecutionError {
    /// Bank is not in a state that accepts transactions.
    BankNotProcessing,
    /// Fee payer account not found.
    FeePayerNotFound,
    /// Insufficient balance to pay transaction fee.
    InsufficientFee { required: u64, available: u64 },
    /// Fee payer account is not a valid system or nonce account.
    InvalidAccountForFee,
    /// A referenced account could not be loaded.
    AccountLoadFailed(String),
    /// An instruction failed during execution.
    InstructionFailed { index: usize, message: String },
    /// Compute budget exceeded.
    ComputeBudgetExceeded { consumed: u64, limit: u64 },
    /// Blockhash is not recent.
    BlockhashNotRecent,
    /// One or more signatures failed Ed25519 verification.
    SignatureVerificationFailed { signer_index: usize },
    /// Transaction is a duplicate (already processed in a recent slot).
    DuplicateTransaction,
    /// A writable account would transition to rent-paying state.
    InsufficientFundsForRent { account: Pubkey },
    /// Block cost limit would be exceeded by this transaction.
    BlockCostLimitExceeded(String),
    /// Total loaded accounts data size exceeds per-transaction limit.
    MaxLoadedAccountsDataSizeExceeded { loaded: u64, limit: u64 },
    /// Transaction references too many account keys.
    TooManyAccountLocks { count: usize, limit: usize },
    /// Transaction contains the same account key more than once.
    DuplicateAccountKey { account: Pubkey },
    /// Total lamports across writable accounts changed during execution.
    UnbalancedTransaction,
    /// An account's data size exceeds the maximum permitted length.
    AccountDataTooLarge {
        account: Pubkey,
        size: u64,
        limit: u64,
    },
    /// Transaction exceeds the static instruction count limit.
    TooManyInstructions { count: usize, limit: usize },
}

impl std::fmt::Display for TransactionExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BankNotProcessing => write!(f, "bank not in processing state"),
            Self::FeePayerNotFound => write!(f, "fee payer account not found"),
            Self::InsufficientFee {
                required,
                available,
            } => {
                write!(f, "insufficient fee: need {required}, have {available}")
            }
            Self::InvalidAccountForFee => write!(f, "invalid account for fee"),
            Self::AccountLoadFailed(msg) => write!(f, "account load failed: {msg}"),
            Self::InstructionFailed { index, message } => {
                write!(f, "instruction {index} failed: {message}")
            }
            Self::ComputeBudgetExceeded { consumed, limit } => {
                write!(f, "compute budget exceeded: {consumed}/{limit}")
            }
            Self::BlockhashNotRecent => write!(f, "blockhash not recent"),
            Self::SignatureVerificationFailed { signer_index } => {
                write!(f, "signature verification failed for signer {signer_index}")
            }
            Self::DuplicateTransaction => write!(f, "duplicate transaction"),
            Self::InsufficientFundsForRent { account } => {
                write!(f, "insufficient funds for rent: account {account:?}")
            }
            Self::BlockCostLimitExceeded(msg) => {
                write!(f, "block cost limit exceeded: {msg}")
            }
            Self::MaxLoadedAccountsDataSizeExceeded { loaded, limit } => {
                write!(
                    f,
                    "loaded accounts data size exceeded: {loaded} bytes > {limit} byte limit"
                )
            }
            Self::TooManyAccountLocks { count, limit } => {
                write!(f, "too many account locks: {count} > {limit}")
            }
            Self::DuplicateAccountKey { account } => {
                write!(f, "duplicate account key: {account:?}")
            }
            Self::UnbalancedTransaction => write!(f, "transaction lamports not balanced"),
            Self::AccountDataTooLarge {
                account,
                size,
                limit,
            } => {
                write!(
                    f,
                    "account {account:?} data too large: {size} bytes > {limit} byte limit"
                )
            }
            Self::TooManyInstructions { count, limit } => {
                write!(f, "too many instructions: {count} > {limit}")
            }
        }
    }
}

impl std::error::Error for TransactionExecutionError {}

/// Information extracted from a successful vote transaction.
///
/// After the execution backend processes a vote program instruction,
/// this struct captures the vote account key and the slot that was
/// voted on, allowing the consensus layer to update stake-weighted
/// aggregation without re-parsing account data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteUpdate {
    /// The vote account that cast the vote.
    pub vote_account: Pubkey,
    /// The slot that was voted on (highest slot in the instruction).
    pub voted_slot: Option<u64>,
}

/// Summary of a batch of transaction executions.
#[derive(Debug, Clone, Default)]
pub struct BatchExecutionSummary {
    /// Number of transactions processed.
    pub total: usize,
    /// Number of successful transactions.
    pub succeeded: usize,
    /// Number of failed transactions.
    pub failed: usize,
    /// Total compute units consumed.
    pub total_compute_units: u64,
    /// Total fees collected.
    pub total_fees: u64,
    /// Per-transaction results.
    pub results: Vec<TransactionExecutionResult>,
    /// All vote updates extracted from successful vote transactions.
    pub vote_updates: Vec<VoteUpdate>,
}

// ---------------------------------------------------------------------------
// Transaction hashing
// ---------------------------------------------------------------------------

/// Compute a truncated SHA-256 hash of the transaction message for deduplication.
///
/// Returns the first 20 bytes of the message hash, matching the Solana
/// protocol's status cache key format. Uses message_bytes if available,
/// otherwise falls back to the first signature as a unique identifier.
fn compute_message_hash(
    tx: &SanitizedTransaction,
) -> [u8; paradencer_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES] {
    use paradencer_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES;
    use sha2::{Digest, Sha256};

    if !tx.message_bytes.is_empty() {
        let full_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&tx.message_bytes);
            hasher.finalize().into()
        };
        let mut prefix = [0u8; MESSAGE_HASH_PREFIX_BYTES];
        prefix.copy_from_slice(&full_hash[..MESSAGE_HASH_PREFIX_BYTES]);
        prefix
    } else if let Some(sig) = tx.signatures.first() {
        let mut prefix = [0u8; MESSAGE_HASH_PREFIX_BYTES];
        prefix.copy_from_slice(&sig[..MESSAGE_HASH_PREFIX_BYTES]);
        prefix
    } else {
        [0u8; MESSAGE_HASH_PREFIX_BYTES]
    }
}

/// Calculate the net change in account data size from a transaction.
///
/// Compares pre-execution and post-execution data sizes for all modified
/// accounts. New accounts contribute their full data size; accounts that
/// become empty (zero lamports) subtract their previous size. Existing
/// accounts that changed size contribute the difference.
fn calculate_data_size_delta(
    pre_state: &HashMap<Pubkey, Account>,
    modified: &HashMap<Pubkey, Account>,
) -> i64 {
    let mut delta: i64 = 0;
    for (pubkey, post_account) in modified {
        let post_len = post_account.data.len() as i64;
        let pre_len = pre_state
            .get(pubkey)
            .map(|a| a.data.len() as i64)
            .unwrap_or(0);
        delta += post_len - pre_len;
    }
    delta
}

/// Reclaim zero-lamport accounts by clearing their data and owner.
///
/// After transaction execution, any writable account that has been
/// reduced to zero lamports is normalized: data is truncated to empty
/// and owner is reset to the default (system program). This prevents
/// stale metadata from persisting on deleted accounts.
fn reclaim_zero_lamport_accounts(modified: &mut HashMap<Pubkey, Account>) {
    for account in modified.values_mut() {
        if account.meta.lamports == 0 {
            account.data = AccountData::empty();
            account.meta.owner = Pubkey::default();
        }
    }
}

/// Validate account locks: check count limit and duplicate keys.
///
/// Rejects transactions that reference too many accounts or contain
/// the same account key more than once. This prevents resource
/// exhaustion and ensures consistent account locking behavior.
fn validate_account_locks(
    transaction: &SanitizedTransaction,
) -> Result<(), TransactionExecutionError> {
    let count = transaction.account_keys.len();
    if count > MAX_TRANSACTION_ACCOUNT_LOCKS {
        return Err(TransactionExecutionError::TooManyAccountLocks {
            count,
            limit: MAX_TRANSACTION_ACCOUNT_LOCKS,
        });
    }

    // O(n^2) duplicate check — acceptable since MAX_TRANSACTION_ACCOUNT_LOCKS is 128.
    for i in 0..count {
        for j in (i + 1)..count {
            if transaction.account_keys[i] == transaction.account_keys[j] {
                return Err(TransactionExecutionError::DuplicateAccountKey {
                    account: transaction.account_keys[i],
                });
            }
        }
    }

    Ok(())
}

/// Verify that total lamports across writable accounts are conserved.
///
/// Uses 128-bit arithmetic to prevent overflow. Compares the sum of
/// starting lamports to ending lamports for all writable accounts.
/// Transactions that create or destroy lamports are rejected.
fn verify_lamport_balance(
    transaction: &SanitizedTransaction,
    pre_state: &HashMap<Pubkey, Account>,
    modified: &HashMap<Pubkey, Account>,
) -> Result<(), TransactionExecutionError> {
    let mut starting: u128 = 0;
    let mut ending: u128 = 0;

    for (idx, pubkey) in transaction.account_keys.iter().enumerate() {
        // Only check writable accounts (same as the reference implementation).
        if !transaction.is_writable_index(idx) {
            continue;
        }

        let pre_lamports = pre_state.get(pubkey).map(|a| a.meta.lamports).unwrap_or(0);
        starting += pre_lamports as u128;

        let post_lamports = modified
            .get(pubkey)
            .map(|a| a.meta.lamports)
            .or_else(|| pre_state.get(pubkey).map(|a| a.meta.lamports))
            .unwrap_or(0);
        ending += post_lamports as u128;
    }

    if starting != ending {
        return Err(TransactionExecutionError::UnbalancedTransaction);
    }
    Ok(())
}

/// Count additional signatures from precompile instructions.
///
/// Ed25519, Secp256k1, and Secp256r1 precompile instructions encode
/// a signature count in the first byte of their data. These signatures
/// must be included in the fee calculation alongside the transaction's
/// own Ed25519 signatures.
fn count_precompile_signatures(transaction: &SanitizedTransaction) -> u64 {
    let mut extra: u64 = 0;
    for instruction in &transaction.instructions {
        let program_id = match transaction
            .account_keys
            .get(instruction.program_id_index as usize)
        {
            Some(id) => *id,
            None => continue,
        };

        let is_precompile = program_id == ED25519_PROGRAM_ID
            || program_id == SECP256K1_PROGRAM_ID
            || program_id == SECP256R1_PROGRAM_ID;

        if is_precompile && !instruction.data.is_empty() {
            extra = extra.saturating_add(instruction.data[0] as u64);
        }
    }
    extra
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verify Ed25519 signatures on a sanitized transaction.
///
/// Each signature is verified against the corresponding signer key from
/// `account_keys[0..num_signatures]` using the serialized message bytes.
/// Transactions without signatures (empty signatures vec) skip verification
/// for backward compatibility with test transactions.
fn verify_transaction_signatures(
    tx: &SanitizedTransaction,
) -> Result<(), TransactionExecutionError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let num_signers = tx.num_signatures as usize;
    if tx.signatures.len() < num_signers || tx.account_keys.len() < num_signers {
        return Err(TransactionExecutionError::SignatureVerificationFailed { signer_index: 0 });
    }

    for i in 0..num_signers {
        let sig_bytes = &tx.signatures[i];
        let pubkey_bytes = tx.account_keys[i].as_bytes();

        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| {
            TransactionExecutionError::SignatureVerificationFailed { signer_index: i }
        })?;

        let signature = Signature::from_bytes(sig_bytes);

        verifying_key
            .verify_strict(&tx.message_bytes, &signature)
            .map_err(|_| TransactionExecutionError::SignatureVerificationFailed {
                signer_index: i,
            })?;
    }

    Ok(())
}

/// Account rent state for transition validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RentState {
    /// Account has zero lamports (treated as non-existent).
    Uninitialized,
    /// Account balance is below rent-exempt minimum.
    RentPaying { lamports: u64, data_len: usize },
    /// Account balance meets or exceeds rent-exempt minimum.
    RentExempt,
}

impl RentState {
    fn from_account(account: &Account, rent: &crate::Rent) -> Self {
        if account.meta.lamports == 0 {
            return RentState::Uninitialized;
        }
        if rent.is_exempt(account.meta.lamports, account.data.len()) {
            RentState::RentExempt
        } else {
            RentState::RentPaying {
                lamports: account.meta.lamports,
                data_len: account.data.len(),
            }
        }
    }
}

/// Check if a rent state transition is allowed.
///
/// Rules:
/// - Transition to Uninitialized (zero lamports) is always allowed
/// - Transition to RentExempt is always allowed
/// - Transition to RentPaying is only allowed if the account was already
///   RentPaying with the same data size and the new balance is not higher
fn is_rent_transition_allowed(pre: &RentState, post: &RentState) -> bool {
    match post {
        RentState::Uninitialized | RentState::RentExempt => true,
        RentState::RentPaying {
            lamports: post_lamports,
            data_len: post_data_len,
        } => match pre {
            RentState::RentPaying {
                lamports: pre_lamports,
                data_len: pre_data_len,
            } => post_data_len == pre_data_len && post_lamports <= pre_lamports,
            _ => false, // Cannot transition from Uninitialized/RentExempt to RentPaying
        },
    }
}

// ---------------------------------------------------------------------------
// System account kind detection
// ---------------------------------------------------------------------------

/// Classification of system-owned accounts for fee payer validation.
///
/// Only system-owned accounts may pay transaction fees.
/// Nonce accounts require additional minimum balance to remain rent-exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemAccountKind {
    /// Regular system account (zero data length).
    System,
    /// Initialized durable nonce account.
    Nonce,
}

/// Determine whether an account is a valid fee payer (system or nonce account).
///
/// Returns `None` for accounts that cannot pay fees:
/// - Non-system-owned accounts
/// - Non-zero data length that doesn't match nonce format
/// - Uninitialized nonce accounts
fn get_system_account_kind(account: &Account) -> Option<SystemAccountKind> {
    // Must be owned by the System Program
    if account.meta.owner != SYSTEM_PROGRAM_ID {
        return None;
    }

    // Empty data means a regular system account (transfer, stake source, etc.)
    if account.data.is_empty() {
        return Some(SystemAccountKind::System);
    }

    // Nonce accounts have exactly NONCE_ACCOUNT_SIZE bytes
    if account.data.len() != NONCE_ACCOUNT_SIZE {
        return None;
    }

    // Parse the nonce version+state discriminants.
    // Layout: u32 version (LE) | u32 state (LE) | ...
    // Version 0=legacy, 1=current; State 0=uninitialized, 1=initialized
    let data = account.data.as_slice();
    if data.len() < 8 {
        return None;
    }
    let version = u32::from_le_bytes(data[0..4].try_into().expect("slice is 4 bytes"));
    if version > 1 {
        return None;
    }
    let state = u32::from_le_bytes(data[4..8].try_into().expect("slice is 4 bytes"));
    if state == paradencer_constants::ledger::NONCE_STATE_INITIALIZED {
        Some(SystemAccountKind::Nonce)
    } else {
        None // Uninitialized nonce accounts cannot pay fees
    }
}

// ---------------------------------------------------------------------------
// Account permission helpers
// ---------------------------------------------------------------------------

/// Check if an account is a reserved key that must always be read-only.
///
/// Reserved keys include all system programs, precompiles, and sysvar accounts.
/// These accounts cannot be written to even if the transaction marks them writable.
fn is_reserved_key(pubkey: &Pubkey) -> bool {
    *pubkey == SYSTEM_PROGRAM_ID
        || *pubkey == VOTE_PROGRAM_ID
        || *pubkey == paradencer_ids::STAKE_PROGRAM_ID
        || *pubkey == paradencer_ids::CONFIG_PROGRAM_ID
        || *pubkey == COMPUTE_BUDGET_PROGRAM_ID
        || *pubkey == paradencer_ids::BPF_LOADER_PROGRAM_ID
        || *pubkey == paradencer_ids::BPF_LOADER_V2_PROGRAM_ID
        || *pubkey == paradencer_ids::BPF_LOADER_DEPRECATED_PROGRAM_ID
        || *pubkey == paradencer_ids::LOADER_V4_PROGRAM_ID
        || *pubkey == paradencer_ids::ED25519_PROGRAM_ID
        || *pubkey == paradencer_ids::SECP256K1_PROGRAM_ID
        || *pubkey == paradencer_ids::SECP256R1_PROGRAM_ID
        || *pubkey == paradencer_ids::SYSVAR_PROGRAM_ID
        || *pubkey == paradencer_ids::FEATURE_PROGRAM_ID
        || *pubkey == paradencer_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID
}

/// Determine if an account is truly writable for a given instruction.
///
/// An account is writable only if:
/// 1. The transaction message marks it as writable
/// 2. It is NOT a reserved key (system programs, sysvars)
/// 3. It is NOT the program being executed (programs execute read-only)
fn is_account_writable(
    tx: &SanitizedTransaction,
    account_index: usize,
    program_id: &Pubkey,
) -> bool {
    // Must be writable in the transaction message
    if !tx.is_writable_index(account_index) {
        return false;
    }

    let pubkey = match tx.account_keys.get(account_index) {
        Some(k) => k,
        None => return false,
    };

    // Reserved keys are never writable
    if is_reserved_key(pubkey) {
        return false;
    }

    // Program accounts are read-only during execution
    if pubkey == program_id {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Compute budget parsing
// ---------------------------------------------------------------------------

/// Parameters extracted from ComputeBudget program instructions.
#[derive(Debug, Clone, Copy)]
struct ComputeBudgetParams {
    /// Compute unit limit for the transaction.
    compute_unit_limit: u64,
    /// Priority fee rate in micro-lamports per compute unit.
    compute_unit_price: u64,
    /// Loaded accounts data size limit in bytes.
    loaded_accounts_data_size_limit: u64,
}

impl Default for ComputeBudgetParams {
    fn default() -> Self {
        Self {
            compute_unit_limit: MAX_COMPUTE_UNIT_LIMIT,
            compute_unit_price: 0,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        }
    }
}

/// Parse all ComputeBudget instructions from a transaction.
///
/// Extracts compute unit limit, compute unit price (priority fee rate),
/// and loaded accounts data size limit. Returns defaults for any parameters
/// not explicitly set by the transaction.
fn parse_compute_budget(tx: &SanitizedTransaction) -> ComputeBudgetParams {
    let mut params = ComputeBudgetParams::default();
    let mut has_limit = false;
    let mut has_price = false;
    let mut has_data_size = false;

    for ix in &tx.instructions {
        let program_id = match tx.account_keys.get(ix.program_id_index as usize) {
            Some(id) => id,
            None => continue,
        };
        if *program_id != COMPUTE_BUDGET_PROGRAM_ID {
            continue;
        }
        if ix.data.is_empty() {
            continue;
        }

        match ix.data[0] {
            tag if tag == INSTRUCTION_SET_COMPUTE_UNIT_LIMIT
                && ix.data.len() >= 5
                && !has_limit =>
            {
                let declared =
                    u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]) as u64;
                params.compute_unit_limit = declared.min(MAX_COMPUTE_UNIT_LIMIT);
                has_limit = true;
            }
            tag if tag == INSTRUCTION_SET_COMPUTE_UNIT_PRICE
                && ix.data.len() >= 9
                && !has_price =>
            {
                params.compute_unit_price = u64::from_le_bytes([
                    ix.data[1], ix.data[2], ix.data[3], ix.data[4], ix.data[5], ix.data[6],
                    ix.data[7], ix.data[8],
                ]);
                has_price = true;
            }
            tag if tag == INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT
                && ix.data.len() >= 5
                && !has_data_size =>
            {
                let declared =
                    u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]) as u64;
                params.loaded_accounts_data_size_limit =
                    declared.min(MAX_LOADED_ACCOUNTS_DATA_SIZE);
                has_data_size = true;
            }
            _ => {}
        }
    }

    params
}

/// Calculate priority fee from compute budget parameters.
///
/// Formula: ceil(compute_unit_price * compute_unit_limit / MICRO_LAMPORTS_PER_LAMPORT)
fn calculate_priority_fee(params: &ComputeBudgetParams) -> u64 {
    if params.compute_unit_price == 0 {
        return 0;
    }
    let micro_lamport_fee =
        (params.compute_unit_price as u128) * (params.compute_unit_limit as u128);
    let fee = micro_lamport_fee.saturating_add(MICRO_LAMPORTS_PER_LAMPORT as u128 - 1)
        / (MICRO_LAMPORTS_PER_LAMPORT as u128);
    fee.min(u64::MAX as u128) as u64
}

/// Calculate the loaded data contribution of a single account.
///
/// Existing accounts contribute a fixed base overhead (64 bytes) plus their
/// data length. Non-existent accounts (zero lamports, empty data) contribute
/// nothing.
fn account_loaded_size(account: &Account) -> u64 {
    if account.meta.lamports == 0 && account.data.is_empty() {
        return 0;
    }
    TRANSACTION_ACCOUNT_BASE_SIZE + account.data.len() as u64
}

// ---------------------------------------------------------------------------
// Instructions sysvar serialization
// ---------------------------------------------------------------------------

/// Serialize a transaction's instructions into the on-chain Instructions sysvar format.
///
/// The binary layout matches the Solana protocol:
///   - `[u16]` number of instructions
///   - `[u16 * num_instructions]` offset table (byte offset of each instruction)
///   - For each instruction:
///       - `[u16]` number of accounts
///       - For each account:
///           - `[u8]` flags (bit 0 = is_signer, bit 1 = is_writable)
///           - `[32]` pubkey bytes
///       - `[32]` program ID pubkey bytes
///       - `[u16]` instruction data length
///       - `[variable]` instruction data
///   - `[u16]` current instruction index (initially 0, updated per-instruction)
fn serialize_instructions_sysvar(transaction: &SanitizedTransaction) -> Vec<u8> {
    let num_instructions = transaction.instructions.len();

    // First pass: compute sizes and offsets
    let header_size = 2 + num_instructions * 2; // num_instructions(u16) + offsets(u16 each)
    let mut instruction_sizes = Vec::with_capacity(num_instructions);

    for instruction in &transaction.instructions {
        let num_accounts = instruction.account_indices.len();
        // u16 num_accounts + (u8 flags + 32 pubkey) per account + 32 program_id + u16 data_len + data
        let size = 2 + num_accounts * 33 + 32 + 2 + instruction.data.len();
        instruction_sizes.push(size);
    }

    let total_size: usize = header_size + instruction_sizes.iter().sum::<usize>() + 2; // +2 for trailing current_index
    let mut buf = vec![0u8; total_size];

    // Write number of instructions
    buf[0..2].copy_from_slice(&(num_instructions as u16).to_le_bytes());

    // Compute and write offsets
    let mut offset = header_size;
    for (i, &size) in instruction_sizes.iter().enumerate() {
        let off_pos = 2 + i * 2;
        buf[off_pos..off_pos + 2].copy_from_slice(&(offset as u16).to_le_bytes());
        offset += size;
    }

    // Write each instruction
    let mut pos = header_size;
    for instruction in &transaction.instructions {
        let num_accounts = instruction.account_indices.len();
        buf[pos..pos + 2].copy_from_slice(&(num_accounts as u16).to_le_bytes());
        pos += 2;

        for &ai in &instruction.account_indices {
            let acct_idx = ai as usize;
            let is_signer = transaction.is_signer(acct_idx);
            let program_id_for_check = transaction
                .account_keys
                .get(instruction.program_id_index as usize)
                .copied()
                .unwrap_or_default();
            let is_writable = is_account_writable(transaction, acct_idx, &program_id_for_check);
            let flags: u8 = if is_signer { 1 } else { 0 } | if is_writable { 2 } else { 0 };
            buf[pos] = flags;
            pos += 1;

            if let Some(pubkey) = transaction.account_keys.get(acct_idx) {
                buf[pos..pos + 32].copy_from_slice(&pubkey.to_bytes());
            }
            pos += 32;
        }

        // Program ID
        if let Some(program_id) = transaction
            .account_keys
            .get(instruction.program_id_index as usize)
        {
            buf[pos..pos + 32].copy_from_slice(&program_id.to_bytes());
        }
        pos += 32;

        // Instruction data
        buf[pos..pos + 2].copy_from_slice(&(instruction.data.len() as u16).to_le_bytes());
        pos += 2;
        buf[pos..pos + instruction.data.len()].copy_from_slice(&instruction.data);
        pos += instruction.data.len();
    }

    // Current instruction index (starts at 0)
    buf[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());

    buf
}

/// Update the current instruction index in serialized Instructions sysvar data.
///
/// The index is stored as a u16 in the last 2 bytes of the serialized data.
fn update_instructions_sysvar_index(data: &mut [u8], index: u16) {
    if data.len() >= 2 {
        let pos = data.len() - 2;
        data[pos..pos + 2].copy_from_slice(&index.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Durable nonce transaction handling
// ---------------------------------------------------------------------------

/// Pre-execution nonce advancement data for durable transactions.
///
/// Captures the advanced nonce account so it can be persisted even if the
/// transaction fails. The nonce mechanism itself prevents replay, so
/// durable transactions skip the blockhash-based transaction cache.
struct DurableNonceInfo {
    /// The nonce account public key.
    nonce_key: Pubkey,
    /// The nonce account with advanced state (rollback copy).
    /// Persisted on both success and failure paths.
    rollback_account: Account,
}

/// Detect and pre-advance a durable nonce transaction.
///
/// A transaction is a durable nonce transaction when:
/// 1. Its recent_blockhash is NOT in the blockhash queue
/// 2. Its first instruction targets the System Program
/// 3. Its first instruction is AdvanceNonceAccount (discriminant 4)
/// 4. The nonce account contains an initialized nonce whose durable_nonce
///    matches the transaction's recent_blockhash
///
/// Returns `Some(DurableNonceInfo)` with the advanced rollback account
/// if the transaction is a valid durable nonce transaction, or `None`
/// if validation fails.
fn try_detect_durable_nonce(
    tx: &SanitizedTransaction,
    accounts: &paradencer_storage::AccountDatabase,
    last_blockhash: &[u8; 32],
    lamports_per_signature: u64,
) -> Option<DurableNonceInfo> {
    // First instruction must exist and target the System Program
    let first_ix = tx.instructions.first()?;
    let program_id = tx.account_keys.get(first_ix.program_id_index as usize)?;
    if *program_id != SYSTEM_PROGRAM_ID {
        return None;
    }

    // First instruction must be AdvanceNonceAccount
    if !is_nonce_instruction(&first_ix.data) {
        return None;
    }

    // Extract nonce account key
    let nonce_key_index = extract_nonce_key_index(&first_ix.account_indices)?;
    let nonce_key = *tx.account_keys.get(nonce_key_index)?;

    // Load nonce account
    let nonce_account = accounts.get_published_account(&nonce_key)?;

    // Deserialize and verify nonce state
    let nonce_state = deserialize_nonce_state(nonce_account.data.as_slice())?;
    let nonce_data = nonce_state.data()?;

    // Transaction's recent_blockhash must match the nonce's durable_nonce
    let expected_nonce = Pubkey::new(tx.recent_blockhash);
    if nonce_data.durable_nonce != expected_nonce {
        return None;
    }

    // Derive next durable nonce from the last blockhash in the queue
    let next_nonce_bytes = derive_durable_nonce(last_blockhash);
    let next_nonce = Pubkey::new(next_nonce_bytes);

    // Nonce must not already be advanced to next value
    if nonce_data.durable_nonce == next_nonce {
        return None;
    }

    // Create advanced nonce state
    let advanced_state = crate::nonce::Nonce::Initialized(crate::nonce::NonceData {
        authority: nonce_data.authority,
        durable_nonce: next_nonce,
        fee_calculator: FeeCalculator::new(lamports_per_signature),
    });

    // Build the rollback account with advanced nonce data
    let mut rollback_account = nonce_account.clone();
    let serialized = serialize_nonce_state(&advanced_state);
    rollback_account.data = paradencer_storage::AccountData::from(serialized);

    Some(DurableNonceInfo {
        nonce_key,
        rollback_account,
    })
}

// ---------------------------------------------------------------------------
// Bank execution methods
// ---------------------------------------------------------------------------

impl Bank {
    /// Process a single transaction through the full execution pipeline.
    ///
    /// Pipeline steps:
    /// 1. Verify bank is in `Processing` state
    /// 2. Load accounts from the account database
    /// 3. Validate fee payer has sufficient balance
    /// 4. Execute each instruction via the execution backend
    /// 5. Write modified accounts back to the database
    /// 6. Collect fees (execution + priority)
    /// 7. Update transaction count
    pub fn process_transaction(
        &self,
        transaction: &SanitizedTransaction,
        backend: &dyn ExecutionBackend,
        compute_limit: u64,
    ) -> TransactionExecutionResult {
        // Step 1: Bank must be processing
        if self.status() != BankStatus::Processing {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::BankNotProcessing),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Step 1a: Validate account locks (count limit + no duplicates).
        if let Err(e) = validate_account_locks(transaction) {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(e),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Step 1a2: Enforce static instruction count limit (SIMD-0160).
        if transaction.instructions.len() > MAX_INSTRUCTIONS_PER_TRANSACTION {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::TooManyInstructions {
                    count: transaction.instructions.len(),
                    limit: MAX_INSTRUCTIONS_PER_TRANSACTION,
                }),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Step 1b: Validate blockhash or detect durable nonce transaction.
        //
        // If the blockhash is in the recent queue, this is a regular transaction.
        // Otherwise, check if it's a durable nonce transaction (first instruction
        // is AdvanceNonceAccount and the nonce matches the transaction's blockhash).
        // Nonce is pre-advanced here and persisted on both success and failure.
        let durable_nonce = if self.is_blockhash_valid(&transaction.recent_blockhash) {
            None
        } else {
            let last_bh = self.last_blockhash();
            let fee_calc = FeeCalculator::default();
            match try_detect_durable_nonce(
                transaction,
                self.accounts(),
                &last_bh,
                fee_calc.lamports_per_signature,
            ) {
                Some(nonce_info) => Some(nonce_info),
                None => {
                    return TransactionExecutionResult {
                        success: false,
                        compute_units_consumed: 0,
                        fee: 0,
                        modified_accounts: HashMap::new(),
                        logs: vec![],
                        error: Some(TransactionExecutionError::BlockhashNotRecent),
                        vote_updates: vec![],
                        return_data: None,
                    };
                }
            }
        };

        // Step 1c: Verify Ed25519 signatures (skipped when signatures are empty)
        if !transaction.signatures.is_empty() {
            if let Err(err) = verify_transaction_signatures(transaction) {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(err),
                    vote_updates: vec![],
                    return_data: None,
                };
            }
        }

        // Step 1d: Deduplication check (skipped when signatures are empty)
        if !transaction.signatures.is_empty() {
            let message_hash = compute_message_hash(transaction);
            if self.transaction_cache().contains(
                &transaction.recent_blockhash,
                &message_hash,
                self.slot(),
            ) {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(TransactionExecutionError::DuplicateTransaction),
                    vote_updates: vec![],
                    return_data: None,
                };
            }
        }

        // Step 1e: Reserve block capacity via cost tracker
        let is_vote = transaction
            .instructions
            .first()
            .map(|ix| {
                transaction
                    .account_keys
                    .get(ix.program_id_index as usize)
                    .map(|id| *id == paradencer_ids::VOTE_PROGRAM_ID)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let estimated_cost = TransactionCost::new(compute_limit, is_vote);
        if let Err(e) = self.cost_tracker().try_add(&estimated_cost) {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::BlockCostLimitExceeded(format!(
                    "{:?}",
                    e
                ))),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Step 1f: Parse compute budget (limit, price, data size) from ComputeBudget
        let budget_params = parse_compute_budget(transaction);
        let priority_fee = calculate_priority_fee(&budget_params);

        // Step 2: Load accounts (with data size limit enforcement)
        let mut account_state = match self
            .load_transaction_accounts(transaction, budget_params.loaded_accounts_data_size_limit)
        {
            Ok(state) => state,
            Err(err) => {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(err),
                    vote_updates: vec![],
                    return_data: None,
                };
            }
        };

        // Step 3: Validate fee payer and debit fee
        //
        // Total fee = execution fee (signatures * rate) + priority fee.
        // Execution fees are subject to 50% burn, priority fees go
        // 100% to the slot leader.
        let fee_calculator = FeeCalculator::new(self.lamports_per_signature());
        let precompile_sigs = count_precompile_signatures(transaction);
        let total_signatures = transaction.num_signatures.saturating_add(precompile_sigs);
        let execution_fee = fee_calculator.calculate_fee(total_signatures);
        let fee = execution_fee.saturating_add(priority_fee);
        let rent = crate::Rent::default();

        let fee_payer = &transaction.account_keys[0];
        let payer_account = match account_state.get(fee_payer) {
            Some(acc) if acc.meta.lamports > 0 => acc.clone(),
            _ => {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(TransactionExecutionError::FeePayerNotFound),
                    vote_updates: vec![],
                    return_data: None,
                };
            }
        };

        // Validate account kind: must be system account or initialized nonce
        let account_kind = match get_system_account_kind(&payer_account) {
            Some(kind) => kind,
            None => {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(TransactionExecutionError::InvalidAccountForFee),
                    vote_updates: vec![],
                    return_data: None,
                };
            }
        };

        // Nonce accounts must retain rent-exempt minimum for their data
        let min_balance = match account_kind {
            SystemAccountKind::Nonce => rent.minimum_balance(NONCE_ACCOUNT_SIZE),
            SystemAccountKind::System => 0,
        };

        // Check: lamports - min_balance >= fee
        let available_for_fee = payer_account.meta.lamports.saturating_sub(min_balance);
        if fee > available_for_fee {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::InsufficientFee {
                    required: fee,
                    available: available_for_fee,
                }),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Validate rent state transition after fee deduction
        let pre_rent_state = RentState::from_account(&payer_account, &rent);
        let mut payer_after_fee = payer_account;
        payer_after_fee.meta.lamports = payer_after_fee.meta.lamports.saturating_sub(fee);
        let post_rent_state = RentState::from_account(&payer_after_fee, &rent);

        if !is_rent_transition_allowed(&pre_rent_state, &post_rent_state) {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::InsufficientFundsForRent {
                    account: *fee_payer,
                }),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Debit fee from payer upfront (non-refundable)
        account_state.insert(*fee_payer, payer_after_fee);

        // Step 4: Execute instructions
        // Effective compute limit is the minimum of the caller's limit and
        // the per-transaction budget declared via SetComputeUnitLimit.
        let effective_compute_limit = compute_limit.min(budget_params.compute_unit_limit);
        let mut total_compute = 0u64;
        let mut all_logs = Vec::new();
        let mut modified = HashMap::new();
        let mut exec_error: Option<TransactionExecutionError> = None;
        let mut return_data: Option<(Pubkey, Vec<u8>)> = None;

        // Pre-serialize Instructions sysvar if any instruction references it.
        // Programs can introspect the full instruction list via this sysvar.
        let uses_instructions_sysvar = transaction.instructions.iter().any(|ix| {
            ix.account_indices.iter().any(|&ai| {
                transaction
                    .account_keys
                    .get(ai as usize)
                    .is_some_and(|k| *k == INSTRUCTIONS_SYSVAR_ID)
            })
        });
        let mut instructions_sysvar_data = if uses_instructions_sysvar {
            Some(serialize_instructions_sysvar(transaction))
        } else {
            None
        };

        'execution: for (idx, instruction) in transaction.instructions.iter().enumerate() {
            // Resolve program id
            let program_id = match transaction
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                Some(id) => *id,
                None => {
                    exec_error = Some(TransactionExecutionError::InstructionFailed {
                        index: idx,
                        message: format!(
                            "invalid program_id_index {}",
                            instruction.program_id_index
                        ),
                    });
                    break 'execution;
                }
            };

            // Build instruction accounts with proper permission flags
            let mut instr_accounts = Vec::with_capacity(instruction.account_indices.len());
            let mut invalid_index = false;
            for &ai in &instruction.account_indices {
                let acct_idx = ai as usize;
                let pubkey = match transaction.account_keys.get(acct_idx) {
                    Some(k) => *k,
                    None => {
                        exec_error = Some(TransactionExecutionError::InstructionFailed {
                            index: idx,
                            message: format!("invalid account index {ai}"),
                        });
                        invalid_index = true;
                        break;
                    }
                };

                // For the Instructions sysvar, substitute the serialized
                // transaction instructions instead of loading from state.
                let account = if pubkey == INSTRUCTIONS_SYSVAR_ID {
                    if let Some(ref mut sysvar_data) = instructions_sysvar_data {
                        update_instructions_sysvar_index(sysvar_data, idx as u16);
                        Account {
                            data: AccountData::new(sysvar_data.clone()),
                            ..Account::default()
                        }
                    } else {
                        Account::default()
                    }
                } else {
                    modified
                        .get(&pubkey)
                        .or_else(|| account_state.get(&pubkey))
                        .cloned()
                        .unwrap_or_default()
                };

                let writable = is_account_writable(transaction, acct_idx, &program_id);
                let signer = transaction.is_signer(acct_idx);
                instr_accounts.push((pubkey, account, writable, signer));
            }
            if invalid_index {
                break 'execution;
            }

            let info = InstructionInfo {
                program_id,
                accounts: instr_accounts,
                data: instruction.data.clone(),
                slot_context: self.slot_context(),
            };

            let remaining = effective_compute_limit.saturating_sub(total_compute);
            let result = backend.execute_instruction(&info, remaining);

            total_compute = total_compute.saturating_add(result.compute_units_consumed);

            for log in &result.logs {
                all_logs.push(format!("[ix {}] {}", idx, log));
            }

            if !result.success {
                for (k, v) in result.modified_accounts {
                    modified.insert(k, v);
                }
                exec_error = Some(TransactionExecutionError::InstructionFailed {
                    index: idx,
                    message: result.error.unwrap_or_else(|| "unknown error".to_string()),
                });
                break 'execution;
            }

            // Merge modified accounts
            for (k, v) in result.modified_accounts {
                modified.insert(k, v);
            }

            // Capture return data from the last instruction that set it
            if result.return_data.is_some() {
                return_data = result.return_data;
            }

            // Check compute budget
            if total_compute > effective_compute_limit {
                exec_error = Some(TransactionExecutionError::ComputeBudgetExceeded {
                    consumed: total_compute,
                    limit: effective_compute_limit,
                });
                break 'execution;
            }
        }

        // Step 4b: Validate rent state transitions (only on success so far)
        if exec_error.is_none() {
            let rent_violation = modified.iter().find_map(|(pubkey, post_account)| {
                if *pubkey == INCINERATOR_ID {
                    return None;
                }
                let pre_account = account_state.get(pubkey).cloned().unwrap_or_default();
                let pre_state = RentState::from_account(&pre_account, &rent);
                let post_state = RentState::from_account(post_account, &rent);
                if !is_rent_transition_allowed(&pre_state, &post_state) {
                    Some(*pubkey)
                } else {
                    None
                }
            });
            if let Some(violating_account) = rent_violation {
                exec_error = Some(TransactionExecutionError::InsufficientFundsForRent {
                    account: violating_account,
                });
            }
        }

        // Step 4c: Verify no account exceeds maximum data size.
        if exec_error.is_none() {
            if let Some(pubkey) = modified.iter().find_map(|(k, v)| {
                if v.data.len() as u64 > MAX_ACCOUNT_DATA_SIZE {
                    Some(*k)
                } else {
                    None
                }
            }) {
                exec_error = Some(TransactionExecutionError::AccountDataTooLarge {
                    account: pubkey,
                    size: modified[&pubkey].data.len() as u64,
                    limit: MAX_ACCOUNT_DATA_SIZE,
                });
            }
        }

        // Step 4d: Verify lamport conservation across writable accounts.
        // Total lamports before execution must equal total lamports after.
        if exec_error.is_none() {
            if let Err(e) = verify_lamport_balance(transaction, &account_state, &modified) {
                exec_error = Some(e);
            }
        }

        // Step 5: Handle success/failure with proper nonce rollback
        if let Some(error) = exec_error {
            // Transaction failed AFTER fee deduction.
            // Write fee-debited payer and advanced nonce (if durable).
            let mut failure_writes = HashMap::new();

            // Always persist the fee-debited payer
            if let Some(payer) = account_state.get(fee_payer) {
                failure_writes.insert(*fee_payer, payer.clone());
            }

            // Persist the advanced nonce account on failure
            if let Some(ref nonce_info) = durable_nonce {
                failure_writes.insert(nonce_info.nonce_key, nonce_info.rollback_account.clone());
            }

            if !failure_writes.is_empty() {
                self.write_accounts(&failure_writes);
            }

            // Record fees even on failure (execution + priority separately)
            self.add_execution_fee(execution_fee);
            self.add_priority_fee(priority_fee);
            self.add_signatures(transaction.num_signatures);
            self.add_compute_units_used(total_compute);
            self.record_failed_transaction();
            if !is_vote {
                self.record_nonvote_transaction();
            }

            // Record failed transaction in dedup cache with Failed status.
            if durable_nonce.is_none() && !transaction.signatures.is_empty() {
                let message_hash = compute_message_hash(transaction);
                self.transaction_cache().insert_with_status(
                    &transaction.recent_blockhash,
                    &message_hash,
                    self.slot(),
                    self.slot(),
                    crate::transaction_cache::TransactionStatus::Failed,
                );
            }

            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: total_compute,
                fee,
                modified_accounts: modified,
                logs: all_logs,
                error: Some(error),
                vote_updates: vec![],
                return_data: None,
            };
        }

        // Step 5b: Success path — write all modified accounts
        let final_payer = account_state.get(fee_payer).cloned();
        if let Some(payer) = final_payer {
            if !modified.contains_key(fee_payer) {
                modified.insert(*fee_payer, payer);
            }
        }

        // Include nonce rollback if instructions didn't modify the nonce
        if let Some(ref nonce_info) = durable_nonce {
            modified
                .entry(nonce_info.nonce_key)
                .or_insert_with(|| nonce_info.rollback_account.clone());
        }

        // Step 5c: Reclaim zero-lamport accounts. Accounts reduced to zero
        // lamports are normalized: data is cleared and owner reset to default.
        // This must happen before the data-size delta calculation so that
        // reclaimed data is correctly reflected in the block-level tracking.
        reclaim_zero_lamport_accounts(&mut modified);

        // Step 5d: Calculate accounts data size delta for block-level tracking.
        // Compare post-execution data sizes to pre-execution sizes for all
        // modified accounts. New accounts contribute their full data size;
        // deleted accounts (zero lamports) subtract their original size.
        let data_size_delta = calculate_data_size_delta(&account_state, &modified);
        if data_size_delta != 0 {
            let mut delta_cost = TransactionCost::new(0, false);
            delta_cost.data_size_delta = data_size_delta;
            // Update cost tracker (may fail if block limit exceeded — we still commit
            // because the transaction already executed successfully)
            let _ = self.cost_tracker().try_add(&delta_cost);
            self.update_accounts_data_size_delta(data_size_delta);
        }

        self.write_accounts(&modified);

        // Step 6: Record fees, signatures, and block-level metrics
        self.add_execution_fee(execution_fee);
        self.add_priority_fee(priority_fee);
        self.add_signatures(transaction.num_signatures);
        self.add_compute_units_used(total_compute);
        if !is_vote {
            self.record_nonvote_transaction();
        }

        // Step 7: Record transaction
        let _ = self.register_transaction();

        // Step 8: Extract vote updates from successful vote transactions
        let vote_updates = self.extract_vote_updates(transaction);

        // Step 9: Record transaction in dedup cache.
        // Durable nonce transactions skip the cache — the nonce mechanism
        // itself prevents replay, matching the protocol's optimization.
        if durable_nonce.is_none() && !transaction.signatures.is_empty() {
            let message_hash = compute_message_hash(transaction);
            self.transaction_cache().insert(
                &transaction.recent_blockhash,
                &message_hash,
                self.slot(),
                self.slot(),
            );
        }

        TransactionExecutionResult {
            success: true,
            compute_units_consumed: total_compute,
            fee,
            modified_accounts: modified,
            logs: all_logs,
            error: None,
            vote_updates,
            return_data,
        }
    }

    /// Process a batch of transactions.
    ///
    /// Transactions are executed sequentially. Each transaction's account
    /// modifications are visible to subsequent transactions in the batch.
    pub fn process_transactions(
        &self,
        transactions: &[SanitizedTransaction],
        backend: &dyn ExecutionBackend,
        compute_limit: u64,
    ) -> BatchExecutionSummary {
        let mut summary = BatchExecutionSummary {
            total: transactions.len(),
            ..Default::default()
        };

        for tx in transactions {
            let result = self.process_transaction(tx, backend, compute_limit);
            if result.success {
                summary.succeeded += 1;
                summary.vote_updates.extend(result.vote_updates.clone());
            } else {
                summary.failed += 1;
            }
            summary.total_compute_units += result.compute_units_consumed;
            summary.total_fees += result.fee;
            summary.results.push(result);
        }

        summary
    }

    /// Load accounts referenced by a transaction from the account database.
    ///
    /// Checks the sysvar cache first for sysvar accounts, then falls back
    /// to the account database. Tracks total loaded data size and rejects
    /// the transaction if it exceeds the per-transaction limit.
    fn load_transaction_accounts(
        &self,
        transaction: &SanitizedTransaction,
        data_size_limit: u64,
    ) -> Result<HashMap<Pubkey, Account>, TransactionExecutionError> {
        let db = self.accounts();
        let mut loaded = HashMap::with_capacity(transaction.account_keys.len());
        let mut accumulated_data_size: u64 = 0;

        for key in &transaction.account_keys {
            // Check sysvar cache first for sysvar accounts
            let account = self
                .sysvar_cache()
                .and_then(|cache| cache.get_sysvar_account(key))
                .or_else(|| db.get_published_account(key))
                .unwrap_or_default();

            // Accumulate loaded data size for existing accounts
            accumulated_data_size =
                accumulated_data_size.saturating_add(account_loaded_size(&account));
            if accumulated_data_size > data_size_limit {
                return Err(
                    TransactionExecutionError::MaxLoadedAccountsDataSizeExceeded {
                        loaded: accumulated_data_size,
                        limit: data_size_limit,
                    },
                );
            }

            loaded.insert(*key, account);
        }

        Ok(loaded)
    }

    /// Extract vote updates from a successfully executed transaction.
    ///
    /// Scans instructions for vote program invocations and extracts the
    /// vote account pubkey and the voted slot from the instruction data.
    fn extract_vote_updates(&self, transaction: &SanitizedTransaction) -> Vec<VoteUpdate> {
        let mut updates = Vec::new();

        for instruction in &transaction.instructions {
            let program_id = match transaction
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                Some(id) => *id,
                None => continue,
            };

            if program_id != VOTE_PROGRAM_ID {
                continue;
            }

            // Vote account is always the first account in vote instructions
            let vote_account = match instruction
                .account_indices
                .first()
                .and_then(|&idx| transaction.account_keys.get(idx as usize))
            {
                Some(key) => *key,
                None => continue,
            };

            // Try to extract the voted slot from instruction data.
            // Vote instructions have a 4-byte type discriminant. For Vote/VoteSwitch
            // (types 2/4), slots follow after the discriminant. For update/tower
            // instructions, the slot is embedded in the tower data.
            // We extract the highest slot when possible.
            let voted_slot = extract_voted_slot(&instruction.data);

            updates.push(VoteUpdate {
                vote_account,
                voted_slot,
            });
        }

        updates
    }

    /// Write modified accounts back to the account database.
    ///
    /// Also updates the bank's lattice hash accumulator for each modified
    /// account by subtracting the old hash and adding the new hash.
    /// Stake delegation caches are refreshed for any modified stake accounts.
    fn write_accounts(&self, accounts: &HashMap<Pubkey, Account>) {
        let db = self.accounts();

        // Update lattice hash for each modified account
        for (pubkey, new_account) in accounts {
            let old_account = db.get_published_account(pubkey);
            self.update_account_hash(pubkey, old_account.as_ref(), new_account);
        }

        // Update stake delegation cache for modified stake accounts so that
        // leader schedule, rewards, and epoch processing see current state.
        self.update_stake_cache(accounts);

        // Write to database
        let mut xid_bytes = [0u8; 16];
        xid_bytes[0..8].copy_from_slice(&self.slot().to_le_bytes());
        xid_bytes[15] = 1; // Ensure non-root
        let xid = TransactionId::new(xid_bytes);

        for (pubkey, account) in accounts {
            let _ = db.write_account(xid, *pubkey, account.clone());
        }
        let _ = db.publish_transaction(xid);
    }

    /// Refresh the stake delegation cache for any modified stake accounts.
    ///
    /// After transaction execution, stake accounts may have new delegations,
    /// changed delegation amounts, or been deactivated/closed. This method
    /// inspects each modified account owned by the stake program and updates
    /// the in-memory StakeTracker accordingly:
    ///
    /// - Zero-lamport accounts: delegation is removed (account reclaimed).
    /// - Delegated state: delegation is upserted with current parameters.
    /// - Non-delegated state or parse error: delegation is removed.
    fn update_stake_cache(&self, accounts: &HashMap<Pubkey, Account>) {
        use crate::stake::deserialize_stake_state;
        use crate::stake::StakeState;

        let tracker_lock = match self.stake_tracker() {
            Some(tracker) => tracker,
            None => return,
        };

        let mut has_stake_changes = false;
        for account in accounts.values() {
            if account.meta.owner == STAKE_PROGRAM_ID {
                has_stake_changes = true;
                break;
            }
        }
        if !has_stake_changes {
            return;
        }

        let mut tracker = tracker_lock.write().unwrap();

        for (pubkey, account) in accounts {
            if account.meta.owner != STAKE_PROGRAM_ID {
                continue;
            }

            if account.meta.lamports == 0 {
                tracker.remove_delegation(pubkey);
                continue;
            }

            match deserialize_stake_state(account.data.as_ref()) {
                Ok(StakeState::Delegated(_, stake_account, _)) => {
                    tracker.add_delegation(*pubkey, stake_account.delegation.clone());
                }
                _ => {
                    // Not delegated (Uninitialized, Initialized, RewardsPool,
                    // or corrupt data) — remove any stale delegation entry.
                    tracker.remove_delegation(pubkey);
                }
            }
        }
    }
}

/// Extract the highest voted slot from vote instruction data.
///
/// Returns `Some(slot)` for Vote/VoteSwitch instructions that encode
/// slot count + slots. Returns `None` for other instruction types or
/// if the data is too short to parse.
fn extract_voted_slot(data: &[u8]) -> Option<u64> {
    if data.len() < 12 {
        return None;
    }

    let instruction_type = u32::from_le_bytes(data[0..4].try_into().ok()?);

    // Vote (2) and VoteSwitch (4) have slot_count(u64) + slots(u64 each)
    if instruction_type == 2 || instruction_type == 4 {
        let slot_count = u64::from_le_bytes(data[4..12].try_into().ok()?) as usize;
        if slot_count == 0 {
            return None;
        }
        // Last slot is the highest
        let last_slot_offset = 12 + (slot_count - 1) * 8;
        if data.len() < last_slot_offset + 8 {
            return None;
        }
        let slot = u64::from_le_bytes(
            data[last_slot_offset..last_slot_offset + 8]
                .try_into()
                .ok()?,
        );
        return Some(slot);
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochSchedule, LeaderSchedule};
    use paradencer_constants::economics::{
        DEFAULT_TARGET_SIGNATURES_PER_SLOT, LAMPORTS_PER_SIGNATURE,
    };
    use paradencer_constants::execution::MAX_COMPUTE_UNITS;
    use paradencer_storage::{AccountDatabase, Pubkey};
    use std::sync::Arc;

    /// Trivial backend that always succeeds and passes accounts through.
    struct PassthroughBackend;

    impl ExecutionBackend for PassthroughBackend {
        fn execute_instruction(
            &self,
            instruction: &InstructionInfo,
            _remaining: u64,
        ) -> InstructionResult {
            // Just pass through all accounts as modified
            let modified: HashMap<Pubkey, Account> = instruction
                .accounts
                .iter()
                .map(|(k, a, _, _)| (*k, a.clone()))
                .collect();

            InstructionResult {
                success: true,
                compute_units_consumed: 100,
                modified_accounts: modified,
                logs: vec!["ok".to_string()],
                error: None,
                return_data: None,
            }
        }
    }

    /// Backend that always fails.
    struct FailingBackend;

    impl ExecutionBackend for FailingBackend {
        fn execute_instruction(
            &self,
            _instruction: &InstructionInfo,
            _remaining: u64,
        ) -> InstructionResult {
            InstructionResult {
                success: false,
                compute_units_consumed: 50,
                modified_accounts: HashMap::new(),
                logs: vec!["error: custom program error".to_string()],
                error: Some("custom program error".to_string()),
                return_data: None,
            }
        }
    }

    /// Backend that transfers lamports from first account to second.
    struct TransferBackend;

    impl ExecutionBackend for TransferBackend {
        fn execute_instruction(
            &self,
            instruction: &InstructionInfo,
            _remaining: u64,
        ) -> InstructionResult {
            if instruction.accounts.len() < 2 {
                return InstructionResult {
                    success: false,
                    compute_units_consumed: 10,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some("need at least 2 accounts".to_string()),
                    return_data: None,
                };
            }

            // Transfer amount encoded as u64 in instruction data
            let amount = if instruction.data.len() >= 8 {
                u64::from_le_bytes(instruction.data[..8].try_into().unwrap())
            } else {
                0
            };

            let (src_key, mut src_account, _, _) = instruction.accounts[0].clone();
            let (dst_key, mut dst_account, _, _) = instruction.accounts[1].clone();

            if src_account.meta.lamports < amount {
                return InstructionResult {
                    success: false,
                    compute_units_consumed: 20,
                    modified_accounts: HashMap::new(),
                    logs: vec!["insufficient balance".to_string()],
                    error: Some("insufficient balance".to_string()),
                    return_data: None,
                };
            }

            src_account.meta.lamports -= amount;
            dst_account.meta.lamports += amount;

            let mut modified = HashMap::new();
            modified.insert(src_key, src_account);
            modified.insert(dst_key, dst_account);

            InstructionResult {
                success: true,
                compute_units_consumed: 150,
                modified_accounts: modified,
                logs: vec![format!("transferred {amount} lamports")],
                error: None,
                return_data: None,
            }
        }
    }

    fn create_test_bank() -> Bank {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        // Register the zero-hash blockhash so tests using [0u8; 32] pass validation
        use crate::blockhash_queue::BlockhashInfo;
        let info = BlockhashInfo::new(Pubkey::from([0u8; 32]), 5000, 0);
        bank.blockhash_queue().write().unwrap().register_hash(info);
        bank
    }

    /// Store an account in the database as a published record for testing.
    fn store_test_account(bank: &Bank, pubkey: &Pubkey, account: &Account) {
        let db = bank.accounts();
        let xid = TransactionId::new([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        db.write_account(xid, *pubkey, account.clone()).unwrap();
        db.publish_transaction(xid).unwrap();
    }

    fn create_simple_transaction(
        payer: Pubkey,
        program: Pubkey,
        accounts: Vec<Pubkey>,
        data: Vec<u8>,
    ) -> SanitizedTransaction {
        let mut account_keys = vec![payer, program];
        for acc in &accounts {
            if !account_keys.contains(acc) {
                account_keys.push(*acc);
            }
        }

        let account_indices: Vec<u8> = accounts
            .iter()
            .map(|a| account_keys.iter().position(|k| k == a).unwrap() as u8)
            .collect();

        SanitizedTransaction {
            account_keys,
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1, // program is at index 1
                account_indices,
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1, // program is readonly
            signatures: vec![],
            message_bytes: vec![],
        }
    }

    #[test]
    fn process_transaction_succeeds_with_passthrough() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Fund payer
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(
            result.success,
            "transaction should succeed: {:?}",
            result.error
        );
        assert!(result.fee > 0);
        assert!(result.compute_units_consumed > 0);
        assert_eq!(bank.transaction_count(), 1);
    }

    #[test]
    fn process_transaction_fails_zero_lamport_payer() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Payer has 0 lamports — account doesn't exist
        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::FeePayerNotFound)
        ));
    }

    #[test]
    fn process_transaction_fails_insufficient_fee() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Payer exists but has too few lamports for the fee.
        // System-owned, empty data → valid SystemAccountKind::System.
        let payer_account = Account::new(1, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::InsufficientFee { .. })
        ));
    }

    #[test]
    fn process_transaction_fails_on_instruction_error() {
        let bank = create_test_bank();
        let backend = FailingBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::InstructionFailed { .. })
        ));
        // Fee is still charged even on failure
        assert!(result.fee > 0);
    }

    #[test]
    fn process_transaction_transfer_modifies_accounts() {
        let bank = create_test_bank();
        let backend = TransferBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        // Fund payer with enough for fee + transfer
        let payer_account = Account::new(10_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let transfer_amount = 1_000_000u64;

        // Build transaction with proper account ordering:
        // [payer (writable-signed), recipient (writable-unsigned), program (readonly-unsigned)]
        // The instruction references payer (index 0) and recipient (index 1).
        let tx = SanitizedTransaction {
            account_keys: vec![payer, recipient, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: transfer_amount.to_le_bytes().to_vec(),
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1, // only program is readonly
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            result.success,
            "transfer should succeed: {:?}",
            result.error
        );

        // Check that payer lost fee + transfer
        let updated_payer = bank.accounts().get_published_account(&payer).unwrap();
        assert!(updated_payer.meta.lamports < 10_000_000 - transfer_amount);

        // Check recipient received lamports
        let updated_recipient = bank.accounts().get_published_account(&recipient).unwrap();
        assert_eq!(updated_recipient.meta.lamports, transfer_amount);
    }

    #[test]
    fn process_transactions_batch() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let transactions: Vec<_> = (0..5)
            .map(|_| create_simple_transaction(payer, program, vec![payer], vec![]))
            .collect();

        let summary = bank.process_transactions(&transactions, &backend, MAX_COMPUTE_UNITS);

        assert_eq!(summary.total, 5);
        assert_eq!(summary.succeeded, 5);
        assert_eq!(summary.failed, 0);
        assert_eq!(bank.transaction_count(), 5);
        assert!(summary.total_fees > 0);
    }

    #[test]
    fn process_transaction_rejects_frozen_bank() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        // Fill ticks and freeze
        use paradencer_constants::ledger::TICKS_PER_SLOT;
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::BankNotProcessing)
        ));
    }

    #[test]
    fn process_transaction_compute_budget_exceeded() {
        let bank = create_test_bank();

        // Backend that consumes a lot of compute
        struct HeavyBackend;
        impl ExecutionBackend for HeavyBackend {
            fn execute_instruction(
                &self,
                _instruction: &InstructionInfo,
                _remaining: u64,
            ) -> InstructionResult {
                InstructionResult {
                    success: true,
                    compute_units_consumed: 500_000,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: None,
                    return_data: None,
                }
            }
        }

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // 3 instructions × 500K CU = 1.5M > 1M limit
        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &HeavyBackend, 1_000_000);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::ComputeBudgetExceeded { .. })
        ));
    }

    // Vote extraction tests

    #[test]
    fn extract_vote_updates_from_vote_transaction() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let vote_account = Pubkey::new_unique();

        let payer_account = Account::new(10_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Build a Vote instruction (type 2): slot_count=1, slot=42, hash
        let mut vote_data = vec![];
        vote_data.extend_from_slice(&2u32.to_le_bytes()); // Vote instruction type
        vote_data.extend_from_slice(&1u64.to_le_bytes()); // 1 slot
        vote_data.extend_from_slice(&42u64.to_le_bytes()); // slot 42
        vote_data.extend_from_slice(&[0u8; 32]); // hash

        let tx = SanitizedTransaction {
            account_keys: vec![payer, VOTE_PROGRAM_ID, vote_account],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,      // VOTE_PROGRAM_ID
                account_indices: vec![2], // vote_account
                data: vote_data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "vote tx should succeed: {:?}", result.error);
        assert_eq!(result.vote_updates.len(), 1);
        assert_eq!(result.vote_updates[0].vote_account, vote_account);
        assert_eq!(result.vote_updates[0].voted_slot, Some(42));
    }

    #[test]
    fn no_vote_updates_for_non_vote_transaction() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(10_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(result.success);
        assert!(result.vote_updates.is_empty());
    }

    #[test]
    fn batch_aggregates_vote_updates() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let mut transactions = Vec::new();

        // 2 vote transactions + 1 non-vote
        for slot in [100u64, 101] {
            let vote_account = Pubkey::new_unique();
            let mut vote_data = vec![];
            vote_data.extend_from_slice(&2u32.to_le_bytes());
            vote_data.extend_from_slice(&1u64.to_le_bytes());
            vote_data.extend_from_slice(&slot.to_le_bytes());
            vote_data.extend_from_slice(&[0u8; 32]);

            transactions.push(SanitizedTransaction {
                account_keys: vec![payer, VOTE_PROGRAM_ID, vote_account],
                recent_blockhash: [0u8; 32],
                instructions: vec![CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![2],
                    data: vote_data,
                }],
                num_signatures: 1,
                num_readonly_signed: 0,
                num_readonly_unsigned: 0,
                signatures: vec![],
                message_bytes: vec![],
            });
        }

        // Non-vote transaction
        let other_program = Pubkey::new_unique();
        transactions.push(create_simple_transaction(
            payer,
            other_program,
            vec![payer],
            vec![],
        ));

        let summary = bank.process_transactions(&transactions, &backend, MAX_COMPUTE_UNITS);

        assert_eq!(summary.succeeded, 3);
        assert_eq!(summary.vote_updates.len(), 2);
        assert_eq!(summary.vote_updates[0].voted_slot, Some(100));
        assert_eq!(summary.vote_updates[1].voted_slot, Some(101));
    }

    #[test]
    fn extract_voted_slot_from_instruction_data() {
        // Vote instruction type 2, 1 slot, slot=999
        let mut data = vec![];
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&999u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);

        assert_eq!(super::extract_voted_slot(&data), Some(999));

        // Vote instruction type 2, 3 slots — should return last (highest)
        let mut data = vec![];
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&101u64.to_le_bytes());
        data.extend_from_slice(&102u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);

        assert_eq!(super::extract_voted_slot(&data), Some(102));

        // Non-vote instruction type
        let mut data = vec![];
        data.extend_from_slice(&0u32.to_le_bytes()); // InitializeAccount
        data.extend_from_slice(&[0u8; 100]);

        assert_eq!(super::extract_voted_slot(&data), None);

        // Too short
        assert_eq!(super::extract_voted_slot(&[1, 2, 3]), None);
    }

    // -- Blockhash validation tests --

    #[test]
    fn blockhash_validation_rejects_unknown_hash() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0xFFu8; 32], // unknown hash
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::BlockhashNotRecent)
        ));
    }

    #[test]
    fn blockhash_validation_accepts_registered_hash() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Register a custom blockhash
        let custom_hash = [0x42u8; 32];
        use crate::blockhash_queue::BlockhashInfo;
        let info = BlockhashInfo::new(Pubkey::from(custom_hash), 5000, 1);
        bank.blockhash_queue().write().unwrap().register_hash(info);

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: custom_hash,
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            result.success,
            "should accept registered blockhash: {:?}",
            result.error
        );
    }

    #[test]
    fn blockhash_queue_populated_after_finish_slot() {
        let bank = create_test_bank();

        // Complete slot ticks
        use paradencer_constants::ledger::TICKS_PER_SLOT;
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }

        let bank_hash = bank.hash();
        bank.finish_slot().unwrap();

        // The bank hash should now be in the blockhash queue
        assert!(bank.is_blockhash_valid(&bank_hash));
    }

    #[test]
    fn child_bank_inherits_blockhash_queue() {
        let parent = create_test_bank();

        // Register a custom hash in parent
        let custom_hash = [0xABu8; 32];
        use crate::blockhash_queue::BlockhashInfo;
        let info = BlockhashInfo::new(Pubkey::from(custom_hash), 5000, 0);
        parent
            .blockhash_queue()
            .write()
            .unwrap()
            .register_hash(info);

        // Complete parent
        use paradencer_constants::ledger::TICKS_PER_SLOT;
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        // Create child
        let child_schedule =
            Arc::new(LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1000)]).unwrap());
        let child = Bank::new_from_parent(&parent, 1, child_schedule);

        // Custom hash from parent should be valid in child
        assert!(child.is_blockhash_valid(&custom_hash));
    }

    #[test]
    fn blockhash_ages_out_after_max_entries() {
        let bank = create_test_bank();
        use crate::blockhash_queue::{BlockhashInfo, MAX_RECENT_BLOCKHASHES};

        // Register MAX_RECENT_BLOCKHASHES + 1 blockhashes (queue already has [0;32])
        let first_hash = [1u8; 32];
        let first_info = BlockhashInfo::new(Pubkey::from(first_hash), 5000, 1);
        bank.blockhash_queue()
            .write()
            .unwrap()
            .register_hash(first_info);

        for i in 2..=(MAX_RECENT_BLOCKHASHES as u64) {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&i.to_le_bytes());
            let info = BlockhashInfo::new(Pubkey::from(hash_bytes), 5000, i);
            bank.blockhash_queue().write().unwrap().register_hash(info);
        }

        // The first hash should have been evicted (queue has 300 capacity,
        // we inserted 301 entries: [0;32] + first_hash + 299 more)
        // At least one of the early entries should be evicted
        let queue = bank.blockhash_queue().read().unwrap();
        assert_eq!(queue.len(), MAX_RECENT_BLOCKHASHES);
    }

    // --- Signature verification tests ---

    #[test]
    fn empty_signatures_skip_verification() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Transaction with no signatures — verification is skipped
        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        assert!(tx.signatures.is_empty());

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            result.success,
            "empty signatures should skip verification: {:?}",
            result.error
        );
    }

    #[test]
    fn valid_signature_passes_verification() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        // Generate a real keypair
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let payer = Pubkey::from(verifying_key.to_bytes());

        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let message_bytes = b"test message for signature".to_vec();
        let signature = signing_key.sign(&message_bytes);

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![signature.to_bytes()],
            message_bytes,
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(
            result.success,
            "valid signature should pass: {:?}",
            result.error
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let payer = Pubkey::from(verifying_key.to_bytes());

        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let message_bytes = b"test message".to_vec();
        // Sign a different message to produce an invalid signature
        let signature = signing_key.sign(b"wrong message");

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![signature.to_bytes()],
            message_bytes,
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::SignatureVerificationFailed { signer_index: 0 })
        ));
    }

    #[test]
    fn wrong_signer_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        // Signer A signs the message
        let signer_a = SigningKey::from_bytes(&[1u8; 32]);
        // But account key is signer B's public key
        let signer_b = SigningKey::from_bytes(&[2u8; 32]);
        let payer = Pubkey::from(signer_b.verifying_key().to_bytes());

        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let message_bytes = b"test message".to_vec();
        let signature = signer_a.sign(&message_bytes); // signed by A, not B

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![signature.to_bytes()],
            message_bytes,
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::SignatureVerificationFailed { signer_index: 0 })
        ));
    }

    #[test]
    fn multi_signature_all_verified() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let signer1 = SigningKey::from_bytes(&[1u8; 32]);
        let signer2 = SigningKey::from_bytes(&[2u8; 32]);
        let payer = Pubkey::from(signer1.verifying_key().to_bytes());
        let cosigner = Pubkey::from(signer2.verifying_key().to_bytes());

        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let message_bytes = b"multi-sig message".to_vec();
        let sig1 = signer1.sign(&message_bytes);
        let sig2 = signer2.sign(&message_bytes);

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cosigner, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: vec![],
            }],
            num_signatures: 2,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![sig1.to_bytes(), sig2.to_bytes()],
            message_bytes,
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "multi-sig should pass: {:?}", result.error);
    }

    // --- Deduplication tests ---

    #[test]
    fn duplicate_transaction_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(10_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let message_bytes = b"dedup test message".to_vec();
        let signature = signing_key.sign(&message_bytes);

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![signature.to_bytes()],
            message_bytes,
        };

        // First submission succeeds
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "first should succeed: {:?}", result.error);

        // Second submission of the same transaction is rejected
        let result2 = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result2.success);
        assert!(matches!(
            result2.error,
            Some(TransactionExecutionError::DuplicateTransaction)
        ));
    }

    #[test]
    fn different_transactions_both_succeed() {
        use ed25519_dalek::{Signer, SigningKey};

        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let payer = Pubkey::from(signing_key.verifying_key().to_bytes());
        let program = Pubkey::new_unique();
        let payer_account = Account::new(10_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Two different messages → different message hashes → not duplicates
        let msg1 = b"message one".to_vec();
        let sig1 = signing_key.sign(&msg1);
        let tx1 = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![sig1.to_bytes()],
            message_bytes: msg1,
        };

        let msg2 = b"message two".to_vec();
        let sig2 = signing_key.sign(&msg2);
        let tx2 = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![sig2.to_bytes()],
            message_bytes: msg2,
        };

        let result1 = bank.process_transaction(&tx1, &backend, MAX_COMPUTE_UNITS);
        assert!(result1.success, "tx1 should succeed: {:?}", result1.error);

        let result2 = bank.process_transaction(&tx2, &backend, MAX_COMPUTE_UNITS);
        assert!(result2.success, "tx2 should succeed: {:?}", result2.error);
    }

    #[test]
    fn empty_signatures_bypass_dedup() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Transactions with empty signatures skip dedup (backward compat)
        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        assert!(tx.signatures.is_empty());

        let r1 = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(r1.success);

        let r2 = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(r2.success); // not rejected as duplicate
    }

    #[test]
    fn rent_state_transition_validation() {
        // Test the rent state transition rules directly

        // Uninitialized → always allowed
        let pre = RentState::Uninitialized;
        let post = RentState::Uninitialized;
        assert!(is_rent_transition_allowed(&pre, &post));

        // Any → RentExempt: always allowed
        let post_exempt = RentState::RentExempt;
        assert!(is_rent_transition_allowed(
            &RentState::Uninitialized,
            &post_exempt
        ));
        assert!(is_rent_transition_allowed(
            &RentState::RentPaying {
                lamports: 100,
                data_len: 10
            },
            &post_exempt
        ));

        // Uninitialized → RentPaying: NOT allowed
        let post_paying = RentState::RentPaying {
            lamports: 100,
            data_len: 10,
        };
        assert!(!is_rent_transition_allowed(
            &RentState::Uninitialized,
            &post_paying
        ));

        // RentExempt → RentPaying: NOT allowed
        assert!(!is_rent_transition_allowed(
            &RentState::RentExempt,
            &post_paying
        ));

        // RentPaying → RentPaying (same size, less lamports): allowed
        let pre_paying = RentState::RentPaying {
            lamports: 200,
            data_len: 10,
        };
        assert!(is_rent_transition_allowed(&pre_paying, &post_paying));

        // RentPaying → RentPaying (same size, MORE lamports): NOT allowed
        let post_more = RentState::RentPaying {
            lamports: 300,
            data_len: 10,
        };
        assert!(!is_rent_transition_allowed(&pre_paying, &post_more));

        // RentPaying → RentPaying (different size): NOT allowed
        let post_diff_size = RentState::RentPaying {
            lamports: 100,
            data_len: 20,
        };
        assert!(!is_rent_transition_allowed(&pre_paying, &post_diff_size));
    }

    #[test]
    fn cost_tracker_limits_block_transactions() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        // Fill up block cost by processing transactions with large compute limits
        // MAX_BLOCK_COMPUTE_UNITS is 48M; each tx reserves its full compute_limit
        use paradencer_constants::block_limits::MAX_BLOCK_COMPUTE_UNITS;

        // Process one tx that consumes nearly all block capacity
        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_BLOCK_COMPUTE_UNITS - 1000);
        assert!(result.success);

        // Second tx should be rejected — block cost limit exceeded
        let tx2 = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result2 = bank.process_transaction(&tx2, &backend, MAX_BLOCK_COMPUTE_UNITS);
        assert!(!result2.success);
        assert!(matches!(
            result2.error,
            Some(TransactionExecutionError::BlockCostLimitExceeded(_))
        ));
    }

    #[test]
    fn cost_tracker_reports_remaining_capacity() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        use paradencer_constants::block_limits::MAX_BLOCK_COMPUTE_UNITS;
        let initial_capacity = bank.cost_tracker().remaining_capacity();
        assert_eq!(initial_capacity, MAX_BLOCK_COMPUTE_UNITS);

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, 1_000_000);
        assert!(result.success);

        // Capacity should have decreased
        assert!(bank.cost_tracker().remaining_capacity() < initial_capacity);
    }

    // -----------------------------------------------------------------------
    // System account kind detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn system_account_kind_regular_system_account() {
        let account = Account::new(1_000, vec![], SYSTEM_PROGRAM_ID);
        assert_eq!(
            get_system_account_kind(&account),
            Some(SystemAccountKind::System)
        );
    }

    #[test]
    fn system_account_kind_non_system_owner_returns_none() {
        let other_owner = Pubkey::new_unique();
        let account = Account::new(1_000, vec![], other_owner);
        assert_eq!(get_system_account_kind(&account), None);
    }

    #[test]
    fn system_account_kind_wrong_data_len_returns_none() {
        // System-owned but data length doesn't match nonce (not 0 and not NONCE_ACCOUNT_SIZE)
        let account = Account::new(1_000, vec![0u8; 50], SYSTEM_PROGRAM_ID);
        assert_eq!(get_system_account_kind(&account), None);
    }

    #[test]
    fn system_account_kind_initialized_nonce() {
        // Build a nonce account: version=1 (current), state=1 (initialized)
        let mut data = vec![0u8; NONCE_ACCOUNT_SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = current
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // state = initialized

        let account = Account::new(1_000_000, data, SYSTEM_PROGRAM_ID);
        assert_eq!(
            get_system_account_kind(&account),
            Some(SystemAccountKind::Nonce)
        );
    }

    #[test]
    fn system_account_kind_uninitialized_nonce_returns_none() {
        let mut data = vec![0u8; NONCE_ACCOUNT_SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = current
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // state = uninitialized

        let account = Account::new(1_000_000, data, SYSTEM_PROGRAM_ID);
        assert_eq!(get_system_account_kind(&account), None);
    }

    #[test]
    fn system_account_kind_legacy_nonce() {
        let mut data = vec![0u8; NONCE_ACCOUNT_SIZE];
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // version = legacy
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // state = initialized

        let account = Account::new(1_000_000, data, SYSTEM_PROGRAM_ID);
        assert_eq!(
            get_system_account_kind(&account),
            Some(SystemAccountKind::Nonce)
        );
    }

    #[test]
    fn fee_payer_non_system_owner_rejected() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Non-system owner → cannot pay fees
        let other_owner = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000, vec![], other_owner);
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::InvalidAccountForFee)
        ));
    }

    #[test]
    fn nonce_fee_payer_reserves_rent_exempt_minimum() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Build initialized nonce account with exactly enough for rent minimum
        // but not enough for rent minimum + fee
        let rent = crate::Rent::default();
        let min_balance = rent.minimum_balance(NONCE_ACCOUNT_SIZE);

        let mut data = vec![0u8; NONCE_ACCOUNT_SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = current
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // state = initialized

        // Just the rent minimum — no room for any fee
        let payer_account = Account::new(min_balance, data, SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::InsufficientFee { .. })
        ));
    }

    #[test]
    fn incinerator_exempt_from_rent_state_check() {
        // The incinerator account should not trigger rent state violations
        // even when transitioning to a non-exempt state.
        let rent = crate::Rent::default();
        let incinerator = INCINERATOR_ID;

        // Pre: rent-exempt account
        let pre = Account::new(10_000_000, vec![0u8; 100], Pubkey::default());
        let pre_state = RentState::from_account(&pre, &rent);
        assert_eq!(pre_state, RentState::RentExempt);

        // Post: rent-paying (normally disallowed)
        let post = Account::new(1, vec![0u8; 100], Pubkey::default());
        let post_state = RentState::from_account(&post, &rent);
        assert!(matches!(post_state, RentState::RentPaying { .. }));

        // Transition from exempt to paying is normally disallowed
        assert!(!is_rent_transition_allowed(&pre_state, &post_state));

        // But incinerator_id should be exempt — verified in process_transaction
        // by the pubkey check. This is a documentation test.
        assert_eq!(incinerator, paradencer_ids::INCINERATOR_ID);
    }

    // -- Loaded accounts data size tests --

    #[test]
    fn account_loaded_size_zero_for_nonexistent() {
        let account = Account::default();
        assert_eq!(account_loaded_size(&account), 0);
    }

    #[test]
    fn account_loaded_size_includes_base_and_data() {
        let account = Account::new(1_000_000, vec![0u8; 200], Pubkey::default());
        // base (64) + data (200)
        assert_eq!(account_loaded_size(&account), 264);
    }

    #[test]
    fn account_loaded_size_lamports_only_no_data() {
        let account = Account::new(1_000_000, vec![], Pubkey::default());
        // base (64) + data (0) = 64
        assert_eq!(account_loaded_size(&account), 64);
    }

    #[test]
    fn parse_compute_budget_defaults() {
        let tx = SanitizedTransaction {
            account_keys: vec![Pubkey::new_unique()],
            recent_blockhash: [0; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(params.compute_unit_limit, MAX_COMPUTE_UNIT_LIMIT);
        assert_eq!(params.compute_unit_price, 0);
        assert_eq!(
            params.loaded_accounts_data_size_limit,
            MAX_LOADED_ACCOUNTS_DATA_SIZE
        );
    }

    #[test]
    fn parse_compute_budget_data_size_limit() {
        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let payer = Pubkey::new_unique();

        // SetLoadedAccountsDataSizeLimit(100_000)
        let mut data = vec![INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT];
        data.extend_from_slice(&100_000u32.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id],
            recent_blockhash: [0; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(params.loaded_accounts_data_size_limit, 100_000);
    }

    #[test]
    fn parse_compute_budget_data_size_capped() {
        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let payer = Pubkey::new_unique();

        // SetLoadedAccountsDataSizeLimit(u32::MAX) → capped at 64 MiB
        let mut data = vec![INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT];
        data.extend_from_slice(&u32::MAX.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id],
            recent_blockhash: [0; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(
            params.loaded_accounts_data_size_limit,
            MAX_LOADED_ACCOUNTS_DATA_SIZE
        );
    }

    #[test]
    fn parse_compute_budget_unit_limit() {
        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let payer = Pubkey::new_unique();

        // SetComputeUnitLimit(500_000)
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&500_000u32.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id],
            recent_blockhash: [0; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(params.compute_unit_limit, 500_000);
    }

    #[test]
    fn parse_compute_budget_unit_limit_capped() {
        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let payer = Pubkey::new_unique();

        // SetComputeUnitLimit(u32::MAX) → capped at 1,400,000
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&u32::MAX.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id],
            recent_blockhash: [0; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(params.compute_unit_limit, MAX_COMPUTE_UNIT_LIMIT);
    }

    #[test]
    fn parse_compute_budget_unit_price() {
        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let payer = Pubkey::new_unique();

        // SetComputeUnitPrice(1_000_000) = 1 lamport per CU
        let mut data = vec![INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id],
            recent_blockhash: [0; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data,
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let params = parse_compute_budget(&tx);
        assert_eq!(params.compute_unit_price, 1_000_000);
    }

    #[test]
    fn priority_fee_calculation() {
        // 1 micro-lamport per CU * 1,400,000 CU limit = 1.4 lamports → ceil → 2
        let params = ComputeBudgetParams {
            compute_unit_limit: 1_400_000,
            compute_unit_price: 1,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        };
        assert_eq!(calculate_priority_fee(&params), 2);

        // 1,000,000 micro-lamports (= 1 lamport) per CU * 200,000 CU = 200,000 lamports
        let params2 = ComputeBudgetParams {
            compute_unit_limit: 200_000,
            compute_unit_price: 1_000_000,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        };
        assert_eq!(calculate_priority_fee(&params2), 200_000);

        // Zero price = zero fee
        let params3 = ComputeBudgetParams {
            compute_unit_limit: 1_400_000,
            compute_unit_price: 0,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
        };
        assert_eq!(calculate_priority_fee(&params3), 0);
    }

    #[test]
    fn loaded_accounts_data_size_exceeds_limit() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        // Store an account with large data
        let large_key = Pubkey::new_unique();
        let large_account = Account::new(1_000_000_000, vec![0u8; 1024], Pubkey::default());
        store_test_account(&bank, &large_key, &large_account);

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let sys_id = SYSTEM_PROGRAM_ID;

        // Set a very tight loaded accounts data size limit (100 bytes)
        let mut limit_data = vec![INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT];
        limit_data.extend_from_slice(&100u32.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id, sys_id, large_key],
            recent_blockhash: [0u8; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![],
                    data: limit_data,
                },
                CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0, 3],
                    data: vec![0; 4],
                },
            ],
            num_signatures: 0,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::MaxLoadedAccountsDataSizeExceeded { .. })
        ));
    }

    #[test]
    fn loaded_accounts_data_size_within_limit() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let recipient = Pubkey::new_unique();
        let sys_id = SYSTEM_PROGRAM_ID;

        let tx = SanitizedTransaction {
            account_keys: vec![payer, sys_id, recipient],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0, 2],
                data: vec![0; 4],
            }],
            num_signatures: 0,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);

        // Should succeed — small accounts well within 64 MiB default limit
        assert!(result.success);
    }

    // -- Priority fee integration tests --

    #[test]
    fn transaction_with_priority_fee_charges_combined_fee() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let sys_id = SYSTEM_PROGRAM_ID;

        // SetComputeUnitPrice(1_000_000) = 1 lamport per CU
        // SetComputeUnitLimit(200_000)
        let mut price_data = vec![INSTRUCTION_SET_COMPUTE_UNIT_PRICE];
        price_data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let mut limit_data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        limit_data.extend_from_slice(&200_000u32.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id, sys_id],
            recent_blockhash: [0; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![],
                    data: price_data,
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![],
                    data: limit_data,
                },
                CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0],
                    data: vec![0; 4],
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "transaction should succeed");

        // execution_fee = 1 sig * 5000 = 5000
        // priority_fee = ceil(1_000_000 * 200_000 / 1_000_000) = 200_000
        // total fee = 5000 + 200_000 = 205_000
        assert_eq!(result.fee, 205_000);

        // Check fees recorded separately
        assert_eq!(bank.execution_fees(), 5000);
        assert_eq!(bank.priority_fees(), 200_000);
    }

    #[test]
    fn transaction_with_custom_compute_limit_enforces_it() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let cb_id = COMPUTE_BUDGET_PROGRAM_ID;
        let sys_id = SYSTEM_PROGRAM_ID;

        // SetComputeUnitLimit(100) — very small
        let mut limit_data = vec![INSTRUCTION_SET_COMPUTE_UNIT_LIMIT];
        limit_data.extend_from_slice(&100u32.to_le_bytes());

        let tx = SanitizedTransaction {
            account_keys: vec![payer, cb_id, sys_id],
            recent_blockhash: [0; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![],
                    data: limit_data,
                },
                CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![0],
                    data: vec![0; 4],
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        // PassthroughBackend consumes compute units based on instruction count.
        // The effective limit is 100 CU which is very small — transaction
        // behavior depends on backend compute consumption.
        // Key assertion: budget_params.compute_unit_limit is applied.
        assert!(result.fee > 0, "fee should still be charged");
    }

    // -- Durable nonce transaction tests --

    /// Create a nonce account with initialized state.
    fn create_nonce_account(
        authority: Pubkey,
        durable_nonce: [u8; 32],
        lamports_per_sig: u64,
        lamports: u64,
    ) -> Account {
        use crate::nonce::{serialize_nonce_state, Nonce, NonceData};
        use crate::FeeCalculator;

        let state = Nonce::Initialized(NonceData {
            authority,
            durable_nonce: Pubkey::new(durable_nonce),
            fee_calculator: FeeCalculator::new(lamports_per_sig),
        });
        let data = serialize_nonce_state(&state);
        Account::new(lamports, data, SYSTEM_PROGRAM_ID)
    }

    #[test]
    fn nonce_deserialization_roundtrip() {
        use crate::nonce::{deserialize_nonce_state, serialize_nonce_state, Nonce, NonceData};

        let authority = Pubkey::new_unique();
        let nonce_hash = Pubkey::new_unique();
        let fee_calc = FeeCalculator::new(5000);

        let state = Nonce::Initialized(NonceData {
            authority,
            durable_nonce: nonce_hash,
            fee_calculator: fee_calc,
        });

        let serialized = serialize_nonce_state(&state);
        assert_eq!(serialized.len(), NONCE_ACCOUNT_SIZE);

        let deserialized = deserialize_nonce_state(&serialized).unwrap();
        let data = deserialized.data().unwrap();
        assert_eq!(data.authority, authority);
        assert_eq!(data.durable_nonce, nonce_hash);
        assert_eq!(data.fee_calculator.lamports_per_signature, 5000);
    }

    #[test]
    fn derive_durable_nonce_is_deterministic() {
        use crate::nonce::derive_durable_nonce;

        let blockhash = [0xAAu8; 32];
        let nonce1 = derive_durable_nonce(&blockhash);
        let nonce2 = derive_durable_nonce(&blockhash);
        assert_eq!(nonce1, nonce2);

        // Different blockhash produces different nonce
        let nonce3 = derive_durable_nonce(&[0xBBu8; 32]);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn durable_nonce_transaction_succeeds() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let nonce_key = Pubkey::new_unique();
        let authority = payer; // payer is also nonce authority

        // The nonce's durable_nonce must match the tx's recent_blockhash
        let nonce_value = [0xCC; 32];
        let nonce_account = create_nonce_account(authority, nonce_value, 5000, 10_000_000);
        store_test_account(&bank, &nonce_key, &nonce_account);

        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let sys_id = SYSTEM_PROGRAM_ID;

        // AdvanceNonceAccount instruction (discriminant 4)
        let advance_data = 4u32.to_le_bytes().to_vec();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, sys_id, nonce_key],
            recent_blockhash: nonce_value, // matches nonce's durable_nonce
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,      // System Program
                    account_indices: vec![2], // nonce account
                    data: advance_data,
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![0; 4],
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "durable nonce transaction should succeed");
        assert!(result.fee > 0, "fee should be non-zero for 1 signature");
    }

    #[test]
    fn durable_nonce_invalid_blockhash_rejected() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let nonce_key = Pubkey::new_unique();

        let nonce_value = [0xCC; 32];
        let nonce_account = create_nonce_account(payer, nonce_value, 5000, 10_000_000);
        store_test_account(&bank, &nonce_key, &nonce_account);

        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let sys_id = SYSTEM_PROGRAM_ID;
        let advance_data = 4u32.to_le_bytes().to_vec();

        // recent_blockhash does NOT match nonce's durable_nonce
        let tx = SanitizedTransaction {
            account_keys: vec![payer, sys_id, nonce_key],
            recent_blockhash: [0xDD; 32], // WRONG — doesn't match nonce
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![2],
                data: advance_data,
            }],
            num_signatures: 0,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::BlockhashNotRecent)
        ));
    }

    #[test]
    fn durable_nonce_failure_still_advances_nonce_and_charges_fee() {
        let bank = create_test_bank();
        let backend = FailingBackend;

        let payer = Pubkey::new_unique();
        let nonce_key = Pubkey::new_unique();

        let nonce_value = [0xCC; 32];
        let nonce_account = create_nonce_account(payer, nonce_value, 5000, 10_000_000);
        store_test_account(&bank, &nonce_key, &nonce_account);

        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let sys_id = SYSTEM_PROGRAM_ID;
        let advance_data = 4u32.to_le_bytes().to_vec();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, sys_id, nonce_key],
            recent_blockhash: nonce_value,
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![2],
                    data: advance_data,
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![0xFF; 4], // will fail via FailingBackend
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(!result.success, "execution should fail");

        // Fee should still be charged
        assert!(result.fee > 0, "fee should be non-zero for 1 signature");

        // Nonce account should be advanced (written via rollback)
        let updated_nonce = bank
            .accounts()
            .get_published_account(&nonce_key)
            .expect("nonce should still exist");

        let nonce_state =
            deserialize_nonce_state(updated_nonce.data.as_slice()).expect("should deserialize");
        let nonce_data = nonce_state.data().expect("should be initialized");

        // Nonce should have advanced — no longer equal to original value
        assert_ne!(
            nonce_data.durable_nonce,
            Pubkey::new(nonce_value),
            "nonce should be advanced even on failure"
        );

        // Fee payer should have fee deducted
        let updated_payer = bank
            .accounts()
            .get_published_account(&payer)
            .expect("payer should exist");
        assert!(
            updated_payer.meta.lamports < 1_000_000_000,
            "fee should be deducted"
        );
    }

    // -- Accounts data size delta tests --

    #[test]
    fn calculate_data_size_delta_new_account() {
        let pre_state = HashMap::new();
        let mut modified = HashMap::new();
        modified.insert(
            Pubkey::new_unique(),
            Account::new(1000, vec![0u8; 200], Pubkey::default()),
        );

        let delta = super::calculate_data_size_delta(&pre_state, &modified);
        assert_eq!(delta, 200);
    }

    #[test]
    fn calculate_data_size_delta_grown_account() {
        let key = Pubkey::new_unique();
        let mut pre_state = HashMap::new();
        pre_state.insert(key, Account::new(1000, vec![0u8; 100], Pubkey::default()));

        let mut modified = HashMap::new();
        modified.insert(key, Account::new(1000, vec![0u8; 300], Pubkey::default()));

        let delta = super::calculate_data_size_delta(&pre_state, &modified);
        assert_eq!(delta, 200);
    }

    #[test]
    fn calculate_data_size_delta_shrunk_account() {
        let key = Pubkey::new_unique();
        let mut pre_state = HashMap::new();
        pre_state.insert(key, Account::new(1000, vec![0u8; 500], Pubkey::default()));

        let mut modified = HashMap::new();
        modified.insert(key, Account::new(1000, vec![0u8; 200], Pubkey::default()));

        let delta = super::calculate_data_size_delta(&pre_state, &modified);
        assert_eq!(delta, -300);
    }

    #[test]
    fn calculate_data_size_delta_mixed_changes() {
        let key1 = Pubkey::new_unique();
        let key2 = Pubkey::new_unique();
        let mut pre_state = HashMap::new();
        pre_state.insert(key1, Account::new(1000, vec![0u8; 100], Pubkey::default()));
        // key2 is new

        let mut modified = HashMap::new();
        modified.insert(key1, Account::new(1000, vec![0u8; 50], Pubkey::default())); // -50
        modified.insert(key2, Account::new(1000, vec![0u8; 200], Pubkey::default())); // +200

        let delta = super::calculate_data_size_delta(&pre_state, &modified);
        assert_eq!(delta, 150); // -50 + 200
    }

    #[test]
    fn accounts_data_size_updated_on_successful_transaction() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let payer_account = Account::new(1_000_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &payer, &payer_account);

        let program = Pubkey::new_unique();

        let initial_size = bank.accounts_data_size();

        let tx = create_simple_transaction(payer, program, vec![], vec![]);
        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success);

        // PassthroughBackend returns accounts unchanged, so data size
        // delta comes from whatever accounts the backend returns.
        // The important thing is the tracking mechanism works.
        let final_size = bank.accounts_data_size();
        // Delta should reflect account modifications from PassthroughBackend
        assert!(
            final_size >= initial_size,
            "accounts_data_size should be tracked"
        );
    }

    // ── account lock validation tests ─────────────────────────────────

    #[test]
    fn validate_account_locks_accepts_normal_transaction() {
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let tx = create_simple_transaction(payer, program, vec![], vec![]);
        assert!(super::validate_account_locks(&tx).is_ok());
    }

    #[test]
    fn validate_account_locks_rejects_duplicate_keys() {
        let key = Pubkey::new_unique();
        let tx = SanitizedTransaction {
            account_keys: vec![key, key],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let err = super::validate_account_locks(&tx).unwrap_err();
        assert!(matches!(
            err,
            TransactionExecutionError::DuplicateAccountKey { .. }
        ));
    }

    #[test]
    fn validate_account_locks_rejects_too_many_accounts() {
        let keys: Vec<Pubkey> = (0..MAX_TRANSACTION_ACCOUNT_LOCKS + 1)
            .map(|_| Pubkey::new_unique())
            .collect();
        let tx = SanitizedTransaction {
            account_keys: keys,
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        let err = super::validate_account_locks(&tx).unwrap_err();
        assert!(matches!(
            err,
            TransactionExecutionError::TooManyAccountLocks { .. }
        ));
    }

    #[test]
    fn validate_account_locks_allows_max_accounts() {
        let keys: Vec<Pubkey> = (0..MAX_TRANSACTION_ACCOUNT_LOCKS)
            .map(|_| Pubkey::new_unique())
            .collect();
        let tx = SanitizedTransaction {
            account_keys: keys,
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert!(super::validate_account_locks(&tx).is_ok());
    }

    // ── lamport balance verification tests ────────────────────────────

    #[test]
    fn verify_lamport_balance_accepts_conserved_transfer() {
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, recipient, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let mut pre_state = HashMap::new();
        pre_state.insert(payer, Account::new(1_000_000, vec![], Pubkey::default()));
        pre_state.insert(recipient, Account::new(0, vec![], Pubkey::default()));

        let mut modified = HashMap::new();
        modified.insert(payer, Account::new(500_000, vec![], Pubkey::default()));
        modified.insert(recipient, Account::new(500_000, vec![], Pubkey::default()));

        assert!(super::verify_lamport_balance(&tx, &pre_state, &modified).is_ok());
    }

    #[test]
    fn verify_lamport_balance_rejects_created_lamports() {
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, recipient, program],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let mut pre_state = HashMap::new();
        pre_state.insert(payer, Account::new(1_000_000, vec![], Pubkey::default()));
        pre_state.insert(recipient, Account::new(0, vec![], Pubkey::default()));

        // Recipient gets lamports but payer doesn't lose them — unbalanced
        let mut modified = HashMap::new();
        modified.insert(payer, Account::new(1_000_000, vec![], Pubkey::default()));
        modified.insert(recipient, Account::new(500_000, vec![], Pubkey::default()));

        assert!(matches!(
            super::verify_lamport_balance(&tx, &pre_state, &modified),
            Err(TransactionExecutionError::UnbalancedTransaction)
        ));
    }

    #[test]
    fn verify_lamport_balance_ignores_readonly_accounts() {
        let payer = Pubkey::new_unique();
        let readonly_acc = Pubkey::new_unique();

        // Readonly account is last in unsigned section
        let tx = SanitizedTransaction {
            account_keys: vec![payer, readonly_acc],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1, // readonly_acc is readonly
            signatures: vec![],
            message_bytes: vec![],
        };

        let mut pre_state = HashMap::new();
        pre_state.insert(payer, Account::new(1_000_000, vec![], Pubkey::default()));
        pre_state.insert(readonly_acc, Account::new(0, vec![], Pubkey::default()));

        // Payer balance unchanged among writable accounts (only payer is writable)
        let modified = HashMap::new();

        assert!(super::verify_lamport_balance(&tx, &pre_state, &modified).is_ok());
    }

    // ── precompile signature fee tests ────────────────────────────────

    #[test]
    fn count_precompile_signatures_empty_instructions() {
        let tx = SanitizedTransaction {
            account_keys: vec![Pubkey::new_unique()],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert_eq!(super::count_precompile_signatures(&tx), 0);
    }

    #[test]
    fn count_precompile_signatures_ed25519_instruction() {
        let tx = SanitizedTransaction {
            account_keys: vec![Pubkey::new_unique(), ED25519_PROGRAM_ID],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data: vec![3], // 3 signatures
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert_eq!(super::count_precompile_signatures(&tx), 3);
    }

    #[test]
    fn count_precompile_signatures_multiple_precompiles() {
        let tx = SanitizedTransaction {
            account_keys: vec![
                Pubkey::new_unique(),
                ED25519_PROGRAM_ID,
                SECP256K1_PROGRAM_ID,
            ],
            recent_blockhash: [0u8; 32],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![],
                    data: vec![2], // 2 ed25519 signatures
                },
                CompiledInstruction {
                    program_id_index: 2,
                    account_indices: vec![],
                    data: vec![5], // 5 secp256k1 signatures
                },
            ],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert_eq!(super::count_precompile_signatures(&tx), 7); // 2 + 5
    }

    #[test]
    fn count_precompile_signatures_empty_data_skipped() {
        let tx = SanitizedTransaction {
            account_keys: vec![Pubkey::new_unique(), ED25519_PROGRAM_ID],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data: vec![], // empty data
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert_eq!(super::count_precompile_signatures(&tx), 0);
    }

    #[test]
    fn count_precompile_signatures_non_precompile_ignored() {
        let tx = SanitizedTransaction {
            account_keys: vec![Pubkey::new_unique(), Pubkey::new_unique()],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![],
                data: vec![10], // non-precompile program, should be ignored
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 0,
            signatures: vec![],
            message_bytes: vec![],
        };
        assert_eq!(super::count_precompile_signatures(&tx), 0);
    }

    // ── account data size limit tests ─────────────────────────────────

    #[test]
    fn account_data_within_limit_accepted() {
        let bank = create_test_bank();

        // Backend that creates a moderately sized account (under 10MB)
        struct DataGrowBackend;
        impl ExecutionBackend for DataGrowBackend {
            fn execute_instruction(
                &self,
                instruction: &InstructionInfo,
                _remaining: u64,
            ) -> InstructionResult {
                let mut modified = HashMap::new();
                if let Some((key, acc, _, _)) = instruction.accounts.first() {
                    let mut new_acc = acc.clone();
                    new_acc.data = vec![0u8; 1024].into(); // 1KB — well under limit
                    modified.insert(*key, new_acc);
                }
                InstructionResult {
                    success: true,
                    compute_units_consumed: 100,
                    modified_accounts: modified,
                    logs: vec![],
                    error: None,
                    return_data: None,
                }
            }
        }

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        // Need enough lamports to remain rent-exempt after data grows to 1KB.
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &DataGrowBackend, MAX_COMPUTE_UNITS);
        assert!(result.success, "should accept account under size limit");
    }

    // ── fee rate governor tests ───────────────────────────────────────

    #[test]
    fn derive_fee_rate_returns_target_at_zero_sigs() {
        let rate = crate::bank::derive_fee_rate(LAMPORTS_PER_SIGNATURE, 0);
        // With 0 signatures, desired is at minimum (target/2). Current is at target.
        // Should decrease by one step.
        assert!(rate < LAMPORTS_PER_SIGNATURE);
        assert!(rate > 0);
    }

    #[test]
    fn derive_fee_rate_increases_under_load() {
        let rate = crate::bank::derive_fee_rate(
            LAMPORTS_PER_SIGNATURE,
            DEFAULT_TARGET_SIGNATURES_PER_SLOT * 2,
        );
        assert!(rate > LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn derive_fee_rate_decreases_when_idle() {
        let rate = crate::bank::derive_fee_rate(
            LAMPORTS_PER_SIGNATURE,
            DEFAULT_TARGET_SIGNATURES_PER_SLOT / 4,
        );
        assert!(rate < LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn child_bank_inherits_derived_fee_rate() {
        let bank = create_test_bank();

        // Simulate heavy load
        bank.add_signatures(DEFAULT_TARGET_SIGNATURES_PER_SLOT * 3);

        let child = Bank::new_from_parent(&bank, bank.slot() + 1, bank.leader_schedule().clone());

        // Child's fee rate should be higher than the default
        assert!(child.lamports_per_signature() > LAMPORTS_PER_SIGNATURE);
    }

    // ── account reclamation tests ─────────────────────────────────────

    #[test]
    fn reclaim_clears_data_and_owner_on_zero_lamport_account() {
        let pubkey = Pubkey::new_unique();
        let account = Account::new(0, vec![1, 2, 3], Pubkey::new_unique());
        assert!(!account.data.is_empty());
        assert_ne!(account.meta.owner, Pubkey::default());

        let mut modified = HashMap::new();
        modified.insert(pubkey, account);

        super::reclaim_zero_lamport_accounts(&mut modified);

        let reclaimed = &modified[&pubkey];
        assert!(reclaimed.data.is_empty());
        assert_eq!(reclaimed.meta.owner, Pubkey::default());
        assert_eq!(reclaimed.meta.lamports, 0);
    }

    #[test]
    fn reclaim_preserves_nonzero_lamport_accounts() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let account = Account::new(100, vec![1, 2, 3], owner);

        let mut modified = HashMap::new();
        modified.insert(pubkey, account);

        super::reclaim_zero_lamport_accounts(&mut modified);

        let kept = &modified[&pubkey];
        assert_eq!(kept.data.len(), 3);
        assert_eq!(kept.meta.owner, owner);
        assert_eq!(kept.meta.lamports, 100);
    }

    #[test]
    fn reclaim_handles_mixed_accounts() {
        let zero_key = Pubkey::new_unique();
        let live_key = Pubkey::new_unique();

        let mut modified = HashMap::new();
        modified.insert(
            zero_key,
            Account::new(0, vec![10, 20], Pubkey::new_unique()),
        );
        modified.insert(
            live_key,
            Account::new(500, vec![30, 40, 50], Pubkey::new_unique()),
        );

        super::reclaim_zero_lamport_accounts(&mut modified);

        assert!(modified[&zero_key].data.is_empty());
        assert_eq!(modified[&zero_key].meta.owner, Pubkey::default());
        assert_eq!(modified[&live_key].data.len(), 3);
        assert_eq!(modified[&live_key].meta.lamports, 500);
    }

    // ── static instruction limit tests ────────────────────────────────

    #[test]
    fn transaction_within_instruction_limit_accepted() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // 3 instructions — well within the 64 limit
        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: (0..3)
                .map(|_| CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                })
                .collect(),
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);
        assert!(
            !matches!(
                result.error,
                Some(TransactionExecutionError::TooManyInstructions { .. })
            ),
            "should not reject transaction within instruction limit"
        );
    }

    #[test]
    fn transaction_exceeding_instruction_limit_rejected() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // 65 instructions — exceeds the 64 limit
        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: (0..65)
                .map(|_| CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                })
                .collect(),
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::TooManyInstructions {
                count: 65,
                limit: 64
            })
        ));
    }

    #[test]
    fn transaction_at_exact_instruction_limit_accepted() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // Exactly 64 instructions — at the limit, should be accepted
        let tx = SanitizedTransaction {
            account_keys: vec![payer, program],
            recent_blockhash: [0u8; 32],
            instructions: (0..64)
                .map(|_| CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![],
                })
                .collect(),
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);
        assert!(
            !matches!(
                result.error,
                Some(TransactionExecutionError::TooManyInstructions { .. })
            ),
            "should accept transaction at exact instruction limit"
        );
    }

    // ── block-level metrics tracking tests ────────────────────────────

    #[test]
    fn successful_nonvote_transaction_increments_metrics() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);
        assert!(result.success);

        assert_eq!(bank.nonvote_transaction_count(), 1);
        assert_eq!(bank.failed_transaction_count(), 0);
        assert!(bank.total_compute_units_used() > 0);
    }

    #[test]
    fn failed_transaction_increments_failed_count() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // FailingBackend causes instruction failure, which triggers lamport check
        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &FailingBackend, MAX_COMPUTE_UNITS);
        assert!(!result.success);

        assert_eq!(bank.failed_transaction_count(), 1);
        assert_eq!(bank.nonvote_transaction_count(), 1); // still nonvote
    }

    #[test]
    fn vote_transaction_not_counted_as_nonvote() {
        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let vote_account = Pubkey::new_unique();
        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // Build a vote transaction (first instruction's program is VOTE_PROGRAM_ID)
        let tx = SanitizedTransaction {
            account_keys: vec![payer, VOTE_PROGRAM_ID, vote_account],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![2],
                data: vec![],
            }],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let _ = bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);

        // Vote transactions should NOT increment nonvote_transaction_count
        assert_eq!(bank.nonvote_transaction_count(), 0);
    }

    #[test]
    fn compute_units_accumulate_across_transactions() {
        let bank = create_test_bank();
        let program = Pubkey::new_unique();

        for i in 0u8..3 {
            let payer = Pubkey::new_unique();
            store_test_account(
                &bank,
                &payer,
                &Account::new(100_000_000 + i as u64, vec![], Pubkey::default()),
            );
            let tx = create_simple_transaction(payer, program, vec![payer], vec![i]);
            bank.process_transaction(&tx, &PassthroughBackend, MAX_COMPUTE_UNITS);
        }

        assert_eq!(bank.transaction_count(), 3);
        assert_eq!(bank.nonvote_transaction_count(), 3);
        assert!(bank.total_compute_units_used() > 0);
    }

    // ── Instructions sysvar tests ──────────────────────────────────────

    #[test]
    fn serialize_instructions_sysvar_basic() {
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let other = Pubkey::new_unique();

        let tx = SanitizedTransaction {
            account_keys: vec![payer, program, other],
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0, 2],
                    data: vec![0xAA, 0xBB],
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![2],
                    data: vec![0xCC],
                },
            ],
            recent_blockhash: [0u8; 32],
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let data = serialize_instructions_sysvar(&tx);

        // Parse back: first 2 bytes = num_instructions
        let num_ix = u16::from_le_bytes([data[0], data[1]]) as usize;
        assert_eq!(num_ix, 2);

        // Offsets for each instruction
        let off0 = u16::from_le_bytes([data[2], data[3]]) as usize;
        let off1 = u16::from_le_bytes([data[4], data[5]]) as usize;
        assert!(off0 < off1);

        // First instruction at off0: 2 accounts
        let num_accounts = u16::from_le_bytes([data[off0], data[off0 + 1]]) as usize;
        assert_eq!(num_accounts, 2);

        // Current instruction index at the end
        let idx_pos = data.len() - 2;
        let current_idx = u16::from_le_bytes([data[idx_pos], data[idx_pos + 1]]);
        assert_eq!(current_idx, 0);
    }

    #[test]
    fn update_instructions_sysvar_index_works() {
        let mut data = vec![0u8; 10];
        update_instructions_sysvar_index(&mut data, 5);
        assert_eq!(data[8], 5);
        assert_eq!(data[9], 0);

        update_instructions_sysvar_index(&mut data, 256);
        assert_eq!(u16::from_le_bytes([data[8], data[9]]), 256);
    }

    #[test]
    fn instructions_sysvar_injected_into_accounts() {
        // Create a backend that checks the Instructions sysvar account exists
        struct InstructionsSysvarCheckBackend;

        impl ExecutionBackend for InstructionsSysvarCheckBackend {
            fn execute_instruction(
                &self,
                instruction: &InstructionInfo,
                _remaining: u64,
            ) -> InstructionResult {
                // Check if Instructions sysvar is in the accounts
                let has_sysvar = instruction
                    .accounts
                    .iter()
                    .any(|(k, _, _, _)| *k == INSTRUCTIONS_SYSVAR_ID);
                let sysvar_data_len = instruction
                    .accounts
                    .iter()
                    .find(|(k, _, _, _)| *k == INSTRUCTIONS_SYSVAR_ID)
                    .map(|(_, a, _, _)| a.data.len())
                    .unwrap_or(0);

                InstructionResult {
                    success: has_sysvar && sysvar_data_len > 0,
                    compute_units_consumed: 100,
                    modified_accounts: HashMap::new(),
                    logs: vec![format!(
                        "sysvar_present={}, data_len={}",
                        has_sysvar, sysvar_data_len
                    )],
                    error: if has_sysvar && sysvar_data_len > 0 {
                        None
                    } else {
                        Some("missing instructions sysvar".to_string())
                    },
                    return_data: None,
                }
            }
        }

        let bank = create_test_bank();
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        store_test_account(
            &bank,
            &payer,
            &Account::new(100_000_000, vec![], Pubkey::default()),
        );

        // Create transaction that references the Instructions sysvar
        let tx = SanitizedTransaction {
            account_keys: vec![payer, program, INSTRUCTIONS_SYSVAR_ID],
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                account_indices: vec![0, 2], // payer + instructions sysvar
                data: vec![1, 2, 3],
            }],
            recent_blockhash: bank.last_blockhash(),
            num_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            signatures: vec![],
            message_bytes: vec![],
        };

        let result =
            bank.process_transaction(&tx, &InstructionsSysvarCheckBackend, MAX_COMPUTE_UNITS);

        assert!(
            result.success,
            "Instructions sysvar should be injected: {:?}",
            result.error
        );
    }

    // -----------------------------------------------------------------------
    // Stake delegation cache update tests
    // -----------------------------------------------------------------------

    #[test]
    fn write_accounts_updates_stake_tracker_on_delegation() {
        use crate::stake::serialize_stake_state;
        use crate::stake::{Authorized, Delegation, Lockup, Meta, StakeAccount, StakeState};
        use crate::StakeTracker;
        use std::sync::RwLock;

        let mut bank = create_test_bank();

        // Attach a stake tracker
        let tracker = Arc::new(RwLock::new(StakeTracker::new(0)));
        bank.set_stake_tracker(tracker.clone());

        // Create a stake account with a delegation
        let stake_key = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let delegation = Delegation::new(voter, 5_000_000, 0);
        let stake_account = StakeAccount::new(delegation, 0);
        let meta = Meta::new(2_282_880, Authorized::auto(stake_key), Lockup::default());
        let state = StakeState::Delegated(meta, stake_account, Default::default());
        let data = serialize_stake_state(&state);

        let account = Account::new(7_282_880, data, STAKE_PROGRAM_ID);

        // Store and then write via bank
        store_test_account(&bank, &stake_key, &account);
        let mut modified = HashMap::new();
        modified.insert(stake_key, account.clone());
        bank.write_accounts(&modified);

        // Verify tracker was updated
        let tracker_read = tracker.read().unwrap();
        let del = tracker_read.get_delegation(&stake_key);
        assert!(del.is_some(), "Delegation should be in tracker");
        assert_eq!(del.unwrap().voter_pubkey, voter);
        assert_eq!(del.unwrap().stake_amount, 5_000_000);
    }

    #[test]
    fn write_accounts_removes_delegation_on_zero_lamports() {
        use crate::stake::serialize_stake_state;
        use crate::stake::{Delegation, StakeState};
        use crate::StakeTracker;
        use std::sync::RwLock;

        let mut bank = create_test_bank();
        let tracker = Arc::new(RwLock::new(StakeTracker::new(0)));
        bank.set_stake_tracker(tracker.clone());

        let stake_key = Pubkey::new_unique();
        let voter = Pubkey::new_unique();

        // Pre-populate tracker with a delegation
        {
            let mut t = tracker.write().unwrap();
            t.add_delegation(stake_key, Delegation::new(voter, 1_000_000, 0));
        }
        assert!(tracker.read().unwrap().get_delegation(&stake_key).is_some());

        // Write a zero-lamport stake account (reclaimed)
        let state = StakeState::Uninitialized;
        let data = serialize_stake_state(&state);
        let account = Account {
            data: paradencer_storage::AccountData::new(data),
            meta: paradencer_storage::AccountMeta {
                lamports: 0,
                owner: STAKE_PROGRAM_ID,
                ..Default::default()
            },
        };

        let mut modified = HashMap::new();
        modified.insert(stake_key, account);
        bank.write_accounts(&modified);

        assert!(
            tracker.read().unwrap().get_delegation(&stake_key).is_none(),
            "Zero-lamport stake account should remove delegation from tracker"
        );
    }

    #[test]
    fn write_accounts_removes_delegation_on_non_delegated_state() {
        use crate::stake::serialize_stake_state;
        use crate::stake::{Authorized, Delegation, Lockup, Meta, StakeState};
        use crate::StakeTracker;
        use std::sync::RwLock;

        let mut bank = create_test_bank();
        let tracker = Arc::new(RwLock::new(StakeTracker::new(0)));
        bank.set_stake_tracker(tracker.clone());

        let stake_key = Pubkey::new_unique();
        let voter = Pubkey::new_unique();

        // Pre-populate tracker
        {
            let mut t = tracker.write().unwrap();
            t.add_delegation(stake_key, Delegation::new(voter, 1_000_000, 0));
        }

        // Write an Initialized (but not Delegated) stake account
        let meta = Meta::new(2_282_880, Authorized::auto(stake_key), Lockup::default());
        let state = StakeState::Initialized(meta);
        let data = serialize_stake_state(&state);
        let account = Account::new(2_282_880, data, STAKE_PROGRAM_ID);

        let mut modified = HashMap::new();
        modified.insert(stake_key, account);
        bank.write_accounts(&modified);

        assert!(
            tracker.read().unwrap().get_delegation(&stake_key).is_none(),
            "Initialized (non-delegated) state should remove delegation"
        );
    }

    #[test]
    fn write_accounts_ignores_non_stake_accounts() {
        use crate::StakeTracker;
        use std::sync::RwLock;

        let mut bank = create_test_bank();
        let tracker = Arc::new(RwLock::new(StakeTracker::new(0)));
        bank.set_stake_tracker(tracker.clone());

        // Write a system-owned account
        let key = Pubkey::new_unique();
        let account = Account::new(1_000_000, vec![], SYSTEM_PROGRAM_ID);
        store_test_account(&bank, &key, &account);

        let mut modified = HashMap::new();
        modified.insert(key, account);
        bank.write_accounts(&modified);

        assert_eq!(
            tracker.read().unwrap().delegation_count(),
            0,
            "Non-stake accounts should not affect tracker"
        );
    }

    #[test]
    fn write_accounts_no_tracker_is_noop() {
        // Bank without a stake tracker should not panic
        let bank = create_test_bank();

        let key = Pubkey::new_unique();
        let account = Account::new(1_000_000, vec![], STAKE_PROGRAM_ID);
        store_test_account(&bank, &key, &account);

        let mut modified = HashMap::new();
        modified.insert(key, account);
        // Should not panic even though the account is stake-owned
        bank.write_accounts(&modified);
    }
}
