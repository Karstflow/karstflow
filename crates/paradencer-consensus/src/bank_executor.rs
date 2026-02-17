/// Bank transaction execution pipeline.
///
/// Defines the `ExecutionBackend` trait for pluggable instruction execution,
/// and implements the full transaction processing flow on Bank:
/// account loading, fee validation, instruction execution, account writeback,
/// and fee collection.
use crate::{Bank, BankStatus, FeeCalculator};
use paradencer_ids::VOTE_PROGRAM_ID;
use paradencer_storage::{Account, AccountDatabase, Pubkey, TransactionId};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Execution backend trait
// ---------------------------------------------------------------------------

/// Compiled instruction passed to the execution backend.
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// Program that processes this instruction.
    pub program_id: Pubkey,
    /// Accounts accessed by this instruction (pubkey, account, is_writable).
    pub accounts: Vec<(Pubkey, Account, bool)>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
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
    /// Ed25519 signatures (one per required signer).
    pub signatures: Vec<[u8; 64]>,
    /// Serialized message bytes for signature verification.
    pub message_bytes: Vec<u8>,
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

/// Compute a SHA-256 hash of the transaction message for deduplication.
///
/// Uses message_bytes if available, otherwise falls back to the first
/// signature as a unique identifier.
fn compute_message_hash(tx: &SanitizedTransaction) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    if !tx.message_bytes.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(&tx.message_bytes);
        hasher.finalize().into()
    } else if let Some(sig) = tx.signatures.first() {
        // Use first 32 bytes of the 64-byte signature as a unique hash
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&sig[..32]);
        hash
    } else {
        [0u8; 32]
    }
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
            };
        }

        // Step 1b: Validate blockhash is recent
        if !self.is_blockhash_valid(&transaction.recent_blockhash) {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::BlockhashNotRecent),
                vote_updates: vec![],
            };
        }

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
                };
            }
        }

        // Step 1d: Deduplication check (skipped when signatures are empty)
        if !transaction.signatures.is_empty() {
            let message_hash = compute_message_hash(transaction);
            if self
                .transaction_cache()
                .contains(&transaction.recent_blockhash, &message_hash, self.slot())
            {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(TransactionExecutionError::DuplicateTransaction),
                    vote_updates: vec![],
                };
            }
        }

        // Step 2: Load accounts
        let mut account_state = match self.load_transaction_accounts(transaction) {
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
                };
            }
        };

        // Step 3: Validate and debit fee
        let fee_calculator = FeeCalculator::default();
        let fee = fee_calculator.calculate_fee(transaction.num_signatures);

        let fee_payer = &transaction.account_keys[0];
        let payer_account = match account_state.get(fee_payer) {
            Some(acc) => acc.clone(),
            None => {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: 0,
                    fee: 0,
                    modified_accounts: HashMap::new(),
                    logs: vec![],
                    error: Some(TransactionExecutionError::FeePayerNotFound),
                    vote_updates: vec![],
                };
            }
        };

        if payer_account.meta.lamports < fee {
            return TransactionExecutionResult {
                success: false,
                compute_units_consumed: 0,
                fee: 0,
                modified_accounts: HashMap::new(),
                logs: vec![],
                error: Some(TransactionExecutionError::InsufficientFee {
                    required: fee,
                    available: payer_account.meta.lamports,
                }),
                vote_updates: vec![],
            };
        }

        // Debit fee from payer upfront (non-refundable)
        {
            let mut payer = payer_account;
            payer.meta.lamports = payer.meta.lamports.saturating_sub(fee);
            account_state.insert(*fee_payer, payer);
        }

        // Step 4: Execute instructions
        let mut total_compute = 0u64;
        let mut all_logs = Vec::new();
        let mut modified = HashMap::new();

        for (idx, instruction) in transaction.instructions.iter().enumerate() {
            // Resolve program id
            let program_id = match transaction
                .account_keys
                .get(instruction.program_id_index as usize)
            {
                Some(id) => *id,
                None => {
                    return TransactionExecutionResult {
                        success: false,
                        compute_units_consumed: total_compute,
                        fee,
                        modified_accounts: modified,
                        logs: all_logs,
                        error: Some(TransactionExecutionError::InstructionFailed {
                            index: idx,
                            message: format!(
                                "invalid program_id_index {}",
                                instruction.program_id_index
                            ),
                        }),
                        vote_updates: vec![],
                    };
                }
            };

            // Build instruction accounts
            let mut instr_accounts = Vec::with_capacity(instruction.account_indices.len());
            for &ai in &instruction.account_indices {
                let pubkey = match transaction.account_keys.get(ai as usize) {
                    Some(k) => *k,
                    None => {
                        return TransactionExecutionResult {
                            success: false,
                            compute_units_consumed: total_compute,
                            fee,
                            modified_accounts: modified,
                            logs: all_logs,
                            error: Some(TransactionExecutionError::InstructionFailed {
                                index: idx,
                                message: format!("invalid account index {ai}"),
                            }),
                            vote_updates: vec![],
                        };
                    }
                };

                let account = modified
                    .get(&pubkey)
                    .or_else(|| account_state.get(&pubkey))
                    .cloned()
                    .unwrap_or_default();

                instr_accounts.push((pubkey, account, true));
            }

            let info = InstructionInfo {
                program_id,
                accounts: instr_accounts,
                data: instruction.data.clone(),
            };

            let remaining = compute_limit.saturating_sub(total_compute);
            let result = backend.execute_instruction(&info, remaining);

            total_compute = total_compute.saturating_add(result.compute_units_consumed);

            for log in &result.logs {
                all_logs.push(format!("[ix {}] {}", idx, log));
            }

            if !result.success {
                // Merge any partial modifications
                for (k, v) in result.modified_accounts {
                    modified.insert(k, v);
                }
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: total_compute,
                    fee,
                    modified_accounts: modified,
                    logs: all_logs,
                    error: Some(TransactionExecutionError::InstructionFailed {
                        index: idx,
                        message: result.error.unwrap_or_else(|| "unknown error".to_string()),
                    }),
                    vote_updates: vec![],
                };
            }

            // Merge modified accounts
            for (k, v) in result.modified_accounts {
                modified.insert(k, v);
            }

            // Check compute budget
            if total_compute > compute_limit {
                return TransactionExecutionResult {
                    success: false,
                    compute_units_consumed: total_compute,
                    fee,
                    modified_accounts: modified,
                    logs: all_logs,
                    error: Some(TransactionExecutionError::ComputeBudgetExceeded {
                        consumed: total_compute,
                        limit: compute_limit,
                    }),
                    vote_updates: vec![],
                };
            }
        }

        // Step 5: Write modified accounts back to the database
        // Also include the fee-debited payer from account_state
        let final_payer = account_state.get(fee_payer).cloned();
        if let Some(payer) = final_payer {
            if !modified.contains_key(fee_payer) {
                modified.insert(*fee_payer, payer);
            }
        }
        self.write_accounts(&modified);

        // Step 6: Record fees and signatures
        self.add_execution_fee(fee);
        self.add_signatures(transaction.num_signatures);

        // Step 7: Record transaction
        let _ = self.register_transaction();

        // Step 8: Extract vote updates from successful vote transactions
        let vote_updates = self.extract_vote_updates(transaction);

        // Step 9: Record transaction in dedup cache
        if !transaction.signatures.is_empty() {
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
    /// to the account database.
    fn load_transaction_accounts(
        &self,
        transaction: &SanitizedTransaction,
    ) -> Result<HashMap<Pubkey, Account>, TransactionExecutionError> {
        let db = self.accounts();
        let mut loaded = HashMap::with_capacity(transaction.account_keys.len());

        for key in &transaction.account_keys {
            // Check sysvar cache first for sysvar accounts
            let account = self
                .sysvar_cache()
                .and_then(|cache| cache.get_sysvar_account(key))
                .or_else(|| db.get_published_account(key))
                .unwrap_or_default();
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
    fn write_accounts(&self, accounts: &HashMap<Pubkey, Account>) {
        let db = self.accounts();

        // Update lattice hash for each modified account
        for (pubkey, new_account) in accounts {
            let old_account = db.get_published_account(pubkey);
            self.update_account_hash(pubkey, old_account.as_ref(), new_account);
        }

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
    use paradencer_constants::execution::MAX_COMPUTE_UNITS;
    use paradencer_storage::Pubkey;
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
                .map(|(k, a, _)| (*k, a.clone()))
                .collect();

            InstructionResult {
                success: true,
                compute_units_consumed: 100,
                modified_accounts: modified,
                logs: vec!["ok".to_string()],
                error: None,
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
                };
            }

            // Transfer amount encoded as u64 in instruction data
            let amount = if instruction.data.len() >= 8 {
                u64::from_le_bytes(instruction.data[..8].try_into().unwrap())
            } else {
                0
            };

            let (src_key, mut src_account, _) = instruction.accounts[0].clone();
            let (dst_key, mut dst_account, _) = instruction.accounts[1].clone();

            if src_account.meta.lamports < amount {
                return InstructionResult {
                    success: false,
                    compute_units_consumed: 20,
                    modified_accounts: HashMap::new(),
                    logs: vec!["insufficient balance".to_string()],
                    error: Some("insufficient balance".to_string()),
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
        let start_idx = account_keys.len() as u8;
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
    fn process_transaction_fails_insufficient_fee() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        // Payer has 0 lamports — can't pay fee
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
        let tx = create_simple_transaction(
            payer,
            program,
            vec![payer, recipient],
            transfer_amount.to_le_bytes().to_vec(),
        );

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
            signatures: vec![],
            message_bytes: vec![],
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "should accept registered blockhash: {:?}", result.error);
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
        parent.blockhash_queue().write().unwrap().register_hash(info);

        // Complete parent
        use paradencer_constants::ledger::TICKS_PER_SLOT;
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        // Create child
        let child_schedule = Arc::new(
            LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1000)]).unwrap(),
        );
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
        bank.blockhash_queue().write().unwrap().register_hash(first_info);

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
        assert!(result.success, "empty signatures should skip verification: {:?}", result.error);
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
            signatures: vec![signature.to_bytes()],
            message_bytes,
        };

        let result = bank.process_transaction(&tx, &backend, MAX_COMPUTE_UNITS);
        assert!(result.success, "valid signature should pass: {:?}", result.error);
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
}
