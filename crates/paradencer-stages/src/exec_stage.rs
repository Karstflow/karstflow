/// Execution tile for leader mode.
///
/// Receives microblocks from the pack scheduler, executes transactions
/// through the sBPF runtime, produces entries with Merkle tree hashing,
/// and emits execution results back to pack for rebate tracking.
///
/// This corresponds to Firedancer's execle tile which handles actual
/// transaction execution during block production.
use crate::pack_stage::{Microblock, PackedTransaction};
use paradencer_consensus::{
    deserialize_transaction, resolve_address_lookups, Bank, BankForks, ExecutionBackend,
};
use paradencer_constants::execution::MAX_COMPUTE_UNITS;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Classification of a transaction's landing status after execution.
///
/// This distinguishes between fully executed transactions, those that only
/// paid fees without applying state changes, and those that never landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionLanded {
    /// Transaction executed and all state changes committed.
    Landed,
    /// Transaction failed but fees were still collected (no state changes).
    LandedFeesOnly,
    /// Transaction was not included (e.g., duplicate, invalid).
    Unlanded,
}

/// Categorized transaction error codes for metrics and diagnostics.
///
/// Maps to Solana's transaction error taxonomy with additional categories
/// for pack/scheduling-level failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionErrorCode {
    /// No error — transaction succeeded.
    Success,
    /// Account required for fee payment was not found or invalid.
    InvalidAccountForFee,
    /// Insufficient lamports to pay transaction fee.
    InsufficientFundsForFee,
    /// An account referenced by the transaction was invalid.
    InvalidAccount,
    /// Transaction signature was already processed (duplicate).
    DuplicateSignature,
    /// Blockhash not found or expired.
    BlockhashNotFound,
    /// An instruction returned an error.
    InstructionError,
    /// Transaction exceeded its compute budget.
    ComputeBudgetExceeded,
    /// Address lookup table entry was not found.
    AddressLookupFailure,
    /// Transaction deserialization failed.
    DeserializationError,
    /// Transaction was too large.
    TransactionTooLarge,
    /// Account data too small for instruction.
    AccountDataTooSmall,
    /// Program execution failed (sBPF runtime error).
    ProgramExecutionFailed,
    /// Other unclassified error.
    Other,
}

impl TransactionErrorCode {
    /// Classify an error string into a structured error code.
    pub fn classify(error_msg: &str) -> Self {
        let lower = error_msg.to_lowercase();
        if lower.contains("insufficient funds") || lower.contains("insufficient lamports") {
            Self::InsufficientFundsForFee
        } else if lower.contains("invalid account") || lower.contains("account not found") {
            Self::InvalidAccount
        } else if lower.contains("blockhash") {
            Self::BlockhashNotFound
        } else if lower.contains("duplicate") {
            Self::DuplicateSignature
        } else if lower.contains("compute") || lower.contains("budget exceeded") {
            Self::ComputeBudgetExceeded
        } else if lower.contains("lookup") {
            Self::AddressLookupFailure
        } else if lower.contains("deserializ") {
            Self::DeserializationError
        } else if lower.contains("too large") {
            Self::TransactionTooLarge
        } else if lower.contains("program") || lower.contains("instruction") {
            Self::InstructionError
        } else {
            Self::Other
        }
    }
}

/// Result of executing a single transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecResult {
    /// Transaction payload (passed through for reference).
    pub payload: Vec<u8>,
    /// Whether execution succeeded.
    pub success: bool,
    /// Compute units actually consumed.
    pub compute_units_consumed: u64,
    /// Compute units that were requested but not consumed (available for rebate).
    pub compute_units_rebated: u64,
    /// Priority fee actually paid (for rebates).
    pub fee_paid: u64,
    /// Landing status classification.
    pub landed: TransactionLanded,
    /// Structured error code for metrics.
    pub error_code: TransactionErrorCode,
    /// Error message if failed.
    pub error: Option<String>,
    /// Execution logs.
    pub logs: Vec<String>,
    /// Modified account states after execution.
    pub modified_accounts: Vec<([u8; 32], Vec<u8>)>,
}

/// Per-transaction rebate information for fee refund tracking.
///
/// After execution, unused compute units may be rebated to the fee payer.
/// This structure tracks the rebate amount per transaction so the pack
/// scheduler can update its fee accounting.
#[derive(Debug, Clone)]
pub struct TransactionRebate {
    /// Index of this transaction within the microblock.
    pub tx_index: u32,
    /// Compute units that were budgeted but not consumed.
    pub rebated_cus: u64,
    /// Actual compute units consumed.
    pub actual_cus: u64,
    /// Whether this transaction was fees-only (failed but fee collected).
    pub fees_only: bool,
}

/// Aggregated rebate summary for a microblock.
#[derive(Debug, Clone, Default)]
pub struct RebateSummary {
    /// Per-transaction rebate entries.
    pub rebates: Vec<TransactionRebate>,
    /// Total rebated CUs across all transactions.
    pub total_rebated_cus: u64,
    /// Total actual CUs consumed across all transactions.
    pub total_actual_cus: u64,
}

/// Result of executing an entire microblock.
#[derive(Debug, Clone)]
pub struct MicroblockExecResult {
    /// The microblock ID.
    pub microblock_id: u64,
    /// Per-transaction results.
    pub transaction_results: Vec<TransactionExecResult>,
    /// Total compute units consumed by all transactions.
    pub total_compute_units: u64,
    /// Number of successful transactions.
    pub success_count: usize,
    /// Number of failed transactions.
    pub failure_count: usize,
    /// Number of transactions that landed (including fees-only).
    pub landed_count: usize,
    /// Number of fees-only transactions.
    pub fees_only_count: usize,
    /// Merkle root hash of the entry produced from this microblock.
    pub entry_hash: [u8; 32],
    /// Rebate summary for pack scheduler feedback.
    pub rebate_summary: RebateSummary,
}

/// Configuration for the execution tile.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    /// This execution tile's index (for multi-tile parallelism).
    pub tile_index: usize,
    /// Total number of execution tiles.
    pub tile_count: usize,
    /// Maximum CUs this tile will process before signaling busy.
    pub max_pending_cus: u64,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            tile_index: 0,
            tile_count: 1,
            max_pending_cus: 48_000_000,
        }
    }
}

/// Statistics for the execution tile.
#[derive(Debug, Default)]
pub struct ExecStats {
    pub microblocks_executed: AtomicU64,
    pub transactions_executed: AtomicU64,
    pub transactions_succeeded: AtomicU64,
    pub transactions_failed: AtomicU64,
    pub compute_units_consumed: AtomicU64,
    pub compute_units_rebated: AtomicU64,
    pub fees_collected: AtomicU64,
    // Landing classification counters.
    pub transactions_landed: AtomicU64,
    pub transactions_landed_fees_only: AtomicU64,
    pub transactions_unlanded: AtomicU64,
    // Error category counters.
    pub err_insufficient_funds: AtomicU64,
    pub err_invalid_account: AtomicU64,
    pub err_blockhash_not_found: AtomicU64,
    pub err_duplicate_signature: AtomicU64,
    pub err_instruction_error: AtomicU64,
    pub err_compute_budget: AtomicU64,
    pub err_other: AtomicU64,
}

impl ExecStats {
    pub fn snapshot(&self) -> ExecStatsSnapshot {
        ExecStatsSnapshot {
            microblocks_executed: self.microblocks_executed.load(Ordering::Relaxed),
            transactions_executed: self.transactions_executed.load(Ordering::Relaxed),
            transactions_succeeded: self.transactions_succeeded.load(Ordering::Relaxed),
            transactions_failed: self.transactions_failed.load(Ordering::Relaxed),
            compute_units_consumed: self.compute_units_consumed.load(Ordering::Relaxed),
            compute_units_rebated: self.compute_units_rebated.load(Ordering::Relaxed),
            fees_collected: self.fees_collected.load(Ordering::Relaxed),
            transactions_landed: self.transactions_landed.load(Ordering::Relaxed),
            transactions_landed_fees_only: self
                .transactions_landed_fees_only
                .load(Ordering::Relaxed),
            transactions_unlanded: self.transactions_unlanded.load(Ordering::Relaxed),
            err_insufficient_funds: self.err_insufficient_funds.load(Ordering::Relaxed),
            err_invalid_account: self.err_invalid_account.load(Ordering::Relaxed),
            err_blockhash_not_found: self.err_blockhash_not_found.load(Ordering::Relaxed),
            err_duplicate_signature: self.err_duplicate_signature.load(Ordering::Relaxed),
            err_instruction_error: self.err_instruction_error.load(Ordering::Relaxed),
            err_compute_budget: self.err_compute_budget.load(Ordering::Relaxed),
            err_other: self.err_other.load(Ordering::Relaxed),
        }
    }

    /// Increment the error category counter for a given error code.
    pub fn record_error(&self, code: TransactionErrorCode) {
        match code {
            TransactionErrorCode::Success => {}
            TransactionErrorCode::InsufficientFundsForFee => {
                self.err_insufficient_funds.fetch_add(1, Ordering::Relaxed);
            }
            TransactionErrorCode::InvalidAccount | TransactionErrorCode::InvalidAccountForFee => {
                self.err_invalid_account.fetch_add(1, Ordering::Relaxed);
            }
            TransactionErrorCode::BlockhashNotFound => {
                self.err_blockhash_not_found.fetch_add(1, Ordering::Relaxed);
            }
            TransactionErrorCode::DuplicateSignature => {
                self.err_duplicate_signature.fetch_add(1, Ordering::Relaxed);
            }
            TransactionErrorCode::InstructionError
            | TransactionErrorCode::ProgramExecutionFailed => {
                self.err_instruction_error.fetch_add(1, Ordering::Relaxed);
            }
            TransactionErrorCode::ComputeBudgetExceeded => {
                self.err_compute_budget.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.err_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Point-in-time statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct ExecStatsSnapshot {
    pub microblocks_executed: u64,
    pub transactions_executed: u64,
    pub transactions_succeeded: u64,
    pub transactions_failed: u64,
    pub compute_units_consumed: u64,
    pub compute_units_rebated: u64,
    pub fees_collected: u64,
    // Landing classification.
    pub transactions_landed: u64,
    pub transactions_landed_fees_only: u64,
    pub transactions_unlanded: u64,
    // Error categories.
    pub err_insufficient_funds: u64,
    pub err_invalid_account: u64,
    pub err_blockhash_not_found: u64,
    pub err_duplicate_signature: u64,
    pub err_instruction_error: u64,
    pub err_compute_budget: u64,
    pub err_other: u64,
}

/// Trait for the actual transaction execution backend.
/// This is pluggable to allow different execution engines.
pub trait ExecutionEngine: Send {
    /// Execute a single transaction and return the result.
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult;
}

/// A simple execution engine that always succeeds (for testing).
pub struct MockExecutionEngine {
    /// Fixed CU consumption per transaction.
    pub cu_per_tx: u64,
}

impl MockExecutionEngine {
    pub fn new(cu_per_tx: u64) -> Self {
        Self { cu_per_tx }
    }
}

impl ExecutionEngine for MockExecutionEngine {
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
        let consumed = self.cu_per_tx.min(tx.compute_units);
        let rebated = tx.compute_units.saturating_sub(consumed);
        TransactionExecResult {
            payload: tx.payload.clone(),
            success: true,
            compute_units_consumed: consumed,
            compute_units_rebated: rebated,
            fee_paid: tx.priority_fee,
            landed: TransactionLanded::Landed,
            error_code: TransactionErrorCode::Success,
            error: None,
            logs: Vec::new(),
            modified_accounts: Vec::new(),
        }
    }
}

/// Real execution engine that routes transactions through the bank pipeline.
///
/// Uses the working bank from BankForks to execute transactions with full
/// account loading, fee deduction, instruction execution via sBPF, and
/// account writeback. This replaces MockExecutionEngine in production.
pub struct BankExecutionEngine {
    bank_forks: Arc<RwLock<BankForks>>,
    backend: Arc<dyn ExecutionBackend>,
}

impl BankExecutionEngine {
    pub fn new(bank_forks: Arc<RwLock<BankForks>>, backend: Arc<dyn ExecutionBackend>) -> Self {
        Self {
            bank_forks,
            backend,
        }
    }

    fn execute_with_bank(&self, tx: &PackedTransaction, bank: &Arc<Bank>) -> TransactionExecResult {
        // Deserialize from wire format.
        let mut deserialized = match deserialize_transaction(&tx.payload) {
            Ok(d) => d,
            Err(msg) => {
                return TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: false,
                    compute_units_consumed: 0,
                    compute_units_rebated: tx.compute_units,
                    fee_paid: 0,
                    landed: TransactionLanded::Unlanded,
                    error_code: TransactionErrorCode::DeserializationError,
                    error: Some(msg),
                    logs: Vec::new(),
                    modified_accounts: Vec::new(),
                };
            }
        };

        // Resolve address lookup table references for V0 transactions.
        if !deserialized.address_table_lookups.is_empty() {
            let db = bank.accounts();
            match resolve_address_lookups(&deserialized.address_table_lookups, |pubkey| {
                db.get_published_account(pubkey)
            }) {
                Ok(resolved) => {
                    deserialized.tx.num_writable_lookup_keys = resolved.writable.len();
                    deserialized.tx.account_keys.extend(resolved.writable);
                    deserialized.tx.account_keys.extend(resolved.readonly);
                }
                Err(e) => {
                    return TransactionExecResult {
                        payload: tx.payload.clone(),
                        success: false,
                        compute_units_consumed: 0,
                        compute_units_rebated: tx.compute_units,
                        fee_paid: 0,
                        landed: TransactionLanded::Unlanded,
                        error_code: TransactionErrorCode::AddressLookupFailure,
                        error: Some(e.to_string()),
                        logs: Vec::new(),
                        modified_accounts: Vec::new(),
                    };
                }
            }
        }

        let sanitized = deserialized.tx;

        // Execute through the full bank pipeline.
        let result = bank.process_transaction(&sanitized, self.backend.as_ref(), MAX_COMPUTE_UNITS);

        let modified_accounts = result
            .modified_accounts
            .iter()
            .map(|(pubkey, account)| (pubkey.to_bytes(), account.data.as_slice().to_vec()))
            .collect();

        let consumed = result.compute_units_consumed;
        let rebated = tx.compute_units.saturating_sub(consumed);

        // Classify landing status and error code.
        let (landed, error_code) = if result.success {
            (TransactionLanded::Landed, TransactionErrorCode::Success)
        } else if result.fee > 0 {
            // Fee was collected but execution failed — fees-only landing.
            let code = result
                .error
                .as_ref()
                .map(|e| TransactionErrorCode::classify(&format!("{:?}", e)))
                .unwrap_or(TransactionErrorCode::Other);
            (TransactionLanded::LandedFeesOnly, code)
        } else {
            let code = result
                .error
                .as_ref()
                .map(|e| TransactionErrorCode::classify(&format!("{:?}", e)))
                .unwrap_or(TransactionErrorCode::Other);
            (TransactionLanded::Unlanded, code)
        };

        TransactionExecResult {
            payload: tx.payload.clone(),
            success: result.success,
            compute_units_consumed: consumed,
            compute_units_rebated: rebated,
            fee_paid: result.fee,
            landed,
            error_code,
            error: result.error.as_ref().map(|e| format!("{:?}", e)),
            logs: result.logs,
            modified_accounts,
        }
    }
}

impl ExecutionEngine for BankExecutionEngine {
    fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
        let bank_forks = self.bank_forks.read().expect("bank_forks lock poisoned");
        let bank = bank_forks.working_bank();
        self.execute_with_bank(tx, &bank)
    }
}

/// The execution tile stage.
pub struct ExecStage {
    config: ExecConfig,
    engine: Box<dyn ExecutionEngine>,
    stats: Arc<ExecStats>,
    /// Pending CUs for backpressure signaling.
    pending_cus: u64,
}

impl ExecStage {
    /// Create a new execution tile with the given engine.
    pub fn new(engine: Box<dyn ExecutionEngine>) -> Self {
        Self::with_config(engine, ExecConfig::default())
    }

    /// Create a new execution tile with the given engine and config.
    pub fn with_config(engine: Box<dyn ExecutionEngine>, config: ExecConfig) -> Self {
        Self {
            config,
            engine,
            stats: Arc::new(ExecStats::default()),
            pending_cus: 0,
        }
    }

    /// Get a shared reference to the statistics.
    pub fn stats(&self) -> Arc<ExecStats> {
        Arc::clone(&self.stats)
    }

    /// Whether this tile is busy (has too many pending CUs).
    pub fn is_busy(&self) -> bool {
        self.pending_cus >= self.config.max_pending_cus
    }

    /// Execute a microblock. Returns the execution result with
    /// per-transaction outcomes, entry hash, and rebate summary.
    pub fn execute_microblock(&mut self, microblock: &Microblock) -> MicroblockExecResult {
        let mut transaction_results = Vec::with_capacity(microblock.transactions.len());
        let mut total_cu = 0u64;
        let mut total_rebated_cu = 0u64;
        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        let mut landed_count = 0usize;
        let mut fees_only_count = 0usize;
        let mut total_fees = 0u64;
        let mut rebates = Vec::new();

        for (idx, tx) in microblock.transactions.iter().enumerate() {
            let result = self.engine.execute(tx);

            total_cu += result.compute_units_consumed;
            total_rebated_cu += result.compute_units_rebated;

            match result.landed {
                TransactionLanded::Landed => {
                    success_count += 1;
                    landed_count += 1;
                    total_fees += result.fee_paid;
                    self.stats
                        .transactions_landed
                        .fetch_add(1, Ordering::Relaxed);
                }
                TransactionLanded::LandedFeesOnly => {
                    failure_count += 1;
                    landed_count += 1;
                    fees_only_count += 1;
                    total_fees += result.fee_paid;
                    self.stats
                        .transactions_landed_fees_only
                        .fetch_add(1, Ordering::Relaxed);
                }
                TransactionLanded::Unlanded => {
                    failure_count += 1;
                    self.stats
                        .transactions_unlanded
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            // Track error category.
            self.stats.record_error(result.error_code);

            // Record rebate for pack scheduler feedback.
            if result.compute_units_rebated > 0
                || result.landed == TransactionLanded::LandedFeesOnly
            {
                rebates.push(TransactionRebate {
                    tx_index: idx as u32,
                    rebated_cus: result.compute_units_rebated,
                    actual_cus: result.compute_units_consumed,
                    fees_only: result.landed == TransactionLanded::LandedFeesOnly,
                });
            }

            transaction_results.push(result);
        }

        // Compute entry hash (simplified: hash of all tx payloads).
        let entry_hash = compute_entry_hash(&transaction_results);

        self.stats
            .microblocks_executed
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .transactions_executed
            .fetch_add(transaction_results.len() as u64, Ordering::Relaxed);
        self.stats
            .transactions_succeeded
            .fetch_add(success_count as u64, Ordering::Relaxed);
        self.stats
            .transactions_failed
            .fetch_add(failure_count as u64, Ordering::Relaxed);
        self.stats
            .compute_units_consumed
            .fetch_add(total_cu, Ordering::Relaxed);
        self.stats
            .compute_units_rebated
            .fetch_add(total_rebated_cu, Ordering::Relaxed);
        self.stats
            .fees_collected
            .fetch_add(total_fees, Ordering::Relaxed);

        MicroblockExecResult {
            microblock_id: microblock.id,
            transaction_results,
            total_compute_units: total_cu,
            success_count,
            failure_count,
            landed_count,
            fees_only_count,
            entry_hash,
            rebate_summary: RebateSummary {
                rebates,
                total_rebated_cus: total_rebated_cu,
                total_actual_cus: total_cu,
            },
        }
    }

    /// The tile's index.
    pub fn tile_index(&self) -> usize {
        self.config.tile_index
    }
}

/// Compute entry mixin hash for PoH integration.
///
/// The mixin hash is SHA-256 over the concatenation of all transaction
/// signatures in the microblock. This matches the Solana entry hash
/// convention where entries are identified by their signature set.
///
/// For transactions without a recognizable signature (too short payload),
/// the first 64 bytes of the payload are used as a stand-in.
fn compute_entry_hash(results: &[TransactionExecResult]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for result in results {
        // Transaction signature is the first 64 bytes of the payload.
        if result.payload.len() >= 64 {
            hasher.update(&result.payload[..64]);
        } else {
            hasher.update(&result.payload);
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_stage::PackedTransaction;

    fn make_tx(id: u8, cu: u64, fee: u64) -> PackedTransaction {
        PackedTransaction {
            payload: vec![id],
            blockhash: [0u8; 32],
            priority_fee: fee,
            compute_units: cu,
            total_cost: 0,
            is_vote: false,
            expires_at_slot: u64::MAX,
            write_accounts: vec![],
            read_accounts: vec![],
            data_size: 100,
            insertion_order: 0,
        }
    }

    fn make_microblock(txns: Vec<PackedTransaction>) -> Microblock {
        let total_cu: u64 = txns.iter().map(|t| t.compute_units).sum();
        let total_data: u64 = txns.iter().map(|t| t.data_size as u64).sum();
        Microblock {
            id: 0,
            target_tile: 0,
            transactions: txns,
            total_compute_units: total_cu,
            total_data_bytes: total_data,
            is_vote_only: false,
        }
    }

    #[test]
    fn execute_single_transaction() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.total_compute_units, 100_000);
        assert_eq!(result.transaction_results.len(), 1);
        assert!(result.transaction_results[0].success);
    }

    #[test]
    fn execute_multiple_transactions() {
        let engine = MockExecutionEngine::new(50_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let txns = vec![make_tx(1, 200_000, 5_000), make_tx(2, 200_000, 3_000)];
        let mb = make_microblock(txns);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 2);
        assert_eq!(result.total_compute_units, 100_000); // 50K each
    }

    #[test]
    fn failing_execution_engine() {
        struct FailEngine;
        impl ExecutionEngine for FailEngine {
            fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: false,
                    compute_units_consumed: 1_000,
                    compute_units_rebated: tx.compute_units.saturating_sub(1_000),
                    fee_paid: 0,
                    landed: TransactionLanded::Unlanded,
                    error_code: TransactionErrorCode::InstructionError,
                    error: Some("deliberate failure".to_string()),
                    logs: vec!["error".to_string()],
                    modified_accounts: Vec::new(),
                }
            }
        }

        let mut stage = ExecStage::new(Box::new(FailEngine));
        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 1);
        assert!(!result.transaction_results[0].success);
        assert!(result.transaction_results[0].error.is_some());
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result1 = stage.execute_microblock(&mb);
        let result2 = stage.execute_microblock(&mb);

        assert_eq!(result1.entry_hash, result2.entry_hash);
    }

    #[test]
    fn entry_hash_differs_for_different_txns() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb1 = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let mb2 = make_microblock(vec![make_tx(2, 200_000, 5_000)]);
        let r1 = stage.execute_microblock(&mb1);
        let r2 = stage.execute_microblock(&mb2);

        assert_ne!(r1.entry_hash, r2.entry_hash);
    }

    #[test]
    fn stats_accumulate() {
        let engine = MockExecutionEngine::new(50_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb1 = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let mb2 = make_microblock(vec![make_tx(2, 200_000, 3_000)]);

        stage.execute_microblock(&mb1);
        stage.execute_microblock(&mb2);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.microblocks_executed, 2);
        assert_eq!(snap.transactions_executed, 2);
        assert_eq!(snap.transactions_succeeded, 2);
        assert_eq!(snap.compute_units_consumed, 100_000);
        assert_eq!(snap.fees_collected, 8_000);
    }

    #[test]
    fn busy_signal() {
        let config = ExecConfig {
            max_pending_cus: 100,
            ..Default::default()
        };
        let engine = MockExecutionEngine::new(50_000);
        let stage = ExecStage::with_config(Box::new(engine), config);

        assert!(!stage.is_busy());
    }

    #[test]
    fn empty_microblock() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![]);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 0);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.total_compute_units, 0);
    }

    #[test]
    fn mock_engine_produces_rebates() {
        let engine = MockExecutionEngine::new(100_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        // Mock consumes 100K of 200K budget → 100K rebated.
        let tx = &result.transaction_results[0];
        assert_eq!(tx.compute_units_consumed, 100_000);
        assert_eq!(tx.compute_units_rebated, 100_000);
        assert_eq!(tx.landed, TransactionLanded::Landed);
        assert_eq!(tx.error_code, TransactionErrorCode::Success);

        // Rebate summary should contain the rebate entry.
        assert_eq!(result.rebate_summary.rebates.len(), 1);
        assert_eq!(result.rebate_summary.total_rebated_cus, 100_000);
        assert_eq!(result.rebate_summary.total_actual_cus, 100_000);
    }

    #[test]
    fn landing_classification_tracks_correctly() {
        struct MixedEngine;
        impl ExecutionEngine for MixedEngine {
            fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
                let id = tx.payload[0];
                match id {
                    1 => TransactionExecResult {
                        payload: tx.payload.clone(),
                        success: true,
                        compute_units_consumed: 50_000,
                        compute_units_rebated: 150_000,
                        fee_paid: 1_000,
                        landed: TransactionLanded::Landed,
                        error_code: TransactionErrorCode::Success,
                        error: None,
                        logs: vec![],
                        modified_accounts: vec![],
                    },
                    2 => TransactionExecResult {
                        payload: tx.payload.clone(),
                        success: false,
                        compute_units_consumed: 10_000,
                        compute_units_rebated: 190_000,
                        fee_paid: 500,
                        landed: TransactionLanded::LandedFeesOnly,
                        error_code: TransactionErrorCode::InstructionError,
                        error: Some("instruction error".into()),
                        logs: vec![],
                        modified_accounts: vec![],
                    },
                    _ => TransactionExecResult {
                        payload: tx.payload.clone(),
                        success: false,
                        compute_units_consumed: 0,
                        compute_units_rebated: 200_000,
                        fee_paid: 0,
                        landed: TransactionLanded::Unlanded,
                        error_code: TransactionErrorCode::BlockhashNotFound,
                        error: Some("blockhash not found".into()),
                        logs: vec![],
                        modified_accounts: vec![],
                    },
                }
            }
        }

        let mut stage = ExecStage::new(Box::new(MixedEngine));
        let txns = vec![
            make_tx(1, 200_000, 1_000),
            make_tx(2, 200_000, 500),
            make_tx(3, 200_000, 0),
        ];
        let mb = make_microblock(txns);
        let result = stage.execute_microblock(&mb);

        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 2);
        assert_eq!(result.landed_count, 2); // Landed + LandedFeesOnly.
        assert_eq!(result.fees_only_count, 1);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.transactions_landed, 1);
        assert_eq!(snap.transactions_landed_fees_only, 1);
        assert_eq!(snap.transactions_unlanded, 1);
        assert_eq!(snap.err_instruction_error, 1);
        assert_eq!(snap.err_blockhash_not_found, 1);
    }

    #[test]
    fn error_code_classification() {
        assert_eq!(
            TransactionErrorCode::classify("insufficient funds for fee"),
            TransactionErrorCode::InsufficientFundsForFee
        );
        assert_eq!(
            TransactionErrorCode::classify("blockhash not found in recent slots"),
            TransactionErrorCode::BlockhashNotFound
        );
        assert_eq!(
            TransactionErrorCode::classify("compute budget exceeded"),
            TransactionErrorCode::ComputeBudgetExceeded
        );
        assert_eq!(
            TransactionErrorCode::classify("failed to deserialize"),
            TransactionErrorCode::DeserializationError
        );
        assert_eq!(
            TransactionErrorCode::classify("unknown error xyz"),
            TransactionErrorCode::Other
        );
    }

    #[test]
    fn rebate_summary_tracks_fees_only() {
        struct FeesOnlyEngine;
        impl ExecutionEngine for FeesOnlyEngine {
            fn execute(&self, tx: &PackedTransaction) -> TransactionExecResult {
                TransactionExecResult {
                    payload: tx.payload.clone(),
                    success: false,
                    compute_units_consumed: tx.compute_units, // All CUs consumed.
                    compute_units_rebated: 0,
                    fee_paid: tx.priority_fee,
                    landed: TransactionLanded::LandedFeesOnly,
                    error_code: TransactionErrorCode::InstructionError,
                    error: Some("instruction failed".into()),
                    logs: vec![],
                    modified_accounts: vec![],
                }
            }
        }

        let mut stage = ExecStage::new(Box::new(FeesOnlyEngine));
        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        let result = stage.execute_microblock(&mb);

        // Fees-only transactions get a rebate entry even with 0 rebated CUs.
        assert_eq!(result.rebate_summary.rebates.len(), 1);
        assert!(result.rebate_summary.rebates[0].fees_only);
        assert_eq!(result.fees_only_count, 1);
    }

    #[test]
    fn stats_track_rebated_cus() {
        let engine = MockExecutionEngine::new(50_000);
        let mut stage = ExecStage::new(Box::new(engine));

        let mb = make_microblock(vec![make_tx(1, 200_000, 5_000)]);
        stage.execute_microblock(&mb);

        let snap = stage.stats().snapshot();
        assert_eq!(snap.compute_units_consumed, 50_000);
        assert_eq!(snap.compute_units_rebated, 150_000);
    }
}
