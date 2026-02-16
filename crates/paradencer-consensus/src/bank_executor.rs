/// Bank transaction execution pipeline.
///
/// Defines the `ExecutionBackend` trait for pluggable instruction execution,
/// and implements the full transaction processing flow on Bank:
/// account loading, fee validation, instruction execution, account writeback,
/// and fee collection.
use crate::{Bank, BankStatus, FeeCalculator};
use paradencer_storage::{Account, AccountDatabase, Pubkey};
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
        }
    }
}

impl std::error::Error for TransactionExecutionError {}

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
            };
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

        // Step 6: Record fees
        self.add_execution_fee(fee);

        // Step 7: Record transaction
        let _ = self.register_transaction();

        TransactionExecutionResult {
            success: true,
            compute_units_consumed: total_compute,
            fee,
            modified_accounts: modified,
            logs: all_logs,
            error: None,
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
    fn load_transaction_accounts(
        &self,
        transaction: &SanitizedTransaction,
    ) -> Result<HashMap<Pubkey, Account>, TransactionExecutionError> {
        let db = self.accounts();
        let mut loaded = HashMap::with_capacity(transaction.account_keys.len());

        for key in &transaction.account_keys {
            let account = db.get(key).unwrap_or_default();
            loaded.insert(*key, account);
        }

        Ok(loaded)
    }

    /// Write modified accounts back to the account database.
    fn write_accounts(&self, accounts: &HashMap<Pubkey, Account>) {
        let db = self.accounts();
        for (pubkey, account) in accounts {
            db.store(pubkey, account);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochSchedule, LeaderSchedule};
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
        Bank::new_genesis(accounts, epoch_schedule, leader_schedule)
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
        bank.accounts().store(&payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, 1_400_000);

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
        let result = bank.process_transaction(&tx, &backend, 1_400_000);

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
        bank.accounts().store(&payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, 1_400_000);

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
        bank.accounts().store(&payer, &payer_account);

        let transfer_amount = 1_000_000u64;
        let tx = create_simple_transaction(
            payer,
            program,
            vec![payer, recipient],
            transfer_amount.to_le_bytes().to_vec(),
        );

        let result = bank.process_transaction(&tx, &backend, 1_400_000);
        assert!(
            result.success,
            "transfer should succeed: {:?}",
            result.error
        );

        // Check that payer lost fee + transfer
        let updated_payer = bank.accounts().get(&payer).unwrap();
        assert!(updated_payer.meta.lamports < 10_000_000 - transfer_amount);

        // Check recipient received lamports
        let updated_recipient = bank.accounts().get(&recipient).unwrap();
        assert_eq!(updated_recipient.meta.lamports, transfer_amount);
    }

    #[test]
    fn process_transactions_batch() {
        let bank = create_test_bank();
        let backend = PassthroughBackend;

        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let payer_account = Account::new(100_000_000, vec![], Pubkey::default());
        bank.accounts().store(&payer, &payer_account);

        let transactions: Vec<_> = (0..5)
            .map(|_| create_simple_transaction(payer, program, vec![payer], vec![]))
            .collect();

        let summary = bank.process_transactions(&transactions, &backend, 1_400_000);

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
        bank.accounts().store(&payer, &payer_account);

        let tx = create_simple_transaction(payer, program, vec![payer], vec![]);
        let result = bank.process_transaction(&tx, &backend, 1_400_000);

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
        bank.accounts().store(&payer, &payer_account);

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
        };

        let result = bank.process_transaction(&tx, &HeavyBackend, 1_000_000);

        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(TransactionExecutionError::ComputeBudgetExceeded { .. })
        ));
    }
}
