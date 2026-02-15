use crate::{ExecutionContext, ExecutionOutcome, StakeProgramExecutor, SystemProgramExecutor, VoteProgramExecutor};
use paradencer_ids::{STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID};
use paradencer_types::{Account, Pubkey};
use std::collections::HashMap;

/// Transaction instruction to be executed
#[derive(Debug, Clone)]
pub struct TransactionInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Account metadata for instruction
#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Transaction to be processed
#[derive(Debug, Clone)]
pub struct Transaction {
    pub signatures: Vec<[u8; 64]>,
    pub message: TransactionMessage,
}

/// Transaction message containing instructions
#[derive(Debug, Clone)]
pub struct TransactionMessage {
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

/// Compiled instruction with account indices
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Result of transaction processing
#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub success: bool,
    pub compute_units_consumed: u64,
    pub modified_accounts: HashMap<Pubkey, Account>,
    pub logs: Vec<String>,
    pub error: Option<String>,
}

/// Transaction processor that executes instructions
pub struct TransactionProcessor {
    system_program: SystemProgramExecutor,
    vote_program: VoteProgramExecutor,
    stake_program: StakeProgramExecutor,
    max_compute_units: u64,
}

impl TransactionProcessor {
    /// Create a new transaction processor
    pub fn new() -> Self {
        Self {
            system_program: SystemProgramExecutor::new(150),
            vote_program: VoteProgramExecutor::new(200),
            stake_program: StakeProgramExecutor::new(250),
            max_compute_units: 1_400_000,
        }
    }

    /// Create with custom compute unit limit
    pub fn with_compute_limit(mut self, max_compute_units: u64) -> Self {
        self.max_compute_units = max_compute_units;
        self
    }

    /// Process a transaction with provided account state
    pub fn process_transaction(
        &self,
        transaction: &Transaction,
        account_state: &HashMap<Pubkey, Account>,
    ) -> TransactionResult {
        let mut total_compute_units = 0u64;
        let mut modified_accounts = HashMap::new();
        let mut all_logs = Vec::new();

        // Process each instruction in sequence
        for (idx, compiled_instruction) in transaction.message.instructions.iter().enumerate() {
            // Get program ID
            let program_id = match transaction.message.account_keys.get(compiled_instruction.program_id_index as usize) {
                Some(id) => *id,
                None => {
                    return TransactionResult {
                        success: false,
                        compute_units_consumed: total_compute_units,
                        modified_accounts,
                        logs: all_logs,
                        error: Some(format!("Invalid program_id_index: {}", compiled_instruction.program_id_index)),
                    };
                }
            };

            // Resolve account references
            let mut instruction_accounts = Vec::new();
            for &account_index in &compiled_instruction.accounts {
                let pubkey = match transaction.message.account_keys.get(account_index as usize) {
                    Some(key) => *key,
                    None => {
                        return TransactionResult {
                            success: false,
                            compute_units_consumed: total_compute_units,
                            modified_accounts,
                            logs: all_logs,
                            error: Some(format!("Invalid account_index: {}", account_index)),
                        };
                    }
                };

                // Get account from state or modified accounts
                let account = modified_accounts
                    .get(&pubkey)
                    .or_else(|| account_state.get(&pubkey))
                    .cloned()
                    .unwrap_or_else(|| Account::default());

                // Determine if writable (simplified: assume all accounts in instruction are writable)
                instruction_accounts.push((pubkey, account, true));
            }

            // Create execution context
            let remaining_compute = self.max_compute_units.saturating_sub(total_compute_units);
            let context = ExecutionContext::new(
                program_id,
                instruction_accounts,
                compiled_instruction.data.clone(),
            )
            .with_compute_budget(remaining_compute);

            // Execute instruction
            let outcome = self.execute_instruction(&context);

            // Update compute units
            total_compute_units = total_compute_units.saturating_add(outcome.compute_units_consumed);

            // Add logs with instruction prefix
            for log in &outcome.logs {
                all_logs.push(format!("Program {} [{}]: {}", program_id, idx, log));
            }

            // Check for failure
            if !outcome.success {
                return TransactionResult {
                    success: false,
                    compute_units_consumed: total_compute_units,
                    modified_accounts,
                    logs: all_logs,
                    error: Some(format!("Instruction {} failed", idx)),
                };
            }

            // Merge modified accounts
            for (pubkey, account) in outcome.modified_accounts {
                modified_accounts.insert(pubkey, account);
            }

            // Check compute budget
            if total_compute_units > self.max_compute_units {
                return TransactionResult {
                    success: false,
                    compute_units_consumed: total_compute_units,
                    modified_accounts,
                    logs: all_logs,
                    error: Some("Compute budget exceeded".to_string()),
                };
            }
        }

        TransactionResult {
            success: true,
            compute_units_consumed: total_compute_units,
            modified_accounts,
            logs: all_logs,
            error: None,
        }
    }

    /// Execute a single instruction
    fn execute_instruction(&self, context: &ExecutionContext) -> ExecutionOutcome {
        // Route to appropriate program
        if context.program_id == SYSTEM_PROGRAM_ID {
            self.system_program.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(150, err)
            })
        } else if context.program_id == VOTE_PROGRAM_ID {
            self.vote_program.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(200, err)
            })
        } else if context.program_id == STAKE_PROGRAM_ID {
            self.stake_program.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(250, err)
            })
        } else {
            // Unknown program
            ExecutionOutcome::failure(
                0,
                format!("Unknown program: {}", context.program_id),
            )
        }
    }

    /// Process a simple instruction directly (for testing)
    pub fn process_instruction(
        &self,
        program_id: Pubkey,
        accounts: Vec<(Pubkey, Account, bool)>,
        instruction_data: Vec<u8>,
    ) -> ExecutionOutcome {
        let context = ExecutionContext::new(program_id, accounts, instruction_data)
            .with_compute_budget(self.max_compute_units);

        self.execute_instruction(&context)
    }
}

impl Default for TransactionProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::{AccountData, AccountMeta as TypesAccountMeta};

    #[test]
    fn test_process_instruction_system_program() {
        let processor = TransactionProcessor::new();

        // Create a simple transfer instruction
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();

        let from_account = Account {
            meta: TypesAccountMeta {
                lamports: 1000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account {
            meta: TypesAccountMeta {
                lamports: 500,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // Transfer instruction (type 2) - transfer 100 lamports
        let mut instruction_data = vec![2, 0, 0, 0]; // instruction type
        instruction_data.extend_from_slice(&100u64.to_le_bytes()); // amount

        let accounts = vec![
            (from, from_account, true),
            (to, to_account, true),
        ];

        let outcome = processor.process_instruction(
            SYSTEM_PROGRAM_ID,
            accounts,
            instruction_data,
        );

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn test_process_instruction_unknown_program() {
        let processor = TransactionProcessor::new();
        let unknown_program = Pubkey::new_unique();

        let outcome = processor.process_instruction(
            unknown_program,
            vec![],
            vec![],
        );

        assert!(!outcome.success);
        assert!(outcome.logs[0].contains("Unknown program"));
    }

    #[test]
    fn test_processor_routes_to_programs() {
        let processor = TransactionProcessor::new();

        // Test System Program routing
        let outcome = processor.process_instruction(
            SYSTEM_PROGRAM_ID,
            vec![],
            vec![], // Empty data
        );
        // Should execute (will return base cost for empty instruction)
        assert!(outcome.success);

        // Test Vote Program routing
        let outcome = processor.process_instruction(
            VOTE_PROGRAM_ID,
            vec![],
            vec![], // Empty data
        );
        assert!(outcome.success);

        // Test Stake Program routing
        let outcome = processor.process_instruction(
            STAKE_PROGRAM_ID,
            vec![],
            vec![], // Empty data
        );
        assert!(outcome.success);
    }
}
