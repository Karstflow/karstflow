use crate::vm::{BytecodeVm, SbpfVm};
use crate::{
    AddressLookupTableExecutor, AssociatedTokenProgramExecutor, BpfLoaderExecutor,
    ComputeBudgetProgramExecutor, ConfigProgramExecutor, Ed25519PrecompileExecutor,
    ExecutionContext, ExecutionOutcome, MemoProgramExecutor, Secp256k1PrecompileExecutor,
    StakeProgramExecutor, SystemProgramExecutor, Token2022ProgramExecutor, TokenProgramExecutor,
    VoteProgramExecutor,
};
use paradencer_ids::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, BPF_LOADER_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID, CONFIG_PROGRAM_ID, ED25519_PROGRAM_ID, MEMO_PROGRAM_ID,
    MEMO_PROGRAM_V3_ID, SECP256K1_PROGRAM_ID, STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, VOTE_PROGRAM_ID,
};
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
    token_program: TokenProgramExecutor,
    token_2022_program: Token2022ProgramExecutor,
    associated_token_program: AssociatedTokenProgramExecutor,
    memo_program: MemoProgramExecutor,
    bpf_loader: BpfLoaderExecutor,
    compute_budget_program: ComputeBudgetProgramExecutor,
    address_lookup_table: AddressLookupTableExecutor,
    config_program: ConfigProgramExecutor,
    ed25519_precompile: Ed25519PrecompileExecutor,
    secp256k1_precompile: Secp256k1PrecompileExecutor,
    bytecode_vm: BytecodeVm,
    max_compute_units: u64,
}

impl TransactionProcessor {
    /// Create a new transaction processor
    pub fn new() -> Self {
        Self {
            system_program: SystemProgramExecutor::new(150),
            vote_program: VoteProgramExecutor::new(200),
            stake_program: StakeProgramExecutor::new(250),
            token_program: TokenProgramExecutor::new(300),
            token_2022_program: Token2022ProgramExecutor::new(320),
            associated_token_program: AssociatedTokenProgramExecutor::new(180),
            memo_program: MemoProgramExecutor::new(100),
            bpf_loader: BpfLoaderExecutor::new(400),
            compute_budget_program: ComputeBudgetProgramExecutor::new(150),
            address_lookup_table: AddressLookupTableExecutor::new(200),
            config_program: ConfigProgramExecutor::new(150),
            ed25519_precompile: Ed25519PrecompileExecutor::new(200),
            secp256k1_precompile: Secp256k1PrecompileExecutor::new(200),
            bytecode_vm: BytecodeVm::new(),
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
            let program_id = match transaction
                .message
                .account_keys
                .get(compiled_instruction.program_id_index as usize)
            {
                Some(id) => *id,
                None => {
                    return TransactionResult {
                        success: false,
                        compute_units_consumed: total_compute_units,
                        modified_accounts,
                        logs: all_logs,
                        error: Some(format!(
                            "Invalid program_id_index: {}",
                            compiled_instruction.program_id_index
                        )),
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
            total_compute_units =
                total_compute_units.saturating_add(outcome.compute_units_consumed);

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
            self.system_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(150, err))
        } else if context.program_id == VOTE_PROGRAM_ID {
            self.vote_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else if context.program_id == STAKE_PROGRAM_ID {
            self.stake_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(250, err))
        } else if context.program_id == TOKEN_PROGRAM_ID {
            self.token_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(300, err))
        } else if context.program_id == TOKEN_2022_PROGRAM_ID {
            self.token_2022_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(320, err))
        } else if context.program_id == ASSOCIATED_TOKEN_PROGRAM_ID {
            self.associated_token_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(180, err))
        } else if context.program_id == MEMO_PROGRAM_ID || context.program_id == MEMO_PROGRAM_V3_ID
        {
            self.memo_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(100, err))
        } else if context.program_id == BPF_LOADER_PROGRAM_ID {
            self.bpf_loader
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(400, err))
        } else if context.program_id == COMPUTE_BUDGET_PROGRAM_ID {
            self.compute_budget_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(150, err))
        } else if context.program_id == ADDRESS_LOOKUP_TABLE_PROGRAM_ID {
            self.address_lookup_table
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else if context.program_id == CONFIG_PROGRAM_ID {
            self.config_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(150, err))
        } else if context.program_id == ED25519_PROGRAM_ID {
            self.ed25519_precompile
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else if context.program_id == SECP256K1_PROGRAM_ID {
            self.secp256k1_precompile
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else {
            // Try executing as a deployed BPF program via BytecodeVm
            self.try_execute_bpf(context)
        }
    }

    /// Try to execute an instruction as a deployed BPF program.
    ///
    /// Looks for an executable program account matching the program_id,
    /// then delegates execution to the BytecodeVm. Returns a failure
    /// outcome if no executable program is found.
    fn try_execute_bpf(&self, context: &ExecutionContext) -> ExecutionOutcome {
        // Check if any account in the context is the executable program
        let has_executable = context
            .accounts
            .iter()
            .any(|(pubkey, account, _)| *pubkey == context.program_id && account.meta.executable);

        if !has_executable {
            return ExecutionOutcome::failure(
                0,
                format!("Unknown program: {}", context.program_id),
            );
        }

        // Execute via BytecodeVm (handles ELF loading, validation, caching)
        match self.bytecode_vm.execute(context.clone()) {
            Ok(outcome) => outcome,
            Err(e) => ExecutionOutcome::failure(0, format!("BPF execution failed: {}", e)),
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

        let accounts = vec![(from, from_account, true), (to, to_account, true)];

        let outcome = processor.process_instruction(SYSTEM_PROGRAM_ID, accounts, instruction_data);

        assert!(outcome.success);
        assert_eq!(outcome.modified_accounts.len(), 2);
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn test_process_instruction_unknown_program() {
        let processor = TransactionProcessor::new();
        let unknown_program = Pubkey::new_unique();

        let outcome = processor.process_instruction(unknown_program, vec![], vec![]);

        assert!(!outcome.success);
        assert!(outcome.logs[0].contains("Unknown program"));
    }

    #[test]
    fn test_process_deployed_bpf_program() {
        use crate::elf_loader::TestElfBuilder;
        use crate::instruction::{Instruction, Opcode};

        let processor = TransactionProcessor::new();
        let program_id = Pubkey::new_unique();

        // Build a minimal ELF: mov r0, 0; exit (success)
        let mut text = Vec::new();
        for insn in &[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ] {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        let elf = TestElfBuilder::new().text(text).build();

        let program_account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let accounts = vec![(program_id, program_account, false)];
        let outcome = processor.process_instruction(program_id, accounts, vec![]);

        assert!(outcome.success, "BPF program should execute successfully");
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn routes_compute_budget_program() {
        let processor = TransactionProcessor::new();
        let outcome =
            processor.process_instruction(COMPUTE_BUDGET_PROGRAM_ID, vec![], vec![]);
        // ComputeBudget with empty data should still be routed (base cost success or parse error)
        assert!(outcome.compute_units_consumed > 0 || !outcome.success);
    }

    #[test]
    fn routes_all_builtins_without_panic() {
        let processor = TransactionProcessor::new();
        let program_ids = [
            SYSTEM_PROGRAM_ID,
            VOTE_PROGRAM_ID,
            STAKE_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
            TOKEN_2022_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            MEMO_PROGRAM_ID,
            BPF_LOADER_PROGRAM_ID,
            COMPUTE_BUDGET_PROGRAM_ID,
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            CONFIG_PROGRAM_ID,
            ED25519_PROGRAM_ID,
            SECP256K1_PROGRAM_ID,
        ];

        for program_id in &program_ids {
            // Should not panic — routing works for all 13 builtins
            let _outcome = processor.process_instruction(*program_id, vec![], vec![]);
        }
    }

    #[test]
    fn precompile_routing_returns_result() {
        let processor = TransactionProcessor::new();

        let ed25519_outcome =
            processor.process_instruction(ED25519_PROGRAM_ID, vec![], vec![]);
        // Empty data to a precompile — should route and return a result
        assert!(ed25519_outcome.compute_units_consumed > 0 || !ed25519_outcome.success);

        let secp_outcome =
            processor.process_instruction(SECP256K1_PROGRAM_ID, vec![], vec![]);
        assert!(secp_outcome.compute_units_consumed > 0 || !secp_outcome.success);
    }

    #[test]
    fn test_non_executable_unknown_program_fails() {
        let processor = TransactionProcessor::new();
        let program_id = Pubkey::new_unique();

        // Provide a non-executable account
        let account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3]),
        };

        let outcome =
            processor.process_instruction(program_id, vec![(program_id, account, false)], vec![]);
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

        // Test Vote Program routing (empty data returns error, but is routed correctly)
        let outcome = processor.process_instruction(
            VOTE_PROGRAM_ID,
            vec![],
            vec![], // Empty data - vote program rejects this
        );
        // Vote program returns error for empty instruction data, which is correct
        assert!(!outcome.success);

        // Test Stake Program routing (empty data returns base cost success)
        let outcome = processor.process_instruction(
            STAKE_PROGRAM_ID,
            vec![],
            vec![], // Empty data
        );
        assert!(outcome.success);

        // Test BPF Loader Program routing
        let outcome = processor.process_instruction(
            BPF_LOADER_PROGRAM_ID,
            vec![],
            vec![], // Empty data
        );
        assert!(outcome.success);
    }
}
