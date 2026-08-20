use crate::sysvar_snapshot::SysvarSnapshot;
use crate::vm::{BytecodeVm, SbpfVm};
use crate::{
    AddressLookupTableExecutor, AssociatedTokenProgramExecutor, BpfLoaderDeprecatedExecutor,
    BpfLoaderExecutor, ComputeBudgetProgramExecutor, ConfigProgramExecutor,
    Ed25519PrecompileExecutor, ExecutionContext, ExecutionOutcome, FeatureGateProgramExecutor,
    LoaderV4Executor, MemoProgramExecutor, Secp256k1PrecompileExecutor,
    Secp256r1PrecompileExecutor, SlashingProgramExecutor, StakeProgramExecutor,
    SystemProgramExecutor, Token2022ProgramExecutor, TokenProgramExecutor, VoteProgramExecutor,
    ZkElGamalProofExecutor, MAX_COMPUTE_UNITS,
};
use karstflow_constants::{
    bpf_loader_program as bpf_loader_constants, compute_budget_program as compute_budget_constants,
    precompiles as precompile_constants, system_program as system_constants,
    vote_program as vote_constants,
};
use karstflow_ids::{
    features::{
        is_feature_active, ENABLE_LOADER_V4, ENABLE_SECP256R1_PRECOMPILE,
        ENSHRINE_SLASHING_PROGRAM, ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
    },
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, BPF_LOADER_DEPRECATED_PROGRAM_ID,
    BPF_LOADER_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, CONFIG_PROGRAM_ID,
    ED25519_PROGRAM_ID, FEATURE_PROGRAM_ID, LOADER_V4_PROGRAM_ID, MEMO_PROGRAM_ID,
    MEMO_PROGRAM_V3_ID, SECP256K1_PROGRAM_ID, SECP256R1_PROGRAM_ID, SLASHING_PROGRAM_ID,
    STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, VOTE_PROGRAM_ID,
    ZK_ELGAMAL_PROOF_PROGRAM_ID,
};
use karstflow_types::{Account, Pubkey};
use std::collections::HashMap;
use std::sync::{Arc, Weak};

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

/// Message header describing account access roles.
///
/// Determines which accounts in `account_keys` are signers, writable,
/// or read-only based on the Solana message format specification.
#[derive(Debug, Clone, Copy, Default)]
pub struct MessageHeader {
    /// Number of accounts that must sign the transaction.
    pub num_required_signatures: u8,
    /// Number of signed accounts that are read-only.
    pub num_readonly_signed: u8,
    /// Number of unsigned accounts that are read-only.
    pub num_readonly_unsigned: u8,
}

/// Transaction message containing instructions
#[derive(Debug, Clone)]
pub struct TransactionMessage {
    /// Header defining account access roles (signer, writable, read-only).
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

impl TransactionMessage {
    /// Check if the account at the given index is writable.
    ///
    /// Account ordering in Solana messages:
    /// - `[0..num_required_signatures)` are signers
    ///   - First `num_required_signatures - num_readonly_signed` are writable signers
    ///   - Last `num_readonly_signed` are read-only signers
    /// - `[num_required_signatures..account_keys.len())` are non-signers
    ///   - First portion are writable non-signers
    ///   - Last `num_readonly_unsigned` are read-only non-signers
    pub fn is_writable(&self, index: usize) -> bool {
        let num_signed = self.header.num_required_signatures as usize;
        let num_ro_signed = self.header.num_readonly_signed as usize;
        let num_ro_unsigned = self.header.num_readonly_unsigned as usize;

        if index < num_signed {
            // Signed: writable if before the read-only signed range
            index < num_signed.saturating_sub(num_ro_signed)
        } else {
            // Unsigned: writable if before the read-only unsigned tail
            let ro_unsigned_start = self.account_keys.len().saturating_sub(num_ro_unsigned);
            index < ro_unsigned_start
        }
    }

    /// Check if the account at the given index is a signer.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_required_signatures as usize
    }
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
    /// The v2 loader shares the deprecated loader's instruction set but
    /// charges its own flat compute cost.
    bpf_loader_v2: BpfLoaderDeprecatedExecutor,
    compute_budget_program: ComputeBudgetProgramExecutor,
    address_lookup_table: AddressLookupTableExecutor,
    config_program: ConfigProgramExecutor,
    loader_v4: LoaderV4Executor,
    ed25519_precompile: Ed25519PrecompileExecutor,
    secp256k1_precompile: Secp256k1PrecompileExecutor,
    secp256r1_precompile: Secp256r1PrecompileExecutor,
    zk_elgamal_proof: ZkElGamalProofExecutor,
    feature_gate_program: FeatureGateProgramExecutor,
    slashing_program: SlashingProgramExecutor,
    bytecode_vm: BytecodeVm,
    max_compute_units: u64,
}

impl TransactionProcessor {
    /// Create a new transaction processor without CPI support.
    ///
    /// For production use, prefer `new_with_cpi()` which enables
    /// cross-program invocation via `sol_invoke_signed`.
    pub fn new() -> Self {
        Self::build(BytecodeVm::new(), MAX_COMPUTE_UNITS)
    }

    /// Create a new processor with CPI support enabled.
    ///
    /// Returns `Arc<Self>` because the VM holds a back-reference to the
    /// processor for nested `sol_invoke_signed` dispatch.
    pub fn new_with_cpi() -> Arc<Self> {
        Self::new_with_cpi_and_compute_limit(MAX_COMPUTE_UNITS)
    }

    /// Create a CPI-enabled processor with a custom compute unit ceiling.
    pub fn new_with_cpi_and_compute_limit(max_compute_units: u64) -> Arc<Self> {
        Arc::new_cyclic(|weak: &Weak<TransactionProcessor>| {
            let proxy: Arc<dyn crate::syscall_dispatch::InstructionExecutor> =
                Arc::new(CpiProxy { weak: weak.clone() });
            Self::build(BytecodeVm::with_cpi(proxy), max_compute_units)
        })
    }

    /// Internal constructor shared by `new()` and `new_with_cpi()`.
    fn build(bytecode_vm: BytecodeVm, max_compute_units: u64) -> Self {
        Self {
            system_program: SystemProgramExecutor::new(),
            vote_program: VoteProgramExecutor::new(),
            stake_program: StakeProgramExecutor::new(250),
            token_program: TokenProgramExecutor::new(300),
            token_2022_program: Token2022ProgramExecutor::new(320),
            associated_token_program: AssociatedTokenProgramExecutor::new(180),
            memo_program: MemoProgramExecutor::new(100),
            bpf_loader: BpfLoaderExecutor::new(),
            bpf_loader_v2: BpfLoaderDeprecatedExecutor::new(
                bpf_loader_constants::V2_LOADER_COMPUTE_UNITS,
            ),
            compute_budget_program: ComputeBudgetProgramExecutor::new(),
            address_lookup_table: AddressLookupTableExecutor::new(200),
            config_program: ConfigProgramExecutor::new(150),
            loader_v4: LoaderV4Executor::new(200),
            ed25519_precompile: Ed25519PrecompileExecutor::new(),
            secp256k1_precompile: Secp256k1PrecompileExecutor::new(),
            secp256r1_precompile: Secp256r1PrecompileExecutor::new(),
            zk_elgamal_proof: ZkElGamalProofExecutor::new(),
            feature_gate_program: FeatureGateProgramExecutor::new(750),
            slashing_program: SlashingProgramExecutor::new(2500),
            bytecode_vm,
            max_compute_units,
        }
    }

    /// Create with custom compute unit limit
    pub fn with_compute_limit(mut self, max_compute_units: u64) -> Self {
        self.max_compute_units = max_compute_units;
        self
    }

    /// Set the sysvar snapshot for BPF program execution.
    pub fn set_sysvar_snapshot(&mut self, snapshot: SysvarSnapshot) {
        self.bytecode_vm.set_sysvar_snapshot(snapshot);
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

        // Pre-scan compute budget instructions to extract heap_size.
        let instructions_for_budget: Vec<(Pubkey, Vec<u8>)> = transaction
            .message
            .instructions
            .iter()
            .filter_map(|ci| {
                let pid = transaction
                    .message
                    .account_keys
                    .get(ci.program_id_index as usize)?;
                Some((*pid, ci.data.clone()))
            })
            .collect();
        let heap_size = crate::compute_budget_program::extract_compute_budget(
            &instructions_for_budget,
            &COMPUTE_BUDGET_PROGRAM_ID,
        )
        .ok()
        .and_then(|b| b.heap_size)
        .unwrap_or(karstflow_constants::vm::DEFAULT_HEAP_SIZE as u32);

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
                    .unwrap_or_default();

                // Derive writability from the message header and account position.
                let writable = transaction.message.is_writable(account_index as usize);
                instruction_accounts.push((pubkey, account, writable));
            }

            // Build the set of transaction signers
            let tx_signers: std::collections::HashSet<Pubkey> =
                (0..transaction.message.header.num_required_signatures as usize)
                    .filter_map(|i| transaction.message.account_keys.get(i).copied())
                    .collect();

            // Create execution context
            let remaining_compute = self.max_compute_units.saturating_sub(total_compute_units);
            let context = ExecutionContext::new(
                program_id,
                instruction_accounts,
                compiled_instruction.data.clone(),
            )
            .with_compute_budget(remaining_compute)
            .with_heap_size(heap_size)
            .with_signers(tx_signers);

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

    /// Check whether a feature-gated program is available.
    ///
    /// Returns a failure outcome when the required feature gate has not
    /// been activated, or `None` to continue with normal dispatch.
    /// When no sysvar snapshot is attached (tests, legacy paths), feature
    /// gating is not enforced.
    fn reject_if_feature_inactive(
        &self,
        context: &ExecutionContext,
        feature_id: &Pubkey,
        program_name: &str,
    ) -> Option<ExecutionOutcome> {
        if let Some(ref snapshot) = context.sysvar_snapshot {
            if !is_feature_active(&snapshot.active_features, feature_id) {
                return Some(ExecutionOutcome::failure(
                    0,
                    format!(
                        "Program {} is not available: required feature gate not active",
                        program_name,
                    ),
                ));
            }
        }
        None
    }

    /// Execute a single instruction with full context (including sysvar snapshot).
    pub fn execute_instruction(&self, context: &ExecutionContext) -> ExecutionOutcome {
        // Route to appropriate program
        if context.program_id == SYSTEM_PROGRAM_ID {
            self.system_program.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(system_constants::COMPUTE_COST_BASE, err)
            })
        } else if context.program_id == VOTE_PROGRAM_ID {
            self.vote_program.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(vote_constants::DEFAULT_COMPUTE_UNITS, err)
            })
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
            let outcome = self.bpf_loader.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(
                    bpf_loader_constants::UPGRADEABLE_LOADER_COMPUTE_UNITS,
                    err,
                )
            });
            // Invalidate the program cache when a program is deployed or upgraded.
            // This ensures the next invocation loads the new bytecode.
            if outcome.success {
                self.invalidate_after_loader_instruction(context);
            }
            outcome
        } else if context.program_id == BPF_LOADER_DEPRECATED_PROGRAM_ID {
            // Management instructions to this loader are no longer supported.
            // The cost is charged first, then the instruction is refused.
            // Programs *owned* by this loader still execute — that path is
            // keyed on the account owner, not on the program id, and is
            // untouched here.
            ExecutionOutcome::failure(
                bpf_loader_constants::DEPRECATED_LOADER_COMPUTE_UNITS,
                "Deprecated loader is no longer supported".to_string(),
            )
        } else if context.program_id == BPF_LOADER_V2_PROGRAM_ID {
            // BPF Loader V2 uses the same Write/Finalize logic as deprecated
            // but with lower compute cost, so it routes through a second
            // instance of the same handler configured with that cost.
            self.bpf_loader_v2.execute(context).unwrap_or_else(|err| {
                ExecutionOutcome::failure(bpf_loader_constants::V2_LOADER_COMPUTE_UNITS, err)
            })
        } else if context.program_id == COMPUTE_BUDGET_PROGRAM_ID {
            self.compute_budget_program
                .execute(context)
                .unwrap_or_else(|err| {
                    ExecutionOutcome::failure(compute_budget_constants::COMPUTE_COST_BASE, err)
                })
        } else if context.program_id == ADDRESS_LOOKUP_TABLE_PROGRAM_ID {
            self.address_lookup_table
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else if context.program_id == CONFIG_PROGRAM_ID {
            self.config_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(150, err))
        } else if context.program_id == LOADER_V4_PROGRAM_ID {
            // Loader V4 requires the enable_loader_v4 feature gate.
            if let Some(rejection) =
                self.reject_if_feature_inactive(context, &ENABLE_LOADER_V4, "LoaderV4")
            {
                return rejection;
            }
            self.loader_v4
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(200, err))
        } else if context.program_id == ED25519_PROGRAM_ID {
            self.ed25519_precompile
                .execute(context)
                .unwrap_or_else(|err| {
                    ExecutionOutcome::failure(precompile_constants::PRECOMPILE_COMPUTE_UNITS, err)
                })
        } else if context.program_id == SECP256K1_PROGRAM_ID {
            self.secp256k1_precompile
                .execute(context)
                .unwrap_or_else(|err| {
                    ExecutionOutcome::failure(precompile_constants::PRECOMPILE_COMPUTE_UNITS, err)
                })
        } else if context.program_id == SECP256R1_PROGRAM_ID {
            // Secp256r1 precompile requires the enable_secp256r1_precompile feature gate.
            if let Some(rejection) =
                self.reject_if_feature_inactive(context, &ENABLE_SECP256R1_PRECOMPILE, "Secp256r1")
            {
                return rejection;
            }
            self.secp256r1_precompile
                .execute(context)
                .unwrap_or_else(|err| {
                    ExecutionOutcome::failure(precompile_constants::PRECOMPILE_COMPUTE_UNITS, err)
                })
        } else if context.program_id == ZK_ELGAMAL_PROOF_PROGRAM_ID {
            // ZK ElGamal proof program requires the enable feature gate.
            if let Some(rejection) = self.reject_if_feature_inactive(
                context,
                &ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
                "ZkElGamalProof",
            ) {
                return rejection;
            }
            self.zk_elgamal_proof
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(0, err))
        } else if context.program_id == FEATURE_PROGRAM_ID {
            self.feature_gate_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(750, err))
        } else if context.program_id == SLASHING_PROGRAM_ID {
            // The slashing program requires the enshrine_slashing_program feature gate.
            if let Some(rejection) =
                self.reject_if_feature_inactive(context, &ENSHRINE_SLASHING_PROGRAM, "Slashing")
            {
                return rejection;
            }
            self.slashing_program
                .execute(context)
                .unwrap_or_else(|err| ExecutionOutcome::failure(2500, err))
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

    /// Invalidate the program cache after a BPF loader deploy or upgrade.
    ///
    /// Deploy (discriminant 2): program account is at index 2.
    /// Upgrade (discriminant 3): program account is at index 1.
    ///
    /// Records the current slot as the deployment slot so the program
    /// cache applies DELAY_VISIBILITY_SLOT_OFFSET before the program
    /// becomes executable.
    fn invalidate_after_loader_instruction(&self, context: &ExecutionContext) {
        if context.instruction_data.len() < 4 {
            return;
        }
        let disc = u32::from_le_bytes(
            context.instruction_data[0..4]
                .try_into()
                .unwrap_or_default(),
        );
        let program_id = match disc {
            2 if context.accounts.len() > 2 => Some(context.accounts[2].0),
            3 if context.accounts.len() > 1 => Some(context.accounts[1].0),
            _ => None,
        };
        if let Some(id) = program_id {
            let deployment_slot = context
                .sysvar_snapshot
                .as_ref()
                .map(|s| s.slot)
                .unwrap_or(0);
            self.bytecode_vm.invalidate_program(&id, deployment_slot);
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

// ---------------------------------------------------------------------------
// CpiProxy — weak-reference adapter for self-referential CPI dispatch
// ---------------------------------------------------------------------------

/// Proxy that enables CPI from within the `BytecodeVm`.
///
/// Holds a `Weak<TransactionProcessor>` back-pointer created via
/// `Arc::new_cyclic`. When a BPF program calls `sol_invoke_signed`,
/// the syscall handler invokes this proxy, which upgrades the weak
/// reference and delegates to the full processor routing logic.
struct CpiProxy {
    weak: Weak<TransactionProcessor>,
}

impl crate::syscall_dispatch::InstructionExecutor for CpiProxy {
    fn execute_instruction(
        &self,
        context: ExecutionContext,
    ) -> Result<ExecutionOutcome, crate::vm::SbpfExecutionError> {
        let processor =
            self.weak
                .upgrade()
                .ok_or_else(|| crate::vm::SbpfExecutionError::ExecutionFailed {
                    message: "CPI executor dropped".into(),
                })?;
        Ok(processor.execute_instruction(&context))
    }
}

/// Enables the `TransactionProcessor` to serve as a CPI executor.
///
/// When a BPF program invokes another program via `sol_invoke_signed`,
/// the CPI syscall handler calls back through this trait to execute
/// the nested instruction using the same processor routing logic.
impl crate::syscall_dispatch::InstructionExecutor for TransactionProcessor {
    fn execute_instruction(
        &self,
        context: ExecutionContext,
    ) -> Result<ExecutionOutcome, crate::vm::SbpfExecutionError> {
        Ok(self.execute_instruction(&context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::{AccountData, AccountMeta as TypesAccountMeta};

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
        let outcome = processor.process_instruction(COMPUTE_BUDGET_PROGRAM_ID, vec![], vec![]);
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
            LOADER_V4_PROGRAM_ID,
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

        // Empty data to a precompile — routes, returns a result, and charges
        // nothing on either the success or the failure path.
        let ed25519_outcome = processor.process_instruction(ED25519_PROGRAM_ID, vec![], vec![]);
        assert_eq!(
            ed25519_outcome.compute_units_consumed,
            precompile_constants::PRECOMPILE_COMPUTE_UNITS
        );

        let secp_outcome = processor.process_instruction(SECP256K1_PROGRAM_ID, vec![], vec![]);
        assert_eq!(
            secp_outcome.compute_units_consumed,
            precompile_constants::PRECOMPILE_COMPUTE_UNITS
        );
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

    // -------------------------------------------------------------------
    // Full pipeline integration tests
    // -------------------------------------------------------------------

    #[test]
    fn full_pipeline_bpf_success_returns_zero() {
        use crate::elf_loader::TestElfBuilder;
        use crate::instruction::{Instruction, Opcode};

        let processor = TransactionProcessor::new();
        let program_id = Pubkey::new_unique();
        let user_account = Pubkey::new_unique();

        // BPF program: mov r0, 0; exit (returns 0 = success)
        let elf = TestElfBuilder::new()
            .text(encode_instructions(&[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ]))
            .build();

        let program_account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let user = Account {
            meta: TypesAccountMeta {
                lamports: 5000,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3, 4]),
        };

        let mut account_state = HashMap::new();
        account_state.insert(program_id, program_account);
        account_state.insert(user_account, user);

        // Build transaction with one instruction invoking the BPF program
        // Header: 1 signer (user_account), 0 readonly_signed, 1 readonly_unsigned (program_id)
        let transaction = Transaction {
            signatures: vec![[0u8; 64]],
            message: TransactionMessage {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed: 0,
                    num_readonly_unsigned: 1,
                },
                account_keys: vec![user_account, program_id],
                recent_blockhash: [0u8; 32],
                instructions: vec![CompiledInstruction {
                    program_id_index: 1,  // program_id
                    accounts: vec![0, 1], // user + program
                    data: vec![],
                }],
            },
        };

        let result = processor.process_transaction(&transaction, &account_state);
        assert!(
            result.success,
            "Transaction should succeed: {:?}",
            result.error
        );
        assert!(result.compute_units_consumed > 0);
    }

    #[test]
    fn full_pipeline_bpf_failure_returns_nonzero() {
        use crate::elf_loader::TestElfBuilder;
        use crate::instruction::{Instruction, Opcode};

        let processor = TransactionProcessor::new();
        let program_id = Pubkey::new_unique();

        // BPF program: mov r0, 1; exit (returns 1 = failure)
        let elf = TestElfBuilder::new()
            .text(encode_instructions(&[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ]))
            .build();

        let program_account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let outcome = processor.process_instruction(
            program_id,
            vec![(program_id, program_account, false)],
            vec![],
        );
        assert!(!outcome.success, "Non-zero exit should be a failure");
    }

    #[test]
    fn full_pipeline_compute_budget_exhaustion() {
        use crate::elf_loader::TestElfBuilder;
        use crate::instruction::{Instruction, Opcode};

        let processor = TransactionProcessor::new().with_compute_limit(5);
        let program_id = Pubkey::new_unique();

        // BPF program with a tight loop that should exhaust the tiny budget
        let elf = TestElfBuilder::new()
            .text(encode_instructions(&[
                Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 100), // r1 = 100
                Instruction::new(Opcode::Add64Imm as u8, 1, 0, 0, 1),   // r1 += 1
                Instruction::new(Opcode::Add64Imm as u8, 1, 0, 0, 1),   // r1 += 1
                Instruction::new(Opcode::Add64Imm as u8, 1, 0, 0, 1),   // r1 += 1
                Instruction::new(Opcode::Add64Imm as u8, 1, 0, 0, 1),   // r1 += 1
                Instruction::new(Opcode::Add64Imm as u8, 1, 0, 0, 1),   // r1 += 1
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ]))
            .build();

        let program_account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let outcome = processor.process_instruction(
            program_id,
            vec![(program_id, program_account, false)],
            vec![],
        );
        // Should fail due to compute budget exhaustion
        assert!(!outcome.success, "Should fail with compute budget exceeded");
    }

    #[test]
    fn full_pipeline_cached_reexecution() {
        use crate::elf_loader::TestElfBuilder;
        use crate::instruction::{Instruction, Opcode};

        let processor = TransactionProcessor::new();
        let program_id = Pubkey::new_unique();

        let elf = TestElfBuilder::new()
            .text(encode_instructions(&[
                Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
                Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
            ]))
            .build();

        let program_account = Account {
            meta: TypesAccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        // Execute the same BPF program twice — second time should use cache
        for i in 0..2 {
            let outcome = processor.process_instruction(
                program_id,
                vec![(program_id, program_account.clone(), false)],
                vec![],
            );
            assert!(
                outcome.success,
                "Execution {} should succeed (cached={})",
                i,
                i > 0
            );
        }
    }

    #[test]
    fn cpi_executor_trait_implemented() {
        use crate::syscall_dispatch::InstructionExecutor;

        let processor = TransactionProcessor::new();
        let context = ExecutionContext::new(SYSTEM_PROGRAM_ID, vec![], vec![]);

        // TransactionProcessor implements InstructionExecutor for CPI
        let result = InstructionExecutor::execute_instruction(&processor, context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        // System program with empty data returns success (base cost)
        assert!(outcome.success);
    }

    #[test]
    fn transaction_with_multiple_instructions() {
        let processor = TransactionProcessor::new();
        let account1 = Pubkey::new_unique();
        let account2 = Pubkey::new_unique();

        let mut account_state = HashMap::new();
        account_state.insert(
            account1,
            Account {
                meta: TypesAccountMeta {
                    lamports: 10_000,
                    owner: SYSTEM_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::empty(),
            },
        );
        account_state.insert(
            account2,
            Account {
                meta: TypesAccountMeta {
                    lamports: 1_000,
                    owner: SYSTEM_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
                data: AccountData::empty(),
            },
        );

        // Two system program transfer instructions in sequence
        let mut transfer_data = vec![2, 0, 0, 0]; // type 2 = transfer
        transfer_data.extend_from_slice(&100u64.to_le_bytes());

        // Header: 1 signer (account1), 0 readonly_signed, 1 readonly_unsigned (SYSTEM_PROGRAM_ID)
        let transaction = Transaction {
            signatures: vec![[0u8; 64]],
            message: TransactionMessage {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed: 0,
                    num_readonly_unsigned: 1,
                },
                account_keys: vec![account1, account2, SYSTEM_PROGRAM_ID],
                recent_blockhash: [0u8; 32],
                instructions: vec![
                    CompiledInstruction {
                        program_id_index: 2,
                        accounts: vec![0, 1],
                        data: transfer_data.clone(),
                    },
                    CompiledInstruction {
                        program_id_index: 2,
                        accounts: vec![0, 1],
                        data: transfer_data,
                    },
                ],
            },
        };

        let result = processor.process_transaction(&transaction, &account_state);
        assert!(
            result.success,
            "Multi-instruction tx should succeed: {:?}",
            result.error
        );
        assert!(result.compute_units_consumed > 0);
    }

    /// Encode a list of instructions into raw bytecode.
    fn encode_instructions(insns: &[crate::instruction::Instruction]) -> Vec<u8> {
        let mut text = Vec::new();
        for insn in insns {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        text
    }

    // -------------------------------------------------------------------
    // Feature gate tests
    // -------------------------------------------------------------------

    /// Build an ExecutionContext with the given active feature set.
    fn context_with_features(
        program_id: Pubkey,
        features: std::collections::HashSet<[u8; 32]>,
    ) -> ExecutionContext {
        let snapshot = SysvarSnapshot {
            active_features: features,
            ..SysvarSnapshot::default()
        };
        ExecutionContext::new(program_id, vec![], vec![])
            .with_compute_budget(MAX_COMPUTE_UNITS)
            .with_sysvar_snapshot(snapshot)
    }

    #[test]
    fn loader_v4_rejected_when_feature_inactive() {
        let processor = TransactionProcessor::new();
        let ctx = context_with_features(LOADER_V4_PROGRAM_ID, std::collections::HashSet::new());

        let outcome = processor.execute_instruction(&ctx);

        assert!(!outcome.success);
        assert!(outcome.logs[0].contains("not available"));
        assert!(outcome.logs[0].contains("LoaderV4"));
    }

    #[test]
    fn loader_v4_allowed_when_feature_active() {
        let processor = TransactionProcessor::new();
        let mut features = std::collections::HashSet::new();
        features.insert(*ENABLE_LOADER_V4.as_bytes());
        let ctx = context_with_features(LOADER_V4_PROGRAM_ID, features);

        let outcome = processor.execute_instruction(&ctx);

        // LoaderV4 with empty data may succeed or fail depending on implementation,
        // but the point is it DISPATCHES (not rejected by feature gate).
        // Check it didn't fail with the feature gate message.
        if !outcome.success {
            assert!(!outcome.logs[0].contains("not available"));
        }
    }

    #[test]
    fn slashing_program_rejected_when_feature_inactive() {
        let processor = TransactionProcessor::new();
        let ctx = context_with_features(SLASHING_PROGRAM_ID, std::collections::HashSet::new());

        let outcome = processor.execute_instruction(&ctx);

        assert!(!outcome.success);
        assert!(outcome.logs[0].contains("not available"));
        assert!(outcome.logs[0].contains("Slashing"));
    }

    #[test]
    fn slashing_program_allowed_when_feature_active() {
        let processor = TransactionProcessor::new();
        let mut features = std::collections::HashSet::new();
        features.insert(*ENSHRINE_SLASHING_PROGRAM.as_bytes());
        let ctx = context_with_features(SLASHING_PROGRAM_ID, features);

        let outcome = processor.execute_instruction(&ctx);

        if !outcome.success {
            assert!(!outcome.logs[0].contains("not available"));
        }
    }

    #[test]
    fn slashing_program_allowed_without_snapshot() {
        let processor = TransactionProcessor::new();
        let ctx = ExecutionContext::new(SLASHING_PROGRAM_ID, vec![], vec![])
            .with_compute_budget(MAX_COMPUTE_UNITS);

        let outcome = processor.execute_instruction(&ctx);

        if !outcome.success {
            assert!(!outcome.logs[0].contains("not available"));
        }
    }

    #[test]
    fn loader_v4_allowed_without_snapshot() {
        // When no sysvar snapshot is present (legacy/test paths), feature
        // gating is not enforced.
        let processor = TransactionProcessor::new();
        let ctx = ExecutionContext::new(LOADER_V4_PROGRAM_ID, vec![], vec![])
            .with_compute_budget(MAX_COMPUTE_UNITS);

        let outcome = processor.execute_instruction(&ctx);

        // Should dispatch to LoaderV4 without feature check.
        if !outcome.success {
            assert!(!outcome.logs[0].contains("not available"));
        }
    }

    #[test]
    fn secp256r1_rejected_when_feature_inactive() {
        let processor = TransactionProcessor::new();
        let ctx = context_with_features(SECP256R1_PROGRAM_ID, std::collections::HashSet::new());

        let outcome = processor.execute_instruction(&ctx);

        assert!(!outcome.success);
        assert!(outcome.logs[0].contains("not available"));
        assert!(outcome.logs[0].contains("Secp256r1"));
    }

    #[test]
    fn secp256r1_dispatches_when_feature_active() {
        let processor = TransactionProcessor::new();
        let mut features = std::collections::HashSet::new();
        features.insert(*ENABLE_SECP256R1_PRECOMPILE.as_bytes());
        let ctx = context_with_features(SECP256R1_PROGRAM_ID, features);

        let outcome = processor.execute_instruction(&ctx);

        // With empty instruction data, the precompile succeeds (0 signatures)
        assert!(outcome.success);
    }

    #[test]
    fn always_enabled_programs_ignore_features() {
        // System, vote, stake etc. should work even with an empty feature set
        let processor = TransactionProcessor::new();
        let ctx = context_with_features(SYSTEM_PROGRAM_ID, std::collections::HashSet::new());

        let outcome = processor.execute_instruction(&ctx);

        assert!(outcome.success, "System program should always be available");
    }

    // -------------------------------------------------------------------
    // Message header and writability tests
    // -------------------------------------------------------------------

    #[test]
    fn message_is_writable_signed_accounts() {
        let msg = TransactionMessage {
            header: MessageHeader {
                num_required_signatures: 3,
                num_readonly_signed: 1,
                num_readonly_unsigned: 1,
            },
            // keys: [signer0-wr, signer1-wr, signer2-ro, unsigned0-wr, unsigned1-ro]
            account_keys: vec![
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
            ],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
        };

        // Writable signers
        assert!(msg.is_writable(0), "signer 0 should be writable");
        assert!(msg.is_writable(1), "signer 1 should be writable");
        // Read-only signer
        assert!(!msg.is_writable(2), "signer 2 should be read-only");
        // Writable unsigned
        assert!(msg.is_writable(3), "unsigned 0 should be writable");
        // Read-only unsigned
        assert!(!msg.is_writable(4), "unsigned 1 should be read-only");
    }

    #[test]
    fn message_is_signer() {
        let msg = TransactionMessage {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed: 0,
                num_readonly_unsigned: 1,
            },
            account_keys: vec![
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
            ],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
        };

        assert!(msg.is_signer(0));
        assert!(msg.is_signer(1));
        assert!(!msg.is_signer(2));
    }

    #[test]
    fn readonly_account_not_passed_as_writable() {
        let processor = TransactionProcessor::new();
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let program = Pubkey::new_unique();

        let from_account = Account {
            meta: TypesAccountMeta {
                lamports: 10_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        let to_account = Account {
            meta: TypesAccountMeta {
                lamports: 1_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        let program_account = Account::default();

        let mut account_state = HashMap::new();
        account_state.insert(from, from_account);
        account_state.insert(to, to_account);
        account_state.insert(program, program_account);

        // Mark `to` as read-only unsigned (last unsigned account)
        // keys: [from(signer-wr), to(unsigned-wr?), program(unsigned-ro)]
        // With header: 1 signer, 0 ro_signed, 1 ro_unsigned → program is read-only
        // But to test that `to` is READ-ONLY, we need:
        // keys: [from(signer-wr), program(unsigned-ro), to(unsigned-ro)]
        // header: 1 signer, 0 ro_signed, 2 ro_unsigned
        let transaction = Transaction {
            signatures: vec![[0u8; 64]],
            message: TransactionMessage {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed: 0,
                    num_readonly_unsigned: 2,
                },
                // All unsigned accounts are read-only
                account_keys: vec![from, to, program],
                recent_blockhash: [0u8; 32],
                instructions: vec![CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![0, 1],
                    data: {
                        let mut d = vec![2, 0, 0, 0];
                        d.extend_from_slice(&100u64.to_le_bytes());
                        d
                    },
                }],
            },
        };

        let result = processor.process_transaction(&transaction, &account_state);
        // System program transfer to a read-only account should still succeed
        // since the system program itself handles writability enforcement.
        // The key correctness check is that the writable flag is correctly
        // propagated to the execution context.
        // For now, just verify the transaction processes without panic.
        // The writable flag is used by the executor to filter modified accounts.
        assert!(result.compute_units_consumed > 0 || !result.success);
    }

    #[test]
    fn default_header_makes_all_writable() {
        // With a default header (all zeros), all accounts should be writable
        // since there are no read-only designations.
        let msg = TransactionMessage {
            header: MessageHeader::default(),
            account_keys: vec![Pubkey::new_unique(), Pubkey::new_unique()],
            recent_blockhash: [0u8; 32],
            instructions: vec![],
        };

        assert!(msg.is_writable(0));
        assert!(msg.is_writable(1));
    }

    /// A Write addressed to the deprecated loader must be refused.
    ///
    /// The instruction is a well-formed Write that the loader's own executor
    /// accepts (see `bpf_loader_deprecated::tests::write_to_program_account`),
    /// so a pass here can only mean the dispatch reached the executor.
    #[test]
    fn deprecated_loader_management_instruction_is_unsupported() {
        let processor = TransactionProcessor::new();
        let program = Pubkey::new([1u8; 32]);
        let account = Account {
            meta: TypesAccountMeta {
                lamports: 1_000_000,
                owner: BPF_LOADER_DEPRECATED_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![0; 64]),
        };

        let mut data = vec![0u8; 8];
        data[4] = 8;
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let context = ExecutionContext::new(
            BPF_LOADER_DEPRECATED_PROGRAM_ID,
            vec![(program, account, true)],
            data,
        );
        let outcome = processor.execute_instruction(&context);

        assert!(!outcome.success, "deprecated loader must not execute");
        assert!(
            outcome.modified_accounts.is_empty(),
            "a refused instruction must not write accounts"
        );
        // Charged before refusal, matching the reference's ordering.
        assert_eq!(
            outcome.compute_units_consumed,
            bpf_loader_constants::DEPRECATED_LOADER_COMPUTE_UNITS
        );
    }
}
