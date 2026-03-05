use super::{
    ExecutionContext, ExecutionOutcome, SystemProgramExecutor, VoteProgramExecutor,
    COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK, COMPUTE_UNIT_COST_PER_ACCOUNT,
    COMPUTE_UNIT_COST_PER_DATA_BYTE, DEFAULT_INSTRUCTION_BASE_COST,
};
use crate::bpf_serialization::{self, InputAccount};
use crate::elf_loader::LoadedProgram;
use crate::interpreter::{self, VmError};
use crate::memory::MemoryMap;
use crate::program_cache::ProgramCache;
use crate::syscall_dispatch::{InstructionExecutor, RuntimeSyscallDispatch};
use crate::sysvar_snapshot::SysvarSnapshot;
use crate::validation;
use karstflow_constants::vm::DEFAULT_HEAP_SIZE;
use karstflow_ids::{
    BPF_LOADER_DEPRECATED_PROGRAM_ID, BPF_LOADER_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID,
    LOADER_V4_PROGRAM_ID, SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID,
};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbpfExecutionError {
    ComputeBudgetExceeded,
    InvalidProgram,
    InvalidAccountData,
    ExecutionFailed { message: String },
}

impl std::fmt::Display for SbpfExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComputeBudgetExceeded => write!(f, "compute budget exceeded"),
            Self::InvalidProgram => write!(f, "invalid program"),
            Self::InvalidAccountData => write!(f, "invalid account data"),
            Self::ExecutionFailed { message } => write!(f, "execution failed: {}", message),
        }
    }
}

impl std::error::Error for SbpfExecutionError {}

pub type SbpfExecutionResult = Result<ExecutionOutcome, SbpfExecutionError>;

pub trait SbpfVm: Send + Sync {
    fn execute(&self, context: ExecutionContext) -> SbpfExecutionResult;
}

pub(crate) struct StubSbpfVm {
    system_program: SystemProgramExecutor,
    vote_program: VoteProgramExecutor,
}

impl StubSbpfVm {
    pub fn new() -> Self {
        Self {
            system_program: SystemProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST),
            vote_program: VoteProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST),
        }
    }

    fn execute_system_program(&self, context: &ExecutionContext) -> SbpfExecutionResult {
        self.system_program
            .execute(context)
            .map_err(|msg| SbpfExecutionError::ExecutionFailed { message: msg })
    }

    fn execute_vote_program(&self, context: &ExecutionContext) -> SbpfExecutionResult {
        self.vote_program
            .execute(context)
            .map_err(|msg| SbpfExecutionError::ExecutionFailed { message: msg })
    }

    fn execute_generic_program(&self, context: &ExecutionContext) -> SbpfExecutionResult {
        let mut compute_used = DEFAULT_INSTRUCTION_BASE_COST;
        let mut modified_accounts = HashMap::new();

        compute_used = compute_used.saturating_add(
            (context.accounts.len() as u64).saturating_mul(COMPUTE_UNIT_COST_PER_ACCOUNT),
        );
        compute_used = compute_used.saturating_add(
            (context.instruction_data.len() as u64).saturating_mul(COMPUTE_UNIT_COST_PER_DATA_BYTE),
        );

        for (pubkey, mut account, writable) in context.accounts.iter().cloned() {
            if writable {
                account.meta.lamports = account.meta.lamports.saturating_add(1);
                modified_accounts.insert(pubkey, account);
                compute_used = compute_used.saturating_add(COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK);
            }
        }

        if compute_used > context.compute_budget {
            return Err(SbpfExecutionError::ComputeBudgetExceeded);
        }

        Ok(ExecutionOutcome {
            success: true,
            compute_units_consumed: compute_used,
            modified_accounts,
            logs: vec!["Program executed successfully (stub)".to_string()],
            return_data: None,
        })
    }
}

impl Default for StubSbpfVm {
    fn default() -> Self {
        Self::new()
    }
}

impl SbpfVm for StubSbpfVm {
    fn execute(&self, context: ExecutionContext) -> SbpfExecutionResult {
        if context.program_id == SYSTEM_PROGRAM_ID {
            self.execute_system_program(&context)
        } else if context.program_id == VOTE_PROGRAM_ID {
            self.execute_vote_program(&context)
        } else {
            self.execute_generic_program(&context)
        }
    }
}

// ---------------------------------------------------------------------------
// BytecodeVm — real sBPF execution engine
// ---------------------------------------------------------------------------

/// Full sBPF virtual machine that loads, validates, and executes bytecode.
///
/// Wires together the ELF loader, static validator, memory model,
/// interpreter, and syscall dispatch into a single `SbpfVm` implementation.
/// Programs are cached after first load to avoid repeated parsing.
pub struct BytecodeVm {
    cache: Mutex<ProgramCache>,
    /// Tracks deployment slots for recently deployed/upgraded programs.
    ///
    /// When a program is deployed at slot N, its effective visibility
    /// slot is N + DELAY_VISIBILITY_SLOT_OFFSET. This map records the
    /// deployment slot so cache insertion applies the delay.
    deployed_at: Mutex<HashMap<Pubkey, u64>>,
    syscall_dispatch: RuntimeSyscallDispatch,
    sysvar_snapshot: SysvarSnapshot,
}

impl BytecodeVm {
    /// Create a new VM with standard syscalls registered.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            deployed_at: Mutex::new(HashMap::new()),
            syscall_dispatch: RuntimeSyscallDispatch::with_standard_syscalls(),
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Create a VM with CPI support, using the given executor for nested invocations.
    pub fn with_cpi(executor: Arc<dyn InstructionExecutor>) -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            deployed_at: Mutex::new(HashMap::new()),
            syscall_dispatch: RuntimeSyscallDispatch::with_cpi_support(executor),
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Create a VM with a custom syscall dispatcher.
    pub fn with_syscalls(syscall_dispatch: RuntimeSyscallDispatch) -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            deployed_at: Mutex::new(HashMap::new()),
            syscall_dispatch,
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Set the sysvar snapshot and rebuild the syscall dispatcher.
    ///
    /// The syscall dispatcher is rebuilt with feature-gated syscall
    /// registration based on the active features in the snapshot.
    /// This must be called whenever the active feature set changes
    /// (typically once per slot).
    pub fn set_sysvar_snapshot(&mut self, snapshot: SysvarSnapshot) {
        self.syscall_dispatch =
            RuntimeSyscallDispatch::with_active_feature_ids(&snapshot.active_features);
        self.sysvar_snapshot = snapshot;
    }

    /// Remove a program from the cache after deployment or upgrade.
    ///
    /// Records the deployment slot so that when the program is next
    /// loaded, it receives an effective visibility delay of
    /// `DELAY_VISIBILITY_SLOT_OFFSET` slots.
    pub fn invalidate_program(&self, program_id: &Pubkey, deployment_slot: u64) {
        let mut cache = self.cache.lock().expect("program_cache lock poisoned");
        cache.invalidate(program_id);
        drop(cache);

        let mut deployed = self.deployed_at.lock().expect("deployed_at lock poisoned");
        deployed.insert(*program_id, deployment_slot);
    }

    /// Load and validate a program from raw ELF bytes.
    fn load_program(&self, elf_bytes: &[u8]) -> Result<LoadedProgram, SbpfExecutionError> {
        let program = crate::elf_loader::load_elf(elf_bytes)
            .map_err(|e| SbpfExecutionError::InvalidProgram)?;

        let syscall_ids = self.syscall_dispatch.registered_ids();
        validation::validate(&program, &syscall_ids)
            .map_err(|errors| SbpfExecutionError::InvalidProgram)?;

        Ok(program)
    }

    /// Convert execution context accounts to the BPF serialization input format.
    fn to_input_accounts(context: &ExecutionContext) -> Vec<InputAccount> {
        context
            .accounts
            .iter()
            .map(|(pubkey, account, writable)| InputAccount {
                key: *pubkey,
                owner: account.meta.owner,
                lamports: account.meta.lamports,
                data: account.data.as_slice().to_vec(),
                is_signer: false,
                is_writable: *writable,
                is_executable: account.meta.executable,
                rent_epoch: account.meta.rent_epoch,
            })
            .collect()
    }

    /// Deserialize modified accounts from the VM output region after execution.
    ///
    /// Uses the standard aligned BPF serialization format. Extracts writable
    /// accounts whose data changed compared to the originals.
    fn collect_modified_accounts(
        input_region: &[u8],
        serialized: &bpf_serialization::SerializedInput,
        original_accounts: &[(Pubkey, Account, bool)],
    ) -> HashMap<Pubkey, Account> {
        let deserialized = bpf_serialization::deserialize_aligned(
            input_region,
            &serialized.account_metas,
            &serialized.pre_lens,
            &serialized.duplicate_indices,
        );

        let mut modified = HashMap::new();
        let results = match deserialized {
            Ok(r) => r,
            Err(_) => return modified,
        };

        for (i, result) in results.into_iter().enumerate() {
            if let Some(deser) = result {
                if i < original_accounts.len() {
                    let (pubkey, orig_account, _) = &original_accounts[i];
                    let orig_data = orig_account.data.as_slice();

                    // Only include accounts that actually changed
                    let changed = deser.lamports != orig_account.meta.lamports
                        || deser.owner != orig_account.meta.owner
                        || deser.data.len() != orig_data.len()
                        || deser.data != orig_data;

                    if changed {
                        modified.insert(
                            *pubkey,
                            Account {
                                meta: AccountMeta {
                                    lamports: deser.lamports,
                                    owner: deser.owner,
                                    executable: orig_account.meta.executable,
                                    rent_epoch: orig_account.meta.rent_epoch,
                                },
                                data: AccountData::new(deser.data),
                            },
                        );
                    }
                }
            }
        }

        modified
    }

    /// Execute a loaded program with the given context.
    ///
    /// Serializes accounts into the standard aligned BPF input format,
    /// runs the interpreter, and deserializes modified accounts.
    fn run_program(
        &self,
        program: &LoadedProgram,
        context: &ExecutionContext,
    ) -> SbpfExecutionResult {
        let input_accounts = Self::to_input_accounts(context);
        let serialized = bpf_serialization::serialize_aligned(
            &input_accounts,
            &context.instruction_data,
            &context.program_id,
        )
        .map_err(|e| SbpfExecutionError::ExecutionFailed { message: e })?;

        // Separate the buffer (moved into MemoryMap) from the metadata (kept for deserialization).
        let bpf_serialization::SerializedInput {
            buffer: input_buffer,
            account_metas,
            pre_lens,
            duplicate_indices,
            ..
        } = serialized;

        let rodata = if program.rodata.is_empty() {
            &program.text_bytes
        } else {
            &program.rodata
        };

        let memory = MemoryMap::new(rodata, DEFAULT_HEAP_SIZE, DEFAULT_HEAP_SIZE, input_buffer);

        // Use the context's snapshot if provided, falling back to the VM default.
        let snapshot = context
            .sysvar_snapshot
            .clone()
            .unwrap_or_else(|| self.sysvar_snapshot.clone());

        // Re-assemble metadata struct for deserialization (buffer comes from VM result).
        let deser_meta = bpf_serialization::SerializedInput {
            buffer: Vec::new(), // not used by collect_modified_accounts
            account_metas,
            pre_lens,
            duplicate_indices,
            instruction_data_offset: 0,
        };

        let deplete_on_failure = karstflow_ids::features::is_feature_active(
            &snapshot.active_features,
            &karstflow_ids::features::DEPLETE_CU_METER_ON_VM_FAILURE,
        );

        match interpreter::execute(
            program,
            memory,
            context.compute_budget,
            &self.syscall_dispatch,
            snapshot,
        ) {
            Ok(result) => {
                let modified_accounts = Self::collect_modified_accounts(
                    &result.input_region,
                    &deser_meta,
                    &context.accounts,
                );

                Ok(ExecutionOutcome {
                    success: result.return_value == 0,
                    compute_units_consumed: result.compute_units_consumed,
                    modified_accounts,
                    logs: result.logs,
                    return_data: result.return_data,
                })
            }
            Err(VmError::ComputeBudgetExceeded) => Err(SbpfExecutionError::ComputeBudgetExceeded),
            Err(e) => {
                if deplete_on_failure {
                    // When the feature is active, consume the entire budget
                    // on non-syscall VM failures (illegal instruction, bad
                    // memory access, etc.) and return a failed outcome.
                    Ok(ExecutionOutcome::failure(
                        context.compute_budget,
                        e.to_string(),
                    ))
                } else {
                    Err(SbpfExecutionError::ExecutionFailed {
                        message: e.to_string(),
                    })
                }
            }
        }
    }
}

impl Default for BytecodeVm {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BytecodeVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BytecodeVm").finish()
    }
}

impl SbpfVm for BytecodeVm {
    fn execute(&self, context: ExecutionContext) -> SbpfExecutionResult {
        // Find the program account — the executable account whose pubkey matches program_id
        let program_account = context
            .accounts
            .iter()
            .find(|(pubkey, account, _)| *pubkey == context.program_id && account.meta.executable)
            .map(|(_, account, _)| account);

        let program = match program_account {
            Some(account) => account,
            None => return Err(SbpfExecutionError::InvalidProgram),
        };

        // Verify the program's owner is a recognized loader. Only accounts
        // owned by one of the BPF loaders or the Loader-v4 are valid
        // executable programs. Rejecting other owners prevents arbitrary
        // executable-flagged accounts from being dispatched as programs.
        if !is_valid_loader_owner(&program.meta.owner) {
            return Err(SbpfExecutionError::InvalidProgram);
        }

        let elf_bytes = program.data.as_slice();

        if elf_bytes.is_empty() {
            return Err(SbpfExecutionError::InvalidAccountData);
        }

        // Current slot for cache visibility checks.
        let current_slot = context
            .sysvar_snapshot
            .as_ref()
            .map(|s| s.slot)
            .unwrap_or(self.sysvar_snapshot.slot);

        // Try cache first
        {
            let mut cache = self.cache.lock().expect("program_cache lock poisoned");
            if let Some(program) = cache.get(&context.program_id, current_slot) {
                let program = program.clone();
                drop(cache);
                return self.run_program(&program, &context);
            }
        }

        // Load, validate, cache, and execute.
        let program = self.load_program(elf_bytes)?;

        // Compute effective_slot: if this program was recently deployed,
        // apply DELAY_VISIBILITY_SLOT_OFFSET; otherwise it's always visible.
        let effective_slot = {
            let mut deployed = self.deployed_at.lock().expect("deployed_at lock poisoned");
            if let Some(deploy_slot) = deployed.remove(&context.program_id) {
                deploy_slot.saturating_add(
                    karstflow_constants::program_cache::DELAY_VISIBILITY_SLOT_OFFSET,
                )
            } else {
                0 // pre-existing program: always visible
            }
        };

        // If the program is not yet visible, don't cache or execute it.
        if current_slot < effective_slot {
            return Err(SbpfExecutionError::InvalidProgram);
        }

        {
            let mut cache = self.cache.lock().expect("program_cache lock poisoned");
            cache.insert(
                context.program_id,
                program.clone(),
                elf_bytes.len(),
                current_slot,
                effective_slot,
            );
        }

        self.run_program(&program, &context)
    }
}

/// Check whether an account owner is a recognized program loader.
///
/// Only accounts owned by these loaders are valid executable programs:
/// - BPF Loader (upgradeable loader, the standard for deployed programs)
/// - BPF Loader v2 (non-upgradeable loader, used for early programs)
/// - BPF Loader Deprecated (original loader, still recognized)
/// - Loader v4 (next-generation loader)
fn is_valid_loader_owner(owner: &Pubkey) -> bool {
    *owner == BPF_LOADER_PROGRAM_ID
        || *owner == BPF_LOADER_V2_PROGRAM_ID
        || *owner == BPF_LOADER_DEPRECATED_PROGRAM_ID
        || *owner == LOADER_V4_PROGRAM_ID
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::{BPF_LOADER_PROGRAM_ID, SYSTEM_PROGRAM_ID};
    use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};

    #[test]
    fn stub_vm_executes_empty_instruction() {
        let vm = StubSbpfVm::new();
        let context = ExecutionContext::new(SYSTEM_PROGRAM_ID, vec![], vec![]);

        let result = vm.execute(context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            DEFAULT_INSTRUCTION_BASE_COST
        );
    }

    #[test]
    fn stub_vm_simulates_transfer() {
        let vm = StubSbpfVm::new();
        let from_pubkey = Pubkey::new_unique();
        let to_pubkey = Pubkey::new_unique();

        let from_account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account {
            meta: AccountMeta {
                lamports: 500,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut instruction_data = vec![];
        instruction_data.extend_from_slice(&2u32.to_le_bytes());
        instruction_data.extend_from_slice(&300u64.to_le_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (from_pubkey, from_account, true),
                (to_pubkey, to_account, true),
            ],
            instruction_data,
        );

        let result = vm.execute(context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.success);

        let from_modified = outcome.modified_accounts.get(&from_pubkey).unwrap();
        assert_eq!(from_modified.meta.lamports, 700);

        let to_modified = outcome.modified_accounts.get(&to_pubkey).unwrap();
        assert_eq!(to_modified.meta.lamports, 800);
    }

    #[test]
    fn stub_vm_rejects_transfer_with_insufficient_lamports() {
        let vm = StubSbpfVm::new();
        let from_pubkey = Pubkey::new_unique();
        let to_pubkey = Pubkey::new_unique();

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

        let mut instruction_data = vec![];
        instruction_data.extend_from_slice(&2u32.to_le_bytes());
        instruction_data.extend_from_slice(&500u64.to_le_bytes());

        let context = ExecutionContext::new(
            SYSTEM_PROGRAM_ID,
            vec![
                (from_pubkey, from_account, true),
                (to_pubkey, to_account, true),
            ],
            instruction_data,
        );

        let result = vm.execute(context);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SbpfExecutionError::ExecutionFailed { .. }
        ));
    }

    #[test]
    fn stub_vm_respects_compute_budget() {
        let vm = StubSbpfVm::new();
        let accounts: Vec<_> = (0..100)
            .map(|_| (Pubkey::new_unique(), Account::zeroed(), true))
            .collect();

        let context = ExecutionContext::new(Pubkey::new_unique(), accounts, vec![0; 1000])
            .with_compute_budget(1000);

        let result = vm.execute(context);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SbpfExecutionError::ComputeBudgetExceeded
        ));
    }

    // --- BytecodeVm tests ---

    /// Build a minimal ELF with the given instructions.
    fn make_elf_program(instructions: &[crate::instruction::Instruction]) -> Vec<u8> {
        let mut text = Vec::new();
        for insn in instructions {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        crate::elf_loader::TestElfBuilder::new().text(text).build()
    }

    /// Make a program account containing an ELF binary.
    fn program_account(elf_bytes: Vec<u8>) -> Account {
        Account {
            meta: AccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf_bytes),
        }
    }

    #[test]
    fn bytecode_vm_executes_minimal_program() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        // Program: mov r0, 0; exit
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let context = ExecutionContext::new(
            program_id,
            vec![(program_id, program_account(elf), false)],
            vec![],
        );

        let result = vm.execute(context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.success);
        assert!(outcome.compute_units_consumed > 0);
    }

    #[test]
    fn bytecode_vm_nonzero_exit_is_failure() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        // Program: mov r0, 1; exit (non-zero return = failure)
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let context = ExecutionContext::new(
            program_id,
            vec![(program_id, program_account(elf), false)],
            vec![],
        );

        let result = vm.execute(context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(!outcome.success); // r0 != 0 → failure
    }

    #[test]
    fn bytecode_vm_rejects_missing_program() {
        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        // No program account provided
        let context = ExecutionContext::new(program_id, vec![], vec![]);

        let result = vm.execute(context);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SbpfExecutionError::InvalidProgram
        ));
    }

    #[test]
    fn bytecode_vm_rejects_empty_program_data() {
        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        let empty_account = Account {
            meta: AccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let context =
            ExecutionContext::new(program_id, vec![(program_id, empty_account, false)], vec![]);

        let result = vm.execute(context);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SbpfExecutionError::InvalidAccountData
        ));
    }

    #[test]
    fn bytecode_vm_caches_program() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let account = program_account(elf);

        // Execute twice — second should hit cache
        for _ in 0..2 {
            let context = ExecutionContext::new(
                program_id,
                vec![(program_id, account.clone(), false)],
                vec![],
            );
            let result = vm.execute(context);
            assert!(result.is_ok());
        }

        // Verify cache has the entry
        let cache = vm.cache.lock().unwrap();
        assert!(cache.contains(&program_id));
    }

    #[test]
    fn bytecode_vm_arithmetic_program() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        // Program: r1 = 10; r2 = 10; r0 = r1 - r2 (= 0 → success); exit
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 10),
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 10),
            Instruction::new(Opcode::Sub64Reg as u8, 0, 0, 0, 0), // r0 = r0 - r0 = 0 but we want r1 - r2
            // Actually: mov r0, r1; sub r0, r2
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        // Let's redo with correct logic
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 1, 0, 0, 5), // r1 = 5
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 5), // r0 = 5
            Instruction::new(Opcode::Sub64Reg as u8, 0, 1, 0, 0), // r0 = r0 - r1 = 0
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let context = ExecutionContext::new(
            program_id,
            vec![(program_id, program_account(elf), false)],
            vec![],
        );

        let result = vm.execute(context);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(outcome.success); // r0 = 0
    }

    // --- Account serialization/deserialization integration tests ---

    #[test]
    fn serialization_roundtrip_unmodified() {
        let pubkey_a = Pubkey::new_unique();
        let pubkey_b = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let account_a = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3, 4]),
        };
        let account_b = Account {
            meta: AccountMeta {
                lamports: 500,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![10, 20]),
        };

        let accounts = vec![
            (pubkey_a, account_a.clone(), true),
            (pubkey_b, account_b.clone(), true),
        ];

        let context = ExecutionContext::new(Pubkey::new_unique(), accounts.clone(), vec![]);
        let input_accounts = BytecodeVm::to_input_accounts(&context);
        let serialized = crate::bpf_serialization::serialize_aligned(
            &input_accounts,
            &context.instruction_data,
            &context.program_id,
        )
        .unwrap();

        // Roundtrip: no modification means no accounts returned
        let result =
            BytecodeVm::collect_modified_accounts(&serialized.buffer, &serialized, &accounts);
        assert!(result.is_empty(), "Unmodified accounts should not appear");
    }

    #[test]
    fn serialization_detects_modified_lamports() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![42, 43]),
        };

        let accounts = vec![(pubkey, account.clone(), true)];
        let context = ExecutionContext::new(Pubkey::new_unique(), accounts.clone(), vec![]);
        let input_accounts = BytecodeVm::to_input_accounts(&context);
        let serialized = crate::bpf_serialization::serialize_aligned(
            &input_accounts,
            &context.instruction_data,
            &context.program_id,
        )
        .unwrap();

        // Patch lamports in aligned format:
        // offset = 8(count) + 1(dup_marker) + 1(is_signer) + 1(is_writable)
        //        + 1(is_executable) + 4(padding) + 32(pubkey) + 32(owner) = 80
        let lamports_offset = 80;
        let mut modified_buf = serialized.buffer.clone();
        let new_lamports: u64 = 2000;
        modified_buf[lamports_offset..lamports_offset + 8]
            .copy_from_slice(&new_lamports.to_le_bytes());

        let result = BytecodeVm::collect_modified_accounts(&modified_buf, &serialized, &accounts);
        assert_eq!(result.len(), 1);
        let modified = result.get(&pubkey).unwrap();
        assert_eq!(modified.meta.lamports, 2000);
        assert_eq!(modified.data.as_slice(), &[42, 43]);
    }

    #[test]
    fn serialization_ignores_readonly_changes() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // Account is NOT writable
        let accounts = vec![(pubkey, account.clone(), false)];
        let context = ExecutionContext::new(Pubkey::new_unique(), accounts.clone(), vec![]);
        let input_accounts = BytecodeVm::to_input_accounts(&context);
        let serialized = crate::bpf_serialization::serialize_aligned(
            &input_accounts,
            &context.instruction_data,
            &context.program_id,
        )
        .unwrap();

        // Patch lamports even though it's read-only
        let lamports_offset = 80;
        let mut modified_buf = serialized.buffer.clone();
        let new_lamports: u64 = 9999;
        modified_buf[lamports_offset..lamports_offset + 8]
            .copy_from_slice(&new_lamports.to_le_bytes());

        let result = BytecodeVm::collect_modified_accounts(&modified_buf, &serialized, &accounts);
        assert!(
            result.is_empty(),
            "Read-only account changes should be ignored"
        );
    }

    #[test]
    fn rejects_executable_with_invalid_owner() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        // Account is executable but has an invalid owner (random pubkey)
        let bad_owner_account = Account {
            meta: AccountMeta {
                lamports: 1,
                owner: Pubkey::new_unique(),
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let context = ExecutionContext::new(
            program_id,
            vec![(program_id, bad_owner_account, false)],
            vec![],
        );

        let result = vm.execute(context);
        assert!(result.is_err(), "executable with invalid owner should fail");
    }

    #[test]
    fn accepts_all_valid_loader_owners() {
        use karstflow_ids::{
            BPF_LOADER_DEPRECATED_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID, LOADER_V4_PROGRAM_ID,
        };

        let valid_owners = [
            BPF_LOADER_PROGRAM_ID,
            BPF_LOADER_V2_PROGRAM_ID,
            BPF_LOADER_DEPRECATED_PROGRAM_ID,
            LOADER_V4_PROGRAM_ID,
        ];

        for owner in &valid_owners {
            assert!(
                is_valid_loader_owner(owner),
                "owner {:?} should be valid",
                owner
            );
        }
    }

    #[test]
    fn rejects_invalid_loader_owners() {
        let invalid_owners = [Pubkey::default(), Pubkey::new_unique(), SYSTEM_PROGRAM_ID];

        for owner in &invalid_owners {
            assert!(
                !is_valid_loader_owner(owner),
                "owner {:?} should be invalid",
                owner
            );
        }
    }

    #[test]
    fn invalidate_program_clears_cache() {
        use crate::instruction::{Instruction, Opcode};

        let vm = BytecodeVm::new();
        let program_id = Pubkey::new_unique();

        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let account = program_account(elf);

        // First execution should cache the program
        let context = ExecutionContext::new(
            program_id,
            vec![(program_id, account.clone(), false)],
            vec![],
        );
        let result = vm.execute(context);
        assert!(result.is_ok());

        // Verify program is cached
        {
            let mut cache = vm.cache.lock().unwrap();
            assert!(cache.get(&program_id, 0).is_some());
        }

        // Invalidate (deployed at slot 0)
        vm.invalidate_program(&program_id, 0);

        // Verify cache is empty for this program
        {
            let mut cache = vm.cache.lock().unwrap();
            assert!(cache.get(&program_id, 0).is_none());
        }
    }

    #[test]
    fn set_sysvar_snapshot_rebuilds_dispatcher() {
        use crate::syscall_dispatch::murmur3_hash;
        use karstflow_ids::features;

        let mut vm = BytecodeVm::new();

        // Default new() uses with_standard_syscalls which registers everything.
        // After set_sysvar_snapshot with empty features, only always-on syscalls present.
        let snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        vm.set_sysvar_snapshot(snap);

        let ids = vm.syscall_dispatch.registered_ids();
        // blake3 should NOT be registered (feature-gated, no features active)
        assert!(!ids.contains(&murmur3_hash("sol_blake3")));
        // sol_log_ should always be registered
        assert!(ids.contains(&murmur3_hash("sol_log_")));

        // Now set a snapshot with blake3 feature active
        let mut snap2 = crate::sysvar_snapshot::SysvarSnapshot::default();
        snap2
            .active_features
            .insert(*features::BLAKE3_SYSCALL_ENABLED.as_bytes());
        vm.set_sysvar_snapshot(snap2);

        let ids2 = vm.syscall_dispatch.registered_ids();
        assert!(ids2.contains(&murmur3_hash("sol_blake3")));
        assert!(ids2.contains(&murmur3_hash("sol_log_")));
    }

    #[test]
    fn deplete_cu_on_vm_failure_returns_outcome_with_full_budget() {
        use crate::instruction::{Instruction, Opcode};
        use karstflow_ids::features;

        let mut vm = BytecodeVm::new();

        // Enable the deplete-on-failure feature
        let mut snap = crate::sysvar_snapshot::SysvarSnapshot::default();
        snap.active_features
            .insert(*features::DEPLETE_CU_METER_ON_VM_FAILURE.as_bytes());
        vm.set_sysvar_snapshot(snap);

        let program_id = Pubkey::new_unique();

        // Build a program that triggers runtime division by zero:
        // mov r2, 0; div32 r1, r2 (runtime error, passes validation)
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0), // r2 = 0
            Instruction::new(Opcode::Div32Reg as u8, 1, 2, 0, 0), // r1 / r2 → div by zero
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let budget = 100_000u64;
        let context = ExecutionContext {
            program_id,
            accounts: vec![(program_id, program_account(elf), false)],
            instruction_data: vec![],
            compute_budget: budget,
            sysvar_snapshot: None,
        };

        let result = vm.execute(context);
        match result {
            Ok(outcome) => {
                assert!(!outcome.success, "VM error should produce failure outcome");
                assert_eq!(
                    outcome.compute_units_consumed, budget,
                    "Entire budget should be consumed on VM failure"
                );
            }
            Err(_) => panic!("Should return Ok(failure) when deplete feature is active"),
        }
    }

    #[test]
    fn without_deplete_feature_vm_failure_returns_error() {
        use crate::instruction::{Instruction, Opcode};

        let mut vm = BytecodeVm::new();
        // Set empty features (no deplete feature)
        vm.set_sysvar_snapshot(crate::sysvar_snapshot::SysvarSnapshot::default());

        let program_id = Pubkey::new_unique();

        // Same runtime div-by-zero program
        let elf = make_elf_program(&[
            Instruction::new(Opcode::Mov64Imm as u8, 2, 0, 0, 0),
            Instruction::new(Opcode::Div32Reg as u8, 1, 2, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ]);

        let context = ExecutionContext {
            program_id,
            accounts: vec![(program_id, program_account(elf), false)],
            instruction_data: vec![],
            compute_budget: 100_000,
            sysvar_snapshot: None,
        };

        let result = vm.execute(context);
        assert!(
            result.is_err(),
            "Without deplete feature, VM error should return Err"
        );
    }
}
