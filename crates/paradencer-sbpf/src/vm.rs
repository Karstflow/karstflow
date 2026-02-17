use super::{
    ExecutionContext, ExecutionOutcome, SystemProgramExecutor, VoteProgramExecutor,
    COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK, COMPUTE_UNIT_COST_PER_ACCOUNT,
    COMPUTE_UNIT_COST_PER_DATA_BYTE, DEFAULT_INSTRUCTION_BASE_COST,
};
use crate::elf_loader::LoadedProgram;
use crate::interpreter::{self, VmError};
use crate::memory::MemoryMap;
use crate::sysvar_snapshot::SysvarSnapshot;
use crate::program_cache::ProgramCache;
use crate::syscall_dispatch::{InstructionExecutor, RuntimeSyscallDispatch};
use crate::validation;
use paradencer_constants::vm::{ACCOUNT_SERIALIZED_META_SIZE, DEFAULT_HEAP_SIZE};
use paradencer_ids::{SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID};
use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};
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

pub struct StubSbpfVm {
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
    syscall_dispatch: RuntimeSyscallDispatch,
    sysvar_snapshot: SysvarSnapshot,
}

impl BytecodeVm {
    /// Create a new VM with standard syscalls registered.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            syscall_dispatch: RuntimeSyscallDispatch::with_standard_syscalls(),
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Create a VM with CPI support, using the given executor for nested invocations.
    pub fn with_cpi(executor: Arc<dyn InstructionExecutor>) -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            syscall_dispatch: RuntimeSyscallDispatch::with_cpi_support(executor),
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Create a VM with a custom syscall dispatcher.
    pub fn with_syscalls(syscall_dispatch: RuntimeSyscallDispatch) -> Self {
        Self {
            cache: Mutex::new(ProgramCache::new()),
            syscall_dispatch,
            sysvar_snapshot: SysvarSnapshot::default(),
        }
    }

    /// Set the sysvar snapshot for this VM.
    pub fn set_sysvar_snapshot(&mut self, snapshot: SysvarSnapshot) {
        self.sysvar_snapshot = snapshot;
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

    /// Serialize account data into the input region for the VM.
    ///
    /// Format per account:
    /// - 1 byte: is_signer (0/1) — always 0 for now
    /// - 1 byte: is_writable (0/1)
    /// - 32 bytes: pubkey
    /// - 32 bytes: owner
    /// - 8 bytes: lamports (little-endian)
    /// - 8 bytes: data length (little-endian)
    /// - N bytes: account data
    /// - padding to 8-byte alignment
    fn serialize_accounts(context: &ExecutionContext) -> Vec<u8> {
        let mut buf = Vec::new();

        // Number of accounts
        buf.extend_from_slice(&(context.accounts.len() as u64).to_le_bytes());

        for (pubkey, account, writable) in &context.accounts {
            // is_signer placeholder
            buf.push(0u8);
            // is_writable
            buf.push(if *writable { 1 } else { 0 });
            // pubkey (32 bytes)
            buf.extend_from_slice(pubkey.as_ref());
            // owner (32 bytes)
            buf.extend_from_slice(account.meta.owner.as_ref());
            // lamports
            buf.extend_from_slice(&account.meta.lamports.to_le_bytes());
            // data length
            let data = account.data.as_slice();
            buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
            // data
            buf.extend_from_slice(data);
            // padding to 8-byte alignment
            let padding = (8 - (buf.len() % 8)) % 8;
            buf.extend(std::iter::repeat_n(0u8, padding));
        }

        // Instruction data
        buf.extend_from_slice(&(context.instruction_data.len() as u64).to_le_bytes());
        buf.extend_from_slice(&context.instruction_data);

        // Program ID
        buf.extend_from_slice(context.program_id.as_ref());

        buf
    }

    /// Deserialize accounts from the VM input region after execution.
    ///
    /// Reads the same format written by `serialize_accounts`, extracting
    /// only writable accounts whose data actually changed compared to originals.
    fn deserialize_accounts(
        input_region: &[u8],
        original_accounts: &[(Pubkey, Account, bool)],
    ) -> Result<HashMap<Pubkey, Account>, SbpfExecutionError> {
        let mut modified = HashMap::new();

        if input_region.len() < 8 {
            return Ok(modified);
        }

        let account_count = u64::from_le_bytes(input_region[..8].try_into().unwrap()) as usize;

        if account_count != original_accounts.len() {
            return Err(SbpfExecutionError::InvalidAccountData);
        }

        let mut offset = 8;

        for (orig_pubkey, orig_account, orig_writable) in original_accounts {
            // Ensure enough data for fixed metadata
            if offset + ACCOUNT_SERIALIZED_META_SIZE > input_region.len() {
                return Err(SbpfExecutionError::InvalidAccountData);
            }

            let _is_signer = input_region[offset];
            let is_writable = input_region[offset + 1];
            offset += 2;

            // Read pubkey (32 bytes)
            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(&input_region[offset..offset + 32]);
            let pubkey = Pubkey::new(pubkey_bytes);
            offset += 32;

            // Read owner (32 bytes)
            let mut owner_bytes = [0u8; 32];
            owner_bytes.copy_from_slice(&input_region[offset..offset + 32]);
            let owner = Pubkey::new(owner_bytes);
            offset += 32;

            // Read lamports (8 bytes)
            let lamports = u64::from_le_bytes(input_region[offset..offset + 8].try_into().unwrap());
            offset += 8;

            // Read data length (8 bytes)
            let data_len =
                u64::from_le_bytes(input_region[offset..offset + 8].try_into().unwrap()) as usize;
            offset += 8;

            // Read data
            if offset + data_len > input_region.len() {
                return Err(SbpfExecutionError::InvalidAccountData);
            }
            let data = &input_region[offset..offset + data_len];
            offset += data_len;

            // Skip padding to 8-byte alignment
            let padding = (8 - (offset % 8)) % 8;
            offset += padding;

            // Only track writable accounts that changed
            if is_writable != 0 && *orig_writable {
                let orig_data = orig_account.data.as_slice();
                let changed = lamports != orig_account.meta.lamports
                    || owner != orig_account.meta.owner
                    || data.len() != orig_data.len()
                    || data != orig_data;

                if changed {
                    let account = Account {
                        meta: AccountMeta {
                            lamports,
                            owner,
                            executable: orig_account.meta.executable,
                            rent_epoch: orig_account.meta.rent_epoch,
                        },
                        data: AccountData::new(data.to_vec()),
                    };
                    modified.insert(pubkey, account);
                }
            }
        }

        Ok(modified)
    }

    /// Execute a loaded program with the given context.
    fn run_program(
        &self,
        program: &LoadedProgram,
        context: &ExecutionContext,
    ) -> SbpfExecutionResult {
        let input_data = Self::serialize_accounts(context);

        let rodata = if program.rodata.is_empty() {
            &program.text_bytes
        } else {
            &program.rodata
        };

        let memory = MemoryMap::new(rodata, DEFAULT_HEAP_SIZE, DEFAULT_HEAP_SIZE, input_data);

        match interpreter::execute(
            program,
            memory,
            context.compute_budget,
            &self.syscall_dispatch,
            self.sysvar_snapshot.clone(),
        ) {
            Ok(result) => {
                let modified_accounts =
                    Self::deserialize_accounts(&result.input_region, &context.accounts)
                        .unwrap_or_default();

                Ok(ExecutionOutcome {
                    success: result.return_value == 0,
                    compute_units_consumed: result.compute_units_consumed,
                    modified_accounts,
                    logs: result.logs,
                    return_data: result.return_data,
                })
            }
            Err(VmError::ComputeBudgetExceeded) => Err(SbpfExecutionError::ComputeBudgetExceeded),
            Err(e) => Err(SbpfExecutionError::ExecutionFailed {
                message: e.to_string(),
            }),
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

        let elf_bytes = match program_account {
            Some(account) => account.data.as_slice(),
            None => return Err(SbpfExecutionError::InvalidProgram),
        };

        if elf_bytes.is_empty() {
            return Err(SbpfExecutionError::InvalidAccountData);
        }

        // Try cache first
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(program) = cache.get(&context.program_id, 0) {
                let program = program.clone();
                drop(cache);
                return self.run_program(&program, &context);
            }
        }

        // Load, validate, cache, and execute
        let program = self.load_program(elf_bytes)?;

        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(context.program_id, program.clone(), elf_bytes.len(), 0);
        }

        self.run_program(&program, &context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::SYSTEM_PROGRAM_ID;
    use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};

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
                owner: Pubkey::default(),
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
                owner: Pubkey::default(),
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

    // --- Account deserialization tests ---

    #[test]
    fn deserialize_accounts_roundtrip() {
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
        let serialized = BytecodeVm::serialize_accounts(&context);

        // Roundtrip: no modification means no accounts returned
        let result = BytecodeVm::deserialize_accounts(&serialized, &accounts).unwrap();
        assert!(result.is_empty(), "Unmodified accounts should not appear");
    }

    #[test]
    fn deserialize_modified_lamports() {
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
        let mut serialized = BytecodeVm::serialize_accounts(&context);

        // Patch lamports in serialized buffer: offset is 8 (count) + 2 (flags) + 32 (pubkey) + 32 (owner) = 74
        let lamports_offset = 8 + 2 + 32 + 32;
        let new_lamports: u64 = 2000;
        serialized[lamports_offset..lamports_offset + 8]
            .copy_from_slice(&new_lamports.to_le_bytes());

        let result = BytecodeVm::deserialize_accounts(&serialized, &accounts).unwrap();
        assert_eq!(result.len(), 1);
        let modified = result.get(&pubkey).unwrap();
        assert_eq!(modified.meta.lamports, 2000);
        assert_eq!(modified.data.as_slice(), &[42, 43]);
    }

    #[test]
    fn deserialize_readonly_ignored() {
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
        let mut serialized = BytecodeVm::serialize_accounts(&context);

        // Patch lamports even though it's read-only
        let lamports_offset = 8 + 2 + 32 + 32;
        let new_lamports: u64 = 9999;
        serialized[lamports_offset..lamports_offset + 8]
            .copy_from_slice(&new_lamports.to_le_bytes());

        let result = BytecodeVm::deserialize_accounts(&serialized, &accounts).unwrap();
        assert!(
            result.is_empty(),
            "Read-only account changes should be ignored"
        );
    }
}
