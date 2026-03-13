// Pre-existing builtin program modules have dead-code variants reserved
// for future instruction types and unused helper methods.
#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    unused_assignments,
    clippy::inherent_to_string,
    clippy::wrong_self_convention,
    clippy::needless_range_loop,
    clippy::useless_vec,
    clippy::len_zero
)]

mod address_lookup_table;
mod associated_token_program;
mod bpf_loader;
mod bpf_loader_deprecated;
pub mod bpf_serialization;
mod compute_budget_program;
mod config_program;
pub mod elf_loader;
mod feature_gate_program;
pub mod instruction;
#[cfg(test)]
mod integration_tests;
pub mod interpreter;
mod loader_v4;
mod memo_program;
pub mod memory;
pub mod precompiles;
mod program_cache;
mod slashing_program;
#[cfg(test)]
mod spl_integration_tests;
mod stake;
pub mod syscall_dispatch;
pub mod syscalls;
mod system_program;
pub mod sysvar_snapshot;
mod token_2022_program;
mod token_program;
mod transaction_processor;
pub mod validation;
mod vm;
mod vote;
mod zk_elgamal_proof;
mod zk_proofs;

pub use address_lookup_table::{
    AddressLookupTableExecutor, LookupTable, LookupTableMeta, LookupTableStatus,
};
pub use associated_token_program::AssociatedTokenProgramExecutor;
pub use bpf_loader::{BpfLoaderExecutor, ProgramAccountState};
pub use bpf_loader_deprecated::BpfLoaderDeprecatedExecutor;
pub use compute_budget_program::{
    extract_compute_budget, ComputeBudgetProgramExecutor, ExtractedComputeBudget,
};
pub use config_program::ConfigProgramExecutor;
pub use feature_gate_program::FeatureGateProgramExecutor;
pub use karstflow_constants::execution::{
    COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK, COMPUTE_UNIT_COST_PER_ACCOUNT,
    COMPUTE_UNIT_COST_PER_DATA_BYTE, DEFAULT_INSTRUCTION_BASE_COST, MAX_COMPUTE_UNITS,
};
pub use loader_v4::{LoaderV4Executor, LoaderV4State};
pub use memo_program::MemoProgramExecutor;
pub use precompiles::{
    Ed25519PrecompileExecutor, Secp256k1PrecompileExecutor, Secp256r1PrecompileExecutor,
};
pub use program_cache::{CacheError, CachedProgram, ProgramCache};
pub use slashing_program::SlashingProgramExecutor;
pub use stake::StakeProgramExecutor;
pub use syscall_dispatch::InstructionExecutor;
pub use system_program::SystemProgramExecutor;
pub use sysvar_snapshot::{SiblingInstruction, SysvarSnapshot};
pub use token_2022_program::Token2022ProgramExecutor;
pub use token_program::TokenProgramExecutor;
pub use transaction_processor::{
    AccountMeta as InstructionAccountMeta, CompiledInstruction, MessageHeader, Transaction,
    TransactionInstruction, TransactionMessage, TransactionProcessor, TransactionResult,
};
pub use vm::{BytecodeVm, SbpfExecutionError, SbpfExecutionResult, SbpfVm};
pub use vote::VoteProgramExecutor;
pub use zk_elgamal_proof::{is_zk_elgamal_active, ZkElGamalProofExecutor};

use karstflow_types::{Account, Pubkey};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub program_id: Pubkey,
    pub accounts: Vec<(Pubkey, Account, bool)>,
    pub instruction_data: Vec<u8>,
    pub compute_budget: u64,
    /// Heap size in bytes for BPF program execution.
    /// Set via `ComputeBudgetInstruction::RequestHeapFrame`.
    pub heap_size: u32,
    /// Sysvar state for this execution (slot, epoch, rent, etc.).
    pub sysvar_snapshot: Option<SysvarSnapshot>,
}

impl ExecutionContext {
    pub fn new(
        program_id: Pubkey,
        accounts: Vec<(Pubkey, Account, bool)>,
        instruction_data: Vec<u8>,
    ) -> Self {
        Self {
            program_id,
            accounts,
            instruction_data,
            compute_budget: MAX_COMPUTE_UNITS,
            heap_size: karstflow_constants::vm::DEFAULT_HEAP_SIZE as u32,
            sysvar_snapshot: None,
        }
    }

    pub fn with_compute_budget(mut self, budget: u64) -> Self {
        self.compute_budget = budget.min(MAX_COMPUTE_UNITS);
        self
    }

    pub fn with_heap_size(mut self, heap_size: u32) -> Self {
        self.heap_size = heap_size;
        self
    }

    pub fn with_sysvar_snapshot(mut self, snapshot: SysvarSnapshot) -> Self {
        self.sysvar_snapshot = Some(snapshot);
        self
    }

    pub fn account_map(&self) -> HashMap<Pubkey, &Account> {
        self.accounts
            .iter()
            .map(|(pubkey, account, _)| (*pubkey, account))
            .collect()
    }

    pub fn writable_accounts(&self) -> Vec<Pubkey> {
        self.accounts
            .iter()
            .filter_map(|(pubkey, _, writable)| if *writable { Some(*pubkey) } else { None })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub compute_units_consumed: u64,
    pub modified_accounts: HashMap<Pubkey, Account>,
    pub logs: Vec<String>,
    pub return_data: Option<Vec<u8>>,
}

impl ExecutionOutcome {
    pub fn success(compute_units: u64) -> Self {
        Self {
            success: true,
            compute_units_consumed: compute_units,
            modified_accounts: HashMap::new(),
            logs: Vec::new(),
            return_data: None,
        }
    }

    pub fn failure(compute_units: u64, error_message: String) -> Self {
        Self {
            success: false,
            compute_units_consumed: compute_units,
            modified_accounts: HashMap::new(),
            logs: vec![format!("Program failed: {}", error_message)],
            return_data: None,
        }
    }

    pub fn with_modified_account(mut self, pubkey: Pubkey, account: Account) -> Self {
        self.modified_accounts.insert(pubkey, account);
        self
    }

    pub fn with_log(mut self, log: String) -> Self {
        self.logs.push(log);
        self
    }
}
