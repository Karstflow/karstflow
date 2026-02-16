mod address_lookup_table;
mod associated_token_program;
mod bpf_loader;
mod compute_budget_program;
mod config_program;
#[cfg(test)]
mod integration_tests;
mod memo_program;
pub mod precompiles;
#[cfg(test)]
mod spl_integration_tests;
mod stake_program;
pub mod syscalls;
mod system_program;
mod token_2022_program;
mod token_program;
mod transaction_processor;
mod vm;
mod vote;

pub use address_lookup_table::{
    AddressLookupTableExecutor, LookupTable, LookupTableMeta, LookupTableStatus,
};
pub use associated_token_program::AssociatedTokenProgramExecutor;
pub use bpf_loader::{BpfLoaderExecutor, ProgramAccountState};
pub use compute_budget_program::{
    extract_compute_budget, ComputeBudgetProgramExecutor, ExtractedComputeBudget,
};
pub use config_program::ConfigProgramExecutor;
pub use memo_program::MemoProgramExecutor;
pub use paradencer_constants::execution::{
    COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK, COMPUTE_UNIT_COST_PER_ACCOUNT,
    COMPUTE_UNIT_COST_PER_DATA_BYTE, DEFAULT_INSTRUCTION_BASE_COST, MAX_COMPUTE_UNITS,
};
pub use precompiles::{Ed25519PrecompileExecutor, Secp256k1PrecompileExecutor};
pub use stake_program::StakeProgramExecutor;
pub use system_program::SystemProgramExecutor;
pub use token_2022_program::Token2022ProgramExecutor;
pub use token_program::TokenProgramExecutor;
pub use transaction_processor::{
    AccountMeta as InstructionAccountMeta, CompiledInstruction, Transaction,
    TransactionInstruction, TransactionMessage, TransactionProcessor, TransactionResult,
};
pub use vm::{SbpfExecutionError, SbpfExecutionResult, SbpfVm, StubSbpfVm};
pub use vote::VoteProgramExecutor;

use paradencer_types::{Account, Pubkey};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContext {
    pub program_id: Pubkey,
    pub accounts: Vec<(Pubkey, Account, bool)>,
    pub instruction_data: Vec<u8>,
    pub compute_budget: u64,
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
        }
    }

    pub fn with_compute_budget(mut self, budget: u64) -> Self {
        self.compute_budget = budget.min(MAX_COMPUTE_UNITS);
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
