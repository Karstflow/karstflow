use super::{
    ExecutionContext, ExecutionOutcome, SystemProgramExecutor, VoteProgramExecutor,
    COMPUTE_UNIT_COST_ACCOUNT_WRITEBACK, COMPUTE_UNIT_COST_PER_ACCOUNT,
    COMPUTE_UNIT_COST_PER_DATA_BYTE, DEFAULT_INSTRUCTION_BASE_COST,
};
use paradencer_ids::{SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID};
use std::collections::HashMap;

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
}
