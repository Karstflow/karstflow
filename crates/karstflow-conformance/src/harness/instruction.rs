//! Instruction-level execution harness.
//!
//! Executes a single instruction against provided accounts and returns
//! the full execution result for comparison.

use karstflow_consensus::{ExecutionBackend, InstructionInfo, InstructionResult, SlotContext};
use karstflow_stages::SbpfExecutionAdapter;
use karstflow_types::{Account, Pubkey};

/// Input for instruction-level conformance test.
#[derive(Debug, Clone)]
pub struct InstructionInput {
    pub program_id: Pubkey,
    pub accounts: Vec<(Pubkey, Account, bool, bool)>, // pubkey, account, writable, signer
    pub data: Vec<u8>,
    pub slot_context: SlotContext,
}

/// Outcome of instruction execution with all observable state.
#[derive(Debug)]
pub struct InstructionOutcome {
    pub result: InstructionResult,
}

/// Execute a single instruction and return the outcome.
pub fn execute_instruction(input: &InstructionInput) -> InstructionOutcome {
    execute_instruction_with_backend(input, &SbpfExecutionAdapter::with_defaults())
}

/// Execute a single instruction with a custom backend.
pub fn execute_instruction_with_backend(
    input: &InstructionInput,
    backend: &dyn ExecutionBackend,
) -> InstructionOutcome {
    let info = InstructionInfo {
        program_id: input.program_id,
        accounts: input.accounts.clone(),
        data: input.data.clone(),
        slot_context: input.slot_context.clone(),
        sibling_instructions: vec![],
    };

    let result =
        backend.execute_instruction(&info, karstflow_constants::execution::MAX_COMPUTE_UNITS);

    InstructionOutcome { result }
}

/// Convenience: build a system program transfer instruction input.
pub fn system_transfer_input(
    from: Pubkey,
    from_account: Account,
    to: Pubkey,
    to_account: Account,
    lamports: u64,
) -> InstructionInput {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes()); // Transfer discriminant
    data.extend_from_slice(&lamports.to_le_bytes());

    InstructionInput {
        program_id: karstflow_ids::SYSTEM_PROGRAM_ID,
        accounts: vec![
            (from, from_account, true, true),
            (to, to_account, true, false),
        ],
        data,
        slot_context: SlotContext::default(),
    }
}

/// Convenience: build a system program CreateAccount instruction input.
pub fn system_create_account_input(
    funder: Pubkey,
    funder_account: Account,
    new_account_key: Pubkey,
    new_account: Account,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> InstructionInput {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes()); // CreateAccount discriminant
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_bytes());

    InstructionInput {
        program_id: karstflow_ids::SYSTEM_PROGRAM_ID,
        accounts: vec![
            (funder, funder_account, true, true),
            (new_account_key, new_account, true, true),
        ],
        data,
        slot_context: SlotContext::default(),
    }
}

/// Helper to create a funded system-owned account.
pub fn funded_account(lamports: u64) -> Account {
    Account {
        meta: karstflow_types::AccountMeta {
            lamports,
            owner: karstflow_ids::SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: karstflow_types::AccountData::empty(),
    }
}
