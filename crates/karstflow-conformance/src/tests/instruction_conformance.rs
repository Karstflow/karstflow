//! Instruction-level conformance tests.
//!
//! Each test executes a single instruction and verifies the outcome
//! matches expected post-state.

use crate::harness::instruction::*;
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};

fn system_account(lamports: u64) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    }
}

// -----------------------------------------------------------------------
// System program: Transfer
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn system_transfer_moves_lamports() {
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
    let input = system_transfer_input(from, system_account(1000), to, system_account(500), 300);

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success, "transfer should succeed");
    let from_post = &outcome.result.modified_accounts[&from];
    let to_post = &outcome.result.modified_accounts[&to];
    assert_eq!(from_post.meta.lamports, 700);
    assert_eq!(to_post.meta.lamports, 800);
}

#[test]
#[ignore]
fn system_transfer_insufficient_funds_fails() {
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
    let input = system_transfer_input(from, system_account(100), to, system_account(0), 200);

    let outcome = execute_instruction(&input);

    assert!(!outcome.result.success, "should fail: insufficient funds");
    assert!(outcome.result.error.is_some());
}

#[test]
#[ignore]
fn system_transfer_zero_amount_succeeds() {
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
    let input = system_transfer_input(from, system_account(1000), to, system_account(500), 0);

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success, "zero transfer should succeed");
}

#[test]
#[ignore]
fn system_transfer_to_self_succeeds() {
    let key = Pubkey::new_unique();
    // Transfer to self: same pubkey as both from and to
    let input = system_transfer_input(key, system_account(1000), key, system_account(1000), 100);

    let outcome = execute_instruction(&input);

    // Self-transfer semantics: should succeed, balance unchanged
    assert!(outcome.result.success);
}

#[test]
#[ignore]
fn system_transfer_exact_balance() {
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
    let input = system_transfer_input(from, system_account(500), to, system_account(0), 500);

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success);
    let from_post = &outcome.result.modified_accounts[&from];
    assert_eq!(from_post.meta.lamports, 0);
}

// -----------------------------------------------------------------------
// System program: CreateAccount
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn system_create_account_allocates_space() {
    let funder = Pubkey::new_unique();
    let new_key = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let input = system_create_account_input(
        funder,
        system_account(10_000),
        new_key,
        system_account(0),
        5_000,
        128,
        &owner,
    );

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success, "create account should succeed");
    let new_account = &outcome.result.modified_accounts[&new_key];
    assert_eq!(new_account.meta.lamports, 5_000);
    assert_eq!(new_account.meta.owner, owner);
    assert_eq!(new_account.data.as_ref().len(), 128);

    let funder_post = &outcome.result.modified_accounts[&funder];
    assert_eq!(funder_post.meta.lamports, 5_000);
}

#[test]
#[ignore]
fn system_create_account_insufficient_funds_fails() {
    let funder = Pubkey::new_unique();
    let new_key = Pubkey::new_unique();
    let owner = Pubkey::new_unique();

    let input = system_create_account_input(
        funder,
        system_account(100),
        new_key,
        system_account(0),
        500,
        64,
        &owner,
    );

    let outcome = execute_instruction(&input);

    assert!(!outcome.result.success);
}

// -----------------------------------------------------------------------
// Unknown program
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn unknown_program_fails() {
    let program_id = Pubkey::new_unique();
    let input = InstructionInput {
        program_id,
        accounts: vec![],
        data: vec![],
        slot_context: karstflow_consensus::SlotContext::default(),
    };

    let outcome = execute_instruction(&input);

    assert!(!outcome.result.success);
    assert!(outcome.result.error.is_some());
}

// -----------------------------------------------------------------------
// Compute budget
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn instruction_consumes_compute_units() {
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
    let input = system_transfer_input(from, system_account(1000), to, system_account(0), 100);

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success);
    assert!(
        outcome.result.compute_units_consumed > 0,
        "should consume CU"
    );
}

// -----------------------------------------------------------------------
// BPF program execution
// -----------------------------------------------------------------------

#[test]
#[ignore]
fn bpf_noop_program_executes() {
    use karstflow_ids::BPF_LOADER_PROGRAM_ID;
    use karstflow_sbpf::elf_loader::TestElfBuilder;
    use karstflow_sbpf::instruction::{Instruction, Opcode};

    let program_id = Pubkey::new_unique();

    // Build minimal ELF: mov r0, 0; exit (success)
    let mut text = Vec::new();
    for insn in &[
        Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
        Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
    ] {
        text.extend_from_slice(&insn.encode().to_le_bytes());
    }
    let elf = TestElfBuilder::new().text(text).build();

    let program_account = Account {
        meta: AccountMeta {
            lamports: 1,
            owner: BPF_LOADER_PROGRAM_ID,
            executable: true,
            rent_epoch: 0,
        },
        data: AccountData::new(elf),
    };

    let input = InstructionInput {
        program_id,
        accounts: vec![(program_id, program_account, false, false)],
        data: vec![],
        slot_context: karstflow_consensus::SlotContext::default(),
    };

    let outcome = execute_instruction(&input);

    assert!(outcome.result.success, "BPF noop should succeed");
    assert!(outcome.result.compute_units_consumed > 0);
}
