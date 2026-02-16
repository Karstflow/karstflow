use super::{ExecutionContext, SbpfVm, StubSbpfVm};
use paradencer_ids::SYSTEM_PROGRAM_ID;
use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};

#[test]
fn end_to_end_create_account_and_transfer() {
    let vm = StubSbpfVm::new();

    let payer_pubkey = Pubkey::new_unique();
    let new_account_pubkey = Pubkey::new_unique();
    let recipient_pubkey = Pubkey::new_unique();

    let mut payer_account = Account {
        meta: AccountMeta {
            lamports: 100_000,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    };

    let new_account = Account::zeroed();

    let new_owner = Pubkey::new_unique();

    let mut create_account_data = vec![];
    create_account_data.extend_from_slice(&0u32.to_le_bytes());
    create_account_data.extend_from_slice(&50_000u64.to_le_bytes());
    create_account_data.extend_from_slice(&128u64.to_le_bytes());
    create_account_data.extend_from_slice(new_owner.as_bytes());

    let create_context = ExecutionContext::new(
        SYSTEM_PROGRAM_ID,
        vec![
            (payer_pubkey, payer_account.clone(), true),
            (new_account_pubkey, new_account, true),
        ],
        create_account_data,
    );

    let create_outcome = vm.execute(create_context).unwrap();
    assert!(create_outcome.success);
    assert_eq!(create_outcome.modified_accounts.len(), 2);

    let created_payer = create_outcome.modified_accounts.get(&payer_pubkey).unwrap();
    assert_eq!(created_payer.meta.lamports, 50_000);

    let created_account = create_outcome
        .modified_accounts
        .get(&new_account_pubkey)
        .unwrap();
    assert_eq!(created_account.meta.lamports, 50_000);
    assert_eq!(created_account.meta.owner, new_owner);
    assert_eq!(created_account.data.as_slice().len(), 0);

    payer_account.meta.lamports = 50_000;
    let recipient_account = Account::zeroed();

    let mut transfer_data = vec![];
    transfer_data.extend_from_slice(&2u32.to_le_bytes());
    transfer_data.extend_from_slice(&10_000u64.to_le_bytes());

    let transfer_context = ExecutionContext::new(
        SYSTEM_PROGRAM_ID,
        vec![
            (payer_pubkey, payer_account, true),
            (recipient_pubkey, recipient_account.clone(), true),
        ],
        transfer_data,
    );

    let transfer_outcome = vm.execute(transfer_context).unwrap();
    assert!(transfer_outcome.success);

    let final_payer = transfer_outcome
        .modified_accounts
        .get(&payer_pubkey)
        .unwrap();
    assert_eq!(final_payer.meta.lamports, 40_000);

    let final_recipient = transfer_outcome
        .modified_accounts
        .get(&recipient_pubkey)
        .unwrap();
    assert_eq!(final_recipient.meta.lamports, 10_000);
}

#[test]
fn end_to_end_allocate_and_assign() {
    let vm = StubSbpfVm::new();

    let account_pubkey = Pubkey::new_unique();
    let mut account = Account {
        meta: AccountMeta {
            lamports: 10_000,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    };

    let mut allocate_data = vec![];
    allocate_data.extend_from_slice(&8u32.to_le_bytes());
    allocate_data.extend_from_slice(&512u64.to_le_bytes());

    let allocate_context = ExecutionContext::new(
        SYSTEM_PROGRAM_ID,
        vec![(account_pubkey, account.clone(), true)],
        allocate_data,
    );

    let allocate_outcome = vm.execute(allocate_context).unwrap();
    assert!(allocate_outcome.success);
    assert!(allocate_outcome
        .logs
        .iter()
        .any(|log| log.contains("Allocate")));

    let allocated_account = allocate_outcome
        .modified_accounts
        .get(&account_pubkey)
        .unwrap();
    account = allocated_account.clone();

    let new_owner = Pubkey::new_unique();

    let mut assign_data = vec![];
    assign_data.extend_from_slice(&1u32.to_le_bytes());
    assign_data.extend_from_slice(new_owner.as_bytes());

    let assign_context = ExecutionContext::new(
        SYSTEM_PROGRAM_ID,
        vec![(account_pubkey, account, true)],
        assign_data,
    );

    let assign_outcome = vm.execute(assign_context).unwrap();
    assert!(assign_outcome.success);
    assert!(assign_outcome.logs.iter().any(|log| log.contains("Assign")));

    let assigned_account = assign_outcome
        .modified_accounts
        .get(&account_pubkey)
        .unwrap();
    assert_eq!(assigned_account.meta.owner, new_owner);
}

#[test]
fn create_account_validates_inputs() {
    let vm = StubSbpfVm::new();

    let payer = Account {
        meta: AccountMeta {
            lamports: 1_000,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    };

    let target = Account::zeroed();

    let mut insufficient_lamports_data = vec![];
    insufficient_lamports_data.extend_from_slice(&0u32.to_le_bytes());
    insufficient_lamports_data.extend_from_slice(&10_000u64.to_le_bytes());
    insufficient_lamports_data.extend_from_slice(&0u64.to_le_bytes());
    insufficient_lamports_data.extend_from_slice(Pubkey::new_unique().as_bytes());

    let context = ExecutionContext::new(
        SYSTEM_PROGRAM_ID,
        vec![
            (Pubkey::new_unique(), payer, true),
            (Pubkey::new_unique(), target, true),
        ],
        insufficient_lamports_data,
    );

    let result = vm.execute(context);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("negative lamports") || err.to_string().contains("Insufficient"),
        "Error was: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Wave 7: End-to-end VM execution pipeline tests
// ---------------------------------------------------------------------------

use crate::elf_loader::TestElfBuilder;
use crate::instruction::{Instruction, Opcode};
use crate::vm::BytecodeVm;
use crate::TransactionProcessor;
use paradencer_ids::BPF_LOADER_PROGRAM_ID;
use std::collections::HashMap;

/// Build a minimal ELF that sets r0=0 and exits (success).
fn build_success_elf() -> Vec<u8> {
    let mut text = Vec::new();
    for insn in &[
        Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
        Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
    ] {
        text.extend_from_slice(&insn.encode().to_le_bytes());
    }
    TestElfBuilder::new().text(text).build()
}

/// Build a minimal ELF that sets r0=1 and exits (failure).
fn build_failure_elf() -> Vec<u8> {
    let mut text = Vec::new();
    for insn in &[
        Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 1),
        Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
    ] {
        text.extend_from_slice(&insn.encode().to_le_bytes());
    }
    TestElfBuilder::new().text(text).build()
}

fn make_executable_account(elf: Vec<u8>) -> Account {
    Account {
        meta: AccountMeta {
            lamports: 1,
            owner: BPF_LOADER_PROGRAM_ID,
            executable: true,
            rent_epoch: 0,
        },
        data: AccountData::new(elf),
    }
}

#[test]
fn bytecode_vm_executes_deployed_program() {
    let vm = BytecodeVm::new();
    let program_id = Pubkey::new_unique();
    let elf = build_success_elf();
    let program_account = make_executable_account(elf);

    let context = ExecutionContext::new(
        program_id,
        vec![(program_id, program_account, false)],
        vec![],
    );

    let outcome = vm.execute(context).unwrap();
    assert!(outcome.success, "Program should succeed with r0=0");
    assert!(outcome.compute_units_consumed > 0);
}

#[test]
fn bytecode_vm_failure_elf_returns_failure() {
    let vm = BytecodeVm::new();
    let program_id = Pubkey::new_unique();
    let elf = build_failure_elf();
    let program_account = make_executable_account(elf);

    let context = ExecutionContext::new(
        program_id,
        vec![(program_id, program_account, false)],
        vec![],
    );

    let outcome = vm.execute(context).unwrap();
    assert!(!outcome.success, "Program should fail with r0=1");
}

#[test]
fn transaction_processor_routes_bpf_via_bytecode_vm() {
    let processor = TransactionProcessor::new();
    let program_id = Pubkey::new_unique();
    let elf = build_success_elf();
    let program_account = make_executable_account(elf);

    let outcome = processor.process_instruction(
        program_id,
        vec![(program_id, program_account, false)],
        vec![],
    );

    assert!(outcome.success, "TransactionProcessor should route to BytecodeVm");
    assert!(outcome.compute_units_consumed > 0);
}

#[test]
fn transaction_processor_handles_bpf_failure() {
    let processor = TransactionProcessor::new();
    let program_id = Pubkey::new_unique();
    let elf = build_failure_elf();
    let program_account = make_executable_account(elf);

    let outcome = processor.process_instruction(
        program_id,
        vec![(program_id, program_account, false)],
        vec![],
    );

    assert!(!outcome.success, "Failed BPF should propagate through TransactionProcessor");
}

#[test]
fn full_transaction_with_builtin_and_bpf() {
    let processor = TransactionProcessor::new();

    // Test 1: System program transfer still works
    let from = Pubkey::new_unique();
    let to = Pubkey::new_unique();
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

    let mut transfer_data = vec![2, 0, 0, 0];
    transfer_data.extend_from_slice(&100u64.to_le_bytes());

    let builtin_outcome = processor.process_instruction(
        SYSTEM_PROGRAM_ID,
        vec![(from, from_account, true), (to, to_account, true)],
        transfer_data,
    );
    assert!(builtin_outcome.success, "Builtin system transfer should work");

    // Test 2: BPF program in same processor works
    let program_id = Pubkey::new_unique();
    let elf = build_success_elf();
    let program_account = make_executable_account(elf);

    let bpf_outcome = processor.process_instruction(
        program_id,
        vec![(program_id, program_account, false)],
        vec![],
    );
    assert!(bpf_outcome.success, "BPF program should work alongside builtins");
}

#[test]
fn full_transaction_process_with_bpf_program() {
    use crate::transaction_processor::{
        CompiledInstruction, Transaction, TransactionMessage,
    };

    let processor = TransactionProcessor::new();
    let program_id = Pubkey::new_unique();
    let elf = build_success_elf();
    let program_account = make_executable_account(elf);

    // Build a transaction that invokes the BPF program
    let transaction = Transaction {
        signatures: vec![[0u8; 64]],
        message: TransactionMessage {
            account_keys: vec![program_id],
            recent_blockhash: [0u8; 32],
            instructions: vec![CompiledInstruction {
                program_id_index: 0,
                accounts: vec![0],
                data: vec![],
            }],
        },
    };

    let mut account_state = HashMap::new();
    account_state.insert(program_id, program_account);

    let result = processor.process_transaction(&transaction, &account_state);

    assert!(result.success, "Full transaction with BPF should succeed: {:?}", result.error);
    assert!(result.compute_units_consumed > 0);
}
