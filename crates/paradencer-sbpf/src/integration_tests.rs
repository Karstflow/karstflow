use super::{ExecutionContext, SbpfVm, StubSbpfVm};
use paradencer_ids::{STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID};
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

// ---------------------------------------------------------------------------
// Wave 8: Vote program end-to-end tests
// ---------------------------------------------------------------------------

/// Helper to build a vote account owned by the vote program.
fn make_vote_owned_account(lamports: u64) -> Account {
    Account {
        meta: paradencer_types::AccountMeta {
            lamports,
            owner: VOTE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    }
}

/// Build InitializeAccount instruction data.
fn build_init_vote_data(node: &Pubkey, voter: &Pubkey, withdrawer: &Pubkey, commission: u8) -> Vec<u8> {
    let mut data = vec![0, 0, 0, 0]; // INSTRUCTION_INITIALIZE_ACCOUNT = 0
    data.extend_from_slice(node.as_bytes());
    data.extend_from_slice(voter.as_bytes());
    data.extend_from_slice(withdrawer.as_bytes());
    data.push(commission);
    data
}

/// Build Vote instruction data (type 2) for given slots.
fn build_vote_data(slots: &[u64], hash: [u8; 32]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes()); // Vote instruction type
    data.extend_from_slice(&(slots.len() as u64).to_le_bytes());
    for slot in slots {
        data.extend_from_slice(&slot.to_le_bytes());
    }
    data.extend_from_slice(&hash);
    data
}

/// Build TowerSync instruction data with votes and optional root.
fn build_tower_sync_data(root: Option<u64>, votes: &[(u64, u32)]) -> Vec<u8> {
    use paradencer_constants::vote_program::INSTRUCTION_TOWER_SYNC;
    let mut data = Vec::new();
    data.extend_from_slice(&INSTRUCTION_TOWER_SYNC.to_le_bytes());
    // root
    match root {
        Some(slot) => {
            data.push(1);
            data.extend_from_slice(&slot.to_le_bytes());
        }
        None => data.push(0),
    }
    // vote count
    data.extend_from_slice(&(votes.len() as u32).to_le_bytes());
    for (slot, conf) in votes {
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(&conf.to_le_bytes());
    }
    // no timestamp
    data.push(0);
    data
}

#[test]
fn vote_program_initialize_and_vote_end_to_end() {
    let processor = TransactionProcessor::new();
    let vote_pubkey = Pubkey::new_unique();
    let node = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();

    // Step 1: Initialize vote account
    let vote_account = make_vote_owned_account(10_000);
    let init_data = build_init_vote_data(&node, &voter, &withdrawer, 5);

    let init_outcome = processor.process_instruction(
        VOTE_PROGRAM_ID,
        vec![(vote_pubkey, vote_account, true)],
        init_data,
    );
    assert!(init_outcome.success, "Init should succeed");

    let initialized = init_outcome.modified_accounts.get(&vote_pubkey).unwrap().clone();
    assert!(initialized.data.as_slice().len() > 0, "Vote state should be serialized");

    // Step 2: Vote on slot 100
    let vote_data = build_vote_data(&[100], [42u8; 32]);
    let vote_outcome = processor.process_instruction(
        VOTE_PROGRAM_ID,
        vec![(vote_pubkey, initialized.clone(), true)],
        vote_data,
    );
    assert!(vote_outcome.success, "Vote should succeed");

    let after_vote = vote_outcome.modified_accounts.get(&vote_pubkey).unwrap().clone();

    // Step 3: Vote on slot 101
    let vote_data_2 = build_vote_data(&[101], [43u8; 32]);
    let vote_outcome_2 = processor.process_instruction(
        VOTE_PROGRAM_ID,
        vec![(vote_pubkey, after_vote.clone(), true)],
        vote_data_2,
    );
    assert!(vote_outcome_2.success, "Second vote should succeed");
}

#[test]
fn vote_program_tower_sync_end_to_end() {
    let processor = TransactionProcessor::new();
    let vote_pubkey = Pubkey::new_unique();
    let node = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();

    // Initialize
    let vote_account = make_vote_owned_account(10_000);
    let init_data = build_init_vote_data(&node, &voter, &withdrawer, 10);

    let init_outcome = processor.process_instruction(
        VOTE_PROGRAM_ID,
        vec![(vote_pubkey, vote_account, true)],
        init_data,
    );
    assert!(init_outcome.success);
    let initialized = init_outcome.modified_accounts.get(&vote_pubkey).unwrap().clone();

    // Tower sync with root=50, votes=[100/3, 101/2, 102/1]
    let sync_data = build_tower_sync_data(Some(50), &[(100, 3), (101, 2), (102, 1)]);
    let sync_outcome = processor.process_instruction(
        VOTE_PROGRAM_ID,
        vec![(vote_pubkey, initialized, true)],
        sync_data,
    );
    assert!(sync_outcome.success, "TowerSync should succeed");

    // Verify account data changed
    let synced = sync_outcome.modified_accounts.get(&vote_pubkey).unwrap();
    assert!(synced.data.as_slice().len() > 0);
}

#[test]
fn all_13_builtin_programs_route_through_processor() {
    use paradencer_ids::{
        ADDRESS_LOOKUP_TABLE_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID,
        CONFIG_PROGRAM_ID, ED25519_PROGRAM_ID, MEMO_PROGRAM_ID, MEMO_PROGRAM_V3_ID,
        SECP256K1_PROGRAM_ID, STAKE_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
        VOTE_PROGRAM_ID,
    };

    let processor = TransactionProcessor::new();

    let all_programs = [
        ("system", SYSTEM_PROGRAM_ID),
        ("vote", VOTE_PROGRAM_ID),
        ("stake", STAKE_PROGRAM_ID),
        ("token", TOKEN_PROGRAM_ID),
        ("token_2022", TOKEN_2022_PROGRAM_ID),
        ("associated_token", ASSOCIATED_TOKEN_PROGRAM_ID),
        ("memo", MEMO_PROGRAM_ID),
        ("memo_v3", MEMO_PROGRAM_V3_ID),
        ("bpf_loader", BPF_LOADER_PROGRAM_ID),
        ("compute_budget", COMPUTE_BUDGET_PROGRAM_ID),
        ("address_lookup", ADDRESS_LOOKUP_TABLE_PROGRAM_ID),
        ("config", CONFIG_PROGRAM_ID),
        ("ed25519", ED25519_PROGRAM_ID),
        ("secp256k1", SECP256K1_PROGRAM_ID),
    ];

    for (name, program_id) in &all_programs {
        // Should not panic — just verify routing works
        let _outcome = processor.process_instruction(*program_id, vec![], vec![]);
        // We don't assert success since empty data may cause legitimate errors
    }
}

// ---------------------------------------------------------------------------
// Stake program integration tests
// ---------------------------------------------------------------------------

fn make_stake_account_for_test(lamports: u64) -> Account {
    use crate::stake::{serialize_stake_state, StakeState};
    use paradencer_constants::stake_program::STAKE_STATE_V2_SIZE;

    let mut buf = serialize_stake_state(&StakeState::Uninitialized);
    buf.resize(STAKE_STATE_V2_SIZE, 0);
    Account {
        meta: AccountMeta {
            lamports,
            owner: STAKE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(buf),
    }
}

fn make_vote_account_for_test() -> Account {
    Account {
        meta: AccountMeta {
            lamports: 10_000,
            owner: VOTE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    }
}

fn build_clock_for_test(epoch: u64, timestamp: i64) -> Account {
    let mut data = vec![0u8; 40];
    data[16..24].copy_from_slice(&epoch.to_le_bytes());
    data[32..40].copy_from_slice(&timestamp.to_le_bytes());
    Account {
        meta: AccountMeta {
            lamports: 1,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(data),
    }
}

fn stake_minimum_balance() -> u64 {
    use paradencer_constants::economics::{
        DEFAULT_EXEMPTION_THRESHOLD, DEFAULT_LAMPORTS_PER_BYTE_YEAR,
    };
    use paradencer_constants::stake_program::STAKE_STATE_V2_SIZE;
    ((DEFAULT_LAMPORTS_PER_BYTE_YEAR * STAKE_STATE_V2_SIZE as u64) as f64
        * DEFAULT_EXEMPTION_THRESHOLD) as u64
}

fn make_stake_executor() -> super::StakeProgramExecutor {
    super::StakeProgramExecutor::new(150)
}

/// Full lifecycle: Initialize → Delegate → Deactivate → Withdraw.
#[test]
fn stake_full_lifecycle() {
    use crate::stake::deserialize_stake_state;

    let executor = make_stake_executor();
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let stake_pk = Pubkey::new_unique();
    let lamports = 5_000_000_000u64;

    // 1. Initialize
    let mut init_data = vec![0u8; 116];
    init_data[0..4].copy_from_slice(&0u32.to_le_bytes());
    init_data[4..36].copy_from_slice(staker.as_bytes());
    init_data[36..68].copy_from_slice(withdrawer.as_bytes());

    let stake_account = make_stake_account_for_test(lamports);
    let init_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![(stake_pk, stake_account, true)],
        init_data,
    );
    let init_outcome = executor.execute(&init_ctx).unwrap();
    assert!(init_outcome.success);
    let initialized_account = init_outcome.modified_accounts[&stake_pk].clone();
    let init_state = deserialize_stake_state(initialized_account.data.as_ref()).unwrap();
    assert!(init_state.is_initialized());

    // 2. Delegate
    let delegate_data = 2u32.to_le_bytes().to_vec();
    let delegate_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![
            (stake_pk, initialized_account.clone(), true),
            (voter, make_vote_account_for_test(), false),
            (Pubkey::new_unique(), build_clock_for_test(5, 0), false),
            (Pubkey::new_unique(), Account::zeroed(), false),
            (Pubkey::new_unique(), Account::zeroed(), false),
            (staker, Account::zeroed(), false),
        ],
        delegate_data,
    );
    let delegate_outcome = executor.execute(&delegate_ctx).unwrap();
    assert!(delegate_outcome.success);
    let delegated_account = delegate_outcome.modified_accounts[&stake_pk].clone();
    let del_state = deserialize_stake_state(delegated_account.data.as_ref()).unwrap();
    assert!(del_state.is_delegated());
    assert_eq!(del_state.stake().unwrap().delegation.voter_pubkey, voter);

    // 3. Deactivate
    let deactivate_data = 5u32.to_le_bytes().to_vec();
    let deactivate_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![
            (stake_pk, delegated_account.clone(), true),
            (Pubkey::new_unique(), build_clock_for_test(20, 0), false),
            (staker, Account::zeroed(), false),
        ],
        deactivate_data,
    );
    let deactivate_outcome = executor.execute(&deactivate_ctx).unwrap();
    assert!(deactivate_outcome.success);
    let deactivated_account = deactivate_outcome.modified_accounts[&stake_pk].clone();
    let deact_state = deserialize_stake_state(deactivated_account.data.as_ref()).unwrap();
    assert!(deact_state.stake().unwrap().delegation.is_deactivated());
    assert_eq!(
        deact_state.stake().unwrap().delegation.deactivation_epoch,
        20
    );

    // 4. Withdraw all
    let recipient_pk = Pubkey::new_unique();
    let mut withdraw_data = 4u32.to_le_bytes().to_vec();
    withdraw_data.extend_from_slice(&lamports.to_le_bytes());

    let withdraw_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![
            (stake_pk, deactivated_account, true),
            (recipient_pk, Account::zeroed(), true),
            (Pubkey::new_unique(), build_clock_for_test(100, 0), false),
            (Pubkey::new_unique(), Account::zeroed(), false),
            (withdrawer, Account::zeroed(), false),
        ],
        withdraw_data,
    );
    let withdraw_outcome = executor.execute(&withdraw_ctx).unwrap();
    assert!(withdraw_outcome.success);
    let final_stake = &withdraw_outcome.modified_accounts[&stake_pk];
    assert_eq!(final_stake.meta.lamports, 0);
    let final_state = deserialize_stake_state(final_stake.data.as_ref()).unwrap();
    assert!(final_state.is_uninitialized());
    let final_recipient = &withdraw_outcome.modified_accounts[&recipient_pk];
    assert_eq!(final_recipient.meta.lamports, lamports);
}

/// Split and merge cycle.
#[test]
fn stake_split_and_merge_cycle() {
    use crate::stake::{
        deserialize_stake_state, Authorized, Delegation, Lockup, Meta, StakeAccount, StakeFlags,
        StakeState,
    };
    use paradencer_constants::stake_program::STAKE_STATE_V2_SIZE;

    let executor = make_stake_executor();
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let min_balance = stake_minimum_balance();

    // Create a delegated account
    let total_lamports = 10_000_000_000u64;
    let stake_amount = total_lamports - min_balance;
    let delegation = Delegation::new(voter, stake_amount, 0);
    let state = StakeState::Delegated(
        Meta::new(
            min_balance,
            Authorized::new(staker, withdrawer),
            Lockup::default(),
        ),
        StakeAccount::new(delegation, 0),
        StakeFlags::EMPTY,
    );
    let mut src_data = crate::stake::serialize_stake_state(&state);
    src_data.resize(STAKE_STATE_V2_SIZE, 0);
    let src_account = Account {
        meta: AccountMeta {
            lamports: total_lamports,
            owner: STAKE_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(src_data),
    };

    let src_pk = Pubkey::new_unique();
    let dst_pk = Pubkey::new_unique();

    // Split 4 SOL
    let split_amount = 4_000_000_000u64;
    let mut split_data = 3u32.to_le_bytes().to_vec();
    split_data.extend_from_slice(&split_amount.to_le_bytes());

    let dst_account = make_stake_account_for_test(0);
    let split_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![
            (src_pk, src_account, true),
            (dst_pk, dst_account, true),
            (staker, Account::zeroed(), false),
        ],
        split_data,
    );
    let split_outcome = executor.execute(&split_ctx).unwrap();
    assert!(split_outcome.success);

    let src_after_split = split_outcome.modified_accounts[&src_pk].clone();
    let dst_after_split = split_outcome.modified_accounts[&dst_pk].clone();
    assert_eq!(src_after_split.meta.lamports, total_lamports - split_amount);
    assert_eq!(dst_after_split.meta.lamports, split_amount);

    // Merge back
    let merge_data = 7u32.to_le_bytes().to_vec();
    let merge_ctx = ExecutionContext::new(
        STAKE_PROGRAM_ID,
        vec![
            (src_pk, src_after_split, true),
            (dst_pk, dst_after_split, true),
            (Pubkey::new_unique(), build_clock_for_test(0, 0), false),
            (Pubkey::new_unique(), Account::zeroed(), false),
            (staker, Account::zeroed(), false),
        ],
        merge_data,
    );
    let merge_outcome = executor.execute(&merge_ctx).unwrap();
    assert!(merge_outcome.success);

    let src_after_merge = &merge_outcome.modified_accounts[&src_pk];
    let dst_after_merge = &merge_outcome.modified_accounts[&dst_pk];
    assert_eq!(src_after_merge.meta.lamports, total_lamports);
    assert_eq!(dst_after_merge.meta.lamports, 0);
}

/// Stake state binary serialization roundtrip.
#[test]
fn stake_serialize_deserialize_roundtrip() {
    use crate::stake::{
        deserialize_stake_state, serialize_stake_state, Authorized, Delegation, Lockup, Meta,
        StakeAccount, StakeFlags, StakeState,
    };

    let voter = Pubkey::new_unique();
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();

    let state = StakeState::Delegated(
        Meta::new(
            stake_minimum_balance(),
            Authorized::new(staker, withdrawer),
            Lockup::default(),
        ),
        StakeAccount::new(Delegation::new(voter, 3_000_000_000, 5), 100),
        StakeFlags::EMPTY,
    );

    let serialized = serialize_stake_state(&state);
    let deserialized = deserialize_stake_state(&serialized).unwrap();
    assert!(deserialized.is_delegated());
    assert_eq!(deserialized.stake().unwrap().delegation.voter_pubkey, voter);
    assert_eq!(
        deserialized.stake().unwrap().delegation.stake_amount,
        3_000_000_000
    );
    assert_eq!(
        deserialized.stake().unwrap().delegation.activation_epoch,
        5
    );
    assert_eq!(deserialized.stake().unwrap().credits_observed, 100);
    assert_eq!(deserialized.meta().unwrap().authorized.staker, staker);
    assert_eq!(
        deserialized.meta().unwrap().authorized.withdrawer,
        withdrawer
    );
}
