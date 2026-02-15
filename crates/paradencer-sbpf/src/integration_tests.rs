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
