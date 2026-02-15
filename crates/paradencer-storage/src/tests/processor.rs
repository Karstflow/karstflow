use crate::accounts::*;
use paradencer_ids::SYSTEM_PROGRAM_ID;

#[test]
fn test_transaction_processor_execute() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let from_account = Pubkey::new([2u8; 32]);
    let to_account = Pubkey::new([3u8; 32]);

    // Setup initial accounts
    let from_initial = Account::new(1000, vec![], SYSTEM_PROGRAM_ID);
    let to_initial = Account::new(500, vec![], SYSTEM_PROGRAM_ID);
    db.write_account(xid, from_account, from_initial).unwrap();
    db.write_account(xid, to_account, to_initial).unwrap();

    // Create Transfer instruction (type 2) - transfer 100 lamports
    let mut instruction_data = vec![2, 0, 0, 0]; // instruction type
    instruction_data.extend_from_slice(&100u64.to_le_bytes()); // amount

    let instruction = Instruction::new(
        SYSTEM_PROGRAM_ID,
        vec![
            AccountRef::writable(from_account),
            AccountRef::writable(to_account),
        ],
        instruction_data,
    );

    let transaction = Transaction::new(vec![Signature::default()], vec![instruction], [0u8; 32]);

    let result = processor.execute_transaction(xid, &transaction).unwrap();

    assert_eq!(result.status, TransactionStatus::Success);
    assert!(result.compute_units_consumed > 0);
}

#[test]
fn test_transaction_processor_account_modification() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let from_account = Pubkey::new([2u8; 32]);
    let to_account = Pubkey::new([3u8; 32]);

    let from_initial = Account::new(2000, vec![], SYSTEM_PROGRAM_ID);
    let to_initial = Account::new(500, vec![], SYSTEM_PROGRAM_ID);
    db.write_account(xid, from_account, from_initial.clone())
        .unwrap();
    db.write_account(xid, to_account, to_initial.clone())
        .unwrap();

    // Transfer 1000 lamports
    let mut instruction_data = vec![2, 0, 0, 0];
    instruction_data.extend_from_slice(&1000u64.to_le_bytes());

    let instruction = Instruction::new(
        SYSTEM_PROGRAM_ID,
        vec![
            AccountRef::writable(from_account),
            AccountRef::writable(to_account),
        ],
        instruction_data,
    );

    let transaction = Transaction::new(vec![Signature::default()], vec![instruction], [0u8; 32]);

    processor.execute_transaction(xid, &transaction).unwrap();

    let modified_to_account = db.read_account(xid, &to_account).unwrap().unwrap();

    // to_account should have received lamports
    assert!(modified_to_account.meta.lamports > to_initial.meta.lamports);
    assert_eq!(modified_to_account.meta.lamports, 1500);
}

#[test]
fn test_transaction_processor_batch_execution() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let from_account = Pubkey::new([2u8; 32]);
    let to_account = Pubkey::new([3u8; 32]);

    // Setup initial accounts
    let from_initial = Account::new(10000, vec![], SYSTEM_PROGRAM_ID);
    let to_initial = Account::new(0, vec![], SYSTEM_PROGRAM_ID);
    db.write_account(xid, from_account, from_initial).unwrap();
    db.write_account(xid, to_account, to_initial).unwrap();

    let transactions: Vec<Transaction> = (0..5)
        .map(|_| {
            // Transfer 100 lamports
            let mut instruction_data = vec![2, 0, 0, 0];
            instruction_data.extend_from_slice(&100u64.to_le_bytes());

            let instruction = Instruction::new(
                SYSTEM_PROGRAM_ID,
                vec![
                    AccountRef::writable(from_account),
                    AccountRef::writable(to_account),
                ],
                instruction_data,
            );
            Transaction::new(vec![Signature::default()], vec![instruction], [0u8; 32])
        })
        .collect();

    let results = processor.execute_batch(xid, &transactions).unwrap();

    assert_eq!(results.len(), 5);
    for result in results {
        assert_eq!(result.status, TransactionStatus::Success);
    }
}

#[test]
fn test_load_accounts_creates_default_for_missing() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let program_id = Pubkey::new([1u8; 32]);
    let missing_account = Pubkey::new([99u8; 32]);

    let instruction = Instruction::new(
        program_id,
        vec![AccountRef::read_only(missing_account)],
        vec![],
    );

    let transaction = Transaction::new(vec![Signature::default()], vec![instruction], [0u8; 32]);

    let loaded = processor.load_accounts(xid, &transaction).unwrap();

    let account = loaded.get(&missing_account).unwrap();
    assert_eq!(account.meta.lamports, 0);
}
