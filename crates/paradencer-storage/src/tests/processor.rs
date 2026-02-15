use crate::accounts::*;

#[test]
fn test_transaction_processor_execute() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let program_id = Pubkey::new([1u8; 32]);
    let account1 = Pubkey::new([2u8; 32]);
    let account2 = Pubkey::new([3u8; 32]);

    let instruction = Instruction::new(
        program_id,
        vec![
            AccountRef::writable(account1),
            AccountRef::read_only(account2),
        ],
        vec![1, 2, 3, 4],
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

    let program_id = Pubkey::new([1u8; 32]);
    let target_account = Pubkey::new([2u8; 32]);

    let initial_account = Account::new(1000, vec![], Pubkey::zeroed());
    db.write_account(xid, target_account, initial_account.clone())
        .unwrap();

    let instruction = Instruction::new(
        program_id,
        vec![AccountRef::writable(target_account)],
        vec![],
    );

    let transaction = Transaction::new(vec![Signature::default()], vec![instruction], [0u8; 32]);

    processor.execute_transaction(xid, &transaction).unwrap();

    let modified_account = db.read_account(xid, &target_account).unwrap().unwrap();

    assert!(modified_account.meta.lamports > initial_account.meta.lamports);
}

#[test]
fn test_transaction_processor_batch_execution() {
    let db = AccountDatabase::new();
    let processor = TransactionProcessor::new(db.clone());
    let xid = TransactionId::from_slot(1);

    let program_id = Pubkey::new([1u8; 32]);
    let account1 = Pubkey::new([2u8; 32]);

    let transactions: Vec<Transaction> = (0..5)
        .map(|i| {
            let instruction =
                Instruction::new(program_id, vec![AccountRef::writable(account1)], vec![i]);
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
