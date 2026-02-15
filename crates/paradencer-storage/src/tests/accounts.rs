use crate::accounts::*;

#[test]
fn test_account_database_create() {
    let db = AccountDatabase::new();
    assert_eq!(db.count_records(), 0);
}

#[test]
fn test_read_write_account() {
    let db = AccountDatabase::new();
    let xid = TransactionId::from_slot(1);
    let pubkey = Pubkey::new([1u8; 32]);
    let account = Account::new(1000, vec![1, 2, 3], Pubkey::zeroed());

    db.write_account(xid, pubkey, account.clone()).unwrap();

    let read_account = db.read_account(xid, &pubkey).unwrap().unwrap();
    assert_eq!(read_account.meta.lamports, 1000);
    assert_eq!(read_account.data.len(), 3);
}

#[test]
fn test_publish_transaction() {
    let db = AccountDatabase::new();
    let xid = TransactionId::from_slot(1);
    let pubkey = Pubkey::new([1u8; 32]);
    let account = Account::new(1000, vec![1, 2, 3], Pubkey::zeroed());

    db.write_account(xid, pubkey, account.clone()).unwrap();
    assert_eq!(db.count_transaction_records(xid), 1);

    db.publish_transaction(xid).unwrap();

    assert_eq!(db.count_transaction_records(xid), 0);

    let published = db.get_published_account(&pubkey).unwrap();
    assert_eq!(published.meta.lamports, 1000);
}

#[test]
fn test_cancel_transaction() {
    let db = AccountDatabase::new();
    let xid = TransactionId::from_slot(1);
    let pubkey = Pubkey::new([1u8; 32]);
    let account = Account::new(1000, vec![1, 2, 3], Pubkey::zeroed());

    db.write_account(xid, pubkey, account).unwrap();
    assert_eq!(db.count_transaction_records(xid), 1);

    db.cancel_transaction(xid).unwrap();

    assert_eq!(db.count_transaction_records(xid), 0);
    assert!(db.get_published_account(&pubkey).is_none());
}

#[test]
fn test_read_fallback_to_published() {
    let db = AccountDatabase::new();
    let pubkey = Pubkey::new([1u8; 32]);
    let account = Account::new(1000, vec![1, 2, 3], Pubkey::zeroed());

    let xid1 = TransactionId::from_slot(1);
    db.write_account(xid1, pubkey, account.clone()).unwrap();
    db.publish_transaction(xid1).unwrap();

    let xid2 = TransactionId::from_slot(2);
    let read_from_new_tx = db.read_account(xid2, &pubkey).unwrap().unwrap();
    assert_eq!(read_from_new_tx.meta.lamports, 1000);
}

#[test]
fn test_cannot_write_to_root() {
    let db = AccountDatabase::new();
    let pubkey = Pubkey::new([1u8; 32]);
    let account = Account::new(1000, vec![], Pubkey::zeroed());

    let result = db.write_account(TransactionId::root(), pubkey, account);
    assert!(result.is_err());
}
