use crate::accounts::*;
use crate::StorageError;

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

// ---------------------------------------------------------------------------
// Fork-aware transaction tree tests
// ---------------------------------------------------------------------------

#[test]
fn fork_prepare_and_read_inherits_parent() {
    let db = AccountDatabase::new();
    let parent = TransactionId::from_slot(1);
    let child = TransactionId::from_slot(2);
    let pubkey = Pubkey::new([10u8; 32]);

    db.prepare_transaction(TransactionId::root(), parent)
        .unwrap();
    db.write_account(parent, pubkey, Account::new(500, vec![], Pubkey::zeroed()))
        .unwrap();

    db.prepare_transaction(parent, child).unwrap();

    // Child inherits parent's account via ancestry walk.
    let acc = db.read_account(child, &pubkey).unwrap().unwrap();
    assert_eq!(acc.meta.lamports, 500);
}

#[test]
fn fork_child_override_parent() {
    let db = AccountDatabase::new();
    let parent = TransactionId::from_slot(1);
    let child = TransactionId::from_slot(2);
    let pubkey = Pubkey::new([10u8; 32]);

    db.prepare_transaction(TransactionId::root(), parent)
        .unwrap();
    db.write_account(parent, pubkey, Account::new(500, vec![], Pubkey::zeroed()))
        .unwrap();

    db.prepare_transaction(parent, child).unwrap();
    db.write_account(child, pubkey, Account::new(999, vec![], Pubkey::zeroed()))
        .unwrap();

    // Child sees its own version.
    let acc = db.read_account(child, &pubkey).unwrap().unwrap();
    assert_eq!(acc.meta.lamports, 999);

    // Parent still sees original.
    let parent_acc = db.read_account(parent, &pubkey).unwrap().unwrap();
    assert_eq!(parent_acc.meta.lamports, 500);
}

#[test]
fn fork_frozen_transaction_rejects_writes() {
    let db = AccountDatabase::new();
    let parent = TransactionId::from_slot(1);
    let child = TransactionId::from_slot(2);
    let pubkey = Pubkey::new([10u8; 32]);

    db.prepare_transaction(TransactionId::root(), parent)
        .unwrap();
    db.prepare_transaction(parent, child).unwrap();

    // Parent is now frozen (has child).
    let result = db.write_account(parent, pubkey, Account::new(100, vec![], Pubkey::zeroed()));
    assert_eq!(result, Err(StorageError::TransactionFrozen));

    // Child is not frozen.
    db.write_account(child, pubkey, Account::new(200, vec![], Pubkey::zeroed()))
        .unwrap();
}

#[test]
fn fork_publish_linearizes_chain() {
    let db = AccountDatabase::new();
    let slot1 = TransactionId::from_slot(1);
    let slot2 = TransactionId::from_slot(2);
    let pk_a = Pubkey::new([1u8; 32]);
    let pk_b = Pubkey::new([2u8; 32]);

    db.prepare_transaction(TransactionId::root(), slot1)
        .unwrap();
    db.write_account(slot1, pk_a, Account::new(100, vec![], Pubkey::zeroed()))
        .unwrap();

    db.prepare_transaction(slot1, slot2).unwrap();
    db.write_account(slot2, pk_b, Account::new(200, vec![], Pubkey::zeroed()))
        .unwrap();
    // Override pk_a in slot2.
    db.write_account(slot2, pk_a, Account::new(150, vec![], Pubkey::zeroed()))
        .unwrap();

    db.publish_transaction(slot2).unwrap();

    // Both accounts should be published.
    let pub_a = db.get_published_account(&pk_a).unwrap();
    assert_eq!(pub_a.meta.lamports, 150); // Child's override wins.

    let pub_b = db.get_published_account(&pk_b).unwrap();
    assert_eq!(pub_b.meta.lamports, 200);

    // Fork tree should be empty.
    assert_eq!(db.fork_count(), 0);
}

#[test]
fn fork_publish_cancels_competitors() {
    let db = AccountDatabase::new();
    let fork_a = TransactionId::from_slot(1);
    let fork_b = TransactionId::from_slot(2);
    let pk = Pubkey::new([10u8; 32]);

    // Two competing forks from root.
    db.prepare_transaction(TransactionId::root(), fork_a)
        .unwrap();
    db.prepare_transaction(TransactionId::root(), fork_b)
        .unwrap();

    db.write_account(fork_a, pk, Account::new(100, vec![], Pubkey::zeroed()))
        .unwrap();
    db.write_account(fork_b, pk, Account::new(999, vec![], Pubkey::zeroed()))
        .unwrap();

    // Publish fork_a — fork_b records should be cancelled.
    db.publish_transaction(fork_a).unwrap();

    assert_eq!(db.get_published_account(&pk).unwrap().meta.lamports, 100);
    assert_eq!(db.count_transaction_records(fork_b), 0);
    assert_eq!(db.fork_count(), 0);
}

#[test]
fn fork_cancel_cascades_to_descendants() {
    let db = AccountDatabase::new();
    let slot1 = TransactionId::from_slot(1);
    let slot2 = TransactionId::from_slot(2);
    let slot3 = TransactionId::from_slot(3);
    let pk = Pubkey::new([10u8; 32]);

    // Write in slot1 BEFORE preparing children.
    db.prepare_transaction(TransactionId::root(), slot1)
        .unwrap();
    db.write_account(slot1, pk, Account::new(100, vec![], Pubkey::zeroed()))
        .unwrap();

    db.prepare_transaction(slot1, slot2).unwrap();
    db.prepare_transaction(slot2, slot3).unwrap();

    db.write_account(slot3, pk, Account::new(300, vec![], Pubkey::zeroed()))
        .unwrap();

    // Cancel slot1 — should cascade to slot2 and slot3.
    db.cancel_transaction(slot1).unwrap();

    assert_eq!(db.count_transaction_records(slot1), 0);
    assert_eq!(db.count_transaction_records(slot2), 0);
    assert_eq!(db.count_transaction_records(slot3), 0);
    assert_eq!(db.fork_count(), 0);
}

#[test]
fn fork_deep_ancestry_read() {
    let db = AccountDatabase::new();
    let s1 = TransactionId::from_slot(1);
    let s2 = TransactionId::from_slot(2);
    let s3 = TransactionId::from_slot(3);
    let s4 = TransactionId::from_slot(4);
    let pk = Pubkey::new([5u8; 32]);

    // Chain: root -> s1 -> s2 -> s3 -> s4
    // Write in s1 BEFORE preparing children (s1 becomes frozen once s2 exists).
    db.prepare_transaction(TransactionId::root(), s1).unwrap();
    db.write_account(s1, pk, Account::new(42, vec![], Pubkey::zeroed()))
        .unwrap();

    db.prepare_transaction(s1, s2).unwrap();
    db.prepare_transaction(s2, s3).unwrap();
    db.prepare_transaction(s3, s4).unwrap();

    // s4 should still see s1's data (walks through s4 -> s3 -> s2 -> s1).
    let acc = db.read_account(s4, &pk).unwrap().unwrap();
    assert_eq!(acc.meta.lamports, 42);
}

#[test]
fn fork_read_falls_back_to_published() {
    let db = AccountDatabase::new();
    let pk = Pubkey::new([5u8; 32]);

    // Pre-publish an account.
    db.store_published_account(pk, Account::new(777, vec![], Pubkey::zeroed()));

    let s1 = TransactionId::from_slot(1);
    db.prepare_transaction(TransactionId::root(), s1).unwrap();

    // s1 has no records for pk — should fall back to published.
    let acc = db.read_account(s1, &pk).unwrap().unwrap();
    assert_eq!(acc.meta.lamports, 777);
}

#[test]
fn fork_count_and_has_fork() {
    let db = AccountDatabase::new();
    assert_eq!(db.fork_count(), 0);
    assert!(!db.has_fork(TransactionId::from_slot(1)));

    let s1 = TransactionId::from_slot(1);
    db.prepare_transaction(TransactionId::root(), s1).unwrap();
    assert_eq!(db.fork_count(), 1);
    assert!(db.has_fork(s1));

    db.cancel_transaction(s1).unwrap();
    assert_eq!(db.fork_count(), 0);
    assert!(!db.has_fork(s1));
}

#[test]
fn fork_competing_branches_deep() {
    let db = AccountDatabase::new();
    //        root
    //       /    \
    //     s1      s2
    //    /  \      |
    //  s3   s4    s5
    let s1 = TransactionId::from_slot(1);
    let s2 = TransactionId::from_slot(2);
    let s3 = TransactionId::from_slot(3);
    let s4 = TransactionId::from_slot(4);
    let s5 = TransactionId::from_slot(5);

    db.prepare_transaction(TransactionId::root(), s1).unwrap();
    db.prepare_transaction(TransactionId::root(), s2).unwrap();
    db.prepare_transaction(s1, s3).unwrap();
    db.prepare_transaction(s1, s4).unwrap();
    db.prepare_transaction(s2, s5).unwrap();

    let pk = Pubkey::new([1u8; 32]);
    db.write_account(s3, pk, Account::new(300, vec![], Pubkey::zeroed()))
        .unwrap();
    db.write_account(s5, pk, Account::new(500, vec![], Pubkey::zeroed()))
        .unwrap();

    // Publish s3 — should cancel s4 (sibling) and s2+s5 (competing branch).
    db.publish_transaction(s3).unwrap();

    assert_eq!(db.get_published_account(&pk).unwrap().meta.lamports, 300);
    assert_eq!(db.fork_count(), 0);
    assert_eq!(db.count_transaction_records(s4), 0);
    assert_eq!(db.count_transaction_records(s5), 0);
}

#[test]
fn fork_clear_resets_tree() {
    let db = AccountDatabase::new();
    let s1 = TransactionId::from_slot(1);
    db.prepare_transaction(TransactionId::root(), s1).unwrap();
    db.write_account(
        s1,
        Pubkey::new([1u8; 32]),
        Account::new(1, vec![], Pubkey::zeroed()),
    )
    .unwrap();

    db.clear_all_accounts();
    assert_eq!(db.fork_count(), 0);
    assert_eq!(db.count_records(), 0);
}
