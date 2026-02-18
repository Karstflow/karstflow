// Startup recovery: reload persisted accounts from disk into memory.
//
// Scans the accounts column family, decodes each record, and inserts
// into the AccountDatabase without re-persisting (avoiding write
// amplification on startup).

use std::time::Instant;

use paradencer_constants::durable_store::CF_ACCOUNTS;
use paradencer_types::Pubkey;

use super::account_encoding::decode_account;
use super::DurableStore;
use crate::accounts::AccountDatabase;
use crate::StorageError;

/// Statistics from a recovery operation.
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    /// Number of accounts loaded from disk.
    pub accounts_loaded: u64,
    /// Total lamports across all recovered accounts.
    pub total_lamports: u64,
    /// Number of records that failed to decode (skipped).
    pub decode_errors: u64,
    /// Time spent on recovery in milliseconds.
    pub elapsed_ms: u64,
}

/// Recover all published accounts from the durable store into the database.
///
/// Scans every key in the accounts column family, decodes the binary
/// account data, and loads each account into memory via
/// `insert_recovered_account()` (no re-persist to disk).
pub fn recover_accounts(
    db: &AccountDatabase,
    store: &dyn DurableStore,
) -> Result<RecoveryStats, StorageError> {
    let start = Instant::now();

    let mut accounts_loaded: u64 = 0;
    let mut total_lamports: u64 = 0;
    let mut decode_errors: u64 = 0;

    // Scan all records in the accounts column family.
    // An empty prefix matches everything.
    let entries = store.prefix_scan(CF_ACCOUNTS, &[])?;

    for (key_bytes, value_bytes) in entries {
        // Key must be exactly 32 bytes (Pubkey).
        if key_bytes.len() != 32 {
            decode_errors += 1;
            continue;
        }

        let pubkey = Pubkey::from(
            <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
        );

        match decode_account(&value_bytes) {
            Some(account) => {
                total_lamports = total_lamports.saturating_add(account.meta.lamports);
                db.insert_recovered_account(pubkey, account);
                accounts_loaded += 1;
            }
            None => {
                decode_errors += 1;
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(RecoveryStats {
        accounts_loaded,
        total_lamports,
        decode_errors,
        elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable::account_encoding::encode_account;
    use crate::durable::FileDurableStore;
    use paradencer_types::{Account, Pubkey};
    use std::sync::Arc;

    fn test_store() -> Arc<FileDurableStore> {
        FileDurableStore::temporary()
            .expect("temporary store")
            .into_arc()
    }

    #[test]
    fn recover_empty_store() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");
        assert_eq!(stats.accounts_loaded, 0);
        assert_eq!(stats.total_lamports, 0);
        assert_eq!(stats.decode_errors, 0);
    }

    #[test]
    fn recover_single_account() {
        let store = test_store();
        let pubkey = Pubkey::from([0xAA; 32]);
        let account = Account::new(1_000_000, vec![1, 2, 3], Pubkey::from([0xBB; 32]));
        let encoded = encode_account(&account);
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded)
            .expect("put");

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 1);
        assert_eq!(stats.total_lamports, 1_000_000);
        assert_eq!(stats.decode_errors, 0);

        let recovered = db.get_published_account(&pubkey).expect("should exist");
        assert_eq!(recovered.meta.lamports, 1_000_000);
        assert_eq!(recovered.data.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn recover_multiple_accounts() {
        let store = test_store();

        for i in 0u8..10 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new(
                (i as u64 + 1) * 100,
                vec![i; (i as usize) * 10],
                Pubkey::from([0xFF; 32]),
            );
            let encoded = encode_account(&account);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded)
                .expect("put");
        }

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 10);
        assert_eq!(stats.total_lamports, 5500); // sum of 100..1000
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(db.get_account_count(), 10);
    }

    #[test]
    fn recover_skips_invalid_key_length() {
        let store = test_store();

        // Valid account with proper 32-byte key.
        let pubkey = Pubkey::from([0x01; 32]);
        let account = Account::new(500, vec![], Pubkey::from([0x02; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        // Invalid: key is only 16 bytes.
        store
            .put(CF_ACCOUNTS, &[0xFF; 16], &encode_account(&account))
            .expect("put");

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 1);
        assert_eq!(stats.decode_errors, 1);
    }

    #[test]
    fn recover_skips_corrupt_value() {
        let store = test_store();

        // Valid account.
        let pubkey = Pubkey::from([0x01; 32]);
        let account = Account::new(100, vec![], Pubkey::from([0x02; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        // Corrupt value (too short to decode).
        let bad_pubkey = Pubkey::from([0x03; 32]);
        store
            .put(CF_ACCOUNTS, bad_pubkey.as_bytes(), &[0; 10])
            .expect("put");

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 1);
        assert_eq!(stats.decode_errors, 1);
    }

    #[test]
    fn recover_does_not_repersist() {
        // Verify that recovery loads into memory but doesn't trigger
        // additional writes to the durable store.
        let store = test_store();

        let pubkey = Pubkey::from([0xAA; 32]);
        let account = Account::new(999, vec![0x42; 64], Pubkey::from([0xBB; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        let disk_before = store.disk_usage().expect("usage");

        let db = AccountDatabase::new();
        recover_accounts(&db, store.as_ref()).expect("recover");

        let disk_after = store.disk_usage().expect("usage");

        // Disk usage should not increase — recovery doesn't write.
        assert_eq!(disk_before, disk_after);

        // But the account should be accessible in memory.
        let recovered = db.get_published_account(&pubkey).expect("should exist");
        assert_eq!(recovered.meta.lamports, 999);
    }

    #[test]
    fn recover_then_overwrite_persists_new_value() {
        let store = test_store();

        let pubkey = Pubkey::from([0xAA; 32]);
        let old_account = Account::new(100, vec![], Pubkey::from([0xBB; 32]));
        store
            .put(
                CF_ACCOUNTS,
                pubkey.as_bytes(),
                &encode_account(&old_account),
            )
            .expect("put");

        // Recover into a database backed by the same store.
        let db = AccountDatabase::with_durable_store(store.clone());
        recover_accounts(&db, store.as_ref()).expect("recover");

        // Overwrite with new value — this should persist.
        let new_account = Account::new(200, vec![1, 2, 3], Pubkey::from([0xCC; 32]));
        db.store_published_account(pubkey, new_account.clone());

        // Read back from disk directly.
        let raw = store
            .get(CF_ACCOUNTS, pubkey.as_bytes())
            .expect("get")
            .expect("should exist");
        let disk_account = decode_account(&raw).expect("decode");
        assert_eq!(disk_account.meta.lamports, 200);
        assert_eq!(disk_account.data.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn recover_preserves_owner_index() {
        let store = test_store();
        let owner = Pubkey::from([0xFF; 32]);

        for i in 0u8..5 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 10, vec![], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        let db = AccountDatabase::new();
        recover_accounts(&db, store.as_ref()).expect("recover");

        // Owner index should be populated.
        assert_eq!(db.accounts_owned_by(&owner), 5);
        let owned = db.get_accounts_by_owner(&owner);
        assert_eq!(owned.len(), 5);
    }
}
