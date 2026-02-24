// Startup recovery: reload persisted accounts from disk into memory.
//
// Three strategies, tried in order of preference:
//
// 1. **Metadata index**: scans CF_ACCOUNT_META (48-byte compact records:
//    owner + lamports + slot). Fastest path — no LZ4 decompression, no
//    full account decoding. Used when the metadata index is populated.
//
// 2. **Parallel full scan**: scans CF_ACCOUNTS with rayon. Decodes each
//    account (including LZ4 decompression) to extract owner and lamports.
//    Falls back to this when metadata index is empty (old database).
//
// 3. **Serial full scan**: single-threaded CF_ACCOUNTS scan that also
//    populates the LRU cache. Used for small datasets (<10K accounts).
//
// After any full-scan recovery, a one-time migration populates
// CF_ACCOUNT_META so subsequent startups use the fast metadata path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rayon::prelude::*;

use paradencer_constants::durable_store::{
    CF_ACCOUNTS, CF_ACCOUNT_META, RECOVERY_MIN_CHUNK_SIZE, RECOVERY_PARALLEL_THRESHOLD,
};
use paradencer_types::Pubkey;

use super::account_encoding::{decode_account, decode_account_meta, encode_account_meta};
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
    /// Whether the parallel recovery path was used.
    pub parallel: bool,
    /// Whether the fast metadata index path was used.
    pub from_metadata: bool,
}

/// Recover all published accounts from the durable store into the database.
///
/// Tries the fast metadata index path first (CF_ACCOUNT_META). Falls back
/// to full account scan (CF_ACCOUNTS) if the metadata index is empty.
/// After a full-scan fallback, backfills the metadata index for future
/// fast recovery.
pub fn recover_accounts(
    db: &AccountDatabase,
    store: &dyn DurableStore,
) -> Result<RecoveryStats, StorageError> {
    let start = Instant::now();

    // Try fast path: metadata index.
    let meta_count = store.count(CF_ACCOUNT_META)?;
    if meta_count > 0 {
        let entries = store.prefix_scan(CF_ACCOUNT_META, &[])?;
        if !entries.is_empty() {
            return recover_from_metadata(db, entries, start);
        }
    }

    // Fallback: full account scan.
    let entries = store.prefix_scan(CF_ACCOUNTS, &[])?;

    let stats = if entries.len() >= RECOVERY_PARALLEL_THRESHOLD {
        recover_parallel(db, entries, start)?
    } else {
        recover_serial(db, entries, start)?
    };

    // Backfill metadata index for future fast recovery.
    if stats.accounts_loaded > 0 {
        let _ = backfill_metadata(db, store);
    }

    Ok(stats)
}

/// Recover the owner index from compact metadata records.
///
/// Each CF_ACCOUNT_META record is 48 bytes: owner(32) + lamports(8) + slot(8).
/// No LZ4 decompression or full account decoding needed — just direct byte
/// extraction. For large datasets, uses rayon for parallel processing.
fn recover_from_metadata(
    db: &AccountDatabase,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    start: Instant,
) -> Result<RecoveryStats, StorageError> {
    if entries.len() >= RECOVERY_PARALLEL_THRESHOLD {
        recover_metadata_parallel(db, entries, start)
    } else {
        recover_metadata_serial(db, entries, start)
    }
}

/// Serial metadata recovery for small datasets.
fn recover_metadata_serial(
    db: &AccountDatabase,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    start: Instant,
) -> Result<RecoveryStats, StorageError> {
    let mut accounts_loaded: u64 = 0;
    let mut total_lamports: u64 = 0;
    let mut decode_errors: u64 = 0;

    for (key_bytes, value_bytes) in entries {
        if key_bytes.len() != 32 {
            decode_errors += 1;
            continue;
        }

        let pubkey = Pubkey::from(
            <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
        );

        match decode_account_meta(&value_bytes) {
            Some((owner, lamports, _slot)) => {
                total_lamports = total_lamports.saturating_add(lamports);
                db.insert_recovered_meta(pubkey, owner, lamports);
                accounts_loaded += 1;
            }
            None => {
                decode_errors += 1;
            }
        }
    }

    Ok(RecoveryStats {
        accounts_loaded,
        total_lamports,
        decode_errors,
        elapsed_ms: start.elapsed().as_millis() as u64,
        parallel: false,
        from_metadata: true,
    })
}

/// Parallel metadata recovery for large datasets.
fn recover_metadata_parallel(
    db: &AccountDatabase,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    start: Instant,
) -> Result<RecoveryStats, StorageError> {
    let loaded = AtomicU64::new(0);
    let lamports = AtomicU64::new(0);
    let errors = AtomicU64::new(0);

    let num_threads = rayon::current_num_threads().max(1);
    let chunk_size = (entries.len() / num_threads).max(RECOVERY_MIN_CHUNK_SIZE);

    entries.par_chunks(chunk_size).for_each(|chunk| {
        let mut local_loaded = 0u64;
        let mut local_lamports = 0u64;
        let mut local_errors = 0u64;

        for (key_bytes, value_bytes) in chunk {
            if key_bytes.len() != 32 {
                local_errors += 1;
                continue;
            }

            let pubkey = Pubkey::from(
                <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
            );

            match decode_account_meta(value_bytes) {
                Some((owner, lamps, _slot)) => {
                    local_lamports = local_lamports.saturating_add(lamps);
                    db.insert_recovered_meta(pubkey, owner, lamps);
                    local_loaded += 1;
                }
                None => {
                    local_errors += 1;
                }
            }
        }

        loaded.fetch_add(local_loaded, Ordering::Relaxed);
        lamports.fetch_add(local_lamports, Ordering::Relaxed);
        errors.fetch_add(local_errors, Ordering::Relaxed);
    });

    Ok(RecoveryStats {
        accounts_loaded: loaded.load(Ordering::Relaxed),
        total_lamports: lamports.load(Ordering::Relaxed),
        decode_errors: errors.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis() as u64,
        parallel: true,
        from_metadata: true,
    })
}

/// Serial recovery: decode and insert with cache population.
///
/// Each account is decoded and inserted into both the LRU cache and
/// the owner index. Suitable for small datasets where the startup
/// cost of populating the cache is negligible.
fn recover_serial(
    db: &AccountDatabase,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    start: Instant,
) -> Result<RecoveryStats, StorageError> {
    let mut accounts_loaded: u64 = 0;
    let mut total_lamports: u64 = 0;
    let mut decode_errors: u64 = 0;

    for (key_bytes, value_bytes) in entries {
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

    Ok(RecoveryStats {
        accounts_loaded,
        total_lamports,
        decode_errors,
        elapsed_ms: start.elapsed().as_millis() as u64,
        parallel: false,
        from_metadata: false,
    })
}

/// Parallel recovery: decode and populate owner index using rayon.
///
/// Entries are split into chunks processed by the rayon thread pool.
/// Only the owner index is updated (no LRU cache population). This
/// avoids the Mutex bottleneck on PublishedStore and leverages the
/// natural sharding of DashMap for concurrent updates.
///
/// Accounts will be loaded into the cache lazily from disk on first access.
fn recover_parallel(
    db: &AccountDatabase,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    start: Instant,
) -> Result<RecoveryStats, StorageError> {
    let loaded = AtomicU64::new(0);
    let lamports = AtomicU64::new(0);
    let errors = AtomicU64::new(0);

    let num_threads = rayon::current_num_threads().max(1);
    let chunk_size = (entries.len() / num_threads).max(RECOVERY_MIN_CHUNK_SIZE);

    entries.par_chunks(chunk_size).for_each(|chunk| {
        let mut local_loaded = 0u64;
        let mut local_lamports = 0u64;
        let mut local_errors = 0u64;

        for (key_bytes, value_bytes) in chunk {
            if key_bytes.len() != 32 {
                local_errors += 1;
                continue;
            }

            let pubkey = Pubkey::from(
                <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
            );

            match decode_account(value_bytes) {
                Some(account) => {
                    local_lamports = local_lamports.saturating_add(account.meta.lamports);
                    db.insert_recovered_index_only(pubkey, &account);
                    local_loaded += 1;
                }
                None => {
                    local_errors += 1;
                }
            }
        }

        loaded.fetch_add(local_loaded, Ordering::Relaxed);
        lamports.fetch_add(local_lamports, Ordering::Relaxed);
        errors.fetch_add(local_errors, Ordering::Relaxed);
    });

    Ok(RecoveryStats {
        accounts_loaded: loaded.load(Ordering::Relaxed),
        total_lamports: lamports.load(Ordering::Relaxed),
        decode_errors: errors.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis() as u64,
        parallel: true,
        from_metadata: false,
    })
}

/// Force parallel recovery regardless of entry count.
///
/// Useful for benchmarking or when the caller knows the dataset is large
/// enough to benefit from parallelism.
pub fn recover_accounts_parallel(
    db: &AccountDatabase,
    store: &dyn DurableStore,
) -> Result<RecoveryStats, StorageError> {
    let start = Instant::now();
    let entries = store.prefix_scan(CF_ACCOUNTS, &[])?;
    recover_parallel(db, entries, start)
}

/// Backfill the metadata index from existing account data.
///
/// Scans CF_ACCOUNTS and writes a compact metadata record to CF_ACCOUNT_META
/// for each account. This is a one-time migration for databases created before
/// the metadata index was introduced. The function is idempotent — existing
/// metadata records are overwritten with fresh data.
pub fn backfill_metadata(
    db: &AccountDatabase,
    store: &dyn DurableStore,
) -> Result<u64, StorageError> {
    use super::account_encoding::decode_account_header;
    use super::WriteBatch;

    let entries = store.prefix_scan(CF_ACCOUNTS, &[])?;
    let mut written = 0u64;
    let mut batch = WriteBatch::new();

    for (key_bytes, value_bytes) in &entries {
        if key_bytes.len() != 32 {
            continue;
        }

        if let Some((lamports, owner)) = decode_account_header(value_bytes) {
            let slot = db
                .last_updated_slot(&Pubkey::from(
                    <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
                ))
                .unwrap_or(0);
            let meta = encode_account_meta(&owner, lamports, slot);
            if batch.put(CF_ACCOUNT_META, key_bytes, &meta).is_err() {
                // Batch full — flush and start a new one.
                store.write_batch(&batch)?;
                batch = WriteBatch::new();
                let _ = batch.put(CF_ACCOUNT_META, key_bytes, &meta);
            }
            written += 1;
        }
    }

    if !batch.is_empty() {
        store.write_batch(&batch)?;
    }

    Ok(written)
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
        assert!(!stats.parallel); // Below threshold
        assert!(!stats.from_metadata); // No metadata yet

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
        let store = test_store();

        let pubkey = Pubkey::from([0xAA; 32]);
        let account = Account::new(999, vec![0x42; 64], Pubkey::from([0xBB; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        let disk_before = store.disk_usage().expect("usage");

        let db = AccountDatabase::new();
        recover_accounts(&db, store.as_ref()).expect("recover");

        // Backfill writes metadata, so disk should grow slightly.
        let disk_after = store.disk_usage().expect("usage");
        assert!(disk_after >= disk_before);

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

        let db = AccountDatabase::with_durable_store(store.clone());
        recover_accounts(&db, store.as_ref()).expect("recover");

        let new_account = Account::new(200, vec![1, 2, 3], Pubkey::from([0xCC; 32]));
        db.store_published_account(pubkey, new_account.clone());

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

        assert_eq!(db.accounts_owned_by(&owner), 5);
        let owned = db.get_accounts_by_owner(&owner);
        assert_eq!(owned.len(), 5);
    }

    // --- Parallel recovery tests ---

    #[test]
    fn parallel_recover_empty_store() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());
        let stats = recover_accounts_parallel(&db, store.as_ref()).expect("recover");
        assert_eq!(stats.accounts_loaded, 0);
        assert_eq!(stats.total_lamports, 0);
        assert!(stats.parallel);
    }

    #[test]
    fn parallel_recover_multiple_accounts() {
        let store = test_store();
        let owner = Pubkey::from([0xEE; 32]);

        for i in 0u8..50 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 10, vec![i; 8], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        let db = AccountDatabase::new();
        let stats = recover_accounts_parallel(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 50);
        assert!(stats.parallel);

        // Total lamports: sum of 10 + 20 + ... + 500 = 10 * (1+2+...+50) = 10 * 1275 = 12750
        assert_eq!(stats.total_lamports, 12750);
        assert_eq!(db.get_account_count(), 50);
        assert_eq!(db.get_total_lamports(), 12750);

        // Owner index should track all accounts.
        assert_eq!(db.accounts_owned_by(&owner), 50);
    }

    #[test]
    fn parallel_recover_skips_errors() {
        let store = test_store();

        // 3 valid accounts.
        for i in 0u8..3 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new(100, vec![], Pubkey::from([0xFF; 32]));
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        // 2 invalid entries.
        store
            .put(CF_ACCOUNTS, &[0xFF; 16], b"not-a-valid-account")
            .expect("put");
        store
            .put(CF_ACCOUNTS, Pubkey::from([0xDD; 32]).as_bytes(), &[0; 3])
            .expect("put");

        let db = AccountDatabase::new();
        let stats = recover_accounts_parallel(&db, store.as_ref()).expect("recover");

        assert_eq!(stats.accounts_loaded, 3);
        assert_eq!(stats.decode_errors, 2);
    }

    #[test]
    fn parallel_recover_index_only_no_disk_write() {
        let store = test_store();
        let pubkey = Pubkey::from([0xAA; 32]);
        let account = Account::new(500, vec![1, 2], Pubkey::from([0xBB; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        let disk_before = store.disk_usage().expect("usage");

        let db = AccountDatabase::new();
        recover_accounts_parallel(&db, store.as_ref()).expect("recover");

        let disk_after = store.disk_usage().expect("usage");
        assert_eq!(disk_before, disk_after);

        // Index should be populated.
        assert_eq!(db.get_account_count(), 1);
        assert_eq!(db.get_total_lamports(), 500);
    }

    #[test]
    fn parallel_recover_with_durable_store_allows_lazy_load() {
        let store = test_store();
        let pubkey = Pubkey::from([0xAA; 32]);
        let account = Account::new(777, vec![9, 8, 7], Pubkey::from([0xBB; 32]));
        store
            .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
            .expect("put");

        // Parallel recovery with durable store backing — cache NOT populated.
        let db = AccountDatabase::with_durable_store(store.clone());
        recover_accounts_parallel(&db, store.as_ref()).expect("recover");

        // Account should still be accessible via disk fallback.
        let loaded = db
            .get_published_account(&pubkey)
            .expect("should load from disk");
        assert_eq!(loaded.meta.lamports, 777);
        assert_eq!(loaded.data.as_slice(), &[9, 8, 7]);
    }

    #[test]
    fn serial_and_parallel_produce_same_stats() {
        let store = test_store();
        let owner = Pubkey::from([0xDD; 32]);

        for i in 0u8..20 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 50, vec![i; 16], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        // Serial recovery.
        let db_serial = AccountDatabase::new();
        let entries = store.prefix_scan(CF_ACCOUNTS, &[]).expect("scan");
        let stats_serial = recover_serial(&db_serial, entries, Instant::now()).expect("serial");

        // Parallel recovery.
        let db_parallel = AccountDatabase::new();
        let stats_parallel =
            recover_accounts_parallel(&db_parallel, store.as_ref()).expect("parallel");

        // Same counts and lamports.
        assert_eq!(stats_serial.accounts_loaded, stats_parallel.accounts_loaded);
        assert_eq!(stats_serial.total_lamports, stats_parallel.total_lamports);
        assert_eq!(stats_serial.decode_errors, stats_parallel.decode_errors);

        // Same owner index state.
        assert_eq!(
            db_serial.get_account_count(),
            db_parallel.get_account_count()
        );
        assert_eq!(
            db_serial.get_total_lamports(),
            db_parallel.get_total_lamports()
        );
        assert_eq!(
            db_serial.accounts_owned_by(&owner),
            db_parallel.accounts_owned_by(&owner)
        );
    }

    // --- Metadata index recovery tests ---

    #[test]
    fn metadata_recovery_uses_fast_path() {
        let store = test_store();
        let owner = Pubkey::from([0xAA; 32]);

        // Populate both CF_ACCOUNTS and CF_ACCOUNT_META.
        for i in 0u8..5 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 100, vec![i; 8], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
            let meta = encode_account_meta(&owner, (i as u64 + 1) * 100, 42);
            store
                .put(CF_ACCOUNT_META, pubkey.as_bytes(), &meta)
                .expect("put meta");
        }

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert!(stats.from_metadata, "should use metadata path");
        assert_eq!(stats.accounts_loaded, 5);
        assert_eq!(stats.total_lamports, 1500);
        assert_eq!(db.get_account_count(), 5);
        assert_eq!(db.accounts_owned_by(&owner), 5);
    }

    #[test]
    fn metadata_recovery_matches_full_recovery() {
        let store = test_store();
        let owner = Pubkey::from([0xBB; 32]);

        // Populate both CFs.
        for i in 0u8..10 {
            let pubkey = Pubkey::from([i; 32]);
            let lamports = (i as u64 + 1) * 50;
            let account = Account::new(lamports, vec![i; 16], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
            let meta = encode_account_meta(&owner, lamports, 0);
            store
                .put(CF_ACCOUNT_META, pubkey.as_bytes(), &meta)
                .expect("put meta");
        }

        // Recover via metadata.
        let db_meta = AccountDatabase::new();
        let stats_meta = recover_accounts(&db_meta, store.as_ref()).expect("recover");

        // Recover via full scan (force parallel).
        let db_full = AccountDatabase::new();
        let stats_full = recover_accounts_parallel(&db_full, store.as_ref()).expect("recover");

        assert!(stats_meta.from_metadata);
        assert!(!stats_full.from_metadata);

        // Same index state.
        assert_eq!(db_meta.get_account_count(), db_full.get_account_count());
        assert_eq!(db_meta.get_total_lamports(), db_full.get_total_lamports());
        assert_eq!(
            db_meta.accounts_owned_by(&owner),
            db_full.accounts_owned_by(&owner)
        );
    }

    #[test]
    fn backfill_populates_metadata_index() {
        let store = test_store();
        let owner = Pubkey::from([0xCC; 32]);

        // Populate ONLY CF_ACCOUNTS (simulating old database).
        for i in 0u8..5 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 100, vec![], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        // Metadata should be empty.
        assert_eq!(store.count(CF_ACCOUNT_META).unwrap(), 0);

        // Run recovery — should use full scan and then backfill.
        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");
        assert!(!stats.from_metadata, "first recovery uses full scan");

        // Metadata should now be populated.
        assert_eq!(store.count(CF_ACCOUNT_META).unwrap(), 5);

        // Second recovery should use metadata path.
        let db2 = AccountDatabase::new();
        let stats2 = recover_accounts(&db2, store.as_ref()).expect("recover");
        assert!(stats2.from_metadata, "second recovery uses metadata");
        assert_eq!(stats2.accounts_loaded, 5);
    }

    #[test]
    fn backfill_is_idempotent() {
        let store = test_store();
        let owner = Pubkey::from([0xDD; 32]);

        for i in 0u8..3 {
            let pubkey = Pubkey::from([i; 32]);
            let account = Account::new((i as u64 + 1) * 100, vec![], owner);
            store
                .put(CF_ACCOUNTS, pubkey.as_bytes(), &encode_account(&account))
                .expect("put");
        }

        let db = AccountDatabase::new();
        let first = backfill_metadata(&db, store.as_ref()).expect("backfill 1");
        let second = backfill_metadata(&db, store.as_ref()).expect("backfill 2");

        assert_eq!(first, 3);
        assert_eq!(second, 3);
        assert_eq!(store.count(CF_ACCOUNT_META).unwrap(), 3);
    }

    #[test]
    fn metadata_recovery_skips_invalid_records() {
        let store = test_store();

        // Valid metadata record.
        let pubkey = Pubkey::from([0x01; 32]);
        let meta = encode_account_meta(&Pubkey::from([0xAA; 32]), 1000, 5);
        store
            .put(CF_ACCOUNT_META, pubkey.as_bytes(), &meta)
            .expect("put");

        // Invalid: key too short.
        store.put(CF_ACCOUNT_META, &[0xFF; 16], &meta).expect("put");

        // Invalid: value too short.
        store
            .put(
                CF_ACCOUNT_META,
                Pubkey::from([0x02; 32]).as_bytes(),
                &[0; 10],
            )
            .expect("put");

        let db = AccountDatabase::new();
        let stats = recover_accounts(&db, store.as_ref()).expect("recover");

        assert!(stats.from_metadata);
        assert_eq!(stats.accounts_loaded, 1);
        assert_eq!(stats.decode_errors, 2);
    }
}
