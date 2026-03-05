// Unified storage engine facade.
//
// Provides a single entry point for initializing persistent storage,
// wiring up the AccountDatabase and Blockstore, and performing
// lifecycle operations (recovery, compaction, flush).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::accounts::AccountDatabase;
use crate::blockstore::Blockstore;
use crate::durable::compaction::{compact_below_slot, CompactionStats};
use crate::durable::recovery::RecoveryStats;
use crate::durable::{DurableStore, FileDurableStore};
use crate::StorageError;

/// Recovery statistics for the full storage engine.
#[derive(Debug, Clone)]
pub struct FullRecoveryStats {
    /// Account recovery stats.
    pub accounts: RecoveryStats,
    /// Number of root slots recovered in the blockstore.
    pub blockstore_roots_recovered: u64,
}

/// Unified persistent storage coordinator.
///
/// Manages the lifecycle of the durable store backing both the
/// AccountDatabase and Blockstore. Provides recovery on startup,
/// compaction for space reclamation, and flush for durability.
pub struct StorageEngine {
    store: Arc<FileDurableStore>,
    data_dir: PathBuf,
}

impl StorageEngine {
    /// Open or create the storage engine at the given data directory.
    ///
    /// Creates two subdirectories:
    /// - `accounts/` — DurableStore for the AccountDatabase
    /// - `blockstore/` — DurableStore for the Blockstore (handled by Blockstore::open)
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        let accounts_dir = data_dir.join("accounts");
        let store = FileDurableStore::open(&accounts_dir)?;

        Ok(Self {
            store: Arc::new(store),
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Get the DurableStore for account persistence.
    pub fn account_store(&self) -> Arc<dyn DurableStore> {
        self.store.clone()
    }

    /// Get the data directory path for the blockstore.
    ///
    /// The Blockstore manages its own DurableStore internally via
    /// `Blockstore::open()`.
    pub fn blockstore_path(&self) -> PathBuf {
        self.data_dir.join("blockstore")
    }

    /// Create an AccountDatabase backed by the engine's durable store.
    pub fn create_account_database(&self) -> AccountDatabase {
        AccountDatabase::with_durable_store(self.store.clone())
    }

    /// Open a Blockstore backed by persistent storage.
    pub fn open_blockstore(&self) -> Result<Blockstore, crate::blockstore::BlockstoreError> {
        Blockstore::open(&self.data_dir)
    }

    /// Recover all persisted data into the given AccountDatabase.
    ///
    /// Automatically selects serial or parallel recovery based on account
    /// count. For large datasets, parallel recovery decodes and updates
    /// the owner index concurrently using rayon. The LRU cache is populated
    /// lazily from disk on first access.
    ///
    /// The Blockstore handles its own recovery in `Blockstore::open()`.
    pub fn recover(&self, account_db: &AccountDatabase) -> Result<FullRecoveryStats, StorageError> {
        let accounts = crate::durable::recovery::recover_accounts(account_db, self.store.as_ref())?;

        // Blockstore roots are recovered during Blockstore::open(), so
        // we report a placeholder here. The caller should read the root
        // count from the blockstore directly.
        Ok(FullRecoveryStats {
            accounts,
            blockstore_roots_recovered: 0,
        })
    }

    /// Force parallel recovery regardless of dataset size.
    ///
    /// Uses rayon to decode accounts and update the owner index
    /// concurrently. The LRU cache is NOT populated; accounts are
    /// loaded from disk lazily on first access.
    pub fn recover_parallel(
        &self,
        account_db: &AccountDatabase,
    ) -> Result<FullRecoveryStats, StorageError> {
        let accounts =
            crate::durable::recovery::recover_accounts_parallel(account_db, self.store.as_ref())?;

        Ok(FullRecoveryStats {
            accounts,
            blockstore_roots_recovered: 0,
        })
    }

    /// Compact old data below the given minimum slot.
    ///
    /// Removes slot-keyed blockstore records below `min_slot` from the
    /// underlying durable store. Account compaction is not slot-keyed
    /// (accounts are keyed by pubkey), so this only affects blockstore data.
    pub fn compact(&self, min_slot: u64) -> Result<CompactionStats, StorageError> {
        compact_below_slot(self.store.as_ref(), min_slot)
    }

    /// Full compaction: remove old slot data and reclaim disk space.
    ///
    /// Deletes slot-keyed records below `min_slot`, then rewrites CF files
    /// that have accumulated significant dead space from overwrites/deletes.
    pub fn compact_and_reclaim(&self, min_slot: u64) -> Result<CompactionStats, StorageError> {
        crate::durable::compact_below_slot_and_reclaim(&self.store, min_slot)
    }

    /// Compact a specific column family by rewriting only live records.
    pub fn compact_cf(&self, cf: &str) -> Result<crate::durable::CfCompactionStats, StorageError> {
        self.store.compact_cf(cf)
    }

    /// Total dead bytes across all column families.
    pub fn total_dead_bytes(&self) -> u64 {
        self.store.total_dead_bytes()
    }

    /// Read cache statistics snapshot.
    pub fn cache_stats(&self) -> crate::durable::CacheStats {
        self.store.cache_stats()
    }

    /// Storage operation metrics snapshot.
    pub fn metrics(&self) -> crate::durable::MetricsSnapshot {
        self.store.metrics()
    }

    /// Run a single auto-compaction pass on all column families.
    ///
    /// Compacts CFs that exceed dead space thresholds. Intended to be called
    /// periodically from a background housekeeping loop.
    pub fn auto_compact(
        &self,
    ) -> Result<Vec<(String, crate::durable::CfCompactionStats)>, crate::StorageError> {
        self.store.auto_compact()
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), StorageError> {
        self.store.flush()
    }

    /// Approximate total disk usage across all column families.
    pub fn disk_usage(&self) -> Result<u64, StorageError> {
        self.store.disk_usage()
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::{Account, Pubkey};

    #[test]
    fn engine_open_and_create_database() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = StorageEngine::open(dir.path()).expect("open");

        let db = engine.create_account_database();
        assert!(db.has_durable_store());
    }

    #[test]
    fn engine_open_blockstore() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = StorageEngine::open(dir.path()).expect("open");

        let bs = engine.open_blockstore().expect("open blockstore");
        assert!(bs.backend.is_persistent());
    }

    #[test]
    fn engine_store_and_recover_accounts() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = StorageEngine::open(dir.path()).expect("open");

        // Store some accounts.
        let db = engine.create_account_database();
        for i in 0u8..10 {
            let pk = Pubkey::from([i; 32]);
            let acct = Account::new((i as u64 + 1) * 100, vec![], Pubkey::from([0xFF; 32]));
            db.store_published_account(pk, acct);
        }
        engine.flush().expect("flush");

        // Create a fresh database and recover.
        let db2 = engine.create_account_database();
        let stats = engine.recover(&db2).expect("recover");

        assert_eq!(stats.accounts.accounts_loaded, 10);
        assert_eq!(stats.accounts.total_lamports, 5500);

        // Verify all accounts are accessible.
        for i in 0u8..10 {
            let pk = Pubkey::from([i; 32]);
            assert!(db2.get_published_account(&pk).is_some());
        }
    }

    #[test]
    fn engine_disk_usage_increases() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = StorageEngine::open(dir.path()).expect("open");

        let before = engine.disk_usage().expect("usage");
        let db = engine.create_account_database();
        let pk = Pubkey::from([0xAA; 32]);
        let acct = Account::new(1000, vec![0u8; 1024], Pubkey::from([0xBB; 32]));
        db.store_published_account(pk, acct);
        engine.flush().expect("flush");

        let after = engine.disk_usage().expect("usage");
        assert!(after > before);
    }

    #[test]
    fn engine_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().to_path_buf();

        // Write.
        {
            let engine = StorageEngine::open(&path).expect("open");
            let db = engine.create_account_database();
            let pk = Pubkey::from([0x01; 32]);
            let acct = Account::new(42, vec![1, 2, 3], Pubkey::from([0x02; 32]));
            db.store_published_account(pk, acct);
            engine.flush().expect("flush");
        }

        // Reopen and recover.
        {
            let engine = StorageEngine::open(&path).expect("reopen");
            let db = engine.create_account_database();
            let stats = engine.recover(&db).expect("recover");
            assert_eq!(stats.accounts.accounts_loaded, 1);

            let pk = Pubkey::from([0x01; 32]);
            let acct = db.get_published_account(&pk).expect("should exist");
            assert_eq!(acct.meta.lamports, 42);
            assert_eq!(acct.data.as_slice(), &[1, 2, 3]);
        }
    }

    #[test]
    fn engine_compact_removes_old_data() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = StorageEngine::open(dir.path()).expect("open");

        // Insert some slot-keyed data.
        let store = engine.account_store();
        for slot in [5u64, 10, 20] {
            store
                .put(
                    karstflow_constants::durable_store::CF_SLOT_META,
                    &slot.to_be_bytes(),
                    b"meta",
                )
                .unwrap();
        }

        let stats = engine.compact(15).expect("compact");
        assert_eq!(stats.records_removed, 2); // slots 5 and 10
    }

    #[test]
    fn engine_full_lifecycle() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().to_path_buf();

        // Phase 1: Write accounts + blockstore data.
        {
            let engine = StorageEngine::open(&path).expect("open");
            let db = engine.create_account_database();

            // Store 100 accounts.
            for i in 0u32..100 {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&i.to_le_bytes());
                let pk = Pubkey::from(bytes);
                let acct = Account::new(i as u64 * 10, vec![0u8; 64], Pubkey::from([0xFF; 32]));
                db.store_published_account(pk, acct);
            }

            // Store blockstore data via the raw store.
            let store = engine.account_store();
            for slot in 0u64..50 {
                store
                    .put(
                        karstflow_constants::durable_store::CF_SLOT_META,
                        &slot.to_be_bytes(),
                        b"meta",
                    )
                    .unwrap();
            }

            engine.flush().expect("flush");
        }

        // Phase 2: Reopen, recover, compact.
        {
            let engine = StorageEngine::open(&path).expect("reopen");
            let db = engine.create_account_database();

            let stats = engine.recover(&db).expect("recover");
            assert_eq!(stats.accounts.accounts_loaded, 100);

            // Compact old blockstore data.
            let compact_stats = engine.compact(25).expect("compact");
            assert_eq!(compact_stats.records_removed, 25); // slots 0..25

            // Accounts should be unaffected by slot-based compaction.
            assert_eq!(db.get_account_count(), 100);

            // Verify a specific account.
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&50u32.to_le_bytes());
            let pk = Pubkey::from(bytes);
            let acct = db.get_published_account(&pk).expect("should exist");
            assert_eq!(acct.meta.lamports, 500);
        }
    }
}
