use super::metadata::{CompressionType, SnapshotConfig, SnapshotManifest, SnapshotMetadata};
use crate::accounts::{Account, AccountDatabase, Pubkey};
use crate::StorageError;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedAccount {
    pub pubkey: Pubkey,
    pub lamports: u64,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

impl SerializedAccount {
    pub fn from_account(pubkey: Pubkey, account: &Account) -> Self {
        Self {
            pubkey,
            lamports: account.meta.lamports,
            owner: account.meta.owner,
            executable: account.meta.executable,
            rent_epoch: account.meta.rent_epoch,
            data: account.data.to_vec(),
        }
    }

    pub fn to_account(&self) -> Account {
        Account {
            meta: crate::accounts::AccountMeta {
                lamports: self.lamports,
                owner: self.owner,
                executable: self.executable,
                rent_epoch: self.rent_epoch,
            },
            data: crate::accounts::AccountData::new(self.data.clone()),
        }
    }

    pub fn data_size(&self) -> usize {
        self.data.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub accounts: Vec<SerializedAccount>,
    pub slot: u64,
}

impl SnapshotData {
    pub fn new(slot: u64) -> Self {
        Self {
            accounts: Vec::new(),
            slot,
        }
    }

    pub fn add_account(&mut self, account: SerializedAccount) {
        self.accounts.push(account);
    }

    pub fn total_lamports(&self) -> u64 {
        self.accounts.iter().map(|a| a.lamports).sum()
    }

    pub fn total_data_size(&self) -> u64 {
        self.accounts.iter().map(|a| a.data_size() as u64).sum()
    }
}

/// Statistics from creating an incremental snapshot via the dirty-set path.
#[derive(Debug, Clone)]
pub struct IncrementalStats {
    /// Number of unique pubkeys tracked as dirty since the base slot.
    pub dirty_pubkeys_tracked: usize,
    /// Number of accounts actually included in the snapshot (still exist in DB).
    pub accounts_included: usize,
    /// The base slot for this incremental snapshot.
    pub base_slot: u64,
    /// The snapshot slot.
    pub snapshot_slot: u64,
}

pub struct SnapshotCreator {
    config: SnapshotConfig,
    progress: Arc<SnapshotProgress>,
}

#[derive(Debug)]
pub struct SnapshotProgress {
    total_accounts: AtomicU64,
    processed_accounts: AtomicU64,
    total_bytes: AtomicU64,
    processed_bytes: AtomicU64,
    chunks_written: AtomicUsize,
}

impl Default for SnapshotProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotProgress {
    pub fn new() -> Self {
        Self {
            total_accounts: AtomicU64::new(0),
            processed_accounts: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            processed_bytes: AtomicU64::new(0),
            chunks_written: AtomicUsize::new(0),
        }
    }

    pub fn set_total(&self, accounts: u64, bytes: u64) {
        self.total_accounts.store(accounts, Ordering::Relaxed);
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn increment_processed(&self, accounts: u64, bytes: u64) {
        self.processed_accounts
            .fetch_add(accounts, Ordering::Relaxed);
        self.processed_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_chunks(&self) {
        self.chunks_written.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_progress(&self) -> SnapshotProgressInfo {
        SnapshotProgressInfo {
            total_accounts: self.total_accounts.load(Ordering::Relaxed),
            processed_accounts: self.processed_accounts.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            processed_bytes: self.processed_bytes.load(Ordering::Relaxed),
            chunks_written: self.chunks_written.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotProgressInfo {
    pub total_accounts: u64,
    pub processed_accounts: u64,
    pub total_bytes: u64,
    pub processed_bytes: u64,
    pub chunks_written: usize,
}

impl SnapshotProgressInfo {
    pub fn percentage(&self) -> f64 {
        if self.total_accounts == 0 {
            0.0
        } else {
            (self.processed_accounts as f64 / self.total_accounts as f64) * 100.0
        }
    }

    pub fn bytes_percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            (self.processed_bytes as f64 / self.total_bytes as f64) * 100.0
        }
    }
}

impl SnapshotCreator {
    pub fn new(config: SnapshotConfig) -> Self {
        Self {
            config,
            progress: Arc::new(SnapshotProgress::new()),
        }
    }

    pub fn get_progress(&self) -> SnapshotProgressInfo {
        self.progress.get_progress()
    }

    pub fn create_full_snapshot(
        &self,
        db: &AccountDatabase,
        slot: u64,
        output_dir: &Path,
    ) -> Result<SnapshotManifest, StorageError> {
        let accounts = self.collect_all_accounts(db)?;
        let snapshot_data = self.serialize_accounts(accounts, slot)?;
        self.write_snapshot(snapshot_data, None, output_dir)
    }

    pub fn create_incremental_snapshot(
        &self,
        db: &AccountDatabase,
        slot: u64,
        base_slot: u64,
        base_accounts: &HashMap<Pubkey, Account>,
        output_dir: &Path,
    ) -> Result<SnapshotManifest, StorageError> {
        let current_accounts = self.collect_all_accounts(db)?;
        let delta_accounts = self.compute_delta(current_accounts, base_accounts);
        let snapshot_data = self.serialize_accounts(delta_accounts, slot)?;
        self.write_snapshot(snapshot_data, Some(base_slot), output_dir)
    }

    /// Create an incremental snapshot using the dirty-set tracker.
    ///
    /// Instead of diffing all accounts against a base snapshot, this method
    /// only includes accounts that were modified since `base_slot`, using
    /// the AccountDatabase's built-in dirty-set tracking. This is much more
    /// efficient for large account sets with small deltas.
    ///
    /// After creation, dirty slots through `slot` are drained from the tracker.
    pub fn create_incremental_from_dirty_set(
        &self,
        db: &AccountDatabase,
        slot: u64,
        base_slot: u64,
        output_dir: &Path,
    ) -> Result<(SnapshotManifest, IncrementalStats), StorageError> {
        let dirty_pubkeys = db.drain_dirty_slots_through(slot);
        let dirty_count = dirty_pubkeys.len();

        let mut delta_accounts = HashMap::with_capacity(dirty_count);
        for pubkey in &dirty_pubkeys {
            if let Some(account) = db.get_published_account(pubkey) {
                delta_accounts.insert(*pubkey, account);
            }
            // If account was deleted (not found), we skip it.
            // A full snapshot will capture the correct final state.
        }

        let accounts_included = delta_accounts.len();
        let snapshot_data = self.serialize_accounts(delta_accounts, slot)?;
        let manifest = self.write_snapshot(snapshot_data, Some(base_slot), output_dir)?;

        let stats = IncrementalStats {
            dirty_pubkeys_tracked: dirty_count,
            accounts_included,
            base_slot,
            snapshot_slot: slot,
        };

        Ok((manifest, stats))
    }

    fn collect_all_accounts(
        &self,
        db: &AccountDatabase,
    ) -> Result<HashMap<Pubkey, Account>, StorageError> {
        Ok(db.get_all_published_accounts())
    }

    fn compute_delta(
        &self,
        current: HashMap<Pubkey, Account>,
        base: &HashMap<Pubkey, Account>,
    ) -> HashMap<Pubkey, Account> {
        let mut delta = HashMap::new();

        for (pubkey, account) in current {
            if let Some(base_account) = base.get(&pubkey) {
                if &account != base_account {
                    delta.insert(pubkey, account);
                }
            } else {
                delta.insert(pubkey, account);
            }
        }

        delta
    }

    fn serialize_accounts(
        &self,
        accounts: HashMap<Pubkey, Account>,
        slot: u64,
    ) -> Result<SnapshotData, StorageError> {
        let total_accounts = accounts.len() as u64;
        let total_bytes: u64 = accounts.values().map(|a| a.data_len() as u64).sum();

        self.progress.set_total(total_accounts, total_bytes);

        let mut snapshot_data = SnapshotData::new(slot);

        let chunk_size = self.config.parallel_workers.max(1);
        let account_vec: Vec<_> = accounts.into_iter().collect();

        let serialized: Vec<_> = account_vec
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                let mut local_serialized = Vec::new();
                for (pubkey, account) in chunk {
                    let serialized = SerializedAccount::from_account(*pubkey, account);
                    let data_size = serialized.data_size() as u64;
                    self.progress.increment_processed(1, data_size);
                    local_serialized.push(serialized);
                }
                local_serialized
            })
            .collect();

        snapshot_data.accounts = serialized;

        Ok(snapshot_data)
    }

    fn write_snapshot(
        &self,
        snapshot_data: SnapshotData,
        base_slot: Option<u64>,
        output_dir: &Path,
    ) -> Result<SnapshotManifest, StorageError> {
        std::fs::create_dir_all(output_dir).map_err(|e| StorageError::AccountDatabaseError {
            details: format!("Failed to create snapshot directory: {}", e),
        })?;

        let total_accounts = snapshot_data.accounts.len() as u64;
        let total_lamports = snapshot_data.total_lamports();
        let account_data_size = snapshot_data.total_data_size();

        let mut metadata = SnapshotMetadata::new(
            snapshot_data.slot,
            total_accounts,
            total_lamports,
            base_slot,
            CompressionType::Zstd,
            account_data_size,
        );

        let serialized =
            bincode::serialize(&snapshot_data).map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to serialize snapshot: {}", e),
            })?;

        let compressed = self.compress_data(&serialized)?;

        let hash = SnapshotMetadata::compute_content_hash(&compressed);
        metadata.update_hash(hash);

        let mut manifest = SnapshotManifest::new(metadata.clone());

        let snapshot_filename = if base_slot.is_some() {
            format!("incremental-{}.snapshot", snapshot_data.slot)
        } else {
            format!("full-{}.snapshot", snapshot_data.slot)
        };

        let snapshot_path = output_dir.join(&snapshot_filename);
        std::fs::write(&snapshot_path, &compressed).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to write snapshot file: {}", e),
            }
        })?;

        manifest.add_chunk(hash);
        self.progress.increment_chunks();

        let manifest_path = output_dir.join(format!("{}.manifest", snapshot_filename));
        let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to serialize manifest: {}", e),
            }
        })?;

        std::fs::write(&manifest_path, manifest_json).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to write manifest file: {}", e),
            }
        })?;

        Ok(manifest)
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        zstd::encode_all(data, self.config.compression_level).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to compress data: {}", e),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::primitives::{AccountData, AccountMeta};

    #[test]
    fn test_serialized_account_roundtrip() {
        let pubkey = Pubkey::zeroed();
        let account = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3, 4]),
        };

        let serialized = SerializedAccount::from_account(pubkey, &account);
        let deserialized = serialized.to_account();

        assert_eq!(account, deserialized);
    }

    #[test]
    fn test_snapshot_data_creation() {
        let mut snapshot_data = SnapshotData::new(100);
        assert_eq!(snapshot_data.slot, 100);
        assert_eq!(snapshot_data.accounts.len(), 0);

        let account = SerializedAccount {
            pubkey: Pubkey::zeroed(),
            lamports: 1000,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
            data: vec![1, 2, 3],
        };

        snapshot_data.add_account(account);
        assert_eq!(snapshot_data.accounts.len(), 1);
        assert_eq!(snapshot_data.total_lamports(), 1000);
        assert_eq!(snapshot_data.total_data_size(), 3);
    }

    #[test]
    fn test_progress_tracking() {
        let progress = SnapshotProgress::new();
        progress.set_total(100, 1000);

        let info = progress.get_progress();
        assert_eq!(info.total_accounts, 100);
        assert_eq!(info.total_bytes, 1000);

        progress.increment_processed(10, 100);
        let info = progress.get_progress();
        assert_eq!(info.processed_accounts, 10);
        assert_eq!(info.processed_bytes, 100);
        assert_eq!(info.percentage(), 10.0);
    }

    #[test]
    fn test_compute_delta() {
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);

        let mut base = HashMap::new();
        let mut current = HashMap::new();

        let pubkey1 = Pubkey::zeroed();
        let account1 = Account {
            meta: AccountMeta {
                lamports: 1000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(vec![1, 2, 3]),
        };

        base.insert(pubkey1, account1.clone());
        current.insert(pubkey1, account1.clone());

        let delta = creator.compute_delta(current, &base);
        assert_eq!(delta.len(), 0);
    }

    #[test]
    fn incremental_from_dirty_set_captures_modified_accounts() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);

        // Store some initial accounts.
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        db.store_published_account_at_slot(pk1, Account::new(1_000, vec![], Pubkey::zeroed()), 10);
        db.store_published_account_at_slot(pk2, Account::new(2_000, vec![], Pubkey::zeroed()), 11);

        let dir = tempfile::tempdir().unwrap();
        let (manifest, stats) = creator
            .create_incremental_from_dirty_set(&db, 11, 0, dir.path())
            .unwrap();

        assert_eq!(stats.dirty_pubkeys_tracked, 2);
        assert_eq!(stats.accounts_included, 2);
        assert_eq!(stats.base_slot, 0);
        assert_eq!(stats.snapshot_slot, 11);
        assert!(manifest.metadata.incremental_base.is_some());
        assert_eq!(manifest.metadata.incremental_base, Some(0));
    }

    #[test]
    fn incremental_from_dirty_set_drains_dirty_tracking() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);

        let pk = Pubkey::new_unique();
        db.store_published_account_at_slot(pk, Account::new(1_000, vec![], Pubkey::zeroed()), 5);

        assert_eq!(db.dirty_account_count(), 1);

        let dir = tempfile::tempdir().unwrap();
        creator
            .create_incremental_from_dirty_set(&db, 5, 0, dir.path())
            .unwrap();

        // Dirty set should be drained after incremental snapshot.
        assert_eq!(db.dirty_account_count(), 0);
    }

    #[test]
    fn incremental_from_dirty_set_only_includes_modified_slots() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);

        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let pk3 = Pubkey::new_unique();

        db.store_published_account_at_slot(pk1, Account::new(100, vec![], Pubkey::zeroed()), 10);
        db.store_published_account_at_slot(pk2, Account::new(200, vec![], Pubkey::zeroed()), 20);
        db.store_published_account_at_slot(pk3, Account::new(300, vec![], Pubkey::zeroed()), 30);

        // Create incremental through slot 20 — should only include pk1 and pk2.
        let dir = tempfile::tempdir().unwrap();
        let (_, stats) = creator
            .create_incremental_from_dirty_set(&db, 20, 0, dir.path())
            .unwrap();

        assert_eq!(stats.dirty_pubkeys_tracked, 2);
        assert_eq!(stats.accounts_included, 2);

        // pk3 should still be tracked.
        assert_eq!(db.dirty_account_count(), 1);
    }

    #[test]
    fn incremental_from_dirty_set_empty_delta() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);

        let dir = tempfile::tempdir().unwrap();
        let (manifest, stats) = creator
            .create_incremental_from_dirty_set(&db, 100, 50, dir.path())
            .unwrap();

        assert_eq!(stats.dirty_pubkeys_tracked, 0);
        assert_eq!(stats.accounts_included, 0);
        assert_eq!(manifest.metadata.total_accounts, 0);
    }

    #[test]
    fn full_then_incremental_snapshot_workflow() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        // Step 1: Create initial state and take a full snapshot.
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        db.store_published_account_at_slot(
            pk1,
            Account::new(1_000, vec![1], Pubkey::zeroed()),
            100,
        );
        db.store_published_account_at_slot(
            pk2,
            Account::new(2_000, vec![2], Pubkey::zeroed()),
            100,
        );

        let full_manifest = creator.create_full_snapshot(&db, 100, dir.path()).unwrap();
        assert_eq!(full_manifest.metadata.total_accounts, 2);

        // Drain dirty set after full snapshot.
        db.drain_dirty_slots_through(100);

        // Step 2: Modify one account, add a new one.
        db.store_published_account_at_slot(
            pk1,
            Account::new(5_000, vec![1, 2, 3], Pubkey::zeroed()),
            200,
        );
        let pk3 = Pubkey::new_unique();
        db.store_published_account_at_slot(
            pk3,
            Account::new(3_000, vec![3], Pubkey::zeroed()),
            200,
        );

        // Step 3: Create incremental snapshot with dirty-set.
        let (incr_manifest, stats) = creator
            .create_incremental_from_dirty_set(&db, 200, 100, dir.path())
            .unwrap();

        assert_eq!(stats.dirty_pubkeys_tracked, 2); // pk1 (modified) + pk3 (new)
        assert_eq!(stats.accounts_included, 2);
        assert_eq!(incr_manifest.metadata.incremental_base, Some(100));
        assert_eq!(incr_manifest.metadata.total_accounts, 2);
    }
}
