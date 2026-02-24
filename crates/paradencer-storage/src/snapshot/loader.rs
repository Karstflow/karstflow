use super::creator::{SerializedAccount, SnapshotData};
use super::metadata::{SnapshotManifest, SnapshotMetadata};
use crate::accounts::{Account, AccountDatabase, Pubkey};
use crate::StorageError;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct SnapshotLoader {
    progress: Arc<LoadProgress>,
}

#[derive(Debug)]
pub struct LoadProgress {
    total_accounts: AtomicU64,
    loaded_accounts: AtomicU64,
    total_bytes: AtomicU64,
    loaded_bytes: AtomicU64,
    validation_errors: AtomicU64,
}

impl Default for LoadProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadProgress {
    pub fn new() -> Self {
        Self {
            total_accounts: AtomicU64::new(0),
            loaded_accounts: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            loaded_bytes: AtomicU64::new(0),
            validation_errors: AtomicU64::new(0),
        }
    }

    pub fn set_total(&self, accounts: u64, bytes: u64) {
        self.total_accounts.store(accounts, Ordering::Relaxed);
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn increment_loaded(&self, accounts: u64, bytes: u64) {
        self.loaded_accounts.fetch_add(accounts, Ordering::Relaxed);
        self.loaded_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.validation_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_progress(&self) -> LoadProgressInfo {
        LoadProgressInfo {
            total_accounts: self.total_accounts.load(Ordering::Relaxed),
            loaded_accounts: self.loaded_accounts.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            loaded_bytes: self.loaded_bytes.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadProgressInfo {
    pub total_accounts: u64,
    pub loaded_accounts: u64,
    pub total_bytes: u64,
    pub loaded_bytes: u64,
    pub validation_errors: u64,
}

impl LoadProgressInfo {
    pub fn percentage(&self) -> f64 {
        if self.total_accounts == 0 {
            0.0
        } else {
            (self.loaded_accounts as f64 / self.total_accounts as f64) * 100.0
        }
    }

    pub fn bytes_percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            (self.loaded_bytes as f64 / self.total_bytes as f64) * 100.0
        }
    }

    pub fn has_errors(&self) -> bool {
        self.validation_errors > 0
    }
}

impl SnapshotLoader {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(LoadProgress::new()),
        }
    }

    pub fn get_progress(&self) -> LoadProgressInfo {
        self.progress.get_progress()
    }

    pub fn load_snapshot(
        &self,
        snapshot_path: &Path,
        manifest_path: &Path,
        db: &AccountDatabase,
    ) -> Result<LoadedSnapshot, StorageError> {
        let manifest = self.load_manifest(manifest_path)?;
        let compressed_data =
            std::fs::read(snapshot_path).map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read snapshot file: {}", e),
            })?;

        if !manifest.verify_chunk(0, &compressed_data) {
            return Err(StorageError::SnapshotChecksumMismatch {
                path: snapshot_path.to_path_buf(),
                fragment_id: manifest.metadata.slot,
                expected: u64::from_le_bytes(manifest.chunk_hashes[0][0..8].try_into().unwrap()),
                found: 0,
            });
        }

        let decompressed_data = self.decompress_data(&compressed_data)?;

        let snapshot_data: SnapshotData =
            bincode::deserialize(&decompressed_data).map_err(|e| {
                StorageError::AccountDatabaseError {
                    details: format!("Failed to deserialize snapshot: {}", e),
                }
            })?;

        let accounts = self.load_accounts(db, &snapshot_data)?;

        // Compute accounts hash for verification.
        let (computed_hash, _) = db.compute_accounts_hash();

        // Verify against the stored accounts hash if available.
        if manifest.metadata.has_accounts_hash() {
            db.verify_accounts_hash(&manifest.metadata.accounts_hash)
                .map_err(|mismatch| StorageError::AccountDatabaseError {
                    details: format!(
                        "Snapshot accounts hash verification failed at slot {}: {}",
                        snapshot_data.slot, mismatch
                    ),
                })?;
        }

        Ok(LoadedSnapshot {
            slot: snapshot_data.slot,
            total_accounts: accounts.len() as u64,
            total_lamports: snapshot_data.total_lamports(),
            metadata: manifest.metadata,
            accounts_hash: computed_hash,
        })
    }

    pub fn load_snapshot_to_map(
        &self,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> Result<(HashMap<Pubkey, Account>, SnapshotMetadata), StorageError> {
        let manifest = self.load_manifest(manifest_path)?;
        let compressed_data =
            std::fs::read(snapshot_path).map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read snapshot file: {}", e),
            })?;

        if !manifest.verify_chunk(0, &compressed_data) {
            return Err(StorageError::SnapshotChecksumMismatch {
                path: snapshot_path.to_path_buf(),
                fragment_id: manifest.metadata.slot,
                expected: u64::from_le_bytes(manifest.chunk_hashes[0][0..8].try_into().unwrap()),
                found: 0,
            });
        }

        let decompressed_data = self.decompress_data(&compressed_data)?;

        let snapshot_data: SnapshotData =
            bincode::deserialize(&decompressed_data).map_err(|e| {
                StorageError::AccountDatabaseError {
                    details: format!("Failed to deserialize snapshot: {}", e),
                }
            })?;

        let total_accounts = snapshot_data.accounts.len() as u64;
        let total_bytes = snapshot_data.total_data_size();
        self.progress.set_total(total_accounts, total_bytes);

        let accounts = self.deserialize_accounts(&snapshot_data.accounts)?;

        Ok((accounts, manifest.metadata))
    }

    fn load_manifest(&self, manifest_path: &Path) -> Result<SnapshotManifest, StorageError> {
        let manifest_json = std::fs::read_to_string(manifest_path).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to read manifest file: {}", e),
            }
        })?;

        let manifest: SnapshotManifest = serde_json::from_str(&manifest_json).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize manifest: {}", e),
            }
        })?;

        Ok(manifest)
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        zstd::decode_all(data).map_err(|e| StorageError::AccountDatabaseError {
            details: format!("Failed to decompress data: {}", e),
        })
    }

    fn load_accounts(
        &self,
        db: &AccountDatabase,
        snapshot_data: &SnapshotData,
    ) -> Result<HashMap<Pubkey, Account>, StorageError> {
        let total_accounts = snapshot_data.accounts.len() as u64;
        let total_bytes = snapshot_data.total_data_size();
        self.progress.set_total(total_accounts, total_bytes);

        let accounts = self.deserialize_accounts(&snapshot_data.accounts)?;

        // Insert all accounts into the database at the snapshot slot.
        db.bulk_insert_published_accounts_at_slot(accounts.clone(), snapshot_data.slot)?;

        Ok(accounts)
    }

    fn deserialize_accounts(
        &self,
        serialized_accounts: &[SerializedAccount],
    ) -> Result<HashMap<Pubkey, Account>, StorageError> {
        let chunk_size = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);

        let accounts: Result<Vec<_>, StorageError> = serialized_accounts
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut local_accounts = Vec::new();
                for serialized in chunk {
                    if !self.validate_account(serialized) {
                        self.progress.increment_errors();
                        return Err(StorageError::AccountDatabaseError {
                            details: format!("Invalid account data for {:?}", serialized.pubkey),
                        });
                    }

                    let account = serialized.to_account();
                    let data_size = serialized.data_size() as u64;
                    self.progress.increment_loaded(1, data_size);
                    local_accounts.push((serialized.pubkey, account));
                }
                Ok(local_accounts)
            })
            .collect();

        let accounts = accounts?;
        let account_map: HashMap<_, _> = accounts.into_iter().flatten().collect();

        Ok(account_map)
    }

    fn validate_account(&self, account: &SerializedAccount) -> bool {
        // Basic validation
        if account.data.len() > 10 * 1024 * 1024 {
            return false;
        }

        true
    }

    pub fn apply_incremental_snapshot(
        &self,
        base_accounts: &mut HashMap<Pubkey, Account>,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> Result<LoadedSnapshot, StorageError> {
        let (delta_accounts, metadata) = self.load_snapshot_to_map(snapshot_path, manifest_path)?;

        if !metadata.is_incremental() {
            return Err(StorageError::AccountDatabaseError {
                details: "Snapshot is not incremental".to_string(),
            });
        }

        let mut total_lamports = 0u64;
        for (pubkey, account) in delta_accounts {
            total_lamports = total_lamports.saturating_add(account.meta.lamports);
            base_accounts.insert(pubkey, account);
        }

        Ok(LoadedSnapshot {
            slot: metadata.slot,
            total_accounts: base_accounts.len() as u64,
            total_lamports,
            metadata,
            // No DB available for in-memory incremental apply — hash not computed.
            accounts_hash: [0u8; 32],
        })
    }

    /// Apply an incremental snapshot directly to AccountDatabase.
    ///
    /// Delta accounts override existing accounts in the database. Accounts
    /// not present in the increment remain unchanged. This avoids the
    /// intermediate HashMap step when the caller already has a live database.
    ///
    /// Validates that:
    /// - The snapshot is marked as incremental.
    /// - The database is not empty (base state must exist).
    /// - If `expected_base_slot` is provided, the metadata's base slot matches.
    pub fn apply_incremental_to_db(
        &self,
        db: &AccountDatabase,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> Result<LoadedSnapshot, StorageError> {
        self.apply_incremental_to_db_checked(db, snapshot_path, manifest_path, None)
    }

    /// Apply an incremental snapshot with explicit base slot validation.
    ///
    /// If `expected_base_slot` is `Some`, validates that the incremental
    /// snapshot's declared base matches. This prevents applying an
    /// incremental from the wrong chain.
    pub fn apply_incremental_to_db_checked(
        &self,
        db: &AccountDatabase,
        snapshot_path: &Path,
        manifest_path: &Path,
        expected_base_slot: Option<u64>,
    ) -> Result<LoadedSnapshot, StorageError> {
        let (delta_accounts, metadata) = self.load_snapshot_to_map(snapshot_path, manifest_path)?;

        if !metadata.is_incremental() {
            return Err(StorageError::AccountDatabaseError {
                details: "Snapshot is not incremental".to_string(),
            });
        }

        // Validate chain: DB must have existing state.
        if db.get_account_count() == 0 {
            return Err(StorageError::AccountDatabaseError {
                details: format!(
                    "Cannot apply incremental snapshot at slot {} to empty database; \
                     base snapshot (slot {:?}) must be loaded first",
                    metadata.slot, metadata.incremental_base,
                ),
            });
        }

        // Validate base slot if the caller provides an expected value.
        if let Some(expected) = expected_base_slot {
            if metadata.incremental_base != Some(expected) {
                return Err(StorageError::AccountDatabaseError {
                    details: format!(
                        "Incremental chain mismatch: expected base slot {}, \
                         but snapshot declares base {:?}",
                        expected, metadata.incremental_base,
                    ),
                });
            }
        }

        let delta_count = delta_accounts.len() as u64;
        db.bulk_insert_published_accounts_at_slot(delta_accounts, metadata.slot)?;

        // Compute accounts hash of the full state after applying increment.
        let (computed_hash, _) = db.compute_accounts_hash();

        // Verify against stored hash if available.
        if metadata.has_accounts_hash() {
            db.verify_accounts_hash(&metadata.accounts_hash)
                .map_err(|mismatch| StorageError::AccountDatabaseError {
                    details: format!(
                        "Incremental snapshot accounts hash verification failed at slot {}: {}",
                        metadata.slot, mismatch
                    ),
                })?;
        }

        Ok(LoadedSnapshot {
            slot: metadata.slot,
            total_accounts: delta_count,
            total_lamports: 0, // Caller can query db for accurate total.
            metadata,
            accounts_hash: computed_hash,
        })
    }
}

impl Default for SnapshotLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct LoadedSnapshot {
    pub slot: u64,
    pub total_accounts: u64,
    pub total_lamports: u64,
    pub metadata: SnapshotMetadata,
    /// Accounts hash computed after loading (for verification).
    pub accounts_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::primitives::{AccountData, AccountMeta};
    use crate::snapshot::creator::SnapshotCreator;
    use crate::snapshot::metadata::SnapshotConfig;

    #[test]
    fn test_progress_tracking() {
        let progress = LoadProgress::new();
        progress.set_total(100, 1000);

        let info = progress.get_progress();
        assert_eq!(info.total_accounts, 100);
        assert_eq!(info.total_bytes, 1000);

        progress.increment_loaded(10, 100);
        let info = progress.get_progress();
        assert_eq!(info.loaded_accounts, 10);
        assert_eq!(info.loaded_bytes, 100);
        assert_eq!(info.percentage(), 10.0);
    }

    #[test]
    fn test_account_validation() {
        let loader = SnapshotLoader::new();

        let valid_account = SerializedAccount {
            pubkey: Pubkey::zeroed(),
            lamports: 1000,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
            data: vec![1, 2, 3],
        };

        assert!(loader.validate_account(&valid_account));

        let invalid_account = SerializedAccount {
            pubkey: Pubkey::zeroed(),
            lamports: 1000,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
            data: vec![0; 11 * 1024 * 1024],
        };

        assert!(!loader.validate_account(&invalid_account));
    }

    #[test]
    fn test_deserialize_accounts() {
        let loader = SnapshotLoader::new();

        let serialized = vec![SerializedAccount {
            pubkey: Pubkey::zeroed(),
            lamports: 1000,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
            data: vec![1, 2, 3],
        }];

        let result = loader.deserialize_accounts(&serialized);
        assert!(result.is_ok());

        let accounts = result.unwrap();
        assert_eq!(accounts.len(), 1);
    }

    // -------------------------------------------------------------------
    // Roundtrip tests: create snapshot → load snapshot → verify
    // -------------------------------------------------------------------

    fn make_account(lamports: u64, data: Vec<u8>, owner: Pubkey) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::new(data),
        }
    }

    #[test]
    fn load_snapshot_inserts_into_database() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        // Store accounts and create a full snapshot.
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let owner = Pubkey::new([10u8; 32]);
        db.store_published_account(pk1, make_account(1_000, vec![1, 2], owner));
        db.store_published_account(pk2, make_account(2_000, vec![3, 4, 5], owner));

        let manifest = creator.create_full_snapshot(&db, 100, dir.path()).unwrap();

        // Load into a fresh database.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        let snapshot_path = dir.path().join("full-100.snapshot");
        let manifest_path = dir.path().join("full-100.snapshot.manifest");
        let result = loader
            .load_snapshot(&snapshot_path, &manifest_path, &db2)
            .unwrap();

        assert_eq!(result.slot, 100);
        assert_eq!(result.total_accounts, 2);

        // Verify accounts exist in the new database.
        let a1 = db2.get_published_account(&pk1).unwrap();
        assert_eq!(a1.meta.lamports, 1_000);
        assert_eq!(a1.data.as_slice(), &[1, 2]);

        let a2 = db2.get_published_account(&pk2).unwrap();
        assert_eq!(a2.meta.lamports, 2_000);
        assert_eq!(a2.data.as_slice(), &[3, 4, 5]);

        // Owner index should be populated.
        assert_eq!(db2.get_account_count(), 2);
        let _ = manifest;
    }

    #[test]
    fn apply_incremental_to_db_merges_delta() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        // Base state: two accounts at slot 100.
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let owner = Pubkey::new([10u8; 32]);
        db.store_published_account_at_slot(pk1, make_account(1_000, vec![1], owner), 100);
        db.store_published_account_at_slot(pk2, make_account(2_000, vec![2], owner), 100);

        // Create full snapshot and drain dirty set.
        creator.create_full_snapshot(&db, 100, dir.path()).unwrap();
        db.drain_dirty_slots_through(100);

        // Modify pk1 and add pk3 at slot 200.
        let pk3 = Pubkey::new_unique();
        db.store_published_account_at_slot(pk1, make_account(5_000, vec![1, 2, 3], owner), 200);
        db.store_published_account_at_slot(pk3, make_account(3_000, vec![3], owner), 200);

        // Create incremental snapshot via dirty-set.
        let (_, stats) = creator
            .create_incremental_from_dirty_set(&db, 200, 100, dir.path())
            .unwrap();
        assert_eq!(stats.accounts_included, 2);

        // Load full snapshot into fresh database, then apply incremental.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();

        let full_snap = dir.path().join("full-100.snapshot");
        let full_manifest = dir.path().join("full-100.snapshot.manifest");
        loader
            .load_snapshot(&full_snap, &full_manifest, &db2)
            .unwrap();

        // Verify base state.
        assert_eq!(
            db2.get_published_account(&pk1).unwrap().meta.lamports,
            1_000
        );
        assert!(db2.get_published_account(&pk3).is_none());

        // Apply incremental.
        let incr_snap = dir.path().join("incremental-200.snapshot");
        let incr_manifest = dir.path().join("incremental-200.snapshot.manifest");
        let incr_result = loader
            .apply_incremental_to_db(&db2, &incr_snap, &incr_manifest)
            .unwrap();

        assert_eq!(incr_result.slot, 200);
        assert_eq!(incr_result.total_accounts, 2);

        // pk1 updated, pk2 unchanged, pk3 new.
        assert_eq!(
            db2.get_published_account(&pk1).unwrap().meta.lamports,
            5_000
        );
        assert_eq!(
            db2.get_published_account(&pk1).unwrap().data.as_slice(),
            &[1, 2, 3]
        );
        assert_eq!(
            db2.get_published_account(&pk2).unwrap().meta.lamports,
            2_000
        );
        assert_eq!(
            db2.get_published_account(&pk3).unwrap().meta.lamports,
            3_000
        );

        assert_eq!(db2.get_account_count(), 3);
    }

    #[test]
    fn apply_incremental_to_db_rejects_full_snapshot() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        // Create a full snapshot (not incremental).
        creator.create_full_snapshot(&db, 50, dir.path()).unwrap();

        let loader = SnapshotLoader::new();
        let snap = dir.path().join("full-50.snapshot");
        let manifest = dir.path().join("full-50.snapshot.manifest");
        let result = loader.apply_incremental_to_db(&db, &snap, &manifest);

        assert!(result.is_err());
    }

    #[test]
    fn full_roundtrip_preserves_account_data() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        // Store accounts with varied data.
        let mut pubkeys = Vec::new();
        for i in 0..20u8 {
            let pk = Pubkey::new_unique();
            let account = make_account(
                (i as u64 + 1) * 100,
                vec![i; (i as usize + 1) * 10],
                Pubkey::new([i + 1; 32]),
            );
            db.store_published_account(pk, account);
            pubkeys.push(pk);
        }

        creator.create_full_snapshot(&db, 500, dir.path()).unwrap();

        // Load into fresh database.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        let snap = dir.path().join("full-500.snapshot");
        let manifest = dir.path().join("full-500.snapshot.manifest");
        loader.load_snapshot(&snap, &manifest, &db2).unwrap();

        // Every account should match exactly.
        for pk in &pubkeys {
            let original = db.get_published_account(pk).unwrap();
            let restored = db2.get_published_account(pk).unwrap();
            assert_eq!(original, restored, "Account mismatch for pubkey {:?}", pk);
        }

        assert_eq!(db2.get_account_count(), 20);
        assert_eq!(db2.get_total_lamports(), db.get_total_lamports());
    }

    #[test]
    fn incremental_roundtrip_with_multiple_deltas() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();
        let owner = Pubkey::new([10u8; 32]);

        // Initial state at slot 100.
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        db.store_published_account_at_slot(pk1, make_account(100, vec![1], owner), 100);
        db.store_published_account_at_slot(pk2, make_account(200, vec![2], owner), 100);

        creator.create_full_snapshot(&db, 100, dir.path()).unwrap();
        db.drain_dirty_slots_through(100);

        // Delta 1: modify pk1 at slot 150.
        db.store_published_account_at_slot(pk1, make_account(150, vec![1, 5], owner), 150);

        // Delta 2: add pk3 at slot 200.
        let pk3 = Pubkey::new_unique();
        db.store_published_account_at_slot(pk3, make_account(300, vec![3], owner), 200);

        let (_, stats) = creator
            .create_incremental_from_dirty_set(&db, 200, 100, dir.path())
            .unwrap();
        assert_eq!(stats.dirty_pubkeys_tracked, 2);

        // Restore: full + incremental into fresh db.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();

        loader
            .load_snapshot(
                &dir.path().join("full-100.snapshot"),
                &dir.path().join("full-100.snapshot.manifest"),
                &db2,
            )
            .unwrap();

        loader
            .apply_incremental_to_db(
                &db2,
                &dir.path().join("incremental-200.snapshot"),
                &dir.path().join("incremental-200.snapshot.manifest"),
            )
            .unwrap();

        // Verify final state matches original db.
        for pk in [pk1, pk2, pk3] {
            let original = db.get_published_account(&pk).unwrap();
            let restored = db2.get_published_account(&pk).unwrap();
            assert_eq!(original, restored);
        }
    }

    #[test]
    fn load_snapshot_sets_correct_slot_on_loaded_result() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        let pk = Pubkey::new_unique();
        db.store_published_account(pk, make_account(42, vec![], Pubkey::zeroed()));
        creator.create_full_snapshot(&db, 777, dir.path()).unwrap();

        let loader = SnapshotLoader::new();
        let result = loader
            .load_snapshot(
                &dir.path().join("full-777.snapshot"),
                &dir.path().join("full-777.snapshot.manifest"),
                &AccountDatabase::new(),
            )
            .unwrap();

        assert_eq!(result.slot, 777);
        assert_eq!(result.metadata.slot, 777);
    }

    #[test]
    fn empty_snapshot_roundtrip() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        creator.create_full_snapshot(&db, 0, dir.path()).unwrap();

        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        let result = loader
            .load_snapshot(
                &dir.path().join("full-0.snapshot"),
                &dir.path().join("full-0.snapshot.manifest"),
                &db2,
            )
            .unwrap();

        assert_eq!(result.total_accounts, 0);
        assert_eq!(db2.get_account_count(), 0);
    }

    // ── incremental chain validation tests ────────────────────────────

    #[test]
    fn apply_incremental_to_empty_db_rejected() {
        let db_src = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();
        let owner = Pubkey::new([10u8; 32]);

        // Create base state and full snapshot.
        let pk = Pubkey::new_unique();
        db_src.store_published_account_at_slot(pk, make_account(1_000, vec![1], owner), 100);
        creator
            .create_full_snapshot(&db_src, 100, dir.path())
            .unwrap();
        db_src.drain_dirty_slots_through(100);

        // Modify and create incremental.
        db_src.store_published_account_at_slot(pk, make_account(2_000, vec![1, 2], owner), 200);
        creator
            .create_incremental_from_dirty_set(&db_src, 200, 100, dir.path())
            .unwrap();

        // Try to apply incremental to an EMPTY database → should fail.
        let empty_db = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        let result = loader.apply_incremental_to_db(
            &empty_db,
            &dir.path().join("incremental-200.snapshot"),
            &dir.path().join("incremental-200.snapshot.manifest"),
        );
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("empty database"));
    }

    #[test]
    fn apply_incremental_checked_rejects_wrong_base_slot() {
        let db_src = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();
        let owner = Pubkey::new([10u8; 32]);

        // Create base and incremental.
        let pk = Pubkey::new_unique();
        db_src.store_published_account_at_slot(pk, make_account(1_000, vec![1], owner), 100);
        creator
            .create_full_snapshot(&db_src, 100, dir.path())
            .unwrap();
        db_src.drain_dirty_slots_through(100);

        db_src.store_published_account_at_slot(pk, make_account(2_000, vec![1, 2], owner), 200);
        creator
            .create_incremental_from_dirty_set(&db_src, 200, 100, dir.path())
            .unwrap();

        // Load full snapshot into fresh DB.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        loader
            .load_snapshot(
                &dir.path().join("full-100.snapshot"),
                &dir.path().join("full-100.snapshot.manifest"),
                &db2,
            )
            .unwrap();

        // Apply incremental with WRONG expected base slot → should fail.
        let result = loader.apply_incremental_to_db_checked(
            &db2,
            &dir.path().join("incremental-200.snapshot"),
            &dir.path().join("incremental-200.snapshot.manifest"),
            Some(50), // Wrong! Snapshot declares base_slot=100.
        );
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("chain mismatch"));
    }

    #[test]
    fn apply_incremental_checked_succeeds_with_correct_base() {
        let db_src = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();
        let owner = Pubkey::new([10u8; 32]);

        // Create base + incremental.
        let pk = Pubkey::new_unique();
        db_src.store_published_account_at_slot(pk, make_account(1_000, vec![1], owner), 100);
        creator
            .create_full_snapshot(&db_src, 100, dir.path())
            .unwrap();
        db_src.drain_dirty_slots_through(100);

        db_src.store_published_account_at_slot(pk, make_account(5_000, vec![1, 2, 3], owner), 200);
        creator
            .create_incremental_from_dirty_set(&db_src, 200, 100, dir.path())
            .unwrap();

        // Load full, then apply incremental with correct base.
        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        loader
            .load_snapshot(
                &dir.path().join("full-100.snapshot"),
                &dir.path().join("full-100.snapshot.manifest"),
                &db2,
            )
            .unwrap();

        let result = loader.apply_incremental_to_db_checked(
            &db2,
            &dir.path().join("incremental-200.snapshot"),
            &dir.path().join("incremental-200.snapshot.manifest"),
            Some(100), // Correct base slot.
        );
        assert!(result.is_ok());

        // Verify accounts are correct.
        let account = db2.get_published_account(&pk).unwrap();
        assert_eq!(account.meta.lamports, 5_000);
    }

    // ── accounts hash verification tests ──────────────────────────────

    #[test]
    fn loaded_snapshot_has_accounts_hash() {
        let db = AccountDatabase::new();
        let config = SnapshotConfig::new();
        let creator = SnapshotCreator::new(config);
        let dir = tempfile::tempdir().unwrap();

        let pk = Pubkey::new_unique();
        db.store_published_account(pk, make_account(1_000, vec![1, 2, 3], Pubkey::zeroed()));
        creator.create_full_snapshot(&db, 42, dir.path()).unwrap();

        let db2 = AccountDatabase::new();
        let loader = SnapshotLoader::new();
        let result = loader
            .load_snapshot(
                &dir.path().join("full-42.snapshot"),
                &dir.path().join("full-42.snapshot.manifest"),
                &db2,
            )
            .unwrap();

        // Non-zero accounts hash stored from creation.
        assert_ne!(result.accounts_hash, [0u8; 32]);
        assert!(result.metadata.has_accounts_hash());

        // Hash matches what we compute from restored DB.
        let (recomputed, _) = db2.compute_accounts_hash();
        assert_eq!(result.accounts_hash, recomputed);
    }
}
