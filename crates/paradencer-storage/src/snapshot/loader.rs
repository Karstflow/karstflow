use super::creator::{SerializedAccount, SnapshotData};
use super::metadata::{SnapshotManifest, SnapshotMetadata};
use crate::accounts::database::AccountDatabase;
use crate::accounts::primitives::{Account, Pubkey};
use crate::accounts::record::TransactionId;
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
        let compressed_data = std::fs::read(snapshot_path)
            .map_err(|e| StorageError::AccountDatabaseError {
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

        let snapshot_data: SnapshotData = bincode::deserialize(&decompressed_data)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize snapshot: {}", e),
            })?;

        let accounts = self.load_accounts(db, &snapshot_data)?;

        Ok(LoadedSnapshot {
            slot: snapshot_data.slot,
            total_accounts: accounts.len() as u64,
            total_lamports: snapshot_data.total_lamports(),
            metadata: manifest.metadata,
        })
    }

    pub fn load_snapshot_to_map(
        &self,
        snapshot_path: &Path,
        manifest_path: &Path,
    ) -> Result<(HashMap<Pubkey, Account>, SnapshotMetadata), StorageError> {
        let manifest = self.load_manifest(manifest_path)?;
        let compressed_data = std::fs::read(snapshot_path)
            .map_err(|e| StorageError::AccountDatabaseError {
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

        let snapshot_data: SnapshotData = bincode::deserialize(&decompressed_data)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize snapshot: {}", e),
            })?;

        let total_accounts = snapshot_data.accounts.len() as u64;
        let total_bytes = snapshot_data.total_data_size();
        self.progress.set_total(total_accounts, total_bytes);

        let accounts = self.deserialize_accounts(&snapshot_data.accounts)?;

        Ok((accounts, manifest.metadata))
    }

    fn load_manifest(&self, manifest_path: &Path) -> Result<SnapshotManifest, StorageError> {
        let manifest_json = std::fs::read_to_string(manifest_path)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read manifest file: {}", e),
            })?;

        let manifest: SnapshotManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize manifest: {}", e),
            })?;

        Ok(manifest)
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        zstd::decode_all(data)
            .map_err(|e| StorageError::AccountDatabaseError {
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

        // In a real implementation, we would need to write these accounts to the database
        // Since AccountDatabase doesn't have a direct bulk insert method, we'll return the map
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::creator::SnapshotData;

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

        let serialized = vec![
            SerializedAccount {
                pubkey: Pubkey::zeroed(),
                lamports: 1000,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
                data: vec![1, 2, 3],
            },
        ];

        let result = loader.deserialize_accounts(&serialized);
        assert!(result.is_ok());

        let accounts = result.unwrap();
        assert_eq!(accounts.len(), 1);
    }
}
