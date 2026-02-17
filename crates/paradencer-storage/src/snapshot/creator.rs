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
}
