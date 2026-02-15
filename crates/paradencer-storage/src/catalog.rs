use crate::{CommittedFragmentRecord, HotStateStore, SnapshotImage, StorageError};
use crate::snapshot::{
    SnapshotConfig, SnapshotCreator, SnapshotLoader, SnapshotManifest, SnapshotMetadata,
};
use crate::accounts::database::AccountDatabase;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const SNAPSHOT_CATALOG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCatalog {
    pub last_snapshot_fragment_id: u64,
    pub snapshots_written: u64,
    snapshots: BTreeMap<u64, SnapshotImage>,
    full_snapshots: BTreeMap<u64, PathBuf>,
    incremental_snapshots: BTreeMap<u64, PathBuf>,
    config: Option<SnapshotConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotCatalogDisk {
    schema_version: u32,
    last_snapshot_fragment_id: u64,
    snapshots_written: u64,
    snapshots: Vec<SnapshotImage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotCatalogDiskV0 {
    last_snapshot_fragment_id: u64,
    snapshots_written: u64,
    snapshots: Vec<SnapshotImageV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotCatalogDiskV1 {
    schema_version: u32,
    last_snapshot_fragment_id: u64,
    snapshots_written: u64,
    snapshots: Vec<SnapshotImageV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotImageV1 {
    fragment_id: u64,
    committed_fragments: u64,
    committed_transactions: u64,
}

fn validate_snapshot_sequence(
    catalog_path: &Path,
    snapshots: &[SnapshotImage],
) -> Result<(), StorageError> {
    let mut previous: Option<&SnapshotImage> = None;
    for snapshot in snapshots {
        if let Some(previous_snapshot) = previous {
            if snapshot.fragment_id <= previous_snapshot.fragment_id {
                return Err(StorageError::CatalogInvariantViolation {
                    path: catalog_path.to_path_buf(),
                    message: format!(
                        "snapshot fragment ids must be strictly increasing ({} then {})",
                        previous_snapshot.fragment_id, snapshot.fragment_id
                    ),
                });
            }
            if snapshot.committed_fragments < previous_snapshot.committed_fragments {
                return Err(StorageError::CatalogInvariantViolation {
                    path: catalog_path.to_path_buf(),
                    message: format!(
                        "committed_fragments must be monotonic ({} then {})",
                        previous_snapshot.committed_fragments, snapshot.committed_fragments
                    ),
                });
            }
            if snapshot.committed_transactions < previous_snapshot.committed_transactions {
                return Err(StorageError::CatalogInvariantViolation {
                    path: catalog_path.to_path_buf(),
                    message: format!(
                        "committed_transactions must be monotonic ({} then {})",
                        previous_snapshot.committed_transactions, snapshot.committed_transactions
                    ),
                });
            }
        }
        if !snapshot.has_valid_checksum() {
            return Err(StorageError::SnapshotChecksumMismatch {
                path: catalog_path.to_path_buf(),
                fragment_id: snapshot.fragment_id,
                expected: SnapshotImage::compute_state_checksum(
                    snapshot.fragment_id,
                    snapshot.committed_fragments,
                    snapshot.committed_transactions,
                ),
                found: snapshot.state_checksum,
            });
        }
        previous = Some(snapshot);
    }
    Ok(())
}

fn validate_catalog_header(
    catalog_path: &Path,
    snapshots_written: u64,
    last_snapshot_fragment_id: u64,
    snapshots: &[SnapshotImage],
) -> Result<(), StorageError> {
    let snapshot_count_u64 =
        u64::try_from(snapshots.len()).map_err(|_| StorageError::CatalogInvariantViolation {
            path: catalog_path.to_path_buf(),
            message: format!(
                "snapshot count ({}) does not fit into u64 for header validation",
                snapshots.len()
            ),
        })?;
    if snapshots_written < snapshot_count_u64 {
        return Err(StorageError::CatalogInvariantViolation {
            path: catalog_path.to_path_buf(),
            message: format!(
                "snapshots_written ({snapshots_written}) must be >= snapshot count ({})",
                snapshots.len()
            ),
        });
    }

    let max_snapshot_fragment_id = snapshots
        .iter()
        .map(|snapshot| snapshot.fragment_id)
        .max()
        .unwrap_or(0);
    if last_snapshot_fragment_id != max_snapshot_fragment_id {
        return Err(StorageError::CatalogInvariantViolation {
            path: catalog_path.to_path_buf(),
            message: format!(
                "last_snapshot_fragment_id ({last_snapshot_fragment_id}) must equal latest snapshot fragment id ({max_snapshot_fragment_id})"
            ),
        });
    }

    Ok(())
}

impl SnapshotCatalog {
    pub fn new() -> Self {
        Self {
            last_snapshot_fragment_id: 0,
            snapshots_written: 0,
            snapshots: BTreeMap::new(),
            full_snapshots: BTreeMap::new(),
            incremental_snapshots: BTreeMap::new(),
            config: None,
        }
    }

    pub fn with_config(mut self, config: SnapshotConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn set_config(&mut self, config: SnapshotConfig) {
        self.config = Some(config);
    }

    pub fn maybe_write_snapshot(
        &mut self,
        record: &CommittedFragmentRecord,
        hot_state_store: &HotStateStore,
        snapshot_interval: u64,
    ) -> Result<bool, StorageError> {
        if snapshot_interval == 0 {
            return Ok(false);
        }
        if !record.fragment_id.is_multiple_of(snapshot_interval) {
            return Ok(false);
        }

        self.write_snapshot(record.fragment_id, hot_state_store)?;
        Ok(true)
    }

    pub fn write_snapshot(
        &mut self,
        fragment_id: u64,
        hot_state_store: &HotStateStore,
    ) -> Result<SnapshotImage, StorageError> {
        if fragment_id < self.last_snapshot_fragment_id {
            return Err(StorageError::SnapshotRegression {
                last_snapshot_fragment_id: self.last_snapshot_fragment_id,
                new_snapshot_fragment_id: fragment_id,
            });
        }

        let snapshot = SnapshotImage::new(
            fragment_id,
            hot_state_store.committed_fragments,
            hot_state_store.committed_transactions,
        );

        self.snapshots.insert(fragment_id, snapshot.clone());
        self.last_snapshot_fragment_id = fragment_id;
        self.snapshots_written = self.snapshots_written.saturating_add(1);
        Ok(snapshot)
    }

    pub fn restore_latest_snapshot(&self) -> Option<SnapshotImage> {
        self.snapshots.values().next_back().cloned()
    }

    pub fn restore_snapshot(&self, fragment_id: u64) -> Result<SnapshotImage, StorageError> {
        self.snapshots
            .get(&fragment_id)
            .cloned()
            .ok_or(StorageError::SnapshotNotFound { fragment_id })
    }

    pub fn enforce_retention(&mut self, max_snapshots: usize) {
        let max_snapshots = max_snapshots.max(1);
        while self.snapshots.len() > max_snapshots {
            let Some(oldest_fragment_id) = self.snapshots.keys().next().copied() else {
                break;
            };
            self.snapshots.remove(&oldest_fragment_id);
        }
        self.last_snapshot_fragment_id = self.snapshots.keys().next_back().copied().unwrap_or(0);
    }

    pub fn rewind_to_fragment(&mut self, target_fragment_id: u64) -> usize {
        let split_key = match target_fragment_id.checked_add(1) {
            Some(next) => next,
            None => return 0,
        };
        let newer_snapshots = self.snapshots.split_off(&split_key);
        let removed = newer_snapshots.len();
        self.last_snapshot_fragment_id = self.snapshots.keys().next_back().copied().unwrap_or(0);
        removed
    }

    pub fn persist_to_file(&self, catalog_path: &Path) -> Result<(), StorageError> {
        let disk_model = SnapshotCatalogDisk {
            schema_version: SNAPSHOT_CATALOG_SCHEMA_VERSION,
            last_snapshot_fragment_id: self.last_snapshot_fragment_id,
            snapshots_written: self.snapshots_written,
            snapshots: self.snapshots.values().cloned().collect(),
        };

        let serialized = serde_json::to_string_pretty(&disk_model).map_err(|error| {
            StorageError::CatalogFileWrite {
                path: catalog_path.to_path_buf(),
                message: error.to_string(),
            }
        })?;

        fs::write(catalog_path, serialized).map_err(|error| StorageError::CatalogFileWrite {
            path: catalog_path.to_path_buf(),
            message: error.to_string(),
        })?;

        Ok(())
    }

    pub fn load_from_file(catalog_path: &Path) -> Result<Self, StorageError> {
        let content = fs::read_to_string(catalog_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::CatalogFileMissing {
                    path: catalog_path.to_path_buf(),
                }
            } else {
                StorageError::CatalogFileRead {
                    path: catalog_path.to_path_buf(),
                    message: error.to_string(),
                }
            }
        })?;
        Self::parse_catalog_content(catalog_path, &content)
    }

    pub fn load_from_file_if_exists(catalog_path: &Path) -> Result<Option<Self>, StorageError> {
        let content = match fs::read_to_string(catalog_path) {
            Ok(content) => content,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(StorageError::CatalogFileRead {
                    path: catalog_path.to_path_buf(),
                    message: error.to_string(),
                });
            }
        };
        Self::parse_catalog_content(catalog_path, &content).map(Some)
    }

    fn parse_catalog_content(catalog_path: &Path, content: &str) -> Result<Self, StorageError> {
        let json_value: serde_json::Value =
            serde_json::from_str(content).map_err(|error| StorageError::CatalogDeserialize {
                path: catalog_path.to_path_buf(),
                message: error.to_string(),
            })?;

        let disk_model =
            match json_value
                .get("schema_version")
                .and_then(|raw| raw.as_u64())
            {
                Some(version) if version == u64::from(SNAPSHOT_CATALOG_SCHEMA_VERSION) => {
                    serde_json::from_value::<SnapshotCatalogDisk>(json_value).map_err(|error| {
                        StorageError::CatalogDeserialize {
                            path: catalog_path.to_path_buf(),
                            message: error.to_string(),
                        }
                    })?
                }
                Some(1) => {
                    let legacy = serde_json::from_value::<SnapshotCatalogDiskV1>(json_value)
                        .map_err(|error| StorageError::CatalogDeserialize {
                            path: catalog_path.to_path_buf(),
                            message: error.to_string(),
                        })?;
                    eprintln!(
                        "[storage] migrating snapshot catalog schema_version 1 -> {}",
                        SNAPSHOT_CATALOG_SCHEMA_VERSION
                    );
                    SnapshotCatalogDisk {
                        schema_version: SNAPSHOT_CATALOG_SCHEMA_VERSION,
                        last_snapshot_fragment_id: legacy.last_snapshot_fragment_id,
                        snapshots_written: legacy.snapshots_written,
                        snapshots: legacy
                            .snapshots
                            .into_iter()
                            .map(|snapshot| {
                                SnapshotImage::new(
                                    snapshot.fragment_id,
                                    snapshot.committed_fragments,
                                    snapshot.committed_transactions,
                                )
                            })
                            .collect(),
                    }
                }
                Some(0) | None => {
                    let legacy = serde_json::from_value::<SnapshotCatalogDiskV0>(json_value)
                        .map_err(|error| StorageError::CatalogDeserialize {
                            path: catalog_path.to_path_buf(),
                            message: error.to_string(),
                        })?;
                    eprintln!(
                        "[storage] migrating snapshot catalog schema_version 0 -> {}",
                        SNAPSHOT_CATALOG_SCHEMA_VERSION
                    );
                    SnapshotCatalogDisk {
                        schema_version: SNAPSHOT_CATALOG_SCHEMA_VERSION,
                        last_snapshot_fragment_id: legacy.last_snapshot_fragment_id,
                        snapshots_written: legacy.snapshots_written,
                        snapshots: legacy
                            .snapshots
                            .into_iter()
                            .map(|snapshot| {
                                SnapshotImage::new(
                                    snapshot.fragment_id,
                                    snapshot.committed_fragments,
                                    snapshot.committed_transactions,
                                )
                            })
                            .collect(),
                    }
                }
                Some(version) => {
                    return Err(StorageError::UnsupportedCatalogSchema {
                        found: version as u32,
                        expected: SNAPSHOT_CATALOG_SCHEMA_VERSION,
                    });
                }
            };

        validate_snapshot_sequence(catalog_path, &disk_model.snapshots)?;
        validate_catalog_header(
            catalog_path,
            disk_model.snapshots_written,
            disk_model.last_snapshot_fragment_id,
            &disk_model.snapshots,
        )?;

        let mut snapshots = BTreeMap::new();
        for snapshot in disk_model.snapshots {
            snapshots.insert(snapshot.fragment_id, snapshot);
        }

        Ok(Self {
            last_snapshot_fragment_id: disk_model.last_snapshot_fragment_id,
            snapshots_written: disk_model.snapshots_written,
            snapshots,
            full_snapshots: BTreeMap::new(),
            incremental_snapshots: BTreeMap::new(),
            config: None,
        })
    }

    pub fn create_full_snapshot(
        &mut self,
        db: &AccountDatabase,
        slot: u64,
        snapshot_dir: &Path,
    ) -> Result<SnapshotManifest, StorageError> {
        let config = self.config.clone().unwrap_or_default();
        let creator = SnapshotCreator::new(config);

        let manifest = creator.create_full_snapshot(db, slot, snapshot_dir)?;

        let snapshot_path = snapshot_dir.join(format!("full-{}.snapshot", slot));
        self.full_snapshots.insert(slot, snapshot_path);

        self.enforce_full_snapshot_retention();

        Ok(manifest)
    }

    pub fn create_incremental_snapshot(
        &mut self,
        db: &AccountDatabase,
        slot: u64,
        base_slot: u64,
        snapshot_dir: &Path,
    ) -> Result<SnapshotManifest, StorageError> {
        let base_snapshot_path = self.full_snapshots
            .get(&base_slot)
            .ok_or_else(|| StorageError::SnapshotNotFound { fragment_id: base_slot })?;

        let base_manifest_path = snapshot_dir.join(format!("full-{}.snapshot.manifest", base_slot));

        let loader = SnapshotLoader::new();
        let (base_accounts, _) = loader.load_snapshot_to_map(base_snapshot_path, &base_manifest_path)?;

        let config = self.config.clone().unwrap_or_default();
        let creator = SnapshotCreator::new(config);

        let manifest = creator.create_incremental_snapshot(
            db,
            slot,
            base_slot,
            &base_accounts,
            snapshot_dir,
        )?;

        let snapshot_path = snapshot_dir.join(format!("incremental-{}.snapshot", slot));
        self.incremental_snapshots.insert(slot, snapshot_path);

        self.enforce_incremental_snapshot_retention();

        Ok(manifest)
    }

    pub fn restore_from_full_snapshot(
        &self,
        db: &AccountDatabase,
        slot: u64,
        snapshot_dir: &Path,
    ) -> Result<(), StorageError> {
        let snapshot_path = self.full_snapshots
            .get(&slot)
            .ok_or_else(|| StorageError::SnapshotNotFound { fragment_id: slot })?;

        let manifest_path = snapshot_dir.join(format!("full-{}.snapshot.manifest", slot));

        let loader = SnapshotLoader::new();
        let (accounts, _) = loader.load_snapshot_to_map(snapshot_path, &manifest_path)?;

        db.clear_all_accounts();
        db.bulk_insert_published_accounts(accounts)?;

        Ok(())
    }

    pub fn restore_with_incrementals(
        &self,
        db: &AccountDatabase,
        base_slot: u64,
        incremental_slots: &[u64],
        snapshot_dir: &Path,
    ) -> Result<(), StorageError> {
        self.restore_from_full_snapshot(db, base_slot, snapshot_dir)?;

        let loader = SnapshotLoader::new();
        let mut accounts = db.get_all_published_accounts();

        for &inc_slot in incremental_slots {
            let snapshot_path = snapshot_dir.join(format!("incremental-{}.snapshot", inc_slot));
            let manifest_path = snapshot_dir.join(format!("incremental-{}.snapshot.manifest", inc_slot));

            loader.apply_incremental_snapshot(&mut accounts, &snapshot_path, &manifest_path)?;
        }

        db.clear_all_accounts();
        db.bulk_insert_published_accounts(accounts)?;

        Ok(())
    }

    pub fn verify_snapshot(
        &self,
        slot: u64,
        snapshot_dir: &Path,
        is_incremental: bool,
    ) -> Result<bool, StorageError> {
        let snapshot_filename = if is_incremental {
            format!("incremental-{}.snapshot", slot)
        } else {
            format!("full-{}.snapshot", slot)
        };

        let snapshot_path = snapshot_dir.join(&snapshot_filename);
        let manifest_path = snapshot_dir.join(format!("{}.manifest", snapshot_filename));

        let loader = SnapshotLoader::new();
        let manifest_json = std::fs::read_to_string(&manifest_path)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read manifest: {}", e),
            })?;

        let manifest: SnapshotManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize manifest: {}", e),
            })?;

        let snapshot_data = std::fs::read(&snapshot_path)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read snapshot: {}", e),
            })?;

        Ok(manifest.verify_chunk(0, &snapshot_data))
    }

    pub fn should_create_full_snapshot(&self, slot: u64) -> bool {
        if let Some(ref config) = self.config {
            if config.full_snapshot_interval == 0 {
                return false;
            }
            slot % config.full_snapshot_interval == 0
        } else {
            false
        }
    }

    pub fn should_create_incremental_snapshot(&self, slot: u64) -> bool {
        if let Some(ref config) = self.config {
            if config.incremental_snapshot_interval == 0 {
                return false;
            }
            slot % config.incremental_snapshot_interval == 0
                && !self.should_create_full_snapshot(slot)
        } else {
            false
        }
    }

    fn enforce_full_snapshot_retention(&mut self) {
        let max_snapshots = self.config
            .as_ref()
            .map(|c| c.max_full_snapshots)
            .unwrap_or(3);

        while self.full_snapshots.len() > max_snapshots {
            if let Some(oldest_slot) = self.full_snapshots.keys().next().copied() {
                self.full_snapshots.remove(&oldest_slot);
            }
        }
    }

    fn enforce_incremental_snapshot_retention(&mut self) {
        let max_snapshots = self.config
            .as_ref()
            .map(|c| c.max_incremental_snapshots)
            .unwrap_or(10);

        while self.incremental_snapshots.len() > max_snapshots {
            if let Some(oldest_slot) = self.incremental_snapshots.keys().next().copied() {
                self.incremental_snapshots.remove(&oldest_slot);
            }
        }
    }

    pub fn get_latest_full_snapshot_slot(&self) -> Option<u64> {
        self.full_snapshots.keys().next_back().copied()
    }

    pub fn get_incremental_snapshots_after(&self, base_slot: u64) -> Vec<u64> {
        self.incremental_snapshots
            .keys()
            .filter(|&&slot| slot > base_slot)
            .copied()
            .collect()
    }

    pub fn list_full_snapshots(&self) -> Vec<u64> {
        self.full_snapshots.keys().copied().collect()
    }

    pub fn list_incremental_snapshots(&self) -> Vec<u64> {
        self.incremental_snapshots.keys().copied().collect()
    }

    pub fn register_full_snapshot(&mut self, slot: u64, path: PathBuf) {
        self.full_snapshots.insert(slot, path);
    }

    pub fn register_incremental_snapshot(&mut self, slot: u64, path: PathBuf) {
        self.incremental_snapshots.insert(slot, path);
    }
}

impl Default for SnapshotCatalog {
    fn default() -> Self {
        Self::new()
    }
}
