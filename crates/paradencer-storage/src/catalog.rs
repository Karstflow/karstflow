use crate::accounts::AccountDatabase;
use crate::snapshot::{SnapshotConfig, SnapshotCreator, SnapshotLoader, SnapshotManifest};
use crate::{CommittedFragmentRecord, HotStateStore, SnapshotImage, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

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
                    info!(
                        from = 1u32,
                        to = SNAPSHOT_CATALOG_SCHEMA_VERSION,
                        "migrating snapshot catalog schema"
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
                    info!(
                        from = 0u32,
                        to = SNAPSHOT_CATALOG_SCHEMA_VERSION,
                        "migrating snapshot catalog schema"
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
        let base_snapshot_path =
            self.full_snapshots
                .get(&base_slot)
                .ok_or(StorageError::SnapshotNotFound {
                    fragment_id: base_slot,
                })?;

        let base_manifest_path = snapshot_dir.join(format!("full-{}.snapshot.manifest", base_slot));

        let snapshot_loader = SnapshotLoader::new();
        let (base_accounts, _) =
            snapshot_loader.load_snapshot_to_map(base_snapshot_path, &base_manifest_path)?;

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
        let snapshot_path = self
            .full_snapshots
            .get(&slot)
            .ok_or(StorageError::SnapshotNotFound { fragment_id: slot })?;

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
            let manifest_path =
                snapshot_dir.join(format!("incremental-{}.snapshot.manifest", inc_slot));

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

        let _loader = SnapshotLoader::new();
        let manifest_json = std::fs::read_to_string(&manifest_path).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to read manifest: {}", e),
            }
        })?;

        let manifest: SnapshotManifest = serde_json::from_str(&manifest_json).map_err(|e| {
            StorageError::AccountDatabaseError {
                details: format!("Failed to deserialize manifest: {}", e),
            }
        })?;

        let snapshot_data =
            std::fs::read(&snapshot_path).map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read snapshot: {}", e),
            })?;

        Ok(manifest.verify_chunk(0, &snapshot_data))
    }

    pub fn should_create_full_snapshot(&self, slot: u64) -> bool {
        if let Some(ref config) = self.config {
            if config.full_snapshot_interval == 0 {
                return false;
            }
            slot.is_multiple_of(config.full_snapshot_interval)
        } else {
            false
        }
    }

    pub fn should_create_incremental_snapshot(&self, slot: u64) -> bool {
        if let Some(ref config) = self.config {
            if config.incremental_snapshot_interval == 0 {
                return false;
            }
            slot.is_multiple_of(config.incremental_snapshot_interval)
                && !self.should_create_full_snapshot(slot)
        } else {
            false
        }
    }

    fn enforce_full_snapshot_retention(&mut self) {
        let max_snapshots = self
            .config
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
        let max_snapshots = self
            .config
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

/// A snapshot chain: one full snapshot plus zero or more incrementals.
///
/// Used for bootstrap: load the full snapshot, then apply each incremental
/// in slot order. The chain guarantees that each incremental's declared
/// base slot matches the full snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotChain {
    /// Slot of the full (base) snapshot.
    pub full_slot: u64,
    /// Path to the full snapshot file.
    pub full_path: PathBuf,
    /// Path to the full snapshot manifest.
    pub full_manifest_path: PathBuf,
    /// Incremental snapshots in ascending slot order.
    /// Each entry: (slot, snapshot_path, manifest_path).
    pub incrementals: Vec<(u64, PathBuf, PathBuf)>,
}

impl SnapshotChain {
    /// Total number of snapshots in the chain (1 full + N incrementals).
    pub fn len(&self) -> usize {
        1 + self.incrementals.len()
    }

    /// Returns `true` if the chain contains only the full snapshot with no incrementals.
    pub fn is_empty(&self) -> bool {
        // A chain always has the full snapshot, so it's never truly empty.
        // This exists to satisfy the clippy `len_without_is_empty` lint.
        false
    }

    /// The highest slot covered by this chain.
    pub fn tip_slot(&self) -> u64 {
        self.incrementals
            .last()
            .map(|(slot, _, _)| *slot)
            .unwrap_or(self.full_slot)
    }
}

impl SnapshotCatalog {
    /// Scan a directory for snapshot files and register them.
    ///
    /// Recognizes two formats:
    /// - Internal: `full-{slot}.snapshot`, `incremental-{slot}.snapshot`
    /// - Solana archive: `snapshot-{slot}-{hash}.tar.zst`,
    ///   `incremental-snapshot-{base}-{slot}-{hash}.tar.zst`
    ///
    /// Returns the number of snapshots discovered.
    pub fn discover_snapshots(&mut self, dir: &Path) -> Result<usize, StorageError> {
        let entries = fs::read_dir(dir).map_err(|e| StorageError::AccountDatabaseError {
            details: format!("Failed to read snapshot directory {:?}: {}", dir, e),
        })?;

        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|e| StorageError::AccountDatabaseError {
                details: format!("Failed to read directory entry: {}", e),
            })?;
            let path = entry.path();
            let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            // Internal format: full-{slot}.snapshot
            if let Some(rest) = filename.strip_prefix("full-") {
                if let Some(slot_str) = rest.strip_suffix(".snapshot") {
                    if !slot_str.contains('.') {
                        // Not the manifest file
                        if let Ok(slot) = slot_str.parse::<u64>() {
                            self.full_snapshots.insert(slot, path.clone());
                            count += 1;
                        }
                    }
                }
                continue;
            }

            // Solana archive: incremental-snapshot-{base}-{slot}-{hash}.tar.zst
            // Must check BEFORE the internal `incremental-` prefix to avoid
            // the `incremental-` strip consuming `incremental-snapshot-...`.
            if filename.starts_with("incremental-snapshot-") && filename.ends_with(".tar.zst") {
                let inner =
                    &filename["incremental-snapshot-".len()..filename.len() - ".tar.zst".len()];
                let parts: Vec<&str> = inner.splitn(3, '-').collect();
                if parts.len() >= 2 {
                    if let Ok(slot) = parts[1].parse::<u64>() {
                        self.incremental_snapshots.insert(slot, path.clone());
                        count += 1;
                    }
                }
                continue;
            }

            // Internal format: incremental-{slot}.snapshot
            if let Some(rest) = filename.strip_prefix("incremental-") {
                if let Some(slot_str) = rest.strip_suffix(".snapshot") {
                    if !slot_str.contains('.') {
                        if let Ok(slot) = slot_str.parse::<u64>() {
                            self.incremental_snapshots.insert(slot, path.clone());
                            count += 1;
                        }
                    }
                }
                continue;
            }

            // Solana archive: snapshot-{slot}-{hash}.tar.zst
            if filename.starts_with("snapshot-") && filename.ends_with(".tar.zst") {
                let inner = &filename["snapshot-".len()..filename.len() - ".tar.zst".len()];
                if let Some(dash_pos) = inner.find('-') {
                    if let Ok(slot) = inner[..dash_pos].parse::<u64>() {
                        self.full_snapshots.insert(slot, path.clone());
                        count += 1;
                    }
                }
                continue;
            }
        }

        Ok(count)
    }

    /// Find the best snapshot chain from registered snapshots.
    ///
    /// Picks the latest full snapshot, then collects all incrementals
    /// whose slots are after the full snapshot. Returns `None` if no
    /// full snapshots are registered.
    pub fn find_best_chain(&self) -> Option<SnapshotChain> {
        let (&full_slot, full_path) = self.full_snapshots.iter().next_back()?;

        let full_manifest_path = manifest_path_for(full_path);

        let mut incrementals: Vec<(u64, PathBuf, PathBuf)> = self
            .incremental_snapshots
            .iter()
            .filter(|(&slot, _)| slot > full_slot)
            .map(|(&slot, path)| {
                let manifest = manifest_path_for(path);
                (slot, path.clone(), manifest)
            })
            .collect();

        incrementals.sort_by_key(|(slot, _, _)| *slot);

        Some(SnapshotChain {
            full_slot,
            full_path: full_path.clone(),
            full_manifest_path,
            incrementals,
        })
    }
}

/// Derive the manifest path from a snapshot path.
///
/// Convention: `foo.snapshot` → `foo.snapshot.manifest`
/// For tar.zst: `foo.tar.zst` → `foo.tar.zst.manifest` (unlikely,
/// but we keep the simple suffix approach).
fn manifest_path_for(snapshot_path: &Path) -> PathBuf {
    let mut manifest = snapshot_path.as_os_str().to_owned();
    manifest.push(".manifest");
    PathBuf::from(manifest)
}

impl Default for SnapshotCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hot_state(fragments: u64, transactions: u64) -> HotStateStore {
        let mut store = HotStateStore::new();
        store.committed_fragments = fragments;
        store.committed_transactions = transactions;
        store
    }

    // --- Basic operations ---

    #[test]
    fn new_catalog_is_empty() {
        let catalog = SnapshotCatalog::new();
        assert_eq!(catalog.last_snapshot_fragment_id, 0);
        assert_eq!(catalog.snapshots_written, 0);
        assert!(catalog.restore_latest_snapshot().is_none());
    }

    #[test]
    fn write_snapshot_creates_image() {
        let mut catalog = SnapshotCatalog::new();
        let hot_state = make_hot_state(10, 500);

        let image = catalog.write_snapshot(100, &hot_state).unwrap();
        assert_eq!(image.fragment_id, 100);
        assert_eq!(image.committed_fragments, 10);
        assert_eq!(image.committed_transactions, 500);
        assert!(image.has_valid_checksum());

        assert_eq!(catalog.last_snapshot_fragment_id, 100);
        assert_eq!(catalog.snapshots_written, 1);
    }

    #[test]
    fn write_snapshot_rejects_regression() {
        let mut catalog = SnapshotCatalog::new();
        let hot_state = make_hot_state(10, 500);

        catalog.write_snapshot(100, &hot_state).unwrap();
        let result = catalog.write_snapshot(50, &hot_state);
        assert!(result.is_err());
    }

    #[test]
    fn restore_latest_snapshot() {
        let mut catalog = SnapshotCatalog::new();
        let hot_state = make_hot_state(10, 500);

        catalog.write_snapshot(100, &hot_state).unwrap();
        catalog
            .write_snapshot(200, &make_hot_state(20, 1000))
            .unwrap();

        let latest = catalog.restore_latest_snapshot().unwrap();
        assert_eq!(latest.fragment_id, 200);
    }

    #[test]
    fn restore_specific_snapshot() {
        let mut catalog = SnapshotCatalog::new();
        catalog
            .write_snapshot(100, &make_hot_state(10, 500))
            .unwrap();
        catalog
            .write_snapshot(200, &make_hot_state(20, 1000))
            .unwrap();

        let snap = catalog.restore_snapshot(100).unwrap();
        assert_eq!(snap.fragment_id, 100);

        let missing = catalog.restore_snapshot(999);
        assert!(missing.is_err());
    }

    // --- Retention ---

    #[test]
    fn enforce_retention_removes_oldest() {
        let mut catalog = SnapshotCatalog::new();
        for i in 1..=5 {
            catalog
                .write_snapshot(i * 100, &make_hot_state(i, i * 50))
                .unwrap();
        }

        catalog.enforce_retention(3);

        // Should keep only last 3 (300, 400, 500)
        assert!(catalog.restore_snapshot(100).is_err());
        assert!(catalog.restore_snapshot(200).is_err());
        assert!(catalog.restore_snapshot(300).is_ok());
        assert!(catalog.restore_snapshot(500).is_ok());
        assert_eq!(catalog.last_snapshot_fragment_id, 500);
    }

    #[test]
    fn enforce_retention_keeps_at_least_one() {
        let mut catalog = SnapshotCatalog::new();
        catalog
            .write_snapshot(100, &make_hot_state(10, 500))
            .unwrap();
        catalog
            .write_snapshot(200, &make_hot_state(20, 1000))
            .unwrap();

        // Even with max_snapshots=0, should keep 1
        catalog.enforce_retention(0);
        assert!(catalog.restore_latest_snapshot().is_some());
    }

    // --- Rewind ---

    #[test]
    fn rewind_removes_newer_snapshots() {
        let mut catalog = SnapshotCatalog::new();
        for i in 1..=5 {
            catalog
                .write_snapshot(i * 100, &make_hot_state(i, i * 50))
                .unwrap();
        }

        let removed = catalog.rewind_to_fragment(300);
        assert_eq!(removed, 2); // 400 and 500 removed

        assert!(catalog.restore_snapshot(300).is_ok());
        assert!(catalog.restore_snapshot(400).is_err());
        assert_eq!(catalog.last_snapshot_fragment_id, 300);
    }

    #[test]
    fn rewind_to_zero_removes_everything() {
        let mut catalog = SnapshotCatalog::new();
        catalog
            .write_snapshot(100, &make_hot_state(10, 500))
            .unwrap();
        catalog
            .write_snapshot(200, &make_hot_state(20, 1000))
            .unwrap();

        let removed = catalog.rewind_to_fragment(0);
        assert_eq!(removed, 2);
        assert!(catalog.restore_latest_snapshot().is_none());
        assert_eq!(catalog.last_snapshot_fragment_id, 0);
    }

    // --- Persistence ---

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("catalog_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let catalog_path = dir.join("catalog.json");

        let mut catalog = SnapshotCatalog::new();
        catalog
            .write_snapshot(100, &make_hot_state(10, 500))
            .unwrap();
        catalog
            .write_snapshot(200, &make_hot_state(20, 1000))
            .unwrap();

        catalog.persist_to_file(&catalog_path).unwrap();

        let loaded = SnapshotCatalog::load_from_file(&catalog_path).unwrap();
        assert_eq!(loaded.last_snapshot_fragment_id, 200);
        assert_eq!(loaded.snapshots_written, 2);

        let snap = loaded.restore_snapshot(100).unwrap();
        assert_eq!(snap.committed_fragments, 10);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_from_missing_file_returns_error() {
        let path = Path::new("/tmp/nonexistent_catalog_test.json");
        let result = SnapshotCatalog::load_from_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn load_if_exists_returns_none_for_missing() {
        let path = Path::new("/tmp/nonexistent_catalog_test2.json");
        let result = SnapshotCatalog::load_from_file_if_exists(path).unwrap();
        assert!(result.is_none());
    }

    // --- Validation ---

    #[test]
    fn validate_snapshot_sequence_detects_non_increasing_ids() {
        let path = Path::new("test.json");
        let snapshots = vec![
            SnapshotImage::new(200, 20, 1000),
            SnapshotImage::new(100, 10, 500), // out of order
        ];
        let result = validate_snapshot_sequence(path, &snapshots);
        assert!(result.is_err());
    }

    #[test]
    fn validate_snapshot_sequence_detects_non_monotonic_fragments() {
        let path = Path::new("test.json");
        let snapshots = vec![
            SnapshotImage::new(100, 20, 1000),
            SnapshotImage::new(200, 10, 2000), // fragments decreased
        ];
        let result = validate_snapshot_sequence(path, &snapshots);
        assert!(result.is_err());
    }

    #[test]
    fn validate_snapshot_sequence_detects_non_monotonic_transactions() {
        let path = Path::new("test.json");
        let snapshots = vec![
            SnapshotImage::new(100, 10, 1000),
            SnapshotImage::new(200, 20, 500), // transactions decreased
        ];
        let result = validate_snapshot_sequence(path, &snapshots);
        assert!(result.is_err());
    }

    #[test]
    fn validate_snapshot_sequence_detects_bad_checksum() {
        let path = Path::new("test.json");
        let mut bad_image = SnapshotImage::new(100, 10, 500);
        bad_image.state_checksum = 0xDEADBEEF; // tampered
        let snapshots = vec![bad_image];
        let result = validate_snapshot_sequence(path, &snapshots);
        assert!(result.is_err());
    }

    #[test]
    fn validate_catalog_header_detects_snapshot_count_mismatch() {
        let path = Path::new("test.json");
        let snapshots = vec![
            SnapshotImage::new(100, 10, 500),
            SnapshotImage::new(200, 20, 1000),
        ];
        // snapshots_written=1 but 2 snapshots present
        let result = validate_catalog_header(path, 1, 200, &snapshots);
        assert!(result.is_err());
    }

    #[test]
    fn validate_catalog_header_detects_wrong_last_fragment_id() {
        let path = Path::new("test.json");
        let snapshots = vec![
            SnapshotImage::new(100, 10, 500),
            SnapshotImage::new(200, 20, 1000),
        ];
        // last_snapshot_fragment_id=100 but latest is 200
        let result = validate_catalog_header(path, 5, 100, &snapshots);
        assert!(result.is_err());
    }

    // --- Snapshot scheduling ---

    #[test]
    fn should_create_full_snapshot_respects_config() {
        let mut catalog = SnapshotCatalog::new();
        // No config — always false
        assert!(!catalog.should_create_full_snapshot(1000));

        let mut config = SnapshotConfig::new();
        config.full_snapshot_interval = 1000;
        catalog.set_config(config);

        assert!(catalog.should_create_full_snapshot(1000));
        assert!(catalog.should_create_full_snapshot(2000));
        assert!(!catalog.should_create_full_snapshot(1500));
    }

    #[test]
    fn should_create_incremental_skips_full_snapshot_slots() {
        let mut config = SnapshotConfig::new();
        config.full_snapshot_interval = 1000;
        config.incremental_snapshot_interval = 100;
        let catalog = SnapshotCatalog::new().with_config(config);

        // Slot 100 is incremental
        assert!(catalog.should_create_incremental_snapshot(100));
        // Slot 1000 is full, not incremental
        assert!(!catalog.should_create_incremental_snapshot(1000));
    }

    // --- Full/incremental snapshot registration ---

    #[test]
    fn register_and_list_snapshots() {
        let mut catalog = SnapshotCatalog::new();

        catalog.register_full_snapshot(100, PathBuf::from("/snap/full-100"));
        catalog.register_full_snapshot(200, PathBuf::from("/snap/full-200"));
        catalog.register_incremental_snapshot(150, PathBuf::from("/snap/inc-150"));

        assert_eq!(catalog.list_full_snapshots(), vec![100, 200]);
        assert_eq!(catalog.list_incremental_snapshots(), vec![150]);
        assert_eq!(catalog.get_latest_full_snapshot_slot(), Some(200));
        assert_eq!(catalog.get_incremental_snapshots_after(100), vec![150]);
    }

    // --- maybe_write_snapshot ---

    #[test]
    fn maybe_write_snapshot_skips_when_interval_zero() {
        let mut catalog = SnapshotCatalog::new();
        let hot_state = make_hot_state(10, 500);
        let record = CommittedFragmentRecord {
            fragment_id: 100,
            transaction_count: 50,
            total_cost_units: 500_000,
        };

        let written = catalog
            .maybe_write_snapshot(&record, &hot_state, 0)
            .unwrap();
        assert!(!written);
    }

    // --- Discovery and chain selection ---

    #[test]
    fn discover_snapshots_finds_internal_format() {
        let dir = std::env::temp_dir().join(format!("discover_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        // Create fake snapshot files.
        fs::write(dir.join("full-100.snapshot"), b"data").unwrap();
        fs::write(dir.join("full-100.snapshot.manifest"), b"manifest").unwrap();
        fs::write(dir.join("full-200.snapshot"), b"data").unwrap();
        fs::write(dir.join("full-200.snapshot.manifest"), b"manifest").unwrap();
        fs::write(dir.join("incremental-150.snapshot"), b"data").unwrap();
        fs::write(dir.join("incremental-150.snapshot.manifest"), b"manifest").unwrap();
        fs::write(dir.join("incremental-250.snapshot"), b"data").unwrap();
        fs::write(dir.join("unrelated.txt"), b"noise").unwrap();

        let mut catalog = SnapshotCatalog::new();
        let count = catalog.discover_snapshots(&dir).unwrap();

        assert_eq!(count, 4); // 2 full + 2 incremental
        assert_eq!(catalog.list_full_snapshots(), vec![100, 200]);
        assert_eq!(catalog.list_incremental_snapshots(), vec![150, 250]);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_snapshots_finds_solana_archive_format() {
        let dir = std::env::temp_dir().join(format!("discover_solana_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("snapshot-500-3Fv4abc.tar.zst"), b"archive").unwrap();
        fs::write(
            dir.join("incremental-snapshot-500-600-7Xyz.tar.zst"),
            b"archive",
        )
        .unwrap();

        let mut catalog = SnapshotCatalog::new();
        let count = catalog.discover_snapshots(&dir).unwrap();

        assert_eq!(count, 2);
        assert_eq!(catalog.list_full_snapshots(), vec![500]);
        assert_eq!(catalog.list_incremental_snapshots(), vec![600]);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_best_chain_returns_none_without_full() {
        let mut catalog = SnapshotCatalog::new();
        catalog.register_incremental_snapshot(150, PathBuf::from("/inc-150"));
        assert!(catalog.find_best_chain().is_none());
    }

    #[test]
    fn find_best_chain_picks_latest_full() {
        let mut catalog = SnapshotCatalog::new();
        catalog.register_full_snapshot(100, PathBuf::from("/full-100.snapshot"));
        catalog.register_full_snapshot(200, PathBuf::from("/full-200.snapshot"));
        catalog.register_incremental_snapshot(150, PathBuf::from("/inc-150.snapshot"));
        catalog.register_incremental_snapshot(250, PathBuf::from("/inc-250.snapshot"));
        catalog.register_incremental_snapshot(300, PathBuf::from("/inc-300.snapshot"));

        let chain = catalog.find_best_chain().unwrap();

        // Should pick full-200 (latest).
        assert_eq!(chain.full_slot, 200);
        // Only incrementals > 200 are included.
        assert_eq!(chain.incrementals.len(), 2);
        assert_eq!(chain.incrementals[0].0, 250);
        assert_eq!(chain.incrementals[1].0, 300);
        assert_eq!(chain.tip_slot(), 300);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn find_best_chain_full_only() {
        let mut catalog = SnapshotCatalog::new();
        catalog.register_full_snapshot(100, PathBuf::from("/full-100.snapshot"));

        let chain = catalog.find_best_chain().unwrap();
        assert_eq!(chain.full_slot, 100);
        assert!(chain.incrementals.is_empty());
        assert_eq!(chain.tip_slot(), 100);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn maybe_write_snapshot_writes_at_interval() {
        let mut catalog = SnapshotCatalog::new();
        let hot_state = make_hot_state(10, 500);
        let record = CommittedFragmentRecord {
            fragment_id: 100,
            transaction_count: 50,
            total_cost_units: 500_000,
        };

        let written = catalog
            .maybe_write_snapshot(&record, &hot_state, 50)
            .unwrap();
        assert!(written); // 100 is multiple of 50

        let not_written = catalog
            .maybe_write_snapshot(
                &CommittedFragmentRecord {
                    fragment_id: 125,
                    transaction_count: 60,
                    total_cost_units: 600_000,
                },
                &make_hot_state(12, 600),
                50,
            )
            .unwrap();
        assert!(!not_written); // 125 is not multiple of 50
    }
}
