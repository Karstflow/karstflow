use crate::{CommittedFragmentRecord, HotStateStore, SnapshotImage, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const SNAPSHOT_CATALOG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCatalog {
    pub last_snapshot_fragment_id: u64,
    pub snapshots_written: u64,
    snapshots: BTreeMap<u64, SnapshotImage>,
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
        }
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
        })
    }
}

impl Default for SnapshotCatalog {
    fn default() -> Self {
        Self::new()
    }
}
