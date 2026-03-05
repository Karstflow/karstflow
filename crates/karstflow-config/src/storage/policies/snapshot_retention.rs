use super::common::ensure_nonzero_usize;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::SnapshotRetentionPolicy;

pub(crate) fn apply_snapshot_retention_policy_toml(
    snapshot_retention_policy: &mut SnapshotRetentionPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.snapshot_max_catalog_entries {
        ensure_nonzero_usize("storage.snapshot_max_catalog_entries", value)?;
        snapshot_retention_policy.max_catalog_snapshots = value;
    }
    Ok(())
}

pub(crate) fn apply_snapshot_retention_policy_env(
    snapshot_retention_policy: &mut SnapshotRetentionPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.snapshot_max_catalog_entries {
        ensure_nonzero_usize("KARSTFLOW_STORAGE_SNAPSHOT_MAX_CATALOG_ENTRIES", value)?;
        snapshot_retention_policy.max_catalog_snapshots = value;
    }
    Ok(())
}
