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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = SnapshotRetentionPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_snapshot_retention_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn toml_applies_value() {
        let mut policy = SnapshotRetentionPolicy::default();
        let profile = StorageProfileToml {
            snapshot_max_catalog_entries: Some(8_192),
            ..Default::default()
        };
        apply_snapshot_retention_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.max_catalog_snapshots, 8_192);
    }

    #[test]
    fn toml_rejects_zero() {
        let mut policy = SnapshotRetentionPolicy::default();
        let profile = StorageProfileToml {
            snapshot_max_catalog_entries: Some(0),
            ..Default::default()
        };
        assert!(apply_snapshot_retention_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn env_applies_value() {
        let mut policy = SnapshotRetentionPolicy::default();
        let env = StorageEnvOverrides {
            snapshot_max_catalog_entries: Some(16_384),
            ..Default::default()
        };
        apply_snapshot_retention_policy_env(&mut policy, &env).unwrap();
        assert_eq!(policy.max_catalog_snapshots, 16_384);
    }

    #[test]
    fn env_rejects_zero() {
        let mut policy = SnapshotRetentionPolicy::default();
        let env = StorageEnvOverrides {
            snapshot_max_catalog_entries: Some(0),
            ..Default::default()
        };
        assert!(apply_snapshot_retention_policy_env(&mut policy, &env).is_err());
    }
}
