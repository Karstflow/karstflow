use super::types::{StorageEnvOverrides, StorageProfileToml};
use karstflow_stages::StorageStartupStrictRestorePolicy;

pub(crate) fn apply_startup_strict_restore_policy_toml(
    startup_strict_restore_policy: &mut StorageStartupStrictRestorePolicy,
    storage_profile: &StorageProfileToml,
) {
    if let Some(value) = storage_profile.startup_strict_restore_latest_requires_snapshot {
        startup_strict_restore_policy.restore_latest_requires_snapshot = value;
    }
    if let Some(value) = storage_profile.startup_strict_restore_specific_requires_snapshot {
        startup_strict_restore_policy.restore_specific_requires_snapshot = value;
    }
}

pub(crate) fn apply_startup_strict_restore_policy_env(
    startup_strict_restore_policy: &mut StorageStartupStrictRestorePolicy,
    env_overrides: &StorageEnvOverrides,
) {
    if let Some(value) = env_overrides.startup_strict_restore_latest_requires_snapshot {
        startup_strict_restore_policy.restore_latest_requires_snapshot = value;
    }
    if let Some(value) = env_overrides.startup_strict_restore_specific_requires_snapshot {
        startup_strict_restore_policy.restore_specific_requires_snapshot = value;
    }
}
