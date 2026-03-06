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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = StorageStartupStrictRestorePolicy::default();
        let profile = StorageProfileToml::default();
        apply_startup_strict_restore_policy_toml(&mut policy, &profile);
        assert!(!policy.restore_latest_requires_snapshot);
        assert!(!policy.restore_specific_requires_snapshot);
    }

    #[test]
    fn toml_applies_values() {
        let mut policy = StorageStartupStrictRestorePolicy::default();
        let profile = StorageProfileToml {
            startup_strict_restore_latest_requires_snapshot: Some(true),
            startup_strict_restore_specific_requires_snapshot: Some(true),
            ..Default::default()
        };
        apply_startup_strict_restore_policy_toml(&mut policy, &profile);
        assert!(policy.restore_latest_requires_snapshot);
        assert!(policy.restore_specific_requires_snapshot);
    }

    #[test]
    fn env_applies_values() {
        let mut policy = StorageStartupStrictRestorePolicy::default();
        let env = StorageEnvOverrides {
            startup_strict_restore_latest_requires_snapshot: Some(true),
            startup_strict_restore_specific_requires_snapshot: Some(false),
            ..Default::default()
        };
        apply_startup_strict_restore_policy_env(&mut policy, &env);
        assert!(policy.restore_latest_requires_snapshot);
        assert!(!policy.restore_specific_requires_snapshot);
    }

    #[test]
    fn toml_partial_applies_only_set_fields() {
        let mut policy = StorageStartupStrictRestorePolicy::default();
        let profile = StorageProfileToml {
            startup_strict_restore_latest_requires_snapshot: Some(true),
            ..Default::default()
        };
        apply_startup_strict_restore_policy_toml(&mut policy, &profile);
        assert!(policy.restore_latest_requires_snapshot);
        assert!(!policy.restore_specific_requires_snapshot);
    }
}
