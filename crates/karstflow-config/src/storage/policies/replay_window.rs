use super::common::ensure_nonzero_usize;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::ReplayWindowPolicy;

pub(crate) fn apply_replay_window_policy_toml(
    replay_window_policy: &mut ReplayWindowPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.replay_window_max_checkpoints {
        ensure_nonzero_usize("storage.replay_window_max_checkpoints", value)?;
        replay_window_policy.max_checkpoints = value;
    }
    if let Some(value) = storage_profile.replay_window_rewind_on_confirmed_reorg {
        replay_window_policy.rewind_on_confirmed_reorg = value;
    }
    Ok(())
}

pub(crate) fn apply_replay_window_policy_env(
    replay_window_policy: &mut ReplayWindowPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.replay_window_max_checkpoints {
        ensure_nonzero_usize("KARSTFLOW_STORAGE_REPLAY_WINDOW_MAX_CHECKPOINTS", value)?;
        replay_window_policy.max_checkpoints = value;
    }
    if let Some(value) = env_overrides.replay_window_rewind_on_confirmed_reorg {
        replay_window_policy.rewind_on_confirmed_reorg = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = ReplayWindowPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_replay_window_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn toml_applies_values() {
        let mut policy = ReplayWindowPolicy::default();
        let profile = StorageProfileToml {
            replay_window_max_checkpoints: Some(512),
            replay_window_rewind_on_confirmed_reorg: Some(true),
            ..Default::default()
        };
        apply_replay_window_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.max_checkpoints, 512);
        assert!(policy.rewind_on_confirmed_reorg);
    }

    #[test]
    fn toml_rejects_zero_max_checkpoints() {
        let mut policy = ReplayWindowPolicy::default();
        let profile = StorageProfileToml {
            replay_window_max_checkpoints: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_window_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn env_applies_values() {
        let mut policy = ReplayWindowPolicy::default();
        let env = StorageEnvOverrides {
            replay_window_max_checkpoints: Some(1024),
            replay_window_rewind_on_confirmed_reorg: Some(true),
            ..Default::default()
        };
        apply_replay_window_policy_env(&mut policy, &env).unwrap();
        assert_eq!(policy.max_checkpoints, 1024);
        assert!(policy.rewind_on_confirmed_reorg);
    }

    #[test]
    fn env_rejects_zero_max_checkpoints() {
        let mut policy = ReplayWindowPolicy::default();
        let env = StorageEnvOverrides {
            replay_window_max_checkpoints: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_window_policy_env(&mut policy, &env).is_err());
    }
}
