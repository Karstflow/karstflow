use super::common::ensure_nonzero_u32;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_stages::{ExecutionHealthPolicy, ReplaySafetyPolicy};

pub(crate) fn apply_execution_health_policy_toml(
    execution_health_policy: &mut ExecutionHealthPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.execution_health_enabled {
        execution_health_policy.enabled = value;
    }
    if let Some(value) = storage_profile.execution_health_transient_failure_threshold {
        ensure_nonzero_u32(
            "storage.execution_health_transient_failure_threshold",
            value,
        )?;
        execution_health_policy.transient_failure_threshold = value;
    }
    if let Some(value) = storage_profile.execution_health_cooldown_ticks {
        ensure_nonzero_u32("storage.execution_health_cooldown_ticks", value)?;
        execution_health_policy.cooldown_ticks = value;
    }
    Ok(())
}

pub(crate) fn apply_execution_health_policy_env(
    execution_health_policy: &mut ExecutionHealthPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.execution_health_enabled {
        execution_health_policy.enabled = value;
    }
    if let Some(value) = env_overrides.execution_health_transient_failure_threshold {
        ensure_nonzero_u32(
            "KARSTFLOW_STORAGE_EXECUTION_HEALTH_TRANSIENT_FAILURE_THRESHOLD",
            value,
        )?;
        execution_health_policy.transient_failure_threshold = value;
    }
    if let Some(value) = env_overrides.execution_health_cooldown_ticks {
        ensure_nonzero_u32("KARSTFLOW_STORAGE_EXECUTION_HEALTH_COOLDOWN_TICKS", value)?;
        execution_health_policy.cooldown_ticks = value;
    }
    Ok(())
}

pub(crate) fn apply_replay_safety_policy_toml(
    replay_safety_policy: &mut ReplaySafetyPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.replay_safety_enabled {
        replay_safety_policy.enabled = value;
    }
    if let Some(value) = storage_profile.replay_safety_conflict_threshold {
        ensure_nonzero_u32("storage.replay_safety_conflict_threshold", value)?;
        replay_safety_policy.replay_conflict_threshold = value;
    }
    if let Some(value) = storage_profile.replay_safety_hold_ticks {
        ensure_nonzero_u32("storage.replay_safety_hold_ticks", value)?;
        replay_safety_policy.hold_ticks = value;
    }
    Ok(())
}

pub(crate) fn apply_replay_safety_policy_env(
    replay_safety_policy: &mut ReplaySafetyPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.replay_safety_enabled {
        replay_safety_policy.enabled = value;
    }
    if let Some(value) = env_overrides.replay_safety_conflict_threshold {
        ensure_nonzero_u32("KARSTFLOW_STORAGE_REPLAY_SAFETY_CONFLICT_THRESHOLD", value)?;
        replay_safety_policy.replay_conflict_threshold = value;
    }
    if let Some(value) = env_overrides.replay_safety_hold_ticks {
        ensure_nonzero_u32("KARSTFLOW_STORAGE_REPLAY_SAFETY_HOLD_TICKS", value)?;
        replay_safety_policy.hold_ticks = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_toml_noop_when_all_none() {
        let mut policy = ExecutionHealthPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_execution_health_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn health_toml_applies_values() {
        let mut policy = ExecutionHealthPolicy::default();
        let profile = StorageProfileToml {
            execution_health_enabled: Some(true),
            execution_health_transient_failure_threshold: Some(8),
            execution_health_cooldown_ticks: Some(32),
            ..Default::default()
        };
        apply_execution_health_policy_toml(&mut policy, &profile).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.transient_failure_threshold, 8);
        assert_eq!(policy.cooldown_ticks, 32);
    }

    #[test]
    fn health_toml_rejects_zero_threshold() {
        let mut policy = ExecutionHealthPolicy::default();
        let profile = StorageProfileToml {
            execution_health_transient_failure_threshold: Some(0),
            ..Default::default()
        };
        assert!(apply_execution_health_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn health_env_applies_values() {
        let mut policy = ExecutionHealthPolicy::default();
        let env = StorageEnvOverrides {
            execution_health_enabled: Some(true),
            execution_health_transient_failure_threshold: Some(6),
            execution_health_cooldown_ticks: Some(24),
            ..Default::default()
        };
        apply_execution_health_policy_env(&mut policy, &env).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.transient_failure_threshold, 6);
        assert_eq!(policy.cooldown_ticks, 24);
    }

    #[test]
    fn replay_safety_toml_applies_values() {
        let mut policy = ReplaySafetyPolicy::default();
        let profile = StorageProfileToml {
            replay_safety_enabled: Some(true),
            replay_safety_conflict_threshold: Some(5),
            replay_safety_hold_ticks: Some(20),
            ..Default::default()
        };
        apply_replay_safety_policy_toml(&mut policy, &profile).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.replay_conflict_threshold, 5);
        assert_eq!(policy.hold_ticks, 20);
    }

    #[test]
    fn replay_safety_toml_rejects_zero_conflict_threshold() {
        let mut policy = ReplaySafetyPolicy::default();
        let profile = StorageProfileToml {
            replay_safety_conflict_threshold: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_safety_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn replay_safety_env_applies_values() {
        let mut policy = ReplaySafetyPolicy::default();
        let env = StorageEnvOverrides {
            replay_safety_enabled: Some(true),
            replay_safety_conflict_threshold: Some(4),
            replay_safety_hold_ticks: Some(18),
            ..Default::default()
        };
        apply_replay_safety_policy_env(&mut policy, &env).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.replay_conflict_threshold, 4);
        assert_eq!(policy.hold_ticks, 18);
    }

    #[test]
    fn replay_safety_env_rejects_zero_hold_ticks() {
        let mut policy = ReplaySafetyPolicy::default();
        let env = StorageEnvOverrides {
            replay_safety_hold_ticks: Some(0),
            ..Default::default()
        };
        assert!(apply_replay_safety_policy_env(&mut policy, &env).is_err());
    }
}
