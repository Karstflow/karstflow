use super::common::ensure_nonzero_u32;
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use paradencer_stages::{ExecutionHealthPolicy, ReplaySafetyPolicy};

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
            "PARADENCER_STORAGE_EXECUTION_HEALTH_TRANSIENT_FAILURE_THRESHOLD",
            value,
        )?;
        execution_health_policy.transient_failure_threshold = value;
    }
    if let Some(value) = env_overrides.execution_health_cooldown_ticks {
        ensure_nonzero_u32("PARADENCER_STORAGE_EXECUTION_HEALTH_COOLDOWN_TICKS", value)?;
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
        ensure_nonzero_u32("PARADENCER_STORAGE_REPLAY_SAFETY_CONFLICT_THRESHOLD", value)?;
        replay_safety_policy.replay_conflict_threshold = value;
    }
    if let Some(value) = env_overrides.replay_safety_hold_ticks {
        ensure_nonzero_u32("PARADENCER_STORAGE_REPLAY_SAFETY_HOLD_TICKS", value)?;
        replay_safety_policy.hold_ticks = value;
    }
    Ok(())
}
