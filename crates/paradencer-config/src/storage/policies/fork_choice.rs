use super::common::{ensure_nonzero_u32, ensure_nonzero_u64};
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::{ConfigError, Result};
use paradencer_stages::{ForkChoiceQuarantinePolicy, ForkChoiceRuntimePolicy};

pub(crate) fn apply_fork_choice_runtime_policy_toml(
    fork_choice_runtime_policy: &mut ForkChoiceRuntimePolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.fork_choice_enabled {
        fork_choice_runtime_policy.enabled = value;
    }
    if let Some(value) = storage_profile.fork_choice_reorg_retry_delay_millis {
        ensure_nonzero_u64("storage.fork_choice_reorg_retry_delay_millis", value)?;
        fork_choice_runtime_policy.reorg_retry_delay_millis = value;
    }
    if let Some(value) = storage_profile.fork_choice_max_reorg_retry_attempts {
        if value == 0 {
            return Err(ConfigError::NonPositiveValue {
                name: "storage.fork_choice_max_reorg_retry_attempts".to_string(),
            });
        }
        fork_choice_runtime_policy.max_reorg_retry_attempts = value;
    }
    if let Some(value) = storage_profile.fork_choice_hold_requires_confirmed_candidate {
        fork_choice_runtime_policy.hold_requires_confirmed_candidate = value;
    }
    Ok(())
}

pub(crate) fn apply_fork_choice_runtime_policy_env(
    fork_choice_runtime_policy: &mut ForkChoiceRuntimePolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.fork_choice_enabled {
        fork_choice_runtime_policy.enabled = value;
    }
    if let Some(value) = env_overrides.fork_choice_reorg_retry_delay_millis {
        ensure_nonzero_u64(
            "PARADENCER_STORAGE_FORK_CHOICE_REORG_RETRY_DELAY_MILLIS",
            value,
        )?;
        fork_choice_runtime_policy.reorg_retry_delay_millis = value;
    }
    if let Some(value) = env_overrides.fork_choice_max_reorg_retry_attempts {
        if value == 0 {
            return Err(ConfigError::NonPositiveValue {
                name: "PARADENCER_STORAGE_FORK_CHOICE_MAX_REORG_RETRY_ATTEMPTS".to_string(),
            });
        }
        fork_choice_runtime_policy.max_reorg_retry_attempts = value;
    }
    if let Some(value) = env_overrides.fork_choice_hold_requires_confirmed_candidate {
        fork_choice_runtime_policy.hold_requires_confirmed_candidate = value;
    }
    Ok(())
}

pub(crate) fn apply_fork_choice_quarantine_policy_toml(
    fork_choice_quarantine_policy: &mut ForkChoiceQuarantinePolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.fork_choice_quarantine_enabled {
        fork_choice_quarantine_policy.enabled = value;
    }
    if let Some(value) = storage_profile.fork_choice_quarantine_consecutive_reorg_threshold {
        ensure_nonzero_u32(
            "storage.fork_choice_quarantine_consecutive_reorg_threshold",
            value,
        )?;
        fork_choice_quarantine_policy.consecutive_reorg_threshold = value;
    }
    if let Some(value) = storage_profile.fork_choice_quarantine_ticks {
        ensure_nonzero_u32("storage.fork_choice_quarantine_ticks", value)?;
        fork_choice_quarantine_policy.quarantine_ticks = value;
    }
    Ok(())
}

pub(crate) fn apply_fork_choice_quarantine_policy_env(
    fork_choice_quarantine_policy: &mut ForkChoiceQuarantinePolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.fork_choice_quarantine_enabled {
        fork_choice_quarantine_policy.enabled = value;
    }
    if let Some(value) = env_overrides.fork_choice_quarantine_consecutive_reorg_threshold {
        ensure_nonzero_u32(
            "PARADENCER_STORAGE_FORK_CHOICE_QUARANTINE_CONSECUTIVE_REORG_THRESHOLD",
            value,
        )?;
        fork_choice_quarantine_policy.consecutive_reorg_threshold = value;
    }
    if let Some(value) = env_overrides.fork_choice_quarantine_ticks {
        ensure_nonzero_u32("PARADENCER_STORAGE_FORK_CHOICE_QUARANTINE_TICKS", value)?;
        fork_choice_quarantine_policy.quarantine_ticks = value;
    }
    Ok(())
}
