use super::common::{ensure_nonzero_u64, ensure_nonzero_u8};
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use paradencer_execution::RetryPolicy;

pub(crate) fn apply_execution_retry_policy_toml(
    retry_policy: &mut RetryPolicy,
    storage_profile: &StorageProfileToml,
) -> Result<()> {
    if let Some(value) = storage_profile.execution_replay_conflict_delay_millis {
        ensure_nonzero_u64("storage.execution_replay_conflict_delay_millis", value)?;
        retry_policy.replay_conflict_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_transient_base_delay_millis {
        ensure_nonzero_u64("storage.execution_transient_base_delay_millis", value)?;
        retry_policy.transient_base_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_transient_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "storage.execution_transient_per_failed_tx_delay_millis",
            value,
        )?;
        retry_policy.transient_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_transient_cap_millis {
        ensure_nonzero_u64("storage.execution_transient_cap_millis", value)?;
        retry_policy.transient_cap_millis = value;
    }
    if let Some(value) = storage_profile.execution_resource_base_delay_millis {
        ensure_nonzero_u64("storage.execution_resource_base_delay_millis", value)?;
        retry_policy.resource_base_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_resource_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "storage.execution_resource_per_failed_tx_delay_millis",
            value,
        )?;
        retry_policy.resource_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_resource_cap_millis {
        ensure_nonzero_u64("storage.execution_resource_cap_millis", value)?;
        retry_policy.resource_cap_millis = value;
    }
    if let Some(value) = storage_profile.execution_fallback_min_delay_millis {
        ensure_nonzero_u64("storage.execution_fallback_min_delay_millis", value)?;
        retry_policy.fallback_min_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_fallback_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "storage.execution_fallback_per_failed_tx_delay_millis",
            value,
        )?;
        retry_policy.fallback_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = storage_profile.execution_max_replay_conflict_attempts {
        ensure_nonzero_u8("storage.execution_max_replay_conflict_attempts", value)?;
        retry_policy.max_retries_replay_conflict = value;
    }
    if let Some(value) = storage_profile.execution_max_transient_attempts {
        ensure_nonzero_u8("storage.execution_max_transient_attempts", value)?;
        retry_policy.max_retries_transient_pressure = value;
    }
    if let Some(value) = storage_profile.execution_max_resource_attempts {
        ensure_nonzero_u8("storage.execution_max_resource_attempts", value)?;
        retry_policy.max_retries_resource_exhaustion = value;
    }
    if let Some(value) = storage_profile.execution_max_fallback_attempts {
        ensure_nonzero_u8("storage.execution_max_fallback_attempts", value)?;
        retry_policy.max_retries_fallback = value;
    }
    Ok(())
}

pub(crate) fn apply_execution_retry_policy_env(
    retry_policy: &mut RetryPolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(value) = env_overrides.execution_replay_conflict_delay_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_REPLAY_CONFLICT_DELAY_MILLIS", value)?;
        retry_policy.replay_conflict_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_base_delay_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_TRANSIENT_BASE_DELAY_MILLIS", value)?;
        retry_policy.transient_base_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "PARADENCER_EXEC_RETRY_TRANSIENT_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.transient_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_cap_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_TRANSIENT_CAP_MILLIS", value)?;
        retry_policy.transient_cap_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_base_delay_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_RESOURCE_BASE_DELAY_MILLIS", value)?;
        retry_policy.resource_base_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "PARADENCER_EXEC_RETRY_RESOURCE_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.resource_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_cap_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_RESOURCE_CAP_MILLIS", value)?;
        retry_policy.resource_cap_millis = value;
    }
    if let Some(value) = env_overrides.execution_fallback_min_delay_millis {
        ensure_nonzero_u64("PARADENCER_EXEC_RETRY_FALLBACK_MIN_DELAY_MILLIS", value)?;
        retry_policy.fallback_min_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_fallback_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "PARADENCER_EXEC_RETRY_FALLBACK_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.fallback_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_max_replay_conflict_attempts {
        ensure_nonzero_u8("PARADENCER_EXEC_RETRY_MAX_REPLAY_CONFLICT_ATTEMPTS", value)?;
        retry_policy.max_retries_replay_conflict = value;
    }
    if let Some(value) = env_overrides.execution_max_transient_attempts {
        ensure_nonzero_u8("PARADENCER_EXEC_RETRY_MAX_TRANSIENT_ATTEMPTS", value)?;
        retry_policy.max_retries_transient_pressure = value;
    }
    if let Some(value) = env_overrides.execution_max_resource_attempts {
        ensure_nonzero_u8("PARADENCER_EXEC_RETRY_MAX_RESOURCE_ATTEMPTS", value)?;
        retry_policy.max_retries_resource_exhaustion = value;
    }
    if let Some(value) = env_overrides.execution_max_fallback_attempts {
        ensure_nonzero_u8("PARADENCER_EXEC_RETRY_MAX_FALLBACK_ATTEMPTS", value)?;
        retry_policy.max_retries_fallback = value;
    }
    Ok(())
}
