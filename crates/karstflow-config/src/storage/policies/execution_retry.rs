use super::common::{ensure_nonzero_u64, ensure_nonzero_u8};
use super::types::{StorageEnvOverrides, StorageProfileToml};
use crate::Result;
use karstflow_execution::RetryPolicy;

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
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_REPLAY_CONFLICT_DELAY_MILLIS", value)?;
        retry_policy.replay_conflict_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_base_delay_millis {
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_TRANSIENT_BASE_DELAY_MILLIS", value)?;
        retry_policy.transient_base_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "KARSTFLOW_EXEC_RETRY_TRANSIENT_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.transient_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_transient_cap_millis {
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_TRANSIENT_CAP_MILLIS", value)?;
        retry_policy.transient_cap_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_base_delay_millis {
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_RESOURCE_BASE_DELAY_MILLIS", value)?;
        retry_policy.resource_base_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "KARSTFLOW_EXEC_RETRY_RESOURCE_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.resource_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_resource_cap_millis {
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_RESOURCE_CAP_MILLIS", value)?;
        retry_policy.resource_cap_millis = value;
    }
    if let Some(value) = env_overrides.execution_fallback_min_delay_millis {
        ensure_nonzero_u64("KARSTFLOW_EXEC_RETRY_FALLBACK_MIN_DELAY_MILLIS", value)?;
        retry_policy.fallback_min_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_fallback_per_failed_tx_delay_millis {
        ensure_nonzero_u64(
            "KARSTFLOW_EXEC_RETRY_FALLBACK_PER_FAILED_TX_DELAY_MILLIS",
            value,
        )?;
        retry_policy.fallback_per_failed_tx_delay_millis = value;
    }
    if let Some(value) = env_overrides.execution_max_replay_conflict_attempts {
        ensure_nonzero_u8("KARSTFLOW_EXEC_RETRY_MAX_REPLAY_CONFLICT_ATTEMPTS", value)?;
        retry_policy.max_retries_replay_conflict = value;
    }
    if let Some(value) = env_overrides.execution_max_transient_attempts {
        ensure_nonzero_u8("KARSTFLOW_EXEC_RETRY_MAX_TRANSIENT_ATTEMPTS", value)?;
        retry_policy.max_retries_transient_pressure = value;
    }
    if let Some(value) = env_overrides.execution_max_resource_attempts {
        ensure_nonzero_u8("KARSTFLOW_EXEC_RETRY_MAX_RESOURCE_ATTEMPTS", value)?;
        retry_policy.max_retries_resource_exhaustion = value;
    }
    if let Some(value) = env_overrides.execution_max_fallback_attempts {
        ensure_nonzero_u8("KARSTFLOW_EXEC_RETRY_MAX_FALLBACK_ATTEMPTS", value)?;
        retry_policy.max_retries_fallback = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_noop_when_all_none() {
        let mut policy = RetryPolicy::default();
        let original = policy;
        let profile = StorageProfileToml::default();
        apply_execution_retry_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy, original);
    }

    #[test]
    fn toml_applies_delay_values() {
        let mut policy = RetryPolicy::default();
        let profile = StorageProfileToml {
            execution_replay_conflict_delay_millis: Some(50),
            execution_transient_base_delay_millis: Some(60),
            execution_transient_per_failed_tx_delay_millis: Some(10),
            execution_transient_cap_millis: Some(500),
            execution_resource_base_delay_millis: Some(400),
            execution_resource_per_failed_tx_delay_millis: Some(40),
            execution_resource_cap_millis: Some(4_000),
            execution_fallback_min_delay_millis: Some(100),
            execution_fallback_per_failed_tx_delay_millis: Some(20),
            ..Default::default()
        };
        apply_execution_retry_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.replay_conflict_delay_millis, 50);
        assert_eq!(policy.transient_base_delay_millis, 60);
        assert_eq!(policy.transient_per_failed_tx_delay_millis, 10);
        assert_eq!(policy.transient_cap_millis, 500);
        assert_eq!(policy.resource_base_delay_millis, 400);
        assert_eq!(policy.resource_per_failed_tx_delay_millis, 40);
        assert_eq!(policy.resource_cap_millis, 4_000);
        assert_eq!(policy.fallback_min_delay_millis, 100);
        assert_eq!(policy.fallback_per_failed_tx_delay_millis, 20);
    }

    #[test]
    fn toml_applies_max_attempts() {
        let mut policy = RetryPolicy::default();
        let profile = StorageProfileToml {
            execution_max_replay_conflict_attempts: Some(6),
            execution_max_transient_attempts: Some(4),
            execution_max_resource_attempts: Some(2),
            execution_max_fallback_attempts: Some(5),
            ..Default::default()
        };
        apply_execution_retry_policy_toml(&mut policy, &profile).unwrap();
        assert_eq!(policy.max_retries_replay_conflict, 6);
        assert_eq!(policy.max_retries_transient_pressure, 4);
        assert_eq!(policy.max_retries_resource_exhaustion, 2);
        assert_eq!(policy.max_retries_fallback, 5);
    }

    #[test]
    fn toml_rejects_zero_replay_conflict_delay() {
        let mut policy = RetryPolicy::default();
        let profile = StorageProfileToml {
            execution_replay_conflict_delay_millis: Some(0),
            ..Default::default()
        };
        assert!(apply_execution_retry_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn toml_rejects_zero_max_attempts() {
        let mut policy = RetryPolicy::default();
        let profile = StorageProfileToml {
            execution_max_replay_conflict_attempts: Some(0),
            ..Default::default()
        };
        assert!(apply_execution_retry_policy_toml(&mut policy, &profile).is_err());
    }

    #[test]
    fn env_applies_values() {
        let mut policy = RetryPolicy::default();
        let env = StorageEnvOverrides {
            execution_replay_conflict_delay_millis: Some(75),
            execution_transient_base_delay_millis: Some(90),
            execution_max_fallback_attempts: Some(7),
            ..Default::default()
        };
        apply_execution_retry_policy_env(&mut policy, &env).unwrap();
        assert_eq!(policy.replay_conflict_delay_millis, 75);
        assert_eq!(policy.transient_base_delay_millis, 90);
        assert_eq!(policy.max_retries_fallback, 7);
    }

    #[test]
    fn env_rejects_zero_resource_cap() {
        let mut policy = RetryPolicy::default();
        let env = StorageEnvOverrides {
            execution_resource_cap_millis: Some(0),
            ..Default::default()
        };
        assert!(apply_execution_retry_policy_env(&mut policy, &env).is_err());
    }
}
