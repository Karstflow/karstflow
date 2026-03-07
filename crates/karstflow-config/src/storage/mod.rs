mod env;
mod policies;
mod types;

pub use types::{StorageEnvOverrides, StorageProfileToml};

use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use env::load_storage_env_overrides;
use karstflow_execution::{AccountStateApplyPolicy, ProgramCacheApplyPolicy};
use karstflow_stages::{
    ExecutionEnginePolicy, ExecutionErrorHandlingPolicy, StorageRuntimePolicy, StorageStartupPolicy,
};
use policies::{
    apply_assembly_policy_env, apply_assembly_policy_toml, apply_execution_health_policy_env,
    apply_execution_health_policy_toml, apply_execution_retry_policy_env,
    apply_execution_retry_policy_toml, apply_fork_choice_quarantine_policy_env,
    apply_fork_choice_quarantine_policy_toml, apply_fork_choice_runtime_policy_env,
    apply_fork_choice_runtime_policy_toml, apply_leader_schedule_policy_env,
    apply_leader_schedule_policy_toml, apply_replay_controller_policy_env,
    apply_replay_controller_policy_toml, apply_replay_safety_policy_env,
    apply_replay_safety_policy_toml, apply_replay_window_policy_env,
    apply_replay_window_policy_toml, apply_scheduler_runtime_policy_env,
    apply_scheduler_runtime_policy_toml, apply_snapshot_retention_policy_env,
    apply_snapshot_retention_policy_toml, apply_startup_strict_restore_policy_env,
    apply_startup_strict_restore_policy_toml,
};
use std::path::PathBuf;

pub fn build_storage_runtime_policy(
    profile: Option<&NodeProfileToml>,
) -> Result<StorageRuntimePolicy> {
    let mut storage_runtime_policy = build_storage_runtime_policy_without_env(profile)?;
    let env_overrides = load_storage_env_overrides()?;
    apply_storage_env_overrides(&mut storage_runtime_policy, &env_overrides)?;
    Ok(storage_runtime_policy)
}

#[cfg(test)]
pub fn build_storage_runtime_policy_with_overrides(
    profile: Option<&NodeProfileToml>,
    env_overrides: &StorageEnvOverrides,
) -> Result<StorageRuntimePolicy> {
    let mut storage_runtime_policy = build_storage_runtime_policy_without_env(profile)?;
    apply_storage_env_overrides(&mut storage_runtime_policy, env_overrides)?;
    Ok(storage_runtime_policy)
}

pub fn parse_storage_startup_policy(
    raw: &str,
    restore_fragment_id: Option<u64>,
) -> Result<StorageStartupPolicy> {
    match raw.to_ascii_lowercase().as_str() {
        "skip" | "skip_restore" => Ok(StorageStartupPolicy::SkipRestore),
        "restore_latest" | "restore_latest_if_available" => {
            Ok(StorageStartupPolicy::RestoreLatestIfAvailable)
        }
        "restore_specific" | "restore_specific_if_available" => {
            let fragment_id = restore_fragment_id
                .ok_or(ConfigError::StorageStartupPolicyRequiresRestoreFragmentId)?;
            Ok(StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id })
        }
        _ => Err(ConfigError::InvalidScope {
            scope: "storage startup policy",
            message: format!("'{raw}'"),
        }),
    }
}

fn build_storage_runtime_policy_without_env(
    profile: Option<&NodeProfileToml>,
) -> Result<StorageRuntimePolicy> {
    let mut storage_runtime_policy = StorageRuntimePolicy::default();

    if let Some(storage_profile) = profile.and_then(|profile| profile.storage.as_ref()) {
        if let Some(snapshot_interval) = storage_profile.snapshot_interval {
            if snapshot_interval == 0 {
                return Err(ConfigError::NonPositiveValue {
                    name: "storage.snapshot_interval".to_string(),
                });
            }
            storage_runtime_policy.snapshot_interval = snapshot_interval;
        }
        apply_snapshot_retention_policy_toml(
            &mut storage_runtime_policy.snapshot_retention_policy,
            storage_profile,
        )?;
        if let Some(startup_policy_value) = storage_profile.startup_policy.as_deref() {
            storage_runtime_policy.startup_policy = parse_storage_startup_policy(
                startup_policy_value,
                storage_profile.restore_fragment_id,
            )?;
        }
        apply_startup_strict_restore_policy_toml(
            &mut storage_runtime_policy.startup_strict_restore_policy,
            storage_profile,
        );
        if let Some(catalog_path) = storage_profile.catalog_path.as_deref() {
            storage_runtime_policy.snapshot_catalog_path = Some(PathBuf::from(catalog_path));
        }

        apply_assembly_policy_toml(&mut storage_runtime_policy.assembly_policy, storage_profile)?;

        if let Some(max_retry_attempts) = storage_profile.max_retry_attempts {
            if max_retry_attempts == 0 {
                return Err(ConfigError::NonPositiveValue {
                    name: "storage.max_retry_attempts".to_string(),
                });
            }
            storage_runtime_policy.max_retry_attempts = max_retry_attempts;
        }
        if let Some(backoff_cap_millis) = storage_profile.retry_backoff_cap_millis {
            if backoff_cap_millis == 0 {
                return Err(ConfigError::NonPositiveValue {
                    name: "storage.retry_backoff_cap_millis".to_string(),
                });
            }
            storage_runtime_policy.retry_backoff_cap_millis = backoff_cap_millis;
        }
        if let Some(policy) = storage_profile.execution_engine_policy.as_deref() {
            storage_runtime_policy.execution_engine_policy =
                parse_execution_engine_policy(policy, "storage.execution_engine_policy")?;
        }
        if let Some(policy) = storage_profile.execution_error_handling_policy.as_deref() {
            storage_runtime_policy.execution_error_handling_policy =
                parse_execution_error_handling_policy(
                    policy,
                    "storage.execution_error_handling_policy",
                )?;
        }
        if let Some(max_consecutive) = storage_profile.execution_error_fail_open_max_consecutive {
            storage_runtime_policy.execution_error_fail_open_max_consecutive = max_consecutive;
        }
        if let Some(policy) = storage_profile
            .runtime_like_account_state_apply_policy
            .as_deref()
        {
            storage_runtime_policy.runtime_like_account_state_apply_policy =
                parse_account_state_apply_policy(
                    policy,
                    "storage.runtime_like_account_state_apply_policy",
                )?;
        }
        if let Some(policy) = storage_profile
            .runtime_like_program_cache_apply_policy
            .as_deref()
        {
            storage_runtime_policy.runtime_like_program_cache_apply_policy =
                parse_program_cache_apply_policy(
                    policy,
                    "storage.runtime_like_program_cache_apply_policy",
                )?;
        }

        apply_execution_retry_policy_toml(
            &mut storage_runtime_policy.execution_retry_policy,
            storage_profile,
        )?;
        apply_leader_schedule_policy_toml(
            &mut storage_runtime_policy.leader_schedule_policy,
            storage_profile,
        )?;
        apply_scheduler_runtime_policy_toml(
            &mut storage_runtime_policy.scheduler_runtime_policy,
            storage_profile,
        )?;
        apply_fork_choice_runtime_policy_toml(
            &mut storage_runtime_policy.fork_choice_runtime_policy,
            storage_profile,
        )?;
        apply_fork_choice_quarantine_policy_toml(
            &mut storage_runtime_policy.fork_choice_quarantine_policy,
            storage_profile,
        )?;
        apply_execution_health_policy_toml(
            &mut storage_runtime_policy.execution_health_policy,
            storage_profile,
        )?;
        apply_replay_safety_policy_toml(
            &mut storage_runtime_policy.replay_safety_policy,
            storage_profile,
        )?;
        apply_replay_controller_policy_toml(
            &mut storage_runtime_policy.replay_controller_policy,
            storage_profile,
        )?;
        apply_replay_window_policy_toml(
            &mut storage_runtime_policy.replay_window_policy,
            storage_profile,
        )?;
    }

    validate_startup_strict_restore_requirements(&storage_runtime_policy)?;

    Ok(storage_runtime_policy)
}

fn apply_storage_env_overrides(
    storage_runtime_policy: &mut StorageRuntimePolicy,
    env_overrides: &StorageEnvOverrides,
) -> Result<()> {
    if let Some(snapshot_interval) = env_overrides.snapshot_interval {
        if snapshot_interval == 0 {
            return Err(ConfigError::NonPositiveValue {
                name: "KARSTFLOW_STORAGE_SNAPSHOT_INTERVAL".to_string(),
            });
        }
        storage_runtime_policy.snapshot_interval = snapshot_interval;
    }
    apply_snapshot_retention_policy_env(
        &mut storage_runtime_policy.snapshot_retention_policy,
        env_overrides,
    )?;

    if let Some(startup_policy_value) = env_overrides.startup_policy.as_deref() {
        storage_runtime_policy.startup_policy =
            parse_storage_startup_policy(startup_policy_value, env_overrides.restore_fragment_id)?;
    }
    apply_startup_strict_restore_policy_env(
        &mut storage_runtime_policy.startup_strict_restore_policy,
        env_overrides,
    );

    if let Some(catalog_path) = env_overrides.catalog_path.as_deref() {
        storage_runtime_policy.snapshot_catalog_path = Some(PathBuf::from(catalog_path));
    }

    apply_assembly_policy_env(&mut storage_runtime_policy.assembly_policy, env_overrides)?;

    if let Some(max_retry_attempts) = env_overrides.max_retry_attempts {
        if max_retry_attempts == 0 {
            return Err(ConfigError::NonPositiveValue {
                name: "KARSTFLOW_STORAGE_MAX_RETRY_ATTEMPTS".to_string(),
            });
        }
        storage_runtime_policy.max_retry_attempts = max_retry_attempts;
    }

    if let Some(backoff_cap_millis) = env_overrides.retry_backoff_cap_millis {
        if backoff_cap_millis == 0 {
            return Err(ConfigError::NonPositiveValue {
                name: "KARSTFLOW_STORAGE_RETRY_BACKOFF_CAP_MILLIS".to_string(),
            });
        }
        storage_runtime_policy.retry_backoff_cap_millis = backoff_cap_millis;
    }
    if let Some(policy) = env_overrides.execution_engine_policy.as_deref() {
        storage_runtime_policy.execution_engine_policy =
            parse_execution_engine_policy(policy, "KARSTFLOW_STORAGE_EXECUTION_ENGINE_POLICY")?;
    }
    if let Some(policy) = env_overrides.execution_error_handling_policy.as_deref() {
        storage_runtime_policy.execution_error_handling_policy =
            parse_execution_error_handling_policy(
                policy,
                "KARSTFLOW_STORAGE_EXECUTION_ERROR_HANDLING_POLICY",
            )?;
    }
    if let Some(max_consecutive) = env_overrides.execution_error_fail_open_max_consecutive {
        storage_runtime_policy.execution_error_fail_open_max_consecutive = max_consecutive;
    }
    if let Some(policy) = env_overrides
        .runtime_like_account_state_apply_policy
        .as_deref()
    {
        storage_runtime_policy.runtime_like_account_state_apply_policy =
            parse_account_state_apply_policy(
                policy,
                "KARSTFLOW_STORAGE_RUNTIME_LIKE_ACCOUNT_STATE_APPLY_POLICY",
            )?;
    }
    if let Some(policy) = env_overrides
        .runtime_like_program_cache_apply_policy
        .as_deref()
    {
        storage_runtime_policy.runtime_like_program_cache_apply_policy =
            parse_program_cache_apply_policy(
                policy,
                "KARSTFLOW_STORAGE_RUNTIME_LIKE_PROGRAM_CACHE_APPLY_POLICY",
            )?;
    }

    apply_execution_retry_policy_env(
        &mut storage_runtime_policy.execution_retry_policy,
        env_overrides,
    )?;
    apply_leader_schedule_policy_env(
        &mut storage_runtime_policy.leader_schedule_policy,
        env_overrides,
    )?;
    apply_scheduler_runtime_policy_env(
        &mut storage_runtime_policy.scheduler_runtime_policy,
        env_overrides,
    )?;
    apply_fork_choice_runtime_policy_env(
        &mut storage_runtime_policy.fork_choice_runtime_policy,
        env_overrides,
    )?;
    apply_fork_choice_quarantine_policy_env(
        &mut storage_runtime_policy.fork_choice_quarantine_policy,
        env_overrides,
    )?;
    apply_execution_health_policy_env(
        &mut storage_runtime_policy.execution_health_policy,
        env_overrides,
    )?;
    apply_replay_safety_policy_env(
        &mut storage_runtime_policy.replay_safety_policy,
        env_overrides,
    )?;
    apply_replay_controller_policy_env(
        &mut storage_runtime_policy.replay_controller_policy,
        env_overrides,
    )?;
    apply_replay_window_policy_env(
        &mut storage_runtime_policy.replay_window_policy,
        env_overrides,
    )?;

    validate_startup_strict_restore_requirements(storage_runtime_policy)?;

    Ok(())
}

fn parse_execution_engine_policy(
    raw: &str,
    scope_name: &'static str,
) -> Result<ExecutionEnginePolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "account_backed" | "account-backed" | "account" => Ok(ExecutionEnginePolicy::AccountBacked),
        "heuristic" => Ok(ExecutionEnginePolicy::Heuristic),
        "runtime_like" | "runtime-like" | "runtime" => Ok(ExecutionEnginePolicy::RuntimeLike),
        _ => Err(ConfigError::InvalidScope {
            scope: scope_name,
            message: format!("'{raw}'"),
        }),
    }
}

fn parse_execution_error_handling_policy(
    raw: &str,
    scope_name: &'static str,
) -> Result<ExecutionErrorHandlingPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fail_open" | "fail-open" | "open" => Ok(ExecutionErrorHandlingPolicy::FailOpen),
        "fail_fast" | "fail-fast" | "fast" => Ok(ExecutionErrorHandlingPolicy::FailFast),
        _ => Err(ConfigError::InvalidScope {
            scope: scope_name,
            message: format!("'{raw}'"),
        }),
    }
}

fn parse_account_state_apply_policy(
    raw: &str,
    scope_name: &'static str,
) -> Result<AccountStateApplyPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "strict" => Ok(AccountStateApplyPolicy::Strict),
        "lenient" => Ok(AccountStateApplyPolicy::Lenient),
        _ => Err(ConfigError::InvalidScope {
            scope: scope_name,
            message: format!("'{raw}'"),
        }),
    }
}

fn parse_program_cache_apply_policy(
    raw: &str,
    scope_name: &'static str,
) -> Result<ProgramCacheApplyPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "strict" => Ok(ProgramCacheApplyPolicy::Strict),
        "lenient" => Ok(ProgramCacheApplyPolicy::Lenient),
        _ => Err(ConfigError::InvalidScope {
            scope: scope_name,
            message: format!("'{raw}'"),
        }),
    }
}

fn validate_startup_strict_restore_requirements(
    storage_runtime_policy: &StorageRuntimePolicy,
) -> Result<()> {
    if storage_runtime_policy.snapshot_catalog_path.is_some() {
        return Ok(());
    }

    match storage_runtime_policy.startup_policy {
        StorageStartupPolicy::RestoreLatestIfAvailable
            if storage_runtime_policy
                .startup_strict_restore_policy
                .restore_latest_requires_snapshot =>
        {
            Err(
                ConfigError::StorageStartupStrictRestoreRequiresCatalogPath {
                    startup_policy: "restore_latest_if_available",
                },
            )
        }
        StorageStartupPolicy::RestoreSpecificIfAvailable { .. }
            if storage_runtime_policy
                .startup_strict_restore_policy
                .restore_specific_requires_snapshot =>
        {
            Err(
                ConfigError::StorageStartupStrictRestoreRequiresCatalogPath {
                    startup_policy: "restore_specific_if_available",
                },
            )
        }
        _ => Ok(()),
    }
}
