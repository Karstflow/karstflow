use super::types::StorageEnvOverrides;
use crate::{ConfigError, Result};

pub(super) fn load_storage_env_overrides() -> Result<StorageEnvOverrides> {
    Ok(StorageEnvOverrides {
        startup_policy: std::env::var("KARSTFLOW_STORAGE_STARTUP_POLICY").ok(),
        restore_fragment_id: parse_optional_u64_env("KARSTFLOW_STORAGE_RESTORE_FRAGMENT_ID")?,
        startup_strict_restore_latest_requires_snapshot: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_STARTUP_STRICT_RESTORE_LATEST_REQUIRES_SNAPSHOT",
        )?,
        startup_strict_restore_specific_requires_snapshot: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_STARTUP_STRICT_RESTORE_SPECIFIC_REQUIRES_SNAPSHOT",
        )?,
        snapshot_interval: parse_optional_u64_env("KARSTFLOW_STORAGE_SNAPSHOT_INTERVAL")?,
        snapshot_max_catalog_entries: parse_optional_usize_env(
            "KARSTFLOW_STORAGE_SNAPSHOT_MAX_CATALOG_ENTRIES",
        )?,
        catalog_path: std::env::var("KARSTFLOW_STORAGE_CATALOG_PATH").ok(),
        assembly_max_fragment_transactions: parse_optional_usize_env(
            "KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_TRANSACTIONS",
        )?,
        assembly_max_fragment_cost_units: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_COST_UNITS",
        )?,
        assembly_max_fragment_wait_ticks: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_ASSEMBLY_MAX_FRAGMENT_WAIT_TICKS",
        )?,
        max_retry_attempts: parse_optional_u8_env("KARSTFLOW_STORAGE_MAX_RETRY_ATTEMPTS")?,
        retry_backoff_cap_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_RETRY_BACKOFF_CAP_MILLIS",
        )?,
        execution_engine_policy: std::env::var("KARSTFLOW_STORAGE_EXECUTION_ENGINE_POLICY").ok(),
        execution_error_handling_policy: std::env::var(
            "KARSTFLOW_STORAGE_EXECUTION_ERROR_HANDLING_POLICY",
        )
        .ok(),
        execution_error_fail_open_max_consecutive: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_EXECUTION_ERROR_FAIL_OPEN_MAX_CONSECUTIVE",
        )?,
        runtime_like_account_state_apply_policy: std::env::var(
            "KARSTFLOW_STORAGE_RUNTIME_LIKE_ACCOUNT_STATE_APPLY_POLICY",
        )
        .ok(),
        runtime_like_program_cache_apply_policy: std::env::var(
            "KARSTFLOW_STORAGE_RUNTIME_LIKE_PROGRAM_CACHE_APPLY_POLICY",
        )
        .ok(),
        execution_replay_conflict_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_REPLAY_CONFLICT_DELAY_MILLIS",
        )?,
        execution_transient_base_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_TRANSIENT_BASE_DELAY_MILLIS",
        )?,
        execution_transient_per_failed_tx_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_TRANSIENT_PER_FAILED_TX_DELAY_MILLIS",
        )?,
        execution_transient_cap_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_TRANSIENT_CAP_MILLIS",
        )?,
        execution_resource_base_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_RESOURCE_BASE_DELAY_MILLIS",
        )?,
        execution_resource_per_failed_tx_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_RESOURCE_PER_FAILED_TX_DELAY_MILLIS",
        )?,
        execution_resource_cap_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_RESOURCE_CAP_MILLIS",
        )?,
        execution_fallback_min_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_FALLBACK_MIN_DELAY_MILLIS",
        )?,
        execution_fallback_per_failed_tx_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_EXEC_RETRY_FALLBACK_PER_FAILED_TX_DELAY_MILLIS",
        )?,
        execution_max_replay_conflict_attempts: parse_optional_u8_env(
            "KARSTFLOW_EXEC_RETRY_MAX_REPLAY_CONFLICT_ATTEMPTS",
        )?,
        execution_max_transient_attempts: parse_optional_u8_env(
            "KARSTFLOW_EXEC_RETRY_MAX_TRANSIENT_ATTEMPTS",
        )?,
        execution_max_resource_attempts: parse_optional_u8_env(
            "KARSTFLOW_EXEC_RETRY_MAX_RESOURCE_ATTEMPTS",
        )?,
        execution_max_fallback_attempts: parse_optional_u8_env(
            "KARSTFLOW_EXEC_RETRY_MAX_FALLBACK_ATTEMPTS",
        )?,
        leader_schedule_enabled: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_LEADER_SCHEDULE_ENABLED",
        )?,
        leader_slot_cycle_length: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_LEADER_SLOT_CYCLE_LENGTH",
        )?,
        leader_slots_per_cycle: parse_optional_u64_env("KARSTFLOW_STORAGE_LEADER_SLOTS_PER_CYCLE")?,
        leader_initial_slot: parse_optional_u64_env("KARSTFLOW_STORAGE_LEADER_INITIAL_SLOT")?,
        leader_hold_retry_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_LEADER_HOLD_RETRY_DELAY_MILLIS",
        )?,
        scheduler_enabled: parse_optional_bool_env("KARSTFLOW_STORAGE_SCHEDULER_ENABLED")?,
        scheduler_slot_duration_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_SCHEDULER_SLOT_DURATION_MILLIS",
        )?,
        scheduler_priority_penalty_class_2_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_SCHEDULER_PRIORITY_PENALTY_CLASS_2_MILLIS",
        )?,
        scheduler_priority_penalty_class_3_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_SCHEDULER_PRIORITY_PENALTY_CLASS_3_MILLIS",
        )?,
        fork_choice_enabled: parse_optional_bool_env("KARSTFLOW_STORAGE_FORK_CHOICE_ENABLED")?,
        fork_choice_reorg_retry_delay_millis: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_REORG_RETRY_DELAY_MILLIS",
        )?,
        fork_choice_max_reorg_retry_attempts: parse_optional_u8_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_MAX_REORG_RETRY_ATTEMPTS",
        )?,
        fork_choice_hold_requires_confirmed_candidate: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_HOLD_REQUIRES_CONFIRMED_CANDIDATE",
        )?,
        fork_choice_quarantine_enabled: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_QUARANTINE_ENABLED",
        )?,
        fork_choice_quarantine_consecutive_reorg_threshold: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_QUARANTINE_CONSECUTIVE_REORG_THRESHOLD",
        )?,
        fork_choice_quarantine_ticks: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_FORK_CHOICE_QUARANTINE_TICKS",
        )?,
        execution_health_enabled: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_EXECUTION_HEALTH_ENABLED",
        )?,
        execution_health_transient_failure_threshold: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_EXECUTION_HEALTH_TRANSIENT_FAILURE_THRESHOLD",
        )?,
        execution_health_cooldown_ticks: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_EXECUTION_HEALTH_COOLDOWN_TICKS",
        )?,
        replay_safety_enabled: parse_optional_bool_env("KARSTFLOW_STORAGE_REPLAY_SAFETY_ENABLED")?,
        replay_safety_conflict_threshold: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_REPLAY_SAFETY_CONFLICT_THRESHOLD",
        )?,
        replay_safety_hold_ticks: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_REPLAY_SAFETY_HOLD_TICKS",
        )?,
        replay_controller_candidate_confirmation_threshold: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_CONFIRMATION_THRESHOLD",
        )?,
        replay_controller_candidate_confirmation_max_failed_ratio_bps: parse_optional_u32_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_CONFIRMATION_MAX_FAILED_RATIO_BPS",
        )?,
        replay_controller_max_candidates: parse_optional_usize_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_MAX_CANDIDATES",
        )?,
        replay_controller_reorg_signal_weight: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_REORG_SIGNAL_WEIGHT",
        )?,
        replay_controller_fragment_recency_weight: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_FRAGMENT_RECENCY_WEIGHT",
        )?,
        replay_controller_failed_transaction_ratio_penalty_weight: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_FAILED_TRANSACTION_RATIO_PENALTY_WEIGHT",
        )?,
        replay_controller_candidate_stale_fragment_lag: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_STALE_FRAGMENT_LAG",
        )?,
        replay_controller_candidate_switch_min_score_delta: parse_optional_u64_env(
            "KARSTFLOW_STORAGE_REPLAY_CONTROLLER_CANDIDATE_SWITCH_MIN_SCORE_DELTA",
        )?,
        replay_window_max_checkpoints: parse_optional_usize_env(
            "KARSTFLOW_STORAGE_REPLAY_WINDOW_MAX_CHECKPOINTS",
        )?,
        replay_window_rewind_on_confirmed_reorg: parse_optional_bool_env(
            "KARSTFLOW_STORAGE_REPLAY_WINDOW_REWIND_ON_CONFIRMED_REORG",
        )?,
    })
}

fn parse_optional_u64_env(name: &str) -> Result<Option<u64>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "u64",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_u8_env(name: &str) -> Result<Option<u8>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<u8>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "u8",
                    source,
                })?;
            if value == 0 {
                Err(ConfigError::NonPositiveValue {
                    name: name.to_string(),
                })
            } else {
                Ok(Some(value))
            }
        }
        None => Ok(None),
    }
}

fn parse_optional_u32_env(name: &str) -> Result<Option<u32>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<u32>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "u32",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_usize_env(name: &str) -> Result<Option<usize>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<usize>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "usize",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_bool_env(name: &str) -> Result<Option<bool>> {
    match std::env::var(name).ok() {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(Some(true)),
            "0" | "false" | "no" => Ok(Some(false)),
            _ => Err(ConfigError::InvalidBooleanValue {
                name: name.to_string(),
                value: raw,
            }),
        },
        None => Ok(None),
    }
}
