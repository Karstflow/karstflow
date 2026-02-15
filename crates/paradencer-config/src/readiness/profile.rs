use super::types::MainnetReadinessProfileToml;
use crate::{ConfigError, MainnetReadinessPolicy, Result};

pub(super) fn apply_profile(
    policy: &mut MainnetReadinessPolicy,
    profile: &MainnetReadinessProfileToml,
) -> Result<()> {
    if let Some(value) = profile.min_runtime_workers {
        policy.min_runtime_workers = ensure_nonzero_usize("readiness.min_runtime_workers", value)?;
    }
    if let Some(value) = profile.min_live_entrypoints {
        policy.min_live_entrypoints =
            ensure_nonzero_usize("readiness.min_live_entrypoints", value)?;
    }
    if let Some(value) = profile.min_transaction_sanitizer_stages {
        policy.min_transaction_sanitizer_stages =
            ensure_nonzero_usize("readiness.min_transaction_sanitizer_stages", value)?;
    }
    if let Some(value) = profile.min_shred_sanitizer_stages {
        policy.min_shred_sanitizer_stages =
            ensure_nonzero_usize("readiness.min_shred_sanitizer_stages", value)?;
    }
    if let Some(value) = profile.min_packet_stream_capacity {
        policy.min_packet_stream_capacity =
            ensure_nonzero_usize("readiness.min_packet_stream_capacity", value)?;
    }
    if let Some(value) = profile.min_shred_stream_capacity {
        policy.min_shred_stream_capacity =
            ensure_nonzero_usize("readiness.min_shred_stream_capacity", value)?;
    }
    if let Some(value) = profile.min_transaction_stream_capacity {
        policy.min_transaction_stream_capacity =
            ensure_nonzero_usize("readiness.min_transaction_stream_capacity", value)?;
    }
    if let Some(value) = profile.min_replay_candidate_confirmation_threshold {
        policy.min_replay_candidate_confirmation_threshold = ensure_nonzero_u32(
            "readiness.min_replay_candidate_confirmation_threshold",
            value,
        )?;
    }
    if let Some(value) = profile.min_replay_failed_ratio_penalty_weight {
        policy.min_replay_failed_ratio_penalty_weight =
            ensure_nonzero_u64("readiness.min_replay_failed_ratio_penalty_weight", value)?;
    }
    if let Some(value) = profile.require_pinned_runtime_mode {
        policy.require_pinned_runtime_mode = value;
    }
    if let Some(value) = profile.require_udp_ingress_mode {
        policy.require_udp_ingress_mode = value;
    }
    if let Some(value) = profile.require_non_stdout_metrics_target {
        policy.require_non_stdout_metrics_target = value;
    }
    if let Some(value) = profile.require_metrics_http_bind {
        policy.require_metrics_http_bind = value;
    }
    if let Some(value) = profile.require_fork_choice_runtime_enabled {
        policy.require_fork_choice_runtime_enabled = value;
    }
    if let Some(value) = profile.require_fail_fast_execution_errors {
        policy.require_fail_fast_execution_errors = value;
    }
    if let Some(value) = profile.require_fail_open_execution_error_circuit_breaker {
        policy.require_fail_open_execution_error_circuit_breaker = value;
    }
    Ok(())
}

fn ensure_nonzero_usize(name: &str, value: usize) -> Result<usize> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(value)
}

fn ensure_nonzero_u32(name: &str, value: u32) -> Result<u32> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(value)
}

fn ensure_nonzero_u64(name: &str, value: u64) -> Result<u64> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(value)
}
