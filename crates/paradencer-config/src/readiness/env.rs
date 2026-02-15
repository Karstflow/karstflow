use crate::{ConfigError, MainnetReadinessPolicy, Result};

pub(super) fn apply_env_overrides(policy: &mut MainnetReadinessPolicy) -> Result<()> {
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_RUNTIME_WORKERS")? {
        policy.min_runtime_workers = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_LIVE_ENTRYPOINTS")? {
        policy.min_live_entrypoints = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_TX_SANITIZERS")? {
        policy.min_transaction_sanitizer_stages = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_SHRED_SANITIZERS")? {
        policy.min_shred_sanitizer_stages = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_PACKET_CAPACITY")? {
        policy.min_packet_stream_capacity = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_SHRED_CAPACITY")? {
        policy.min_shred_stream_capacity = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_READINESS_MIN_TRANSACTION_CAPACITY")?
    {
        policy.min_transaction_stream_capacity = value;
    }
    if let Some(value) =
        parse_optional_u32_env("PARADENCER_READINESS_MIN_REPLAY_CANDIDATE_CONFIRMATION_THRESHOLD")?
    {
        policy.min_replay_candidate_confirmation_threshold = value;
    }
    if let Some(value) =
        parse_optional_u64_env("PARADENCER_READINESS_MIN_REPLAY_FAILED_RATIO_PENALTY_WEIGHT")?
    {
        policy.min_replay_failed_ratio_penalty_weight = value;
    }
    if let Some(value) =
        parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_PINNED_RUNTIME_MODE")?
    {
        policy.require_pinned_runtime_mode = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_UDP_INGRESS_MODE")? {
        policy.require_udp_ingress_mode = value;
    }
    if let Some(value) =
        parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_NON_STDOUT_METRICS_TARGET")?
    {
        policy.require_non_stdout_metrics_target = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_METRICS_HTTP_BIND")?
    {
        policy.require_metrics_http_bind = value;
    }
    if let Some(value) =
        parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_FORK_CHOICE_RUNTIME_ENABLED")?
    {
        policy.require_fork_choice_runtime_enabled = value;
    }
    if let Some(value) =
        parse_optional_bool_env("PARADENCER_READINESS_REQUIRE_FAIL_FAST_EXECUTION_ERRORS")?
    {
        policy.require_fail_fast_execution_errors = value;
    }
    if let Some(value) = parse_optional_bool_env(
        "PARADENCER_READINESS_REQUIRE_FAIL_OPEN_EXECUTION_ERROR_CIRCUIT_BREAKER",
    )? {
        policy.require_fail_open_execution_error_circuit_breaker = value;
    }
    Ok(())
}

fn parse_optional_usize_env(name: &str) -> Result<Option<usize>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<usize>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "usize",
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

fn parse_optional_u32_env(name: &str) -> Result<Option<u32>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<u32>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "u32",
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

fn parse_optional_u64_env(name: &str) -> Result<Option<u64>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<u64>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "u64",
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
