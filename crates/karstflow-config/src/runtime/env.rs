use super::parsers::{
    map_legacy_core_sharing_flag, parse_execution_mode, parse_pinned_core_policy,
};
use crate::{ConfigError, Result};
use karstflow_core::RuntimeSpec;

pub(super) fn apply_env_overrides(runtime_spec: &mut RuntimeSpec) -> Result<()> {
    if let Ok(mode_value) = std::env::var("KARSTFLOW_EXEC_MODE") {
        runtime_spec.mode = parse_execution_mode(Some(mode_value))?;
    }
    if let Some(workers) = parse_optional_usize_env("KARSTFLOW_WORKERS")? {
        runtime_spec.workers = workers;
    }
    if let Some(run_for_seconds) = parse_optional_u64_env("KARSTFLOW_RUN_SECONDS")? {
        runtime_spec.run_for_seconds = Some(run_for_seconds);
    }
    if let Some(allow_core_sharing) =
        parse_optional_bool_env("KARSTFLOW_PINNED_ALLOW_CORE_SHARING")?
    {
        runtime_spec.pinned_allow_core_sharing = allow_core_sharing;
        runtime_spec.pinned_core_policy = map_legacy_core_sharing_flag(allow_core_sharing);
    }
    if let Ok(policy_value) = std::env::var("KARSTFLOW_PINNED_CORE_POLICY") {
        runtime_spec.pinned_core_policy = parse_pinned_core_policy(Some(policy_value))?;
    }
    if let Ok(raw_core_ids) = std::env::var("KARSTFLOW_PINNED_SERVICE_CORES") {
        runtime_spec.pinned_service_core_ids = Some(parse_pinned_service_cores_env(
            &raw_core_ids,
            "KARSTFLOW_PINNED_SERVICE_CORES",
        )?);
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

fn parse_pinned_service_cores_env(raw: &str, name: &'static str) -> Result<Vec<usize>> {
    let parsed = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<usize>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "usize",
                    source,
                })
        })
        .collect::<Result<Vec<_>>>()?;

    if parsed.is_empty() {
        return Err(ConfigError::InvalidScope {
            scope: name,
            message: "must contain at least one core id".to_string(),
        });
    }
    Ok(parsed)
}
