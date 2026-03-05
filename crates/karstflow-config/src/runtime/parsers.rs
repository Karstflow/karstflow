use crate::{ConfigError, Result};
use karstflow_core::{ExecutionMode, PinnedCorePolicy};

pub fn parse_execution_mode(raw: Option<String>) -> Result<ExecutionMode> {
    match raw {
        Some(value) => ExecutionMode::from_env(&value).ok_or_else(|| ConfigError::InvalidScope {
            scope: "KARSTFLOW_EXEC_MODE",
            message: format!("'{value}'"),
        }),
        None => Ok(ExecutionMode::Tokio),
    }
}

pub fn parse_pinned_core_policy(raw: Option<String>) -> Result<PinnedCorePolicy> {
    match raw {
        Some(value) => {
            PinnedCorePolicy::from_env(&value).ok_or_else(|| ConfigError::InvalidScope {
                scope: "KARSTFLOW_PINNED_CORE_POLICY",
                message: format!("'{value}'"),
            })
        }
        None => Ok(PinnedCorePolicy::Adaptive),
    }
}

pub fn map_legacy_core_sharing_flag(allow_core_sharing: bool) -> PinnedCorePolicy {
    if allow_core_sharing {
        PinnedCorePolicy::Shared
    } else {
        PinnedCorePolicy::Strict
    }
}

pub(super) fn ensure_nonzero_usize(name: &str, value: usize) -> Result<usize> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(value)
}

pub fn parse_pinned_service_core_ids(
    core_ids: &[usize],
    scope_name: &'static str,
) -> Result<Vec<usize>> {
    if core_ids.is_empty() {
        return Err(ConfigError::InvalidScope {
            scope: scope_name,
            message: "must contain at least one core id".to_string(),
        });
    }
    Ok(core_ids.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_execution_mode_tokio() {
        let result = parse_execution_mode(Some("tokio".to_string())).unwrap();
        assert_eq!(result, ExecutionMode::Tokio);
    }

    #[test]
    fn parse_execution_mode_pinned() {
        let result = parse_execution_mode(Some("pinned".to_string())).unwrap();
        assert_eq!(result, ExecutionMode::Pinned);
    }

    #[test]
    fn parse_execution_mode_case_insensitive() {
        let result = parse_execution_mode(Some("TOKIO".to_string())).unwrap();
        assert_eq!(result, ExecutionMode::Tokio);
    }

    #[test]
    fn parse_execution_mode_none_defaults_to_tokio() {
        let result = parse_execution_mode(None).unwrap();
        assert_eq!(result, ExecutionMode::Tokio);
    }

    #[test]
    fn parse_execution_mode_invalid_returns_error() {
        let result = parse_execution_mode(Some("invalid".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn parse_pinned_core_policy_strict() {
        let result = parse_pinned_core_policy(Some("strict".to_string())).unwrap();
        assert_eq!(result, PinnedCorePolicy::Strict);
    }

    #[test]
    fn parse_pinned_core_policy_shared() {
        let result = parse_pinned_core_policy(Some("shared".to_string())).unwrap();
        assert_eq!(result, PinnedCorePolicy::Shared);
    }

    #[test]
    fn parse_pinned_core_policy_adaptive() {
        let result = parse_pinned_core_policy(Some("adaptive".to_string())).unwrap();
        assert_eq!(result, PinnedCorePolicy::Adaptive);
    }

    #[test]
    fn parse_pinned_core_policy_none_defaults_to_adaptive() {
        let result = parse_pinned_core_policy(None).unwrap();
        assert_eq!(result, PinnedCorePolicy::Adaptive);
    }

    #[test]
    fn parse_pinned_core_policy_invalid_returns_error() {
        let result = parse_pinned_core_policy(Some("bogus".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn map_legacy_flag_shared() {
        assert_eq!(map_legacy_core_sharing_flag(true), PinnedCorePolicy::Shared);
    }

    #[test]
    fn map_legacy_flag_strict() {
        assert_eq!(
            map_legacy_core_sharing_flag(false),
            PinnedCorePolicy::Strict
        );
    }

    #[test]
    fn ensure_nonzero_usize_rejects_zero() {
        let result = ensure_nonzero_usize("test_field", 0);
        assert!(result.is_err());
    }

    #[test]
    fn ensure_nonzero_usize_accepts_positive() {
        let result = ensure_nonzero_usize("test_field", 42).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn parse_pinned_service_core_ids_rejects_empty() {
        let result = parse_pinned_service_core_ids(&[], "test_scope");
        assert!(result.is_err());
    }

    #[test]
    fn parse_pinned_service_core_ids_accepts_non_empty() {
        let ids = vec![0, 1, 2];
        let result = parse_pinned_service_core_ids(&ids, "test_scope").unwrap();
        assert_eq!(result, vec![0, 1, 2]);
    }
}
