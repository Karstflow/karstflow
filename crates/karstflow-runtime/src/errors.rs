use thiserror::Error;

pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("tokio runtime build failed: {0}")]
    TokioRuntimeBuild(#[from] std::io::Error),
    #[error("tokio task join error: {0}")]
    TokioTaskJoin(#[from] tokio::task::JoinError),
    #[error("no CPU cores detected")]
    NoCpuCoresDetected,
    #[error("pinned strict policy requires {service_count} dedicated cores but only {core_count} are available")]
    StrictPolicyInsufficientCores {
        service_count: usize,
        core_count: usize,
    },
    #[error("pinned adaptive policy rejected oversubscription ratio {oversubscription_ratio:.2} (services={service_count}, cores={core_count})")]
    AdaptivePolicyRejected {
        oversubscription_ratio: f64,
        service_count: usize,
        core_count: usize,
    },
    #[error(
        "explicit pinned core assignment length mismatch: expected {service_count} entries, found {assigned_count}"
    )]
    ExplicitPinnedAssignmentLengthMismatch {
        service_count: usize,
        assigned_count: usize,
    },
    #[error("explicit pinned core id {core_id} is not available on this host")]
    ExplicitPinnedCoreUnavailable { core_id: usize },
    #[error(
        "pinned strict policy requires unique core ids; duplicate assignment for core id {core_id}"
    )]
    StrictPolicyDuplicateCoreAssignment { core_id: usize },
    #[error("failed to spawn service thread '{service_name}': {source}")]
    ThreadSpawn {
        service_name: String,
        source: std::io::Error,
    },
    #[error("service thread panicked")]
    ServiceThreadPanic,
    #[error("service '{service_name}' failed: {reason}")]
    ServiceFailure {
        service_name: String,
        reason: String,
    },
}

impl RuntimeError {
    pub fn service_failure(service_name: &str, reason: &str) -> Self {
        Self::ServiceFailure {
            service_name: service_name.to_string(),
            reason: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_failure_constructor() {
        let err = RuntimeError::service_failure("my_service", "crashed");
        let msg = err.to_string();
        assert!(msg.contains("my_service"));
        assert!(msg.contains("crashed"));
    }

    #[test]
    fn no_cpu_cores_display() {
        let err = RuntimeError::NoCpuCoresDetected;
        assert_eq!(err.to_string(), "no CPU cores detected");
    }

    #[test]
    fn strict_policy_insufficient_cores_display() {
        let err = RuntimeError::StrictPolicyInsufficientCores {
            service_count: 8,
            core_count: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("8"));
        assert!(msg.contains("4"));
    }

    #[test]
    fn adaptive_policy_rejected_display() {
        let err = RuntimeError::AdaptivePolicyRejected {
            oversubscription_ratio: 3.50,
            service_count: 14,
            core_count: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("3.50"));
        assert!(msg.contains("14"));
        assert!(msg.contains("4"));
    }

    #[test]
    fn explicit_pinned_length_mismatch_display() {
        let err = RuntimeError::ExplicitPinnedAssignmentLengthMismatch {
            service_count: 5,
            assigned_count: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn explicit_pinned_core_unavailable_display() {
        let err = RuntimeError::ExplicitPinnedCoreUnavailable { core_id: 99 };
        assert!(err.to_string().contains("99"));
    }

    #[test]
    fn strict_policy_duplicate_core_display() {
        let err = RuntimeError::StrictPolicyDuplicateCoreAssignment { core_id: 7 };
        assert!(err.to_string().contains("7"));
    }

    #[test]
    fn service_thread_panic_display() {
        let err = RuntimeError::ServiceThreadPanic;
        assert_eq!(err.to_string(), "service thread panicked");
    }
}
