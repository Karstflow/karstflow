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
