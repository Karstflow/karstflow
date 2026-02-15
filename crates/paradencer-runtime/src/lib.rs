mod affinity;
mod errors;
mod executors;
mod probes;
mod service;
mod validation;

pub use affinity::{build_pinned_affinity_plan, PinnedAffinityPlan, PinnedAssignmentSource};
pub use errors::{RuntimeError, RuntimeResult};
pub use executors::run_services;
pub use probes::{
    probe_service_lifecycle, ServiceProbeFailure, ServiceProbeOptions, ServiceProbeReport,
};
pub use service::{Service, ServiceContext, ShutdownSwitch};
