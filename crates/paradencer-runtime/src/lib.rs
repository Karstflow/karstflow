mod affinity;
mod errors;
mod executors;
mod probes;
mod service;
mod tile_adapter;
mod tile_executor;
mod validation;

pub use affinity::{build_pinned_affinity_plan, PinnedAffinityPlan, PinnedAssignmentSource};
pub use errors::{RuntimeError, RuntimeResult};
pub use executors::run_services;
pub use probes::{
    probe_service_lifecycle, ServiceProbeFailure, ServiceProbeOptions, ServiceProbeReport,
};
pub use service::{Service, ServiceContext, ShutdownSwitch};
pub use tile_adapter::TileAdapter;
pub use tile_executor::run_tiles;
