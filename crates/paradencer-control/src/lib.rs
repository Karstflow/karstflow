mod bootstrap;
mod command;
mod errors;
mod output;
mod preflight;
mod runner;
mod surface;

pub use bootstrap::{
    build_consensus_infrastructure, build_diagnostics_summary_from_probe, build_pipeline_service,
    build_repair_service, build_replay_service, build_replay_service_with_block_input,
    build_shred_pipeline, build_turbine_service, build_vote_broadcast_service,
    ensure_mainnet_readiness, evaluate_mainnet_readiness, load_node_config,
    materialize_service_pair_from_config, materialize_services_from_config,
    maybe_start_metrics_http_bridge, print_preflight_ok, run_diagnostics_phase,
    run_preflight_phase, run_preflight_phase_with_probe_report, run_runtime_phase,
    run_startup_checks, run_startup_checks_with_probe_report, start_gossip_service,
    BlockstoreShredProvider, ConsensusBundle, DiagnosticsSummary, GossipHandle,
    MainnetReadinessReport, MaterializedServicePair, PipelineBundle, RepairBundle, ReplayBundle,
    ReplayBundleWithExternalInput, ServiceBundle, ShredPipelineBundle, TurbineBundle,
    VoteBroadcastBundle,
};
pub use command::{parse_command, ControlCommand, ControlCommandWithConfig};
pub use errors::{ControlPlaneError, Result};
pub use output::{
    render_diagnostics_cluster_mode_line, render_diagnostics_lane_capacity_line,
    render_diagnostics_ok_line, render_diagnostics_probe_line,
    render_diagnostics_readiness_issue_line, render_diagnostics_readiness_line,
    render_diagnostics_services_line, render_diagnostics_stage_mix_line,
    render_diagnostics_topology_line, render_pinned_affinity_line,
    render_preflight_readiness_issue_line, render_preflight_readiness_line,
    render_readiness_policy_line,
};
pub use preflight::{
    ensure_service_startup_probe_ok, run_network_socket_preflight, run_service_startup_preflight,
    run_service_startup_probe,
};
pub use runner::dispatch_command;
pub use surface::{render_config_summary, validate_identity_keypair_from_env};
