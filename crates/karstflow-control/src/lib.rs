mod bootstrap;
mod command;
mod errors;
mod output;
mod preflight;
pub mod program_binaries;
mod runner;
pub mod snapshot_download;
mod surface;
pub mod system_check;
#[cfg(test)]
mod testsuite;
mod vote_sender;
pub mod wait_for_supermajority;

pub use bootstrap::{
    bootstrap_from_development_genesis, bootstrap_from_genesis_file, build_blockstore,
    build_consensus_from_bank_forks, build_consensus_infrastructure,
    build_diagnostics_summary_from_probe, build_local_transaction_submitter,
    build_pipeline_service, build_repair_service, build_replay_service,
    build_replay_service_with_block_input, build_replay_service_with_consensus,
    build_shred_pipeline, build_storage_maintenance_service, build_turbine_service,
    build_vote_broadcast_service, development_faucet_pubkey, ensure_mainnet_readiness,
    evaluate_mainnet_readiness, load_node_config, materialize_service_pair_from_config,
    materialize_services_from_config, materialize_services_from_config_with_blockstore,
    maybe_spawn_quic_bridge, maybe_start_metrics_http_bridge,
    maybe_start_rpc_http_server_with_consensus, print_preflight_ok, resolve_validator_identity,
    restore_from_snapshot_archive, run_diagnostics_phase, run_preflight_phase,
    run_preflight_phase_with_probe_report, run_runtime_phase, run_runtime_phase_with_consensus,
    run_startup_checks, run_startup_checks_with_probe_report, save_tower_to_disk,
    spawn_snapshot_thread, spawn_snapshot_thread_with_gossip, start_gossip_service,
    BlockstoreShredProvider, ConsensusBundle, ConsensusLeaderLookup, ConsensusTransactionSubmitter,
    DiagnosticsSummary, GossipHandle, LocalTransactionSubmitter, MainnetReadinessReport,
    MaterializedServicePair, TpuLoopbackSubmitter,
};

// Re-export TransactionSubmitter trait so downstream crates can cast submitters.
pub use karstflow_rpc::TransactionSubmitter;

// Continue bootstrap re-exports (split to avoid merge conflict).
pub use bootstrap::{
    PipelineBundle, RepairBundle, ReplayBundle, ReplayBundleWithExternalInput, ServiceBundle,
    ShredPipelineBundle, StorageMaintenanceBundle, TurbineBundle, VoteBroadcastBundle,
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
pub use vote_sender::{build_vote_sender_service, VoteSenderBundle};
