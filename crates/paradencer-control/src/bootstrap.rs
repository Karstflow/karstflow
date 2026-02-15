use crate::errors::{ControlPlaneError, Result};
use crate::output::{
    render_phase_cluster_mode_line, render_pinned_affinity_line, render_preflight_ok_line,
    render_topology_line,
};
use crate::{
    ensure_service_startup_probe_ok, run_network_socket_preflight, run_service_startup_probe,
};
use paradencer_config::NodeConfig;
use paradencer_core::{ExecutionMode, LinkKind, PinnedCorePolicy, StageKind};
use paradencer_ingress::IngressMode;
use paradencer_observability::spawn_metrics_http_bridge;
use paradencer_rpc::{metrics_file_provider, spawn_rpc_http_server};
use paradencer_runtime::{build_pinned_affinity_plan, run_services, Service, ServiceProbeReport};
use paradencer_stages::{ExecutionErrorHandlingPolicy, MetricsOutputTarget};
use paradencer_topology::{materialize_services, MaterializedTopology};
use std::collections::HashSet;
use std::path::Path;

pub struct ServiceBundle {
    pub topology_name: String,
    pub stage_count: usize,
    pub link_count: usize,
    pub services: Vec<Box<dyn Service>>,
}

pub struct MaterializedServicePair {
    pub startup: MaterializedTopology,
    pub runtime: MaterializedTopology,
}

pub struct DiagnosticsSummary {
    pub topology_name: String,
    pub stage_count: usize,
    pub link_count: usize,
    pub ingress_gateway_stages: usize,
    pub transaction_sanitizer_stages: usize,
    pub shred_sanitizer_stages: usize,
    pub block_builder_stages: usize,
    pub telemetry_stages: usize,
    pub packet_stream_capacity: usize,
    pub shred_stream_capacity: usize,
    pub transaction_stream_capacity: usize,
    pub runtime_service_names: Vec<String>,
    pub startup_probe_report: ServiceProbeReport,
}

pub struct MainnetReadinessReport {
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub failed_checks: Vec<String>,
}

pub fn load_node_config(config_path: Option<&Path>) -> Result<NodeConfig> {
    match config_path {
        Some(path) => NodeConfig::from_file(path),
        None => NodeConfig::from_env(),
    }
    .map_err(ControlPlaneError::from)
}

pub fn materialize_services_from_config(node_config: &NodeConfig) -> Result<MaterializedTopology> {
    materialize_services(
        node_config.topology_spec.clone(),
        node_config.ingress_policy.clone(),
        node_config.metrics_output_format,
        node_config.metrics_output_target.clone(),
        node_config.storage_runtime_policy.clone(),
    )
    .map_err(ControlPlaneError::from)
}

pub fn materialize_service_pair_from_config(
    node_config: &NodeConfig,
) -> Result<MaterializedServicePair> {
    let startup = materialize_services_from_config(node_config)?;
    let runtime = materialize_services_from_config(node_config)?;
    Ok(MaterializedServicePair { startup, runtime })
}

pub fn run_startup_checks(
    node_config: &NodeConfig,
    services: &mut [Box<dyn Service>],
    phase_label: &str,
    probe_ticks: u32,
) -> Result<()> {
    let _startup_probe_report =
        run_startup_checks_with_probe_report(node_config, services, phase_label, probe_ticks)?;
    Ok(())
}

pub fn run_startup_checks_with_probe_report(
    node_config: &NodeConfig,
    services: &mut [Box<dyn Service>],
    phase_label: &str,
    probe_ticks: u32,
) -> Result<ServiceProbeReport> {
    println!(
        "{}",
        render_phase_cluster_mode_line(phase_label, node_config.cluster_mode)
    );
    if let Some(affinity_plan) =
        build_pinned_affinity_plan(&node_config.runtime_spec, services.len())?
    {
        println!(
            "{}",
            render_pinned_affinity_line(
                phase_label,
                affinity_plan.available_core_count,
                affinity_plan.assignment_source,
                &affinity_plan.assigned_core_ids
            )
        );
    }
    run_network_socket_preflight(node_config)?;
    let startup_probe_report = run_service_startup_probe(services, probe_ticks);
    ensure_service_startup_probe_ok(&startup_probe_report)?;
    Ok(startup_probe_report)
}

pub fn maybe_start_metrics_http_bridge(node_config: &NodeConfig) -> Result<()> {
    if let Some(bind_addr) = node_config.metrics_http_bind {
        match &node_config.metrics_output_target {
            MetricsOutputTarget::File(path) => {
                spawn_metrics_http_bridge(bind_addr, path.clone())?;
            }
            _ => return Err(ControlPlaneError::MetricsHttpRequiresFileTarget),
        }
    }
    Ok(())
}

pub fn maybe_start_rpc_http_server(node_config: &NodeConfig) -> Result<()> {
    if !node_config.rpc_enabled {
        return Ok(());
    }
    let bind_addr = node_config.rpc_bind.ok_or(ControlPlaneError::Config(
        paradencer_config::ConfigError::RpcEnabledRequiresBindAddr,
    ))?;
    let metrics_file_path = match &node_config.metrics_output_target {
        MetricsOutputTarget::File(path) => Some(path.clone()),
        _ => None,
    };
    let runtime_snapshot_provider = metrics_file_path.map(metrics_file_provider);
    spawn_rpc_http_server(
        bind_addr,
        node_config.rpc_full_api,
        node_config.rpc_private,
        runtime_snapshot_provider,
    )?;
    Ok(())
}

pub fn print_preflight_ok() {
    println!("{}", render_preflight_ok_line());
}

pub fn run_runtime_phase(
    node_config: &NodeConfig,
    startup_services: &mut [Box<dyn Service>],
    runtime_bundle: ServiceBundle,
) -> Result<()> {
    run_startup_checks(node_config, startup_services, "startup", 0)?;
    maybe_start_metrics_http_bridge(node_config)?;
    maybe_start_rpc_http_server(node_config)?;
    println!(
        "{}",
        render_topology_line(
            &runtime_bundle.topology_name,
            runtime_bundle.stage_count,
            runtime_bundle.link_count
        )
    );
    run_services(&node_config.runtime_spec, runtime_bundle.services)
        .map_err(ControlPlaneError::from)
}

pub fn run_preflight_phase(
    node_config: &NodeConfig,
    services: &mut [Box<dyn Service>],
    probe_ticks: u32,
) -> Result<()> {
    let _startup_probe_report =
        run_preflight_phase_with_probe_report(node_config, services, probe_ticks)?;
    Ok(())
}

pub fn run_preflight_phase_with_probe_report(
    node_config: &NodeConfig,
    services: &mut [Box<dyn Service>],
    probe_ticks: u32,
) -> Result<ServiceProbeReport> {
    let startup_probe_report =
        run_startup_checks_with_probe_report(node_config, services, "preflight", probe_ticks)?;
    print_preflight_ok();
    Ok(startup_probe_report)
}

pub fn run_diagnostics_phase(
    node_config: &NodeConfig,
    topology_name: String,
    stage_count: usize,
    link_count: usize,
    services: &mut [Box<dyn Service>],
    probe_ticks: u32,
) -> Result<DiagnosticsSummary> {
    if let Some(affinity_plan) =
        build_pinned_affinity_plan(&node_config.runtime_spec, services.len())?
    {
        println!(
            "{}",
            render_pinned_affinity_line(
                "diagnostics",
                affinity_plan.available_core_count,
                affinity_plan.assignment_source,
                &affinity_plan.assigned_core_ids
            )
        );
    }
    run_network_socket_preflight(node_config)?;
    let startup_probe_report = run_service_startup_probe(services, probe_ticks);
    ensure_service_startup_probe_ok(&startup_probe_report)?;
    Ok(build_diagnostics_summary_from_probe(
        node_config,
        topology_name,
        stage_count,
        link_count,
        services,
        startup_probe_report,
    ))
}

pub fn build_diagnostics_summary_from_probe(
    node_config: &NodeConfig,
    topology_name: String,
    stage_count: usize,
    link_count: usize,
    services: &[Box<dyn Service>],
    startup_probe_report: ServiceProbeReport,
) -> DiagnosticsSummary {
    let runtime_service_names = services
        .iter()
        .map(|service| service.name().to_string())
        .collect::<Vec<_>>();
    let ingress_gateway_stages = node_config
        .topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::IngressGateway)
        .count();
    let transaction_sanitizer_stages = node_config
        .topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::TransactionSanitizer)
        .count();
    let shred_sanitizer_stages = node_config
        .topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::ShredSanitizer)
        .count();
    let block_builder_stages = node_config
        .topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::BlockBuilder)
        .count();
    let telemetry_stages = node_config
        .topology_spec
        .stages
        .iter()
        .filter(|stage| stage.stage_kind == StageKind::Telemetry)
        .count();
    let packet_stream_capacity = node_config
        .topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::PacketStream)
        .map(|link| link.capacity)
        .sum();
    let shred_stream_capacity = node_config
        .topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::ShredStream)
        .map(|link| link.capacity)
        .sum();
    let transaction_stream_capacity = node_config
        .topology_spec
        .links
        .iter()
        .filter(|link| link.link_kind == LinkKind::TransactionStream)
        .map(|link| link.capacity)
        .sum();
    DiagnosticsSummary {
        topology_name,
        stage_count,
        link_count,
        ingress_gateway_stages,
        transaction_sanitizer_stages,
        shred_sanitizer_stages,
        block_builder_stages,
        telemetry_stages,
        packet_stream_capacity,
        shred_stream_capacity,
        transaction_stream_capacity,
        runtime_service_names,
        startup_probe_report,
    }
}

pub fn evaluate_mainnet_readiness(
    node_config: &NodeConfig,
    diagnostics_summary: &DiagnosticsSummary,
) -> MainnetReadinessReport {
    let mut failed_checks = Vec::new();
    let readiness_policy = &node_config.mainnet_readiness_policy;
    let mut checks_total = 0_usize;

    checks_total = checks_total.saturating_add(1);
    if node_config.runtime_spec.workers < readiness_policy.min_runtime_workers {
        failed_checks.push(format!(
            "runtime worker count is {}, expected at least {}",
            node_config.runtime_spec.workers, readiness_policy.min_runtime_workers,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if node_config.live_entrypoints.len() < readiness_policy.min_live_entrypoints {
        failed_checks.push(format!(
            "live entrypoint count is {}, expected at least {}",
            node_config.live_entrypoints.len(),
            readiness_policy.min_live_entrypoints,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if diagnostics_summary.transaction_sanitizer_stages
        < readiness_policy.min_transaction_sanitizer_stages
    {
        failed_checks.push(format!(
            "transaction_sanitizer stage count is {}, expected at least {}",
            diagnostics_summary.transaction_sanitizer_stages,
            readiness_policy.min_transaction_sanitizer_stages,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if diagnostics_summary.shred_sanitizer_stages < readiness_policy.min_shred_sanitizer_stages {
        failed_checks.push(format!(
            "shred_sanitizer stage count is {}, expected at least {}",
            diagnostics_summary.shred_sanitizer_stages, readiness_policy.min_shred_sanitizer_stages,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if diagnostics_summary.packet_stream_capacity < readiness_policy.min_packet_stream_capacity {
        failed_checks.push(format!(
            "packet_stream capacity is {}, expected at least {}",
            diagnostics_summary.packet_stream_capacity, readiness_policy.min_packet_stream_capacity,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if diagnostics_summary.shred_stream_capacity < readiness_policy.min_shred_stream_capacity {
        failed_checks.push(format!(
            "shred_stream capacity is {}, expected at least {}",
            diagnostics_summary.shred_stream_capacity, readiness_policy.min_shred_stream_capacity,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if diagnostics_summary.transaction_stream_capacity
        < readiness_policy.min_transaction_stream_capacity
    {
        failed_checks.push(format!(
            "transaction_stream capacity is {}, expected at least {}",
            diagnostics_summary.transaction_stream_capacity,
            readiness_policy.min_transaction_stream_capacity,
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if node_config
        .storage_runtime_policy
        .replay_controller_policy
        .candidate_confirmation_threshold
        < readiness_policy.min_replay_candidate_confirmation_threshold
    {
        failed_checks.push(format!(
            "replay_controller candidate_confirmation_threshold is {}, expected at least {}",
            node_config
                .storage_runtime_policy
                .replay_controller_policy
                .candidate_confirmation_threshold,
            readiness_policy.min_replay_candidate_confirmation_threshold
        ));
    }
    checks_total = checks_total.saturating_add(1);
    if node_config
        .storage_runtime_policy
        .replay_controller_policy
        .failed_transaction_ratio_penalty_weight
        < readiness_policy.min_replay_failed_ratio_penalty_weight
    {
        failed_checks.push(format!(
            "replay_controller failed_transaction_ratio_penalty_weight is {}, expected at least {}",
            node_config
                .storage_runtime_policy
                .replay_controller_policy
                .failed_transaction_ratio_penalty_weight,
            readiness_policy.min_replay_failed_ratio_penalty_weight
        ));
    }
    if readiness_policy.require_pinned_runtime_mode {
        checks_total = checks_total.saturating_add(1);
        if node_config.runtime_spec.mode != ExecutionMode::Pinned {
            failed_checks.push(format!(
                "runtime mode is '{}', expected 'pinned'",
                node_config.runtime_spec.mode
            ));
        }
    }
    if node_config.runtime_spec.mode == ExecutionMode::Pinned {
        if let Some(explicit_core_ids) = node_config.runtime_spec.pinned_service_core_ids.as_ref() {
            checks_total = checks_total.saturating_add(1);
            if explicit_core_ids.len() != diagnostics_summary.runtime_service_names.len() {
                failed_checks.push(format!(
                    "runtime pinned_service_core_ids has {} entries, expected {} to match runtime services",
                    explicit_core_ids.len(),
                    diagnostics_summary.runtime_service_names.len()
                ));
            }
            if node_config.runtime_spec.pinned_core_policy == PinnedCorePolicy::Strict {
                checks_total = checks_total.saturating_add(1);
                let unique_count = explicit_core_ids
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .len();
                if unique_count != explicit_core_ids.len() {
                    failed_checks.push(
                        "runtime pinned_service_core_ids contains duplicate core ids while pinned_core_policy='strict'".to_string(),
                    );
                }
            }
        }
    }
    if readiness_policy.require_udp_ingress_mode {
        checks_total = checks_total.saturating_add(1);
        if node_config.ingress_policy.ingress_mode != IngressMode::Udp {
            failed_checks.push("ingress mode is not 'udp'".to_string());
        }
    }
    if readiness_policy.require_non_stdout_metrics_target {
        checks_total = checks_total.saturating_add(1);
        if matches!(
            node_config.metrics_output_target,
            MetricsOutputTarget::Stdout
        ) {
            failed_checks
                .push("metrics.output_target is 'stdout', expected file or udp".to_string());
        }
    }
    if readiness_policy.require_metrics_http_bind {
        checks_total = checks_total.saturating_add(1);
        if node_config.metrics_http_bind.is_none() {
            failed_checks.push("metrics_http_bind is required but not configured".to_string());
        }
    }
    if readiness_policy.require_fork_choice_runtime_enabled {
        checks_total = checks_total.saturating_add(1);
        if !node_config
            .storage_runtime_policy
            .fork_choice_runtime_policy
            .enabled
        {
            failed_checks.push(
                "storage.fork_choice_enabled is false, expected true for readiness".to_string(),
            );
        }
    }
    if readiness_policy.require_fail_fast_execution_errors {
        checks_total = checks_total.saturating_add(1);
        if node_config
            .storage_runtime_policy
            .execution_error_handling_policy
            != ExecutionErrorHandlingPolicy::FailFast
        {
            failed_checks.push(
                "storage.execution_error_handling_policy is not 'fail_fast', expected fail_fast for readiness".to_string(),
            );
        }
    }
    if readiness_policy.require_fail_open_execution_error_circuit_breaker {
        checks_total = checks_total.saturating_add(1);
        let is_fail_open = matches!(
            node_config
                .storage_runtime_policy
                .execution_error_handling_policy,
            ExecutionErrorHandlingPolicy::FailOpen
        );
        if is_fail_open
            && node_config
                .storage_runtime_policy
                .execution_error_fail_open_max_consecutive
                == 0
        {
            failed_checks.push(
                "storage.execution_error_fail_open_max_consecutive is 0 while fail_open mode is active".to_string(),
            );
        }
    }

    let checks_failed = failed_checks.len();
    MainnetReadinessReport {
        checks_passed: checks_total.saturating_sub(checks_failed),
        checks_failed,
        failed_checks,
    }
}

pub fn ensure_mainnet_readiness(report: &MainnetReadinessReport) -> Result<()> {
    if report.checks_failed == 0 {
        return Ok(());
    }
    Err(ControlPlaneError::MainnetReadinessFailed {
        reasons: report.failed_checks.join("; "),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_mainnet_readiness, evaluate_mainnet_readiness, load_node_config,
        materialize_service_pair_from_config, materialize_services_from_config,
        maybe_start_metrics_http_bridge, maybe_start_rpc_http_server, run_diagnostics_phase,
    };
    use crate::errors::ControlPlaneError;
    use paradencer_config::NodeConfig;
    use paradencer_core::LinkKind;

    #[test]
    fn load_node_config_from_profile_file_path() {
        let profile_path = std::env::temp_dir().join(format!(
            "paradencer-bootstrap-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&profile_path, "[runtime]\nworkers=5\n").unwrap();

        let result = load_node_config(Some(profile_path.as_path()));
        std::fs::remove_file(&profile_path).unwrap();

        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.runtime_spec.workers, 5);
    }

    #[test]
    fn maybe_start_metrics_http_bridge_rejects_non_file_metrics_target() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config.metrics_http_bind = Some("127.0.0.1:0".parse().unwrap());
        node_config.metrics_output_target = paradencer_stages::MetricsOutputTarget::Stdout;

        let result = maybe_start_metrics_http_bridge(&node_config);
        assert!(result.is_err());
    }

    #[test]
    fn maybe_start_rpc_http_server_rejects_enabled_without_bind() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config.rpc_enabled = true;
        node_config.rpc_bind = None;

        let result = maybe_start_rpc_http_server(&node_config);
        assert!(result.is_err());
    }

    #[test]
    fn materialize_services_from_config_builds_default_services() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let materialized = materialize_services_from_config(&node_config).unwrap();
        assert_eq!(materialized.services.len(), 5);
    }

    #[test]
    fn materialize_service_pair_from_config_builds_startup_and_runtime_services() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let pair = materialize_service_pair_from_config(&node_config).unwrap();
        assert_eq!(pair.startup.services.len(), pair.runtime.services.len());
        assert_eq!(pair.runtime.services.len(), 5);
    }

    #[test]
    fn run_diagnostics_phase_returns_probe_summary() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let expected_packet_capacity: usize = materialized
            .topology_spec
            .links
            .iter()
            .filter(|link| link.link_kind == LinkKind::PacketStream)
            .map(|link| link.capacity)
            .sum();
        let expected_shred_capacity: usize = materialized
            .topology_spec
            .links
            .iter()
            .filter(|link| link.link_kind == LinkKind::ShredStream)
            .map(|link| link.capacity)
            .sum();
        let expected_transaction_capacity: usize = materialized
            .topology_spec
            .links
            .iter()
            .filter(|link| link.link_kind == LinkKind::TransactionStream)
            .map(|link| link.capacity)
            .sum();
        let summary = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            1,
        )
        .unwrap();
        assert_eq!(summary.topology_name, "default-pipeline");
        assert_eq!(summary.stage_count, 5);
        assert_eq!(summary.link_count, 3);
        assert_eq!(summary.ingress_gateway_stages, 1);
        assert_eq!(summary.transaction_sanitizer_stages, 1);
        assert_eq!(summary.shred_sanitizer_stages, 1);
        assert_eq!(summary.block_builder_stages, 1);
        assert_eq!(summary.telemetry_stages, 1);
        assert_eq!(summary.packet_stream_capacity, expected_packet_capacity);
        assert_eq!(summary.shred_stream_capacity, expected_shred_capacity);
        assert_eq!(
            summary.transaction_stream_capacity,
            expected_transaction_capacity
        );
        assert_eq!(summary.runtime_service_names.len(), 5);
        assert_eq!(summary.startup_probe_report.started_ok, 5);
        assert_eq!(summary.startup_probe_report.ticked_ok, 5);
        assert_eq!(summary.startup_probe_report.stopped_ok, 5);
    }

    #[test]
    fn mainnet_readiness_fails_for_default_profile() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let summary = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        )
        .unwrap();
        let readiness = evaluate_mainnet_readiness(&node_config, &summary);
        assert!(readiness.checks_failed > 0);
        assert!(ensure_mainnet_readiness(&readiness).is_err());
    }

    #[test]
    fn diagnostics_fails_early_for_mismatched_pinned_service_core_ids_length() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config.runtime_spec.mode = paradencer_core::ExecutionMode::Pinned;
        node_config.runtime_spec.pinned_service_core_ids = Some(vec![0, 1]);
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let result = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        );
        assert!(matches!(
            result,
            Err(ControlPlaneError::Runtime(
                paradencer_runtime::RuntimeError::ExplicitPinnedAssignmentLengthMismatch { .. }
            ))
        ));
    }

    #[test]
    fn diagnostics_fails_early_for_duplicate_pinned_service_core_ids_in_strict_mode() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config.runtime_spec.mode = paradencer_core::ExecutionMode::Pinned;
        node_config.runtime_spec.pinned_core_policy = paradencer_core::PinnedCorePolicy::Strict;
        node_config.runtime_spec.pinned_service_core_ids = Some(vec![0, 0, 0, 0, 0]);
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let result = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        );
        assert!(matches!(
            result,
            Err(ControlPlaneError::Runtime(
                paradencer_runtime::RuntimeError::StrictPolicyDuplicateCoreAssignment { .. }
            ))
        ));
    }

    #[test]
    fn mainnet_readiness_requires_fork_choice_runtime_when_policy_enabled() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config
            .mainnet_readiness_policy
            .require_fork_choice_runtime_enabled = true;
        node_config
            .storage_runtime_policy
            .fork_choice_runtime_policy
            .enabled = false;
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let summary = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        )
        .unwrap();
        let readiness = evaluate_mainnet_readiness(&node_config, &summary);
        assert!(readiness.failed_checks.iter().any(|check| {
            check.contains("storage.fork_choice_enabled is false, expected true for readiness")
        }));
    }

    #[test]
    fn mainnet_readiness_requires_fail_fast_execution_errors_when_policy_enabled() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config
            .mainnet_readiness_policy
            .require_fail_fast_execution_errors = true;
        node_config
            .storage_runtime_policy
            .execution_error_handling_policy =
            paradencer_stages::ExecutionErrorHandlingPolicy::FailOpen;
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let summary = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        )
        .unwrap();
        let readiness = evaluate_mainnet_readiness(&node_config, &summary);
        assert!(readiness.failed_checks.iter().any(|check| {
            check.contains("storage.execution_error_handling_policy is not 'fail_fast'")
        }));
    }

    #[test]
    fn mainnet_readiness_requires_fail_open_circuit_breaker_when_policy_enabled() {
        let mut node_config = NodeConfig::from_profile(None).unwrap();
        node_config
            .mainnet_readiness_policy
            .require_fail_open_execution_error_circuit_breaker = true;
        node_config
            .storage_runtime_policy
            .execution_error_handling_policy =
            paradencer_stages::ExecutionErrorHandlingPolicy::FailOpen;
        node_config
            .storage_runtime_policy
            .execution_error_fail_open_max_consecutive = 0;
        let mut materialized = materialize_services_from_config(&node_config).unwrap();
        let summary = run_diagnostics_phase(
            &node_config,
            materialized.topology_spec.topology_name.clone(),
            materialized.topology_spec.stages.len(),
            materialized.topology_spec.links.len(),
            materialized.services.as_mut_slice(),
            0,
        )
        .unwrap();
        let readiness = evaluate_mainnet_readiness(&node_config, &summary);
        assert!(readiness.failed_checks.iter().any(|check| {
            check.contains("storage.execution_error_fail_open_max_consecutive is 0")
        }));
    }
}
