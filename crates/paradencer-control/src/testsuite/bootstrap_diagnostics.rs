use crate::bootstrap::{
    ensure_mainnet_readiness, evaluate_mainnet_readiness, materialize_services_from_config,
    run_diagnostics_phase,
};
use paradencer_config::NodeConfig;
use paradencer_core::LinkKind;

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
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
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
    assert_eq!(summary.runtime_service_names.len(), 7);
    assert_eq!(summary.startup_probe_report.started_ok, 7);
    assert_eq!(summary.startup_probe_report.ticked_ok, 7);
    assert_eq!(summary.startup_probe_report.stopped_ok, 7);
}

#[test]
fn mainnet_readiness_fails_for_default_profile() {
    let node_config = NodeConfig::from_profile(None).unwrap();
    let mut materialized = materialize_services_from_config(&node_config).unwrap();
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
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
    use crate::errors::ControlPlaneError;

    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.runtime_spec.mode = paradencer_core::ExecutionMode::Pinned;
    // Use a mismatched length: always 2 core IDs regardless of service count.
    node_config.runtime_spec.pinned_service_core_ids = Some(vec![0, 1]);
    let mut materialized = materialize_services_from_config(&node_config).unwrap();
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
    // Guard: if service count happens to be 2, the test premise is invalid.
    assert_ne!(
        materialized.services.len(),
        2,
        "test requires service count != 2 for length mismatch"
    );
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
    use crate::errors::ControlPlaneError;

    let mut node_config = NodeConfig::from_profile(None).unwrap();
    node_config.runtime_spec.mode = paradencer_core::ExecutionMode::Pinned;
    node_config.runtime_spec.pinned_core_policy = paradencer_core::PinnedCorePolicy::Strict;
    let mut materialized = materialize_services_from_config(&node_config).unwrap();
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
    // Build a core ID list matching service count, all zeros (duplicates).
    let service_count = materialized.services.len();
    node_config.runtime_spec.pinned_service_core_ids = Some(vec![0; service_count]);
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
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
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
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
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
    if let Some(rpt) = materialized.reporter {
        materialized.services.push(Box::new(rpt));
    }
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
    assert!(readiness
        .failed_checks
        .iter()
        .any(|check| { check.contains("storage.execution_error_fail_open_max_consecutive is 0") }));
}
