use super::*;
use karstflow_execution::{ExecutionError, ExecutionFailureClass};

#[test]
fn metrics_reporter_writes_json_metrics_to_file_target() {
    let (packet_outbound, _packet_inbound) = bounded_link::<InboundPacket>(8);
    let (shred_outbound, _shred_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, _transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let metrics_path = unique_temp_file("karstflow-metrics", "jsonl");

    let mut reporter = MetricsReporter::with_output_format_and_stats(
        LinkTelemetryStats {
            packet_link_stats: vec![packet_outbound.stats()],
            shred_link_stats: vec![shred_outbound.stats()],
            transaction_link_stats: vec![transaction_outbound.stats()],
        },
        MetricsOutputFormat::JsonLines,
        MetricsOutputTarget::File(metrics_path.clone()),
        StageTelemetryStats {
            ingress_filter_stats: std::sync::Arc::new(IngressFilterStats::default()),
            shred_filter_stats: std::sync::Arc::new(ShredFilterStats::default()),
            block_assembly_stats: std::sync::Arc::new(BlockAssemblyStats::default()),
        },
    );

    let context = ServiceContext::new(ShutdownSwitch::new());
    reporter.tick(&context).unwrap();

    let content = fs::read_to_string(&metrics_path).unwrap();
    fs::remove_file(&metrics_path).unwrap();
    assert!(content.contains("\"event\":\"mesh_metrics\""));
}

#[test]
fn metrics_reporter_returns_runtime_error_when_file_target_cannot_be_opened() {
    let (packet_outbound, _packet_inbound) = bounded_link::<InboundPacket>(8);
    let (shred_outbound, _shred_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, _transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let missing_parent = unique_temp_file("karstflow-missing-parent", "dir");
    let metrics_path = missing_parent.join("metrics.jsonl");

    let mut reporter = MetricsReporter::with_output_format_and_stats(
        LinkTelemetryStats {
            packet_link_stats: vec![packet_outbound.stats()],
            shred_link_stats: vec![shred_outbound.stats()],
            transaction_link_stats: vec![transaction_outbound.stats()],
        },
        MetricsOutputFormat::JsonLines,
        MetricsOutputTarget::File(metrics_path),
        StageTelemetryStats {
            ingress_filter_stats: std::sync::Arc::new(IngressFilterStats::default()),
            shred_filter_stats: std::sync::Arc::new(ShredFilterStats::default()),
            block_assembly_stats: std::sync::Arc::new(BlockAssemblyStats::default()),
        },
    );

    let context = ServiceContext::new(ShutdownSwitch::new());
    let result = reporter.tick(&context);
    assert!(result.is_err());
}

#[test]
fn metrics_reporter_sends_udp_datagram_for_json_metrics() {
    let (packet_outbound, _packet_inbound) = bounded_link::<InboundPacket>(8);
    let (shred_outbound, _shred_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, _transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "[tests] skipping UDP metrics reporter assertion: socket bind is not permitted"
            );
            return;
        }
        Err(error) => panic!("failed to bind UDP receiver socket: {error}"),
    };
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let target = receiver.local_addr().unwrap();

    let mut reporter = MetricsReporter::with_output_format_and_stats(
        LinkTelemetryStats {
            packet_link_stats: vec![packet_outbound.stats()],
            shred_link_stats: vec![shred_outbound.stats()],
            transaction_link_stats: vec![transaction_outbound.stats()],
        },
        MetricsOutputFormat::JsonLines,
        MetricsOutputTarget::Udp(target),
        StageTelemetryStats {
            ingress_filter_stats: std::sync::Arc::new(IngressFilterStats::default()),
            shred_filter_stats: std::sync::Arc::new(ShredFilterStats::default()),
            block_assembly_stats: std::sync::Arc::new(BlockAssemblyStats::default()),
        },
    );

    let context = ServiceContext::new(ShutdownSwitch::new());
    match reporter.tick(&context) {
        Ok(()) => {}
        Err(error) if error.to_string().contains("Permission denied") => {
            eprintln!("[tests] skipping UDP metrics reporter assertion: UDP send is not permitted");
            return;
        }
        Err(error) => panic!("failed to emit UDP metrics payload: {error}"),
    }

    let mut buffer = [0_u8; 2048];
    let (received_len, _) = receiver.recv_from(&mut buffer).unwrap();
    let payload = std::str::from_utf8(&buffer[..received_len]).unwrap();
    assert!(payload.contains("\"event\":\"mesh_metrics\""));
}

#[test]
fn metrics_reporter_exports_block_assembly_leader_and_fork_counters() {
    let (packet_outbound, _packet_inbound) = bounded_link::<InboundPacket>(8);
    let (shred_outbound, _shred_inbound) = bounded_link::<InboundPacket>(8);
    let (transaction_outbound, _transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let metrics_path = unique_temp_file("karstflow-metrics-prom", "txt");
    let block_stats = std::sync::Arc::new(BlockAssemblyStats::default());
    block_stats.increment_leader_gate_permit();
    block_stats.increment_leader_gate_hold();
    block_stats.increment_fork_choice_keep();
    block_stats.increment_fork_choice_reorg();
    block_stats.increment_execution_health_cooldown_entries();
    block_stats.increment_execution_health_cooldown_skipped_ticks();
    block_stats.increment_replay_safety_hold_entries();
    block_stats.increment_replay_safety_hold_skipped_ticks();
    block_stats.increment_fork_choice_quarantine_entries();
    block_stats.increment_fork_choice_quarantine_skipped_ticks();
    block_stats.increment_slot_transition_committed();
    block_stats.increment_slot_transition_dropped();
    block_stats.increment_slot_transition_reorg_pending();
    block_stats.record_execution_error(&ExecutionError::AdapterApplyFailure {
        fragment_id: 77,
        message: "apply failed".to_string(),
    });
    block_stats.record_execution_error(&ExecutionError::AdapterStateConflict {
        fragment_id: 77,
        detail: "state conflict".to_string(),
    });
    block_stats.record_execution_error(&ExecutionError::AdapterContractViolation {
        fragment_id: 77,
        detail: "contract violation".to_string(),
    });
    block_stats.increment_execution_error_fail_open_continue();
    block_stats.increment_execution_error_fail_fast_halt();
    block_stats.increment_execution_error_fail_open_circuit_breaker_halt();
    block_stats.set_execution_error_consecutive_current(2);
    block_stats
        .increment_retry_scheduled_for_failure_class(Some(ExecutionFailureClass::ReplayConflict));
    block_stats.increment_retry_scheduled_for_failure_class(Some(
        ExecutionFailureClass::TransientSchedulerPressure,
    ));
    block_stats.increment_retry_scheduled_for_failure_class(Some(
        ExecutionFailureClass::ResourceExhaustion,
    ));
    block_stats.increment_retry_scheduled_for_failure_class(None);
    block_stats.increment_dropped_for_failure_class(Some(ExecutionFailureClass::ReplayConflict));
    block_stats.increment_dropped_for_failure_class(Some(
        ExecutionFailureClass::DeterministicTransactionFailure,
    ));
    block_stats.increment_dropped_for_failure_class(Some(
        ExecutionFailureClass::TransientSchedulerPressure,
    ));
    block_stats
        .increment_dropped_for_failure_class(Some(ExecutionFailureClass::ResourceExhaustion));
    block_stats.increment_dropped_for_failure_class(None);
    block_stats.increment_dropped_reorg_retry_exhausted();
    block_stats.increment_replay_controller_holds();
    block_stats.increment_replay_controller_confirmed_candidates();
    block_stats.increment_replay_controller_candidate_switches();
    block_stats.increment_replay_controller_stale_candidates_pruned(2);
    block_stats.increment_replay_controller_switch_suppressed();
    block_stats.set_replay_controller_active_candidate_failed_ratio_bps(1337);
    block_stats.set_replay_controller_tracked_candidates(4);
    block_stats.set_replay_window_checkpoint_depth(3);
    block_stats.increment_replay_window_rewinds();
    block_stats.increment_replay_window_catalog_snapshots_pruned(2);
    block_stats.increment_execution_state_rewind_failures();

    let mut reporter = MetricsReporter::with_output_format_and_stats(
        LinkTelemetryStats {
            packet_link_stats: vec![packet_outbound.stats()],
            shred_link_stats: vec![shred_outbound.stats()],
            transaction_link_stats: vec![transaction_outbound.stats()],
        },
        MetricsOutputFormat::PrometheusText,
        MetricsOutputTarget::File(metrics_path.clone()),
        StageTelemetryStats {
            ingress_filter_stats: std::sync::Arc::new(IngressFilterStats::default()),
            shred_filter_stats: std::sync::Arc::new(ShredFilterStats::default()),
            block_assembly_stats: block_stats,
        },
    );
    let context = ServiceContext::new(ShutdownSwitch::new());
    reporter.tick(&context).unwrap();

    let content = fs::read_to_string(&metrics_path).unwrap();
    fs::remove_file(&metrics_path).unwrap();
    assert!(content.contains("karstflow_block_assembly_leader_gate_permit_total 1"));
    assert!(content.contains("karstflow_block_assembly_leader_gate_hold_total 1"));
    assert!(content.contains("karstflow_block_assembly_fork_choice_keep_total 1"));
    assert!(content.contains("karstflow_block_assembly_fork_choice_reorg_total 1"));
    assert!(content.contains("karstflow_block_assembly_execution_health_cooldown_entries_total 1",));
    assert!(content
        .contains("karstflow_block_assembly_execution_health_cooldown_skipped_ticks_total 1",));
    assert!(content.contains("karstflow_block_assembly_replay_safety_hold_entries_total 1"));
    assert!(content.contains("karstflow_block_assembly_replay_safety_hold_skipped_ticks_total 1"));
    assert!(content.contains("karstflow_block_assembly_fork_choice_quarantine_entries_total 1"));
    assert!(
        content.contains("karstflow_block_assembly_fork_choice_quarantine_skipped_ticks_total 1")
    );
    assert!(content.contains("karstflow_block_assembly_slot_transition_committed_total 1"));
    assert!(content.contains("karstflow_block_assembly_slot_transition_dropped_total 1"));
    assert!(content.contains("karstflow_block_assembly_slot_transition_reorg_pending_total 1"));
    assert!(content.contains("karstflow_block_assembly_execution_error_total 3"));
    assert!(content.contains("karstflow_block_assembly_execution_error_adapter_apply_total 1"));
    assert!(
        content.contains("karstflow_block_assembly_execution_error_adapter_state_conflict_total 1")
    );
    assert!(content
        .contains("karstflow_block_assembly_execution_error_adapter_contract_violation_total 1"));
    assert!(content.contains("karstflow_block_assembly_execution_error_fail_open_continue_total 1"));
    assert!(content.contains("karstflow_block_assembly_execution_error_fail_fast_halt_total 1"));
    assert!(content.contains(
        "karstflow_block_assembly_execution_error_fail_open_circuit_breaker_halt_total 1"
    ));
    assert!(content.contains("karstflow_block_assembly_execution_error_consecutive_current 2"));
    assert!(content.contains("karstflow_block_assembly_retry_scheduled_replay_conflict_total 1"));
    assert!(content.contains("karstflow_block_assembly_retry_scheduled_transient_pressure_total 1"));
    assert!(
        content.contains("karstflow_block_assembly_retry_scheduled_resource_exhaustion_total 1")
    );
    assert!(content.contains("karstflow_block_assembly_retry_scheduled_fallback_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_replay_conflict_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_deterministic_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_transient_pressure_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_resource_exhaustion_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_fallback_total 1"));
    assert!(content.contains("karstflow_block_assembly_dropped_reorg_retry_exhausted_total 1"));
    assert!(content.contains("karstflow_block_assembly_replay_controller_holds_total 1"));
    assert!(
        content.contains("karstflow_block_assembly_replay_controller_confirmed_candidates_total 1")
    );
    assert!(
        content.contains("karstflow_block_assembly_replay_controller_candidate_switches_total 1")
    );
    assert!(content
        .contains("karstflow_block_assembly_replay_controller_stale_candidates_pruned_total 2"));
    assert!(
        content.contains("karstflow_block_assembly_replay_controller_switch_suppressed_total 1")
    );
    assert!(content.contains(
        "karstflow_block_assembly_replay_controller_active_candidate_failed_ratio_bps 1337"
    ));
    assert!(content.contains("karstflow_block_assembly_replay_controller_tracked_candidates 4"));
    assert!(content.contains("karstflow_block_assembly_replay_window_checkpoint_depth 3"));
    assert!(content.contains("karstflow_block_assembly_replay_window_rewinds_total 1"));
    assert!(
        content.contains("karstflow_block_assembly_replay_window_catalog_snapshots_pruned_total 2")
    );
    assert!(content.contains("karstflow_block_assembly_execution_state_rewind_failures_total 1"));
    assert!(content.contains("karstflow_ingress_dropped_cost_budget_source"));
    assert!(content.contains("karstflow_ingress_dropped_downstream_backpressure"));
    assert!(content.contains("karstflow_shred_accepted"));
}
