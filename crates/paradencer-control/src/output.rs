use paradencer_config::ClusterMode;
use std::path::Path;

pub fn render_phase_cluster_mode_line(phase_label: &str, cluster_mode: ClusterMode) -> String {
    format!("[{phase_label}] cluster_mode={cluster_mode:?}")
}

pub fn render_preflight_ok_line() -> &'static str {
    "[preflight] ok"
}

pub fn render_preflight_readiness_line(checks_passed: usize, checks_failed: usize) -> String {
    let status = if checks_failed == 0 {
        "ready"
    } else {
        "not_ready"
    };
    format!(
        "[preflight] mainnet_readiness status={status} checks_passed={checks_passed} checks_failed={checks_failed}"
    )
}

pub fn render_preflight_readiness_issue_line(issue: &str) -> String {
    format!("[preflight] mainnet_readiness_issue={issue}")
}

pub fn render_topology_line(topology_name: &str, stage_count: usize, link_count: usize) -> String {
    format!("[topology] name='{topology_name}' stages={stage_count} links={link_count}")
}

pub fn render_keys_valid_line(path: &Path) -> String {
    format!("[keys] identity keypair is valid: {}", path.display())
}

pub fn render_version_line(binary_name: &str, version: &str) -> String {
    format!("{binary_name} {version}")
}

pub fn render_diagnostics_cluster_mode_line(cluster_mode: ClusterMode) -> String {
    format!("[diagnostics] cluster_mode={cluster_mode:?}")
}

pub fn render_diagnostics_topology_line(
    topology_name: &str,
    stage_count: usize,
    link_count: usize,
) -> String {
    format!("[diagnostics] topology name='{topology_name}' stages={stage_count} links={link_count}")
}

pub fn render_diagnostics_ok_line() -> &'static str {
    "[diagnostics] ok"
}

pub fn render_diagnostics_probe_line(
    probe_ticks: u32,
    started_ok: usize,
    ticked_ok: usize,
    stopped_ok: usize,
    failed_count: usize,
) -> String {
    format!(
        "[diagnostics] startup_probe probe_ticks={probe_ticks} started_ok={started_ok} ticked_ok={ticked_ok} stopped_ok={stopped_ok} failures={failed_count}"
    )
}

pub fn render_diagnostics_stage_mix_line(
    ingress_gateway_stages: usize,
    transaction_sanitizer_stages: usize,
    shred_sanitizer_stages: usize,
    block_builder_stages: usize,
    telemetry_stages: usize,
) -> String {
    format!(
        "[diagnostics] stage_mix ingress_gateway={ingress_gateway_stages} transaction_sanitizer={transaction_sanitizer_stages} shred_sanitizer={shred_sanitizer_stages} block_builder={block_builder_stages} telemetry={telemetry_stages}"
    )
}

pub fn render_diagnostics_lane_capacity_line(
    packet_stream_capacity: usize,
    shred_stream_capacity: usize,
    transaction_stream_capacity: usize,
) -> String {
    format!(
        "[diagnostics] lane_capacity packet_stream={packet_stream_capacity} shred_stream={shred_stream_capacity} transaction_stream={transaction_stream_capacity}"
    )
}

pub fn render_diagnostics_services_line(runtime_service_names: &[String]) -> String {
    let rendered = runtime_service_names.join(",");
    format!("[diagnostics] runtime_services={rendered}")
}

pub fn render_diagnostics_readiness_line(checks_passed: usize, checks_failed: usize) -> String {
    let status = if checks_failed == 0 {
        "ready"
    } else {
        "not_ready"
    };
    format!(
        "[diagnostics] mainnet_readiness status={status} checks_passed={checks_passed} checks_failed={checks_failed}"
    )
}

pub fn render_diagnostics_readiness_issue_line(issue: &str) -> String {
    format!("[diagnostics] mainnet_readiness_issue={issue}")
}

pub fn render_readiness_policy_line(
    scope: &str,
    readiness_policy: &paradencer_config::MainnetReadinessPolicy,
) -> String {
    format!(
        "[{scope}] mainnet_readiness_policy min_runtime_workers={} min_live_entrypoints={} min_tx_sanitizers={} min_shred_sanitizers={} min_packet_capacity={} min_shred_capacity={} min_transaction_capacity={} min_replay_candidate_confirmation_threshold={} min_replay_failed_ratio_penalty_weight={} require_pinned_mode={} require_udp_ingress={} require_non_stdout_metrics={} require_metrics_http_bind={} require_fork_choice_runtime_enabled={} require_fail_fast_execution_errors={} require_fail_open_execution_error_circuit_breaker={}",
        readiness_policy.min_runtime_workers,
        readiness_policy.min_live_entrypoints,
        readiness_policy.min_transaction_sanitizer_stages,
        readiness_policy.min_shred_sanitizer_stages,
        readiness_policy.min_packet_stream_capacity,
        readiness_policy.min_shred_stream_capacity,
        readiness_policy.min_transaction_stream_capacity,
        readiness_policy.min_replay_candidate_confirmation_threshold,
        readiness_policy.min_replay_failed_ratio_penalty_weight,
        readiness_policy.require_pinned_runtime_mode,
        readiness_policy.require_udp_ingress_mode,
        readiness_policy.require_non_stdout_metrics_target,
        readiness_policy.require_metrics_http_bind,
        readiness_policy.require_fork_choice_runtime_enabled,
        readiness_policy.require_fail_fast_execution_errors,
        readiness_policy.require_fail_open_execution_error_circuit_breaker
    )
}

pub fn render_pinned_affinity_line(
    scope: &str,
    available_core_count: usize,
    assignment_source: paradencer_runtime::PinnedAssignmentSource,
    assigned_core_ids: &[usize],
) -> String {
    let assignment_source = match assignment_source {
        paradencer_runtime::PinnedAssignmentSource::Auto => "auto",
        paradencer_runtime::PinnedAssignmentSource::Explicit => "explicit",
    };
    let unique_assigned_cores = assigned_core_ids
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    format!(
        "[{scope}] pinned_affinity available_cores={available_core_count} assigned_services={} unique_assigned_cores={unique_assigned_cores} source={assignment_source}",
        assigned_core_ids.len()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        render_diagnostics_cluster_mode_line, render_diagnostics_lane_capacity_line,
        render_diagnostics_ok_line, render_diagnostics_probe_line,
        render_diagnostics_readiness_issue_line, render_diagnostics_readiness_line,
        render_diagnostics_services_line, render_diagnostics_stage_mix_line,
        render_diagnostics_topology_line, render_keys_valid_line, render_phase_cluster_mode_line,
        render_pinned_affinity_line, render_preflight_ok_line,
        render_preflight_readiness_issue_line, render_preflight_readiness_line,
        render_readiness_policy_line, render_topology_line, render_version_line,
    };
    use paradencer_config::ClusterMode;

    #[test]
    fn output_renderers_produce_expected_strings() {
        assert_eq!(
            render_phase_cluster_mode_line("startup", ClusterMode::Dev),
            "[startup] cluster_mode=Dev"
        );
        assert_eq!(render_preflight_ok_line(), "[preflight] ok");
        assert_eq!(
            render_preflight_readiness_line(6, 2),
            "[preflight] mainnet_readiness status=not_ready checks_passed=6 checks_failed=2"
        );
        assert_eq!(
            render_preflight_readiness_issue_line("ingress mode is not 'udp'"),
            "[preflight] mainnet_readiness_issue=ingress mode is not 'udp'"
        );
        assert_eq!(
            render_topology_line("default-pipeline", 5, 3),
            "[topology] name='default-pipeline' stages=5 links=3"
        );
        assert_eq!(
            render_keys_valid_line(std::path::Path::new("/tmp/keypair.json")),
            "[keys] identity keypair is valid: /tmp/keypair.json"
        );
        assert_eq!(
            render_version_line("paradencer-node", "0.1.0"),
            "paradencer-node 0.1.0"
        );
        assert_eq!(
            render_diagnostics_cluster_mode_line(ClusterMode::Live),
            "[diagnostics] cluster_mode=Live"
        );
        assert_eq!(
            render_diagnostics_topology_line("default-pipeline", 5, 3),
            "[diagnostics] topology name='default-pipeline' stages=5 links=3"
        );
        assert_eq!(
            render_diagnostics_probe_line(2, 5, 10, 5, 0),
            "[diagnostics] startup_probe probe_ticks=2 started_ok=5 ticked_ok=10 stopped_ok=5 failures=0"
        );
        assert_eq!(
            render_diagnostics_stage_mix_line(1, 2, 3, 1, 1),
            "[diagnostics] stage_mix ingress_gateway=1 transaction_sanitizer=2 shred_sanitizer=3 block_builder=1 telemetry=1"
        );
        assert_eq!(
            render_diagnostics_lane_capacity_line(1024, 768, 1536),
            "[diagnostics] lane_capacity packet_stream=1024 shred_stream=768 transaction_stream=1536"
        );
        assert_eq!(
            render_diagnostics_services_line(&[
                "edge-intake".to_string(),
                "tx-filter".to_string(),
                "block-assembler".to_string()
            ]),
            "[diagnostics] runtime_services=edge-intake,tx-filter,block-assembler"
        );
        assert_eq!(
            render_diagnostics_readiness_line(8, 0),
            "[diagnostics] mainnet_readiness status=ready checks_passed=8 checks_failed=0"
        );
        assert_eq!(
            render_diagnostics_readiness_issue_line("runtime mode is 'tokio', expected 'pinned'"),
            "[diagnostics] mainnet_readiness_issue=runtime mode is 'tokio', expected 'pinned'"
        );
        let readiness_policy = paradencer_config::MainnetReadinessPolicy::default();
        assert_eq!(
            render_readiness_policy_line("diagnostics", &readiness_policy),
            "[diagnostics] mainnet_readiness_policy min_runtime_workers=4 min_live_entrypoints=1 min_tx_sanitizers=2 min_shred_sanitizers=2 min_packet_capacity=4096 min_shred_capacity=4096 min_transaction_capacity=8192 min_replay_candidate_confirmation_threshold=2 min_replay_failed_ratio_penalty_weight=50 require_pinned_mode=true require_udp_ingress=true require_non_stdout_metrics=true require_metrics_http_bind=false require_fork_choice_runtime_enabled=false require_fail_fast_execution_errors=false require_fail_open_execution_error_circuit_breaker=false"
        );
        assert_eq!(
            render_pinned_affinity_line(
                "diagnostics",
                24,
                paradencer_runtime::PinnedAssignmentSource::Explicit,
                &[2, 4, 6, 8, 8]
            ),
            "[diagnostics] pinned_affinity available_cores=24 assigned_services=5 unique_assigned_cores=4 source=explicit"
        );
        assert_eq!(render_diagnostics_ok_line(), "[diagnostics] ok");
    }
}
