use karstflow_control::{
    build_diagnostics_summary_from_probe, ensure_mainnet_readiness, evaluate_mainnet_readiness,
    materialize_services_from_config, render_diagnostics_cluster_mode_line,
    render_diagnostics_lane_capacity_line, render_diagnostics_ok_line,
    render_diagnostics_probe_line, render_diagnostics_readiness_issue_line,
    render_diagnostics_readiness_line, render_diagnostics_services_line,
    render_diagnostics_stage_mix_line, render_diagnostics_topology_line,
    render_preflight_readiness_issue_line, render_preflight_readiness_line,
    render_readiness_policy_line, run_diagnostics_phase, run_preflight_phase,
    run_preflight_phase_with_probe_report,
};

pub(crate) fn preflight_with_node_config(
    node_config: karstflow_config::NodeConfig,
    probe_ticks: u32,
    mainnet_readiness: bool,
) -> karstflow_control::Result<()> {
    let _tracing_guard = crate::init_tracing_from_config(&node_config)?;
    let mut materialized_topology = materialize_services_from_config(&node_config)?;
    // Push reporter into services (no aggregator needed for preflight).
    if let Some(rpt) = materialized_topology.reporter.take() {
        materialized_topology.services.push(Box::new(rpt));
    }
    if !mainnet_readiness {
        return run_preflight_phase(
            &node_config,
            materialized_topology.services.as_mut_slice(),
            probe_ticks,
        );
    }

    let startup_probe_report = run_preflight_phase_with_probe_report(
        &node_config,
        materialized_topology.services.as_mut_slice(),
        probe_ticks,
    )?;
    let diagnostics_summary = build_diagnostics_summary_from_probe(
        &node_config,
        materialized_topology.topology_spec.topology_name.clone(),
        materialized_topology.topology_spec.stages.len(),
        materialized_topology.topology_spec.links.len(),
        materialized_topology.services.as_slice(),
        startup_probe_report,
    );
    let readiness_report = evaluate_mainnet_readiness(&node_config, &diagnostics_summary);
    println!(
        "{}",
        render_readiness_policy_line("preflight", &node_config.mainnet_readiness_policy)
    );
    println!(
        "{}",
        render_preflight_readiness_line(
            readiness_report.checks_passed,
            readiness_report.checks_failed,
        )
    );
    for issue in &readiness_report.failed_checks {
        println!("{}", render_preflight_readiness_issue_line(issue));
    }
    ensure_mainnet_readiness(&readiness_report)
}

pub(crate) fn diagnostics_with_node_config(
    node_config: karstflow_config::NodeConfig,
    probe_ticks: u32,
    mainnet_readiness: bool,
) -> karstflow_control::Result<()> {
    let _tracing_guard = crate::init_tracing_from_config(&node_config)?;
    let mut materialized_topology = materialize_services_from_config(&node_config)?;
    // Push reporter into services (no aggregator needed for diagnostics).
    if let Some(rpt) = materialized_topology.reporter.take() {
        materialized_topology.services.push(Box::new(rpt));
    }
    let diagnostics_summary = run_diagnostics_phase(
        &node_config,
        materialized_topology.topology_spec.topology_name.clone(),
        materialized_topology.topology_spec.stages.len(),
        materialized_topology.topology_spec.links.len(),
        materialized_topology.services.as_mut_slice(),
        probe_ticks,
    )?;
    println!(
        "{}",
        render_diagnostics_cluster_mode_line(node_config.cluster_mode)
    );
    println!(
        "{}",
        render_diagnostics_topology_line(
            &diagnostics_summary.topology_name,
            diagnostics_summary.stage_count,
            diagnostics_summary.link_count,
        )
    );
    println!(
        "{}",
        render_diagnostics_probe_line(
            probe_ticks,
            diagnostics_summary.startup_probe_report.started_ok,
            diagnostics_summary.startup_probe_report.ticked_ok,
            diagnostics_summary.startup_probe_report.stopped_ok,
            diagnostics_summary.startup_probe_report.failures.len()
        )
    );
    println!(
        "{}",
        render_diagnostics_stage_mix_line(
            diagnostics_summary.ingress_gateway_stages,
            diagnostics_summary.transaction_sanitizer_stages,
            diagnostics_summary.shred_sanitizer_stages,
            diagnostics_summary.block_builder_stages,
            diagnostics_summary.telemetry_stages,
        )
    );
    println!(
        "{}",
        render_diagnostics_lane_capacity_line(
            diagnostics_summary.packet_stream_capacity,
            diagnostics_summary.shred_stream_capacity,
            diagnostics_summary.transaction_stream_capacity,
        )
    );
    println!(
        "{}",
        render_diagnostics_services_line(&diagnostics_summary.runtime_service_names)
    );
    if mainnet_readiness {
        let readiness_report = evaluate_mainnet_readiness(&node_config, &diagnostics_summary);
        println!(
            "{}",
            render_readiness_policy_line("diagnostics", &node_config.mainnet_readiness_policy)
        );
        println!(
            "{}",
            render_diagnostics_readiness_line(
                readiness_report.checks_passed,
                readiness_report.checks_failed,
            )
        );
        for issue in &readiness_report.failed_checks {
            println!("{}", render_diagnostics_readiness_issue_line(issue));
        }
        ensure_mainnet_readiness(&readiness_report)?;
    }
    println!("{}", render_diagnostics_ok_line());
    Ok(())
}
