use paradencer_control::{
    build_diagnostics_summary_from_probe, build_pipeline_service, dispatch_command,
    ensure_mainnet_readiness, evaluate_mainnet_readiness, materialize_service_pair_from_config,
    materialize_services_from_config, parse_command, render_diagnostics_cluster_mode_line,
    render_diagnostics_lane_capacity_line, render_diagnostics_ok_line,
    render_diagnostics_probe_line, render_diagnostics_readiness_issue_line,
    render_diagnostics_readiness_line, render_diagnostics_services_line,
    render_diagnostics_stage_mix_line, render_diagnostics_topology_line,
    render_preflight_readiness_issue_line, render_preflight_readiness_line,
    render_readiness_policy_line, run_diagnostics_phase, run_preflight_phase,
    run_preflight_phase_with_probe_report, run_runtime_phase, ServiceBundle,
};

fn main() -> paradencer_control::Result<()> {
    let parsed_command = parse_command(std::env::args())?;
    dispatch_command(
        parsed_command,
        run_with_node_config,
        preflight_with_node_config,
        diagnostics_with_node_config,
    )
}

fn run_with_node_config(
    node_config: paradencer_config::NodeConfig,
) -> paradencer_control::Result<()> {
    let mut topology_pair = materialize_service_pair_from_config(&node_config)?;
    let runtime_topology = topology_pair.runtime;

    // Build the transaction pipeline for block production.
    // The pipeline handle will be used by consensus/gossip to control
    // leader slots; the input sender will be connected to the network layer.
    let pipeline_bundle =
        build_pipeline_service(paradencer_stages::PipelineServiceConfig::default());
    let _pipeline_handle = pipeline_bundle.handle;
    let _pipeline_input = pipeline_bundle.input;

    let mut services = runtime_topology.services;
    services.push(pipeline_bundle.service);

    run_runtime_phase(
        &node_config,
        topology_pair.startup.services.as_mut_slice(),
        ServiceBundle {
            topology_name: runtime_topology.topology_spec.topology_name,
            stage_count: runtime_topology.topology_spec.stages.len(),
            link_count: runtime_topology.topology_spec.links.len(),
            services,
        },
    )
}

fn preflight_with_node_config(
    node_config: paradencer_config::NodeConfig,
    probe_ticks: u32,
    mainnet_readiness: bool,
) -> paradencer_control::Result<()> {
    let mut materialized_topology = materialize_services_from_config(&node_config)?;
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

fn diagnostics_with_node_config(
    node_config: paradencer_config::NodeConfig,
    probe_ticks: u32,
    mainnet_readiness: bool,
) -> paradencer_control::Result<()> {
    let mut materialized_topology = materialize_services_from_config(&node_config)?;
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
