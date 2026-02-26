use paradencer_plugin::PluginService;

use paradencer_control::{
    build_diagnostics_summary_from_probe, build_pipeline_service, build_repair_service,
    build_replay_service_with_block_input, build_turbine_service, build_vote_broadcast_service,
    dispatch_command, ensure_mainnet_readiness, evaluate_mainnet_readiness,
    materialize_service_pair_from_config, materialize_services_from_config, parse_command,
    render_diagnostics_cluster_mode_line, render_diagnostics_lane_capacity_line,
    render_diagnostics_ok_line, render_diagnostics_probe_line,
    render_diagnostics_readiness_issue_line, render_diagnostics_readiness_line,
    render_diagnostics_services_line, render_diagnostics_stage_mix_line,
    render_diagnostics_topology_line, render_preflight_readiness_issue_line,
    render_preflight_readiness_line, render_readiness_policy_line, resolve_validator_identity,
    run_diagnostics_phase, run_preflight_phase, run_preflight_phase_with_probe_report,
    run_runtime_phase, start_gossip_service, BlockstoreShredProvider, ServiceBundle,
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
    // Initialize the plugin service. Loads external plugins from JSON config files
    // specified via PARADENCER_PLUGIN_CONFIG env var (comma-separated paths).
    let mut plugin_service = if node_config.plugin_config_files.is_empty() {
        PluginService::empty()
    } else {
        let config_refs: Vec<&std::path::Path> = node_config
            .plugin_config_files
            .iter()
            .map(|p| p.as_path())
            .collect();
        PluginService::new(&config_refs).map_err(|e| {
            paradencer_control::ControlPlaneError::Plugin {
                message: format!("failed to load plugins: {e}"),
            }
        })?
    };
    let _plugin_manager = plugin_service.manager();

    // Resolve the validator identity — loads from file in Live mode,
    // generates ephemeral keypair in Dev mode.
    let identity = resolve_validator_identity(&node_config)?;

    // Start gossip for cluster peer discovery. The service runs on a
    // dedicated background thread and must stay alive for the entire
    // node lifetime.
    let gossip_handle = start_gossip_service(&node_config, &identity)?;
    let cluster_info = gossip_handle.cluster_info.clone();
    let node_id = gossip_handle.node_id;

    let mut topology_pair = materialize_service_pair_from_config(&node_config)?;
    let runtime_topology = topology_pair.runtime;

    // Connect the shred collection pipeline to the replay service.
    // Assembled blocks from the TVU receive path (EdgeIntake → ShredFilter →
    // ShredNetworkService → ShredCollector) feed directly into replay for
    // consensus processing.
    let shred_block_input = runtime_topology
        .shred_block_receiver
        .expect("topology must provide shred block receiver");
    // Keep the direct shred sender alive so ShredCollector's input doesn't close.
    let _direct_shred_sender = runtime_topology.direct_shred_sender;
    let replay_bundle = build_replay_service_with_block_input(
        paradencer_stages::ReplayServiceConfig::default(),
        shred_block_input,
        1_000_000, // initial stake for fork choice
    );
    let consensus = replay_bundle.consensus;

    // Wire replay signals to the plugin service.
    // Subscribe to the SignalBus, then start the plugin observer that
    // translates ReplaySignal → PluginEvent for all loaded plugins.
    {
        let (plugin_tx, plugin_rx) = crossbeam_channel::bounded(256);
        let signal_rx = replay_bundle
            .signal_bus
            .lock()
            .unwrap()
            .subscribe()
            .expect("signal bus subscriber limit not reached");

        // Bridge thread: ReplaySignal → PluginEvent conversion.
        std::thread::Builder::new()
            .name("plugin-bridge".into())
            .spawn(move || {
                while let Ok(signal) = signal_rx.recv() {
                    let event = match signal {
                        paradencer_stages::ReplaySignal::SlotCompleted(info) => {
                            paradencer_plugin::PluginEvent::SlotCompleted {
                                slot: info.slot,
                                parent_slot: info.parent_slot,
                                bank_hash: info.bank_hash,
                                block_hash: info.block_hash,
                                transaction_count: info.transaction_count,
                                executed_count: info.executed_count,
                                fee_collected: info.fee_lamports_collected,
                                capitalization: info.capitalization,
                                entry_count: 0,
                                compute_units: 0,
                                priority_fee: 0,
                            }
                        }
                        paradencer_stages::ReplaySignal::SlotDead(info) => {
                            paradencer_plugin::PluginEvent::SlotDead {
                                slot: info.slot,
                                reason: format!("{:?}", info.reason),
                            }
                        }
                        paradencer_stages::ReplaySignal::RootAdvanced(info) => {
                            paradencer_plugin::PluginEvent::RootAdvanced {
                                new_root: info.new_root,
                                previous_root: info.previous_root,
                            }
                        }
                        paradencer_stages::ReplaySignal::OptimisticConfirmation(info) => {
                            paradencer_plugin::PluginEvent::OptimisticConfirmation {
                                slot: info.slot,
                            }
                        }
                        // PohReset and BecameLeader are internal signals, not exposed to plugins.
                        _ => continue,
                    };
                    if plugin_tx.send(event).is_err() {
                        break;
                    }
                }
            })
            .expect("failed to spawn plugin bridge thread");

        plugin_service.start_slot_observer(plugin_rx);
    }

    // Build the transaction pipeline for block production.
    // Pipeline inputs come directly from the topology — each TxFilter stage
    // forwards accepted raw transactions into the pipeline via a dedicated channel.
    let pipeline_bundle = build_pipeline_service(
        paradencer_stages::PipelineServiceConfig::default(),
        runtime_topology.pipeline_inputs,
    );
    let _pipeline_handle = pipeline_bundle.handle;

    // Build the turbine retransmit service for shred propagation.
    // Uses the gossip-derived identity and cluster state to route shreds
    // through the turbine tree.
    let turbine_bundle = build_turbine_service(node_id, cluster_info.clone())?;
    let _retransmit = turbine_bundle.retransmit;

    // Build the repair service for slot recovery from peers.
    // The coordinator runs poll-driven in the node runtime; background I/O
    // handles actual UDP request/response on a dedicated thread.
    // When persistent storage is available, serve shreds from the blockstore.
    let shred_provider: Option<std::sync::Arc<dyn paradencer_net::ShredProvider>> = consensus
        .storage_engine
        .as_ref()
        .and_then(|engine| match engine.open_blockstore() {
            Ok(bs) => Some(
                std::sync::Arc::new(BlockstoreShredProvider::new(std::sync::Arc::new(bs)))
                    as std::sync::Arc<dyn paradencer_net::ShredProvider>,
            ),
            Err(e) => {
                eprintln!(
                    "warning: failed to open blockstore for repair: {e}, using in-memory fallback"
                );
                None
            }
        });
    let repair_bundle = build_repair_service(
        node_id,
        cluster_info.clone(),
        consensus.vote_processor.clone(),
        shred_provider,
    )?;
    let _repair_io = repair_bundle.io_handle;

    // Build the vote broadcast service. Monitors the shared Tower for
    // new consensus decisions and pushes them to gossip as CrdsValue
    // entries. Mirrors Firedancer's tower→txsend→gossip pipeline.
    let vote_broadcast_bundle = build_vote_broadcast_service(
        &identity,
        consensus.tower,
        consensus.bank_forks,
        cluster_info,
    );

    let mut services = runtime_topology.services;
    services.push(replay_bundle.service);
    services.push(pipeline_bundle.service);
    services.push(turbine_bundle.service);
    services.push(repair_bundle.service);
    services.push(vote_broadcast_bundle.service);

    // Keep gossip and plugins alive until run_runtime_phase returns.
    let _gossip = gossip_handle;

    let result = run_runtime_phase(
        &node_config,
        topology_pair.startup.services.as_mut_slice(),
        ServiceBundle {
            topology_name: runtime_topology.topology_spec.topology_name,
            stage_count: runtime_topology.topology_spec.stages.len(),
            link_count: runtime_topology.topology_spec.links.len(),
            services,
        },
    );

    // Cleanly shut down plugin service after runtime exits.
    plugin_service.shutdown();
    result
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
