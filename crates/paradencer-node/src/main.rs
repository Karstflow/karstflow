mod plugin_notifier;

use paradencer_observability::{init_tracing, TracingConfig};
use paradencer_plugin::PluginService;
use tracing::{info, warn};

use paradencer_control::{
    build_diagnostics_summary_from_probe, build_pipeline_service, build_repair_service,
    build_replay_service_with_block_input, build_replay_service_with_consensus,
    build_turbine_service, build_vote_broadcast_service, build_vote_sender_service,
    dispatch_command, ensure_mainnet_readiness, evaluate_mainnet_readiness,
    materialize_service_pair_from_config, materialize_services_from_config,
    maybe_spawn_quic_bridge, parse_command, render_diagnostics_cluster_mode_line,
    render_diagnostics_lane_capacity_line, render_diagnostics_ok_line,
    render_diagnostics_probe_line, render_diagnostics_readiness_issue_line,
    render_diagnostics_readiness_line, render_diagnostics_services_line,
    render_diagnostics_stage_mix_line, render_diagnostics_topology_line,
    render_preflight_readiness_issue_line, render_preflight_readiness_line,
    render_readiness_policy_line, resolve_validator_identity, restore_from_snapshot_archive,
    run_diagnostics_phase, run_preflight_phase, run_preflight_phase_with_probe_report,
    run_runtime_phase_with_consensus, save_tower_to_disk, spawn_snapshot_thread,
    start_gossip_service, BlockstoreShredProvider, ServiceBundle,
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

fn init_tracing_from_config(
    node_config: &paradencer_config::NodeConfig,
) -> paradencer_control::Result<paradencer_observability::TracingGuard> {
    let tracing_config = TracingConfig {
        stderr_level: node_config.log_stderr_level.clone(),
        file_level: node_config.log_file_level.clone(),
        log_file_path: node_config.log_file_path.clone(),
        colorize_stderr: node_config.log_colorize,
        json_file_format: node_config.log_json_file,
    };
    init_tracing(&tracing_config).map_err(paradencer_control::ControlPlaneError::from)
}

fn run_with_node_config(
    node_config: paradencer_config::NodeConfig,
) -> paradencer_control::Result<()> {
    let _tracing_guard = init_tracing_from_config(&node_config)?;

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
    // Plugin manager is wired to BankForks below, after consensus is built.

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
    // Shred arrival receiver feeds the repair coordinator with turbine
    // progress information so it avoids requesting shreds already received.
    let shred_arrival_rx = runtime_topology
        .shred_arrival_receiver
        .unwrap_or_else(|| crossbeam_channel::bounded(1).1);

    // Choose bootstrap path: snapshot archive or genesis.
    // When PARADENCER_SNAPSHOT_ARCHIVE is set, restore from a Solana snapshot
    // to join an existing network. Otherwise bootstrap from genesis state.
    let replay_bundle = if let Some(ref archive_path) = node_config.snapshot_archive_path {
        let identity_pubkey = paradencer_storage::Pubkey::from(*identity.pubkey());
        let consensus = restore_from_snapshot_archive(
            archive_path,
            node_config.data_dir.as_deref(),
            Some(&identity_pubkey),
            node_config.wait_for_supermajority_bank_hash.as_deref(),
        )?;
        build_replay_service_with_consensus(
            paradencer_stages::ReplayServiceConfig::default(),
            shred_block_input,
            consensus,
            Some(*identity.pubkey()),
        )
    } else {
        build_replay_service_with_block_input(
            paradencer_stages::ReplayServiceConfig::default(),
            shred_block_input,
            1_000_000, // initial stake for fork choice
        )
    };
    let consensus = replay_bundle.consensus;

    // Attach bank notifier so account/transaction changes are forwarded
    // to loaded Geyser plugins. The notifier propagates to child banks
    // automatically via new_from_parent.
    {
        let plugin_manager = plugin_service.manager();
        let notifier =
            std::sync::Arc::new(plugin_notifier::PluginBankNotifier::new(plugin_manager));
        let mut forks = consensus.bank_forks.write().unwrap();
        forks.set_bank_notifier(notifier);
    }

    // Wait-for-supermajority Phase 2: block until 80% of stake is online.
    // Only activates when a bank hash is configured (coordinated restart).
    // Gossip is already running, so peers accumulate while we poll.
    if node_config.wait_for_supermajority_bank_hash.is_some() {
        let forks = consensus.bank_forks.read().unwrap();
        let bank = forks.working_bank();
        if let Some(vote_cache) = bank.vote_account_cache() {
            let cache = vote_cache.read().unwrap();
            let shred_version = node_config.expected_shred_version.unwrap_or(0);
            drop(forks);
            let wfs_config =
                paradencer_control::wait_for_supermajority::WaitForSupermajorityConfig::default();
            match paradencer_control::wait_for_supermajority::wait_for_supermajority_phase2(
                &cache,
                &cluster_info,
                identity.pubkey(),
                shred_version,
                &wfs_config,
            ) {
                Ok(status) => {
                    info!(
                        online_percent = status.online_percent,
                        online_stake = status.online_stake,
                        total_stake = status.total_stake,
                        "supermajority online — proceeding with startup",
                    );
                }
                Err(e) => {
                    return Err(e);
                }
            }
        } else {
            warn!("no vote account cache available — skipping wait-for-supermajority phase 2");
        }
    }

    // Clone the tower handle for persistence (tower Arc moves into vote broadcast later).
    let tower_for_persist = std::sync::Arc::clone(&consensus.tower);

    // Tower persistence: save voting state to disk on every root advance.
    // This ensures tower lockouts survive validator restarts without losing
    // more than one root advance worth of progress.
    if let Some(ref data_dir) = node_config.data_dir {
        let tower_save_rx = replay_bundle
            .signal_bus
            .lock()
            .unwrap()
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let tower_arc = std::sync::Arc::clone(&tower_for_persist);
        let identity_pubkey = paradencer_storage::Pubkey::from(*identity.pubkey());
        let save_dir = data_dir.clone();

        std::thread::Builder::new()
            .name("tower-persist".into())
            .spawn(move || {
                while let Ok(signal) = tower_save_rx.recv() {
                    if let paradencer_stages::ReplaySignal::RootAdvanced(_) = signal {
                        let tower_r = tower_arc.read().unwrap();
                        if let Err(e) = save_tower_to_disk(&tower_r, &save_dir, &identity_pubkey) {
                            warn!(error = %e, "failed to persist tower on root advance");
                        }
                    }
                }
            })
            .expect("failed to spawn tower-persist thread");
    }

    // Snapshot creation: periodically create full and incremental snapshots
    // when the root advances. Only runs when persistent storage is available.
    let _snapshot_thread = if node_config.data_dir.is_some() {
        let snapshot_dir = node_config.data_dir.as_ref().unwrap().join("snapshots");
        spawn_snapshot_thread(
            &replay_bundle.signal_bus,
            consensus.accounts.clone(),
            consensus.bank_forks.clone(),
            snapshot_dir,
            paradencer_storage::SnapshotConfig::new(),
        )
    } else {
        None
    };

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
                                parent_blockhash: info.parent_blockhash,
                                block_time: if info.timestamp != 0 {
                                    Some(info.timestamp)
                                } else {
                                    None
                                },
                                block_height: Some(info.slot),
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

    // Optionally spawn QUIC ingress bridge. When enabled, this adds
    // a pipeline input channel that receives reassembled transactions
    // from QUIC TPU connections processed by the NetworkTile + QuicTile.
    let mut pipeline_inputs = runtime_topology.pipeline_inputs;
    let _quic_bridge = match maybe_spawn_quic_bridge(&node_config) {
        Ok(Some((quic_input, handle))) => {
            pipeline_inputs.push(quic_input);
            Some(handle)
        }
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "QUIC bridge failed to start, continuing without QUIC ingress");
            None
        }
    };

    // Build the transaction pipeline for block production.
    // Pipeline inputs come from topology TxFilter stages plus optional QUIC bridge.
    let pipeline_bundle = build_pipeline_service(
        paradencer_stages::PipelineServiceConfig::default(),
        pipeline_inputs,
    );
    // Wire leader slot orchestration: subscribe to replay signals and
    // drive the pipeline handle when this validator becomes leader.
    {
        let leader_signal_rx = replay_bundle
            .signal_bus
            .lock()
            .unwrap()
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let handle = pipeline_bundle.handle.clone();

        std::thread::Builder::new()
            .name("leader-orchestrator".into())
            .spawn(move || {
                while let Ok(signal) = leader_signal_rx.recv() {
                    match signal {
                        paradencer_stages::ReplaySignal::BecameLeader(info) => {
                            info!(
                                start_slot = info.start_slot,
                                end_slot = info.end_slot,
                                epoch = info.epoch,
                                "activating block production for leader range",
                            );
                            handle.begin_slot(info.start_slot);
                        }
                        paradencer_stages::ReplaySignal::SlotCompleted(info) => {
                            if handle.is_leading() && info.slot == handle.current_slot() {
                                handle.end_slot();
                                // Register the new blockhash so the resolv
                                // stage can validate transactions referencing it.
                                handle.register_blockhash(info.bank_hash, info.slot);
                            }
                        }
                        paradencer_stages::ReplaySignal::RootAdvanced(info) => {
                            // Advance the resolv slot so stale transactions
                            // referencing blockhashes older than the root are
                            // expired.
                            handle.advance_slot(info.new_root);
                        }
                        _ => {}
                    }
                }
            })
            .expect("failed to spawn leader orchestrator thread");
    }

    // Build the turbine retransmit service for shred propagation.
    // Uses the gossip-derived identity and cluster state to route shreds
    // through the turbine tree.
    let turbine_bundle = build_turbine_service(node_id, cluster_info.clone())?;
    let _retransmit = turbine_bundle.retransmit;

    // Build the repair service for slot recovery from peers.
    // The coordinator runs poll-driven in the node runtime; background I/O
    // handles actual UDP request/response on a dedicated thread.
    // When persistent storage is available, open the blockstore once and share
    // the same Arc between the repair service and the RPC server.
    let shared_blockstore: Option<std::sync::Arc<paradencer_storage::Blockstore>> = consensus
        .storage_engine
        .as_ref()
        .and_then(|engine| match engine.open_blockstore() {
            Ok(bs) => Some(std::sync::Arc::new(bs)),
            Err(e) => {
                warn!(error = %e, "failed to open blockstore, using in-memory fallback");
                None
            }
        });
    let shred_provider: Option<std::sync::Arc<dyn paradencer_net::ShredProvider>> =
        shared_blockstore.as_ref().map(|bs| {
            std::sync::Arc::new(BlockstoreShredProvider::new(std::sync::Arc::clone(bs)))
                as std::sync::Arc<dyn paradencer_net::ShredProvider>
        });
    let repair_bundle = build_repair_service(
        node_id,
        cluster_info.clone(),
        consensus.vote_processor.clone(),
        consensus.bank_forks.clone(),
        shred_provider,
        shred_arrival_rx,
    )?;
    let _repair_io = repair_bundle.io_handle;

    // Keep handles to consensus state for the live RPC provider.
    let rpc_bank_forks = consensus.bank_forks.clone();
    let rpc_commitment_tracker = consensus.commitment_tracker.clone();
    let rpc_cluster_info = cluster_info.clone();

    // Build the vote broadcast service. Monitors the shared Tower for
    // new consensus decisions and pushes them to gossip as CrdsValue
    // entries.
    let vote_sender_tower = consensus.tower.clone();
    let vote_sender_forks = consensus.bank_forks.clone();
    let vote_sender_cluster = cluster_info.clone();
    let vote_broadcast_bundle = build_vote_broadcast_service(
        &identity,
        consensus.tower,
        consensus.bank_forks,
        cluster_info,
    );

    // Build the direct vote sender service. Sends vote transactions
    // via UDP to the next N leaders' TPU_VOTE sockets for low-latency
    // consensus participation.
    let vote_sender_bundle = build_vote_sender_service(
        &identity,
        vote_sender_tower,
        vote_sender_forks,
        vote_sender_cluster,
    );

    let metrics_http_content = runtime_topology.metrics_http_content.clone();
    let health_status = runtime_topology.health_status.clone();
    let mut services = runtime_topology.services;
    services.push(replay_bundle.service);
    services.push(pipeline_bundle.service);
    services.push(turbine_bundle.service);
    services.push(repair_bundle.service);
    services.push(vote_broadcast_bundle.service);
    if let Ok(bundle) = vote_sender_bundle {
        services.push(bundle.service);
    }

    // Keep gossip and plugins alive until run_runtime_phase returns.
    let _gossip = gossip_handle;

    let result = run_runtime_phase_with_consensus(
        &node_config,
        topology_pair.startup.services.as_mut_slice(),
        ServiceBundle {
            topology_name: runtime_topology.topology_spec.topology_name,
            stage_count: runtime_topology.topology_spec.stages.len(),
            link_count: runtime_topology.topology_spec.links.len(),
            services,
            metrics_http_content,
            health_status,
        },
        Some(rpc_bank_forks),
        Some(rpc_commitment_tracker),
        Some(rpc_cluster_info),
        *identity.pubkey(),
        shared_blockstore,
    );

    // Save tower state to disk before shutdown so lockouts survive restarts.
    if let Some(ref data_dir) = node_config.data_dir {
        let tower_r = tower_for_persist.read().unwrap();
        let identity_pubkey = paradencer_storage::Pubkey::from(*identity.pubkey());
        if let Err(e) = save_tower_to_disk(&tower_r, data_dir, &identity_pubkey) {
            warn!(error = %e, "failed to save tower on shutdown");
        } else {
            info!(
                root = ?tower_r.root(),
                last_vote = ?tower_r.last_vote_slot(),
                "tower state saved to disk on shutdown",
            );
        }
    }

    // Cleanly shut down plugin service after runtime exits.
    plugin_service.shutdown();
    result
}

fn preflight_with_node_config(
    node_config: paradencer_config::NodeConfig,
    probe_ticks: u32,
    mainnet_readiness: bool,
) -> paradencer_control::Result<()> {
    let _tracing_guard = init_tracing_from_config(&node_config)?;
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
    let _tracing_guard = init_tracing_from_config(&node_config)?;
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
