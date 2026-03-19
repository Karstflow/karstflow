mod diagnostics;
mod leader_orchestrator;
mod plugin_notifier;
mod shredding;
mod slot_driver;
mod turbine_receiver;

use karstflow_observability::{init_tracing, TracingConfig};
use karstflow_plugin::PluginService;
use tracing::{info, warn};

use karstflow_control::{
    bootstrap_from_development_genesis, bootstrap_from_genesis_file, build_pipeline_service,
    build_repair_service, build_replay_service_with_consensus, build_storage_maintenance_service,
    build_turbine_service, build_vote_broadcast_service, build_vote_sender_service,
    dispatch_command, materialize_service_pair_from_config, maybe_spawn_quic_bridge, parse_command,
    resolve_validator_identity, restore_from_snapshot_archive, run_runtime_phase_with_consensus,
    save_tower_to_disk, start_gossip_service, BlockstoreShredProvider,
    ConsensusTransactionSubmitter, ServiceBundle,
};

fn main() -> karstflow_control::Result<()> {
    let parsed_command = parse_command(std::env::args())?;
    dispatch_command(
        parsed_command,
        run_with_node_config,
        diagnostics::preflight_with_node_config,
        diagnostics::diagnostics_with_node_config,
    )
}

fn init_tracing_from_config(
    node_config: &karstflow_config::NodeConfig,
) -> karstflow_control::Result<karstflow_observability::TracingGuard> {
    let tracing_config = TracingConfig {
        stderr_level: node_config.log_stderr_level.clone(),
        file_level: node_config.log_file_level.clone(),
        log_file_path: node_config.log_file_path.clone(),
        colorize_stderr: node_config.log_colorize,
        json_file_format: node_config.log_json_file,
    };
    init_tracing(&tracing_config).map_err(karstflow_control::ControlPlaneError::from)
}

fn run_with_node_config(
    node_config: karstflow_config::NodeConfig,
) -> karstflow_control::Result<()> {
    let _tracing_guard = init_tracing_from_config(&node_config)?;

    // Install a panic hook that aborts the process on any thread panic.
    // For a validator, crashing fast and restarting via supervisor is safer
    // than running with silently degraded worker threads.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        tracing::error!("fatal panic detected, aborting process");
        std::process::abort();
    }));

    // Initialize the plugin service. Loads external plugins from JSON config files
    // specified via KARSTFLOW_PLUGIN_CONFIG env var (comma-separated paths).
    let mut plugin_service = if node_config.plugin_config_files.is_empty() {
        PluginService::empty()
    } else {
        let config_refs: Vec<&std::path::Path> = node_config
            .plugin_config_files
            .iter()
            .map(|p| p.as_path())
            .collect();
        PluginService::new(&config_refs).map_err(|e| {
            karstflow_control::ControlPlaneError::Plugin {
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
    // Push reporter into startup services (no aggregator needed for startup checks).
    if let Some(rpt) = topology_pair.startup.reporter.take() {
        topology_pair.startup.services.push(Box::new(rpt));
    }
    let runtime_topology = topology_pair.runtime;

    // Connect the shred collection pipeline to the replay service.
    // Assembled blocks from the TVU receive path (EdgeIntake -> ShredFilter ->
    // ShredNetworkService -> ShredCollector) feed directly into replay for
    // consensus processing.
    let shred_block_input = runtime_topology
        .shred_block_receiver
        .expect("topology must provide shred block receiver");
    // Direct shred sender feeds produced shreds into ShredCollector for
    // self-replay. Used by the leader orchestrator during block production.
    // Clone for TVU receive path (cross-node shred injection).
    let direct_shred_sender = runtime_topology.direct_shred_sender;
    let tvu_shred_sender = direct_shred_sender.as_ref().and_then(|s| {
        if let karstflow_mesh::DualSender::Channel(ref port) = s {
            Some(karstflow_mesh::DualSender::Channel(port.clone()))
        } else {
            None
        }
    });
    // Shred arrival receiver feeds the repair coordinator with turbine
    // progress information so it avoids requesting shreds already received.
    let shred_arrival_rx = runtime_topology
        .shred_arrival_receiver
        .unwrap_or_else(|| crossbeam_channel::bounded(1).1);

    // Live mode without snapshot: download snapshot from network peers.
    // Gossip is already running, so we can discover peers with snapshots.
    let mut snapshot_archive_path_override: Option<std::path::PathBuf> = None;
    if node_config.cluster_mode == karstflow_config::ClusterMode::Live
        && node_config.snapshot_archive_path.is_none()
        && node_config.genesis_path.is_none()
    {
        info!("live mode: downloading snapshot from network peers...");
        let download_config =
            karstflow_control::snapshot_download::SnapshotDownloadConfig::default();
        let output_dir = node_config
            .data_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/karstflow-snapshots"));
        std::fs::create_dir_all(&output_dir).ok();

        let crds_table = gossip_handle.cluster_info.crds_table().clone();
        match karstflow_control::snapshot_download::download_snapshot_from_network(
            &crds_table,
            &output_dir,
            &download_config,
        ) {
            Ok(result) => {
                info!(
                    path = %result.full_snapshot_path.display(),
                    peer = %result.peer.rpc_addr,
                    "snapshot downloaded successfully"
                );
                snapshot_archive_path_override = Some(result.full_snapshot_path);
            }
            Err(e) => {
                warn!(error = %e, "snapshot download failed — cannot join live network without snapshot");
                return Err(karstflow_control::ControlPlaneError::Bootstrap {
                    message: format!("snapshot download failed: {e}"),
                });
            }
        }
    }

    // Choose bootstrap path: snapshot archive -> genesis file -> empty genesis.
    let effective_snapshot_path = snapshot_archive_path_override
        .as_deref()
        .or(node_config.snapshot_archive_path.as_deref());
    let is_dev_mode = effective_snapshot_path.is_none() && node_config.genesis_path.is_none();
    let replay_bundle = if let Some(archive_path) = effective_snapshot_path {
        // Path 1: Restore from a Solana snapshot archive to join an existing network.
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        let consensus = restore_from_snapshot_archive(
            archive_path,
            node_config.data_dir.as_deref(),
            Some(&identity_pubkey),
            node_config.wait_for_supermajority_bank_hash.as_deref(),
        )?;
        build_replay_service_with_consensus(
            karstflow_stages::ReplayServiceConfig::default(),
            shred_block_input,
            consensus,
            Some(*identity.pubkey()),
        )
    } else if let Some(ref genesis_path) = node_config.genesis_path {
        // Path 2: Bootstrap from a genesis.bin file (fresh cluster or dev mode).
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        let consensus = bootstrap_from_genesis_file(
            genesis_path,
            node_config.data_dir.as_deref(),
            Some(&identity_pubkey),
        )?;
        // Disable PoH verification for cluster mode — each node generates
        // independent PoH chains. Production clusters will share PoH chain
        // from genesis after proper PoH synchronization is implemented.
        let mut replay_config = karstflow_stages::ReplayServiceConfig::default();
        replay_config.replay_config.verify_poh = false;
        replay_config.replay_config.replay_mode = true;
        build_replay_service_with_consensus(
            replay_config,
            shred_block_input,
            consensus,
            Some(*identity.pubkey()),
        )
    } else {
        // Path 3: Development mode — auto-generate genesis with funded accounts.
        // Creates a single-node cluster with 500 SOL identity and 500M SOL
        // faucet for requestAirdrop. Only available in Dev cluster mode.
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        let consensus = bootstrap_from_development_genesis(
            node_config.data_dir.as_deref(),
            Some(&identity_pubkey),
        )?;
        build_replay_service_with_consensus(
            karstflow_stages::ReplayServiceConfig::default(),
            shred_block_input,
            consensus,
            Some(*identity.pubkey()),
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
        let mut forks = consensus
            .bank_forks
            .write()
            .expect("bank_forks lock poisoned");
        forks.set_bank_notifier(notifier);
    }

    // Wire leader lookup for shred signature verification.
    // The deferred handle was created empty during topology materialization;
    // now that BankForks is available we populate it with the real provider.
    if let Some(ref handle) = runtime_topology.leader_lookup_handle {
        handle.set(std::sync::Arc::new(
            karstflow_control::ConsensusLeaderLookup::new(consensus.bank_forks.clone()),
        ));
    }

    // Wait-for-supermajority Phase 2: block until 80% of stake is online.
    // Only activates when a bank hash is configured (coordinated restart).
    // Gossip is already running, so peers accumulate while we poll.
    if node_config.wait_for_supermajority_bank_hash.is_some() {
        let forks = consensus
            .bank_forks
            .read()
            .expect("bank_forks lock poisoned");
        let bank = forks.working_bank();
        if let Some(vote_cache) = bank.vote_account_cache() {
            let cache = vote_cache.read().expect("vote_cache lock poisoned");
            let shred_version = node_config.expected_shred_version.unwrap_or(0);
            drop(forks);
            let wfs_config =
                karstflow_control::wait_for_supermajority::WaitForSupermajorityConfig::default();
            match karstflow_control::wait_for_supermajority::wait_for_supermajority_phase2(
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
            .expect("signal_bus lock poisoned")
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let tower_arc = std::sync::Arc::clone(&tower_for_persist);
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        let save_dir = data_dir.clone();

        std::thread::Builder::new()
            .name("tower-persist".into())
            .spawn(move || {
                while let Ok(signal) = tower_save_rx.recv() {
                    if let karstflow_stages::ReplaySignal::RootAdvanced(_) = signal {
                        let tower_r = tower_arc.read().expect("tower lock poisoned");
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
    // Publishes snapshot hashes via gossip so peers can discover snapshots.
    let _snapshot_thread = if let Some(data_dir) = &node_config.data_dir {
        let snapshot_dir = data_dir.join("snapshots");
        karstflow_control::spawn_snapshot_thread_with_gossip(
            &replay_bundle.signal_bus,
            consensus.accounts.clone(),
            consensus.bank_forks.clone(),
            snapshot_dir,
            karstflow_storage::SnapshotConfig::new(),
            Some(cluster_info.clone()),
        )
    } else {
        None
    };

    // Gossip status publisher: advertise lowest slot and epoch slots so
    // peers know what data this node can serve for repair and catch-up.
    {
        let gossip_status_rx = replay_bundle
            .signal_bus
            .lock()
            .expect("signal_bus lock poisoned")
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let gossip_ci = cluster_info.clone();
        let gossip_forks = consensus.bank_forks.clone();

        std::thread::Builder::new()
            .name("gossip-status".into())
            .spawn(move || {
                // Track the last published lowest slot to avoid redundant updates.
                let mut last_lowest_slot: u64 = 0;

                while let Ok(signal) = gossip_status_rx.recv() {
                    match signal {
                        karstflow_stages::ReplaySignal::RootAdvanced(info) => {
                            // Publish lowest slot on root advancement so repair
                            // peers know the oldest slot we can serve.
                            if info.new_root > last_lowest_slot {
                                gossip_ci.publish_lowest_slot(info.new_root);
                                last_lowest_slot = info.new_root;
                            }
                        }
                        karstflow_stages::ReplaySignal::SlotCompleted(info) => {
                            // Publish epoch slots when a slot completes so peers
                            // know which slots we have available. Use epoch_index 0
                            // with a simple slot range encoding.
                            let forks = gossip_forks.read().ok();
                            let root = forks
                                .as_ref()
                                .map(|f| f.root_slot())
                                .unwrap_or(info.parent_slot);

                            // Encode a minimal epoch slots payload: the root slot
                            // followed by the completed slot, encoded as little-endian u64.
                            let mut payload = Vec::with_capacity(16);
                            payload.extend_from_slice(&root.to_le_bytes());
                            payload.extend_from_slice(&info.slot.to_le_bytes());
                            gossip_ci.publish_epoch_slots(0, payload);
                        }
                        _ => {}
                    }
                }
            })
            .expect("failed to spawn gossip-status thread");
    }

    // Wire SlotCompleted signals to consensus slot channel.
    // This ensures leader-produced slots (frozen by slot driver, not
    // by replay_block) still trigger consensus decisions (voting +
    // root advancement). Without this, the tower never advances and
    // root stays at 0.
    {
        let consensus_signal_rx = replay_bundle
            .signal_bus
            .lock()
            .expect("signal_bus lock poisoned")
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let consensus_tx = replay_bundle.consensus_slot_tx.clone();

        std::thread::Builder::new()
            .name("consensus-slot".into())
            .spawn(move || {
                while let Ok(signal) = consensus_signal_rx.recv() {
                    if let karstflow_stages::ReplaySignal::SlotCompleted(info) = signal {
                        let _ = consensus_tx.try_send(info.slot);
                    }
                }
            })
            .expect("failed to spawn consensus-slot thread");
    }

    // Wire replay signals to the plugin service.
    // Subscribe to the SignalBus, then start the plugin observer that
    // translates ReplaySignal -> PluginEvent for all loaded plugins.
    {
        let (plugin_tx, plugin_rx) = crossbeam_channel::bounded(256);
        let signal_rx = replay_bundle
            .signal_bus
            .lock()
            .expect("signal_bus lock poisoned")
            .subscribe()
            .expect("signal bus subscriber limit not reached");

        // Bridge thread: ReplaySignal -> PluginEvent conversion.
        std::thread::Builder::new()
            .name("plugin-bridge".into())
            .spawn(move || {
                while let Ok(signal) = signal_rx.recv() {
                    let event = match signal {
                        karstflow_stages::ReplaySignal::SlotCompleted(info) => {
                            karstflow_plugin::PluginEvent::SlotCompleted {
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
                        karstflow_stages::ReplaySignal::SlotDead(info) => {
                            karstflow_plugin::PluginEvent::SlotDead {
                                slot: info.slot,
                                reason: format!("{:?}", info.reason),
                            }
                        }
                        karstflow_stages::ReplaySignal::RootAdvanced(info) => {
                            karstflow_plugin::PluginEvent::RootAdvanced {
                                new_root: info.new_root,
                                previous_root: info.previous_root,
                            }
                        }
                        karstflow_stages::ReplaySignal::OptimisticConfirmation(info) => {
                            karstflow_plugin::PluginEvent::OptimisticConfirmation {
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

    // Open the blockstore early so it is available for both block production
    // (leader orchestrator shred storage) and the repair/RPC services below.
    let storage_engine_for_maintenance = consensus.storage_engine.clone();
    let shared_blockstore: Option<std::sync::Arc<karstflow_storage::Blockstore>> = consensus
        .storage_engine
        .as_ref()
        .and_then(|engine| match engine.open_blockstore() {
            Ok(bs) => Some(std::sync::Arc::new(bs)),
            Err(e) => {
                warn!(error = %e, "failed to open blockstore, using in-memory fallback");
                None
            }
        });

    // Build the transaction pipeline for block production.
    // Pipeline inputs come from topology TxFilter stages plus optional QUIC bridge.
    // Wire real sBPF execution engine so leader-produced blocks execute transactions
    // through the full bank pipeline instead of the test mock.
    let leader_exec_engine: Box<dyn karstflow_stages::ExecutionEngine> = {
        let backend = std::sync::Arc::new(karstflow_stages::SbpfExecutionAdapter::with_defaults());
        Box::new(karstflow_stages::BankExecutionEngine::new(
            consensus.bank_forks.clone(),
            backend,
        ))
    };
    // Dev mode uses hashes_per_tick=1 for instant ticks (fast E2E tests).
    // Cluster/live mode calibrates hashes_per_tick to the current hardware's
    // SHA-256 speed, targeting ~400ms per slot (64 ticks × ~6.25ms each).
    // On fast hardware (mainnet AMD EPYC): hashes_per_tick ≈ 62,500.
    // On slower hardware (MacBook): auto-adjusted lower for ~400ms slots.
    let pipeline_config = if is_dev_mode {
        karstflow_stages::PipelineServiceConfig::dev()
    } else {
        karstflow_stages::PipelineServiceConfig::calibrated()
    };
    let pipeline_bundle =
        build_pipeline_service(pipeline_config, pipeline_inputs, Some(leader_exec_engine));
    // Wire replay slot completions to the resolv stage's blockhash ring.
    // This follows the reference implementation pattern: when replay freezes
    // a bank (for both leader and non-leader slots), the resulting blockhash
    // is registered with resolv so future transactions referencing it can
    // be validated.
    {
        let resolv_signal_rx = replay_bundle
            .signal_bus
            .lock()
            .expect("signal_bus lock poisoned")
            .subscribe()
            .expect("signal bus subscriber limit not reached");
        let resolv_pipeline = pipeline_bundle.handle.clone();

        std::thread::Builder::new()
            .name("resolv-blockhash".into())
            .spawn(move || {
                while let Ok(signal) = resolv_signal_rx.recv() {
                    if let karstflow_stages::ReplaySignal::SlotCompleted(info) = signal {
                        resolv_pipeline.register_blockhash(info.bank_hash, info.slot);
                        resolv_pipeline.advance_slot(info.slot);
                    }
                }
            })
            .expect("failed to spawn resolv-blockhash thread");
    }

    // Deferred turbine retransmit handle — populated after turbine service
    // is built, read by the leader orchestrator during block production.
    let deferred_retransmit: std::sync::Arc<
        std::sync::RwLock<Option<std::sync::Arc<karstflow_net::RetransmitService>>>,
    > = std::sync::Arc::new(std::sync::RwLock::new(None));

    // Wire leader slot orchestration.
    {
        let leader_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        let leader_signing_key = ed25519_dalek::SigningKey::from_bytes(identity.secret_key());
        let shred_version = node_config.expected_shred_version.unwrap_or(1);

        // In cluster mode (genesis file), skip self-replay via ShredCollector.
        // The slot driver manages bank lifecycle directly for leader slots.
        // Self-replay would cause BankFrozen → mark_dead → BlockCostLimitExceeded.
        let orchestrator_shred_sender = if node_config.genesis_path.is_some() {
            None
        } else {
            direct_shred_sender
        };

        leader_orchestrator::spawn_leader_orchestrator(
            &replay_bundle.signal_bus,
            pipeline_bundle.handle.clone(),
            leader_pubkey,
            leader_signing_key,
            shred_version,
            deferred_retransmit.clone(),
            shared_blockstore.clone(),
            orchestrator_shred_sender,
        );
    }

    // Cluster slot driver for genesis-file mode.
    let has_genesis_file = node_config.genesis_path.is_some();
    if has_genesis_file && !is_dev_mode {
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        slot_driver::spawn_cluster_slot_driver(
            identity_pubkey,
            consensus.bank_forks.clone(),
            replay_bundle.signal_bus.clone(),
            pipeline_bundle.handle.clone(),
            if is_dev_mode {
                1
            } else {
                karstflow_constants::ledger::DEFAULT_HASHES_PER_TICK
            },
        );
    }

    // Dev mode genesis completion.
    if is_dev_mode {
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
        slot_driver::spawn_dev_slot_driver(
            identity_pubkey,
            consensus.bank_forks.clone(),
            replay_bundle.signal_bus.clone(),
            pipeline_bundle.handle.clone(),
        );
    }

    // Build the turbine retransmit service for shred propagation.
    // Uses the gossip-derived identity and cluster state to route shreds
    // through the turbine tree.
    let turbine_bundle = build_turbine_service(
        node_id,
        cluster_info.clone(),
        consensus.vote_processor.clone(),
        &node_config.network_config,
    )?;
    let retransmit_service = turbine_bundle.retransmit;

    // Wire turbine retransmit into the leader orchestrator (deferred).
    if let Ok(mut guard) = deferred_retransmit.write() {
        *guard = Some(retransmit_service.clone());
    }

    // Spawn turbine receiver: listens on TVU port and feeds received
    // shreds directly into ShredCollector for cross-node block propagation.
    if let Some(tvu_sender) = tvu_shred_sender {
        let tvu_addr = node_config.tvu_bind_addr();
        turbine_receiver::spawn_turbine_receiver(tvu_addr, tvu_sender);
    }

    // Build the repair service for slot recovery from peers.
    // The coordinator runs poll-driven in the node runtime; background I/O
    // handles actual UDP request/response on a dedicated thread.
    let shred_provider: Option<std::sync::Arc<dyn karstflow_net::ShredProvider>> =
        shared_blockstore.as_ref().map(|bs| {
            std::sync::Arc::new(BlockstoreShredProvider::new(std::sync::Arc::clone(bs)))
                as std::sync::Arc<dyn karstflow_net::ShredProvider>
        });
    let repair_bundle = build_repair_service(
        node_id,
        cluster_info.clone(),
        consensus.vote_processor.clone(),
        consensus.bank_forks.clone(),
        shred_provider,
        shred_arrival_rx,
        node_config.repair_bind_addr(),
    )?;
    // Keep repair I/O handle alive — its JoinHandle keeps the background
    // UDP requester/server thread running for the repair service lifetime.
    let _repair_io = repair_bundle.io_handle;
    let repair_stats = repair_bundle.repair_stats;

    // Keep handles to consensus state for the live RPC provider and gossip vote handler.
    let rpc_bank_forks = consensus.bank_forks.clone();
    let rpc_commitment_tracker = consensus.commitment_tracker.clone();
    let rpc_cluster_info = cluster_info.clone();
    let gossip_vote_processor = consensus.vote_processor.clone();
    let gossip_fork_choice = consensus.fork_choice.clone();
    let gossip_commitment = consensus.commitment_tracker.clone();

    // Build the vote broadcast service. Monitors the shared Tower for
    // new consensus decisions and pushes them to gossip as CrdsValue
    // entries.
    let vote_sender_tower = consensus.tower.clone();
    let vote_sender_forks = consensus.bank_forks.clone();
    let reporter_bank_forks = consensus.bank_forks.clone();
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

    // Gossip vote handler: poll CRDS for vote values from other validators
    // and feed them into VoteProcessor + CommitmentTracker for faster
    // optimistic confirmation and fork choice updates.
    let consensus_stats = std::sync::Arc::new(karstflow_stages::AtomicConsensusStats::default());
    {
        let gv_cluster_info = rpc_cluster_info.clone();
        let gv_vote_processor = gossip_vote_processor;
        let gv_fork_choice = gossip_fork_choice;
        let gv_commitment = gossip_commitment;
        let gv_consensus_stats = std::sync::Arc::clone(&consensus_stats);

        std::thread::Builder::new()
            .name("gossip-votes".into())
            .spawn(move || {
                let mut cursor: u64 = gv_cluster_info.cursor();

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(
                        karstflow_constants::gossip::GOSSIP_VOTE_POLL_INTERVAL_MS,
                    ));

                    let (values, new_cursor) = gv_cluster_info.values_since_cursor(cursor);
                    if new_cursor == cursor {
                        // Even without new votes, flush VP stats on each poll
                        // so Prometheus always has fresh consensus data.
                        if let Ok(vp) = gv_vote_processor.lock() {
                            let s = vp.get_stats();
                            gv_consensus_stats.total_slots_with_votes.store(
                                s.total_slots_with_votes as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.slots_with_supermajority.store(
                                s.slots_with_supermajority as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.slots_propagated.store(
                                s.slots_propagated as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.slots_duplicate_confirmed.store(
                                s.slots_duplicate_confirmed as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.slots_super_confirmed.store(
                                s.slots_super_confirmed as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.total_validators.store(
                                s.total_validators as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats.active_validators.store(
                                s.active_validators as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            gv_consensus_stats
                                .total_stake
                                .store(s.total_stake, std::sync::atomic::Ordering::Relaxed);
                        }
                        continue;
                    }
                    cursor = new_cursor;

                    // Filter for vote CRDS values from other validators.
                    let votes: Vec<_> = values
                        .iter()
                        .filter_map(|v| {
                            if let karstflow_net::gossip::crds::CrdsValueData::Vote(vote) = &v.data
                            {
                                Some((v.origin, vote.slot))
                            } else {
                                None
                            }
                        })
                        .collect();

                    if votes.is_empty() {
                        continue;
                    }

                    // Lock vote processor to resolve identity -> vote account
                    // and process each gossip vote.
                    let mut vp = gv_vote_processor
                        .lock()
                        .expect("vote_processor lock poisoned");
                    let mut fc = gv_fork_choice.lock().expect("fork_choice lock poisoned");
                    let mut ct = gv_commitment.lock().expect("commitment lock poisoned");

                    for (node_identity, slot) in votes {
                        let node_pubkey = karstflow_storage::Pubkey::from(node_identity);
                        if let Some(vote_account) = vp.vote_account_for_node_identity(&node_pubkey)
                        {
                            let _events =
                                vp.process_gossip_vote(vote_account, slot, Some(&mut fc), &mut ct);
                        }
                    }
                }
            })
            .expect("failed to spawn gossip-votes thread");
    }

    // Build MetricsAggregator from pipeline stage stats and attach to reporter.
    // This enables all pipeline metrics (verify, resolv, pack, exec, shred,
    // gossip) to appear on the Prometheus /metrics endpoint.
    let reporter = runtime_topology.reporter.map(|rpt| {
        let mut aggregator = karstflow_stages::MetricsAggregator::new()
            .with_verify(std::sync::Arc::clone(
                &pipeline_bundle.handle.stage_stats.verify,
            ))
            .with_resolv(std::sync::Arc::clone(
                &pipeline_bundle.handle.stage_stats.resolv,
            ))
            .with_pack(std::sync::Arc::clone(
                &pipeline_bundle.handle.stage_stats.pack,
            ))
            .with_exec(std::sync::Arc::clone(
                &pipeline_bundle.handle.stage_stats.exec,
            ))
            .with_gossip_live(karstflow_stages::GossipStatsRef {
                push_messages_sent: gossip_handle.gossip_stats.push_messages_sent.clone(),
                push_messages_received: gossip_handle.gossip_stats.push_messages_received.clone(),
                pull_requests_sent: gossip_handle.gossip_stats.pull_requests_sent.clone(),
                pull_responses_received: gossip_handle.gossip_stats.pull_responses_received.clone(),
                pings_sent: gossip_handle.gossip_stats.pings_sent.clone(),
                pongs_received: gossip_handle.gossip_stats.pongs_received.clone(),
                prune_messages_received: gossip_handle.gossip_stats.prune_messages_received.clone(),
                nodes_discovered: gossip_handle.gossip_stats.nodes_discovered.clone(),
                nodes_pruned: gossip_handle.gossip_stats.nodes_pruned.clone(),
                bytes_sent: gossip_handle.gossip_stats.bytes_sent.clone(),
                bytes_received: gossip_handle.gossip_stats.bytes_received.clone(),
                send_errors: gossip_handle.gossip_stats.send_errors.clone(),
                receive_errors: gossip_handle.gossip_stats.receive_errors.clone(),
            });
        if let Some(ref shred_stats) = runtime_topology.shred_network_stats {
            aggregator = aggregator.with_shred_network(std::sync::Arc::clone(shred_stats));
        }
        if let Some(ref fec_stats) = runtime_topology.fec_resolver_stats {
            aggregator = aggregator.with_fec_resolver_live(std::sync::Arc::clone(fec_stats));
        }
        aggregator = aggregator.with_repair_live(std::sync::Arc::clone(&repair_stats));
        aggregator = aggregator.with_consensus_live(std::sync::Arc::clone(&consensus_stats));
        if let Some(ref bs) = shared_blockstore {
            aggregator = aggregator.with_blockstore(std::sync::Arc::clone(bs.stats()));
        }
        rpt.with_bank_forks(reporter_bank_forks.clone())
            .with_aggregator(aggregator)
    });

    let metrics_http_content = runtime_topology.metrics_http_content.clone();
    let health_status = runtime_topology.health_status.clone();
    let mut services = runtime_topology.services;
    // Push reporter into services after aggregator is attached.
    if let Some(rpt) = reporter {
        services.push(Box::new(rpt));
    }
    services.push(replay_bundle.service);
    services.push(pipeline_bundle.service);
    services.push(turbine_bundle.service);
    services.push(repair_bundle.service);
    services.push(vote_broadcast_bundle.service);
    match vote_sender_bundle {
        Ok(bundle) => services.push(bundle.service),
        Err(ref e) => {
            warn!(error = %e, "vote sender service unavailable, direct vote propagation disabled")
        }
    }

    // Storage maintenance: periodic compaction and flush of the durable store.
    if let Some(engine) = storage_engine_for_maintenance {
        let maintenance = build_storage_maintenance_service(engine, Default::default());
        services.push(maintenance.service);
    }

    // Shred store: persist completed FEC sets to the blockstore for repair
    // serving, restart recovery, and historical queries.
    if let (Some(blockstore), Some(fec_store_rx)) = (
        shared_blockstore.as_ref().cloned(),
        runtime_topology.fec_store_receiver,
    ) {
        let shred_store = karstflow_stages::ShredStoreService::new(
            karstflow_stages::ShredStoreConfig::default(),
            blockstore,
            fec_store_rx,
        )
        .with_signal_bus(std::sync::Arc::clone(&replay_bundle.signal_bus));
        services.push(Box::new(shred_store));
    }

    // Bridge retransmit decisions from the shred pipeline to the turbine
    // retransmit service. Each decision carries raw shred bytes that get
    // forwarded to turbine tree children via UDP.
    let _retransmit_bridge = if let Some(mut retransmit_rx) = runtime_topology.retransmit_receiver {
        let retransmit = std::sync::Arc::clone(&retransmit_service);
        Some(
            std::thread::Builder::new()
                .name("retransmit-fwd".into())
                .spawn(move || loop {
                    match retransmit_rx.try_recv() {
                        Ok(Some(decision)) => {
                            retransmit.forward_raw(&decision.shred_data);
                        }
                        Ok(None) => {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                        }
                        Err(_) => break,
                    }
                })
                .expect("failed to spawn retransmit forwarder thread"),
        )
    } else {
        None
    };

    // Keep gossip, retransmit, and plugins alive until run_runtime_phase returns.
    let _gossip = gossip_handle;
    let _retransmit = retransmit_service;

    // For cluster mode (genesis file), use ConsensusTransactionSubmitter
    // which resolves the current leader's TPU from gossip and forwards.
    // For single-node dev mode, bootstrap creates its own submitter.
    let tx_submitter: Option<std::sync::Arc<dyn karstflow_control::TransactionSubmitter>> =
        if has_genesis_file {
            Some(std::sync::Arc::new(ConsensusTransactionSubmitter::new(
                rpc_bank_forks.clone(),
                rpc_cluster_info.clone(),
                *identity.pubkey(),
                node_config.tpu_bind_addr(),
            )))
        } else {
            None
        };

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
        tx_submitter,
    );

    // Save tower state to disk before shutdown so lockouts survive restarts.
    if let Some(ref data_dir) = node_config.data_dir {
        let tower_r = tower_for_persist
            .read()
            .expect("tower lock poisoned at shutdown");
        let identity_pubkey = karstflow_storage::Pubkey::from(*identity.pubkey());
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
