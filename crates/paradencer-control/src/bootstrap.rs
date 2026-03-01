use crate::errors::{ControlPlaneError, Result};
use crate::output::{
    render_phase_cluster_mode_line, render_pinned_affinity_line, render_preflight_ok_line,
    render_topology_line,
};
use crate::{
    ensure_service_startup_probe_ok, run_network_socket_preflight, run_service_startup_probe,
};
use paradencer_config::{NodeConfig, ValidatorIdentity};
use paradencer_consensus::{
    bootstrap_from_snapshot, collect_validator_stakes, deserialize_transaction,
    resolve_address_lookups, Bank, BankForks, CommitmentLevel, CommitmentTracker, EpochSchedule,
    ForkChoice, LeaderSchedule, SavedTower, StakeTracker, Tower, TowerPersistenceError,
    VoteProcessor, VoteProcessorConfig,
};
use paradencer_core::{ExecutionMode, LinkKind, PinnedCorePolicy, StageKind};
use paradencer_execution::{ExecutionBridge, SbpfBackend};
use paradencer_mesh::{bounded_link, InPort, OutPort};
use paradencer_net::tile::{BridgeConfig, BridgeHandle};
use paradencer_net::{
    ClusterInfo, ContactInfo, GossipConfig, GossipService, GossipServiceStats, InMemoryShredStore,
    IngressMode, NodeId, OutboundRepair, RepairCoordinator, RepairCoordinatorConfig, RepairRequest,
    RepairService, RepairServiceConfig, RepairTarget, RetransmitService, RetransmitStats,
    ShredData, ShredIndex, ShredProvider, Slot, TurbineConfig, TurbineStats, TurbineTreeBuilder,
    UdpShredTransport, ValidatorInfo,
};
use paradencer_observability::spawn_metrics_http_bridge;
use paradencer_rpc::{
    metrics_file_provider, spawn_rpc_http_server, BankAccessProvider, TransactionSubmitter,
};
use paradencer_runtime::{build_pinned_affinity_plan, run_services, Service, ServiceProbeReport};
use paradencer_stages::{
    ExecutionErrorHandlingPolicy, MetricsContent, MetricsHttpServer, MetricsOutputTarget,
    PipelineHandle, PipelineServiceBuilder, PipelineServiceConfig, RawTransaction, ReplayService,
    ReplayServiceConfig, SbpfExecutionAdapter, SharedHealthStatus, ShredArrival, ShredCollector,
    ShredCollectorConfig,
};
use paradencer_storage::{
    AccountDatabase, Blockstore, MaintenanceConfig, Pubkey, SnapshotAction, SnapshotConfig,
    SnapshotCreator, SnapshotRestorer, SnapshotScheduler, StorageEngine, StorageMaintenanceService,
};
use paradencer_topology::{materialize_services_with_blockstore, MaterializedTopology};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use tracing::{error, info, warn};

pub struct ServiceBundle {
    pub topology_name: String,
    pub stage_count: usize,
    pub link_count: usize,
    pub services: Vec<Box<dyn Service>>,
    /// Shared metrics content buffer from topology materialization.
    /// Present when metrics output target is `Http`.
    pub metrics_http_content: Option<MetricsContent>,
    /// Shared health status for probe endpoints.
    pub health_status: Option<SharedHealthStatus>,
}

pub struct MaterializedServicePair {
    pub startup: MaterializedTopology,
    pub runtime: MaterializedTopology,
}

/// Result of building a transaction pipeline service.
///
/// Contains the service (for the runtime) and the cross-service handle
/// (for consensus and gossip to control leader slots).
pub struct PipelineBundle {
    /// The pipeline service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Handle for cross-service communication (begin/end slot, blockhash).
    pub handle: Arc<PipelineHandle>,
}

/// Build a transaction pipeline service for block production.
///
/// Creates the unified verify → resolv → pack → exec → PoH pipeline.
/// Input channels are provided by the topology materializer — each
/// `TransactionSanitizer` stage produces an `InPort<RawTransaction>`
/// that feeds directly into the pipeline.
///
/// The returned `PipelineHandle` allows other services (consensus, gossip)
/// to signal leader slots and register blockhashes.
pub fn build_pipeline_service(
    config: PipelineServiceConfig,
    inputs: Vec<InPort<RawTransaction>>,
) -> PipelineBundle {
    let mut builder = PipelineServiceBuilder::new().with_config(config);
    for input in inputs {
        builder = builder.add_input(input);
    }
    let (service, handle) = builder.build();
    PipelineBundle {
        service: Box::new(service),
        handle,
    }
}

// ---------------------------------------------------------------------------
// Consensus infrastructure + replay service
// ---------------------------------------------------------------------------

/// Shared consensus infrastructure used by replay and other services.
///
/// These components hold the mutable consensus state that multiple services
/// need access to: bank forks, fork choice, tower, vote processing, and
/// commitment tracking.
pub struct ConsensusBundle {
    pub bank_forks: Arc<RwLock<BankForks>>,
    pub fork_choice: Arc<Mutex<ForkChoice>>,
    pub execution_bridge: Arc<ExecutionBridge>,
    pub vote_processor: Arc<Mutex<VoteProcessor>>,
    pub tower: Arc<RwLock<Tower>>,
    pub commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    /// Persistent storage engine. `None` when running in-memory only.
    pub storage_engine: Option<Arc<StorageEngine>>,
    /// Shared account database for snapshot creation.
    /// `None` when running in-memory only.
    pub accounts: Option<Arc<AccountDatabase>>,
}

/// Result of building the replay service.
pub struct ReplayBundle {
    /// The replay service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Shared consensus infrastructure for other services to use.
    pub consensus: ConsensusBundle,
    /// Input channel sender for assembled blocks.
    pub block_input: OutPort<paradencer_stages::AssembledBlock>,
}

/// Attempt to load tower state from disk for crash recovery.
///
/// If a saved tower exists and belongs to the specified validator, the
/// voting history is restored. On first start (no saved tower) or on
/// any load error, returns a fresh empty tower so the node can proceed.
fn try_load_tower(data_dir: Option<&Path>, validator_identity: Option<&Pubkey>) -> Tower {
    let (Some(dir), Some(identity)) = (data_dir, validator_identity) else {
        return Tower::new();
    };

    match SavedTower::load_and_verify(dir, identity) {
        Ok(saved) => {
            let tower = saved.to_tower();
            info!(
                root = ?tower.root(),
                last_vote = ?tower.last_vote_slot(),
                votes = tower.votes().len(),
                "restored tower from disk",
            );
            tower
        }
        Err(TowerPersistenceError::NotFound(_)) => {
            info!("no saved tower found, starting fresh");
            Tower::new()
        }
        Err(e) => {
            warn!(error = %e, "failed to load saved tower, starting fresh");
            Tower::new()
        }
    }
}

/// Save the current tower state to disk for crash recovery.
///
/// Snapshots the tower under the validator's identity and writes it
/// atomically to `data_dir/tower.bin`. Errors are returned but should
/// typically be logged rather than treated as fatal.
pub fn save_tower_to_disk(
    tower: &Tower,
    data_dir: &Path,
    validator_identity: &Pubkey,
) -> Result<()> {
    let saved = SavedTower::from_tower(tower, *validator_identity);
    saved
        .save_to_directory(data_dir)
        .map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("failed to save tower: {e}"),
        })
}

/// Build consensus infrastructure from genesis state.
///
/// Creates all shared consensus components (BankForks, ForkChoice, Tower,
/// VoteProcessor, CommitmentTracker) initialized from a genesis bank.
/// The initial stake is used as a fallback for fork choice weight calculations
/// when no real stake data is available from the bank's stake tracker.
///
/// When `data_dir` is provided, accounts are backed by persistent storage
/// and recovered from disk on startup. Otherwise runs in-memory only.
///
/// If the bank has a populated stake tracker (e.g., from snapshot bootstrap),
/// the real total stake is used for fork choice and vote processing instead
/// of the hardcoded initial_stake fallback.
pub fn build_consensus_infrastructure(
    initial_stake: u64,
    data_dir: Option<&Path>,
    validator_pubkey: Option<&[u8; 32]>,
) -> Result<ConsensusBundle> {
    let (accounts, storage_engine) = if let Some(dir) = data_dir {
        let engine = StorageEngine::open(dir).map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("failed to open storage engine at {}: {e}", dir.display()),
        })?;
        let db = engine.create_account_database();
        let stats = engine
            .recover(&db)
            .map_err(|e| ControlPlaneError::Bootstrap {
                message: format!("account recovery failed: {e}"),
            })?;
        info!(
            accounts_loaded = stats.accounts.accounts_loaded,
            total_lamports = stats.accounts.total_lamports,
            "recovered accounts from persistent storage",
        );
        (Arc::new(db), Some(Arc::new(engine)))
    } else {
        (Arc::new(AccountDatabase::new()), None)
    };

    // Keep a reference for snapshot creation before accounts moves into the bank.
    let accounts_for_snapshot = if storage_engine.is_some() {
        Some(Arc::clone(&accounts))
    } else {
        None
    };

    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = match validator_pubkey {
        Some(pk) => Pubkey::from(*pk),
        None => Pubkey::new_unique(),
    };
    let validators = vec![(validator, initial_stake)];
    let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
    let genesis = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

    // Extract real stake data from the bank if available.
    // When restoring from a snapshot, the bank's stake tracker is populated
    // with actual delegations — use that for accurate consensus weights.
    let (effective_stake, vote_processor_tracker) =
        if let Some(tracker_arc) = genesis.stake_tracker() {
            let tracker = tracker_arc.read().unwrap();
            let real_stake = tracker.total_stake();
            if real_stake > 0 {
                info!(
                    delegations = tracker.delegation_count(),
                    total_lamports = real_stake,
                    "using real stake for consensus",
                );
                (real_stake, tracker.clone())
            } else {
                (initial_stake, StakeTracker::new(0))
            }
        } else {
            (initial_stake, StakeTracker::new(0))
        };

    let bank_forks = Arc::new(RwLock::new(BankForks::new(genesis)));
    let fork_choice = Arc::new(Mutex::new(ForkChoice::new(effective_stake)));
    let execution_bridge = Arc::new(ExecutionBridge::new());
    let vote_processor = Arc::new(Mutex::new(VoteProcessor::new(
        VoteProcessorConfig::default(),
        vote_processor_tracker,
    )));
    let identity_pubkey = validator_pubkey.map(|pk| Pubkey::from(*pk));
    let tower = Arc::new(RwLock::new(try_load_tower(
        data_dir,
        identity_pubkey.as_ref(),
    )));
    let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));

    Ok(ConsensusBundle {
        bank_forks,
        fork_choice,
        execution_bridge,
        vote_processor,
        tower,
        commitment_tracker,
        storage_engine,
        accounts: accounts_for_snapshot,
    })
}

/// Build consensus infrastructure from pre-initialized BankForks.
///
/// Use this when bootstrapping from a snapshot: the caller runs
/// `bootstrap_from_snapshot()` to produce a fully initialized `BankForks`
/// (with stake tracker, vote account cache, feature set, sysvar cache, and
/// stake history already populated), then wraps it with the remaining
/// consensus components (ForkChoice, Tower, VoteProcessor, CommitmentTracker).
///
/// The VoteProcessor receives a clone of the working bank's stake tracker
/// so consensus weight calculations use real delegation data from the snapshot.
/// ForkChoice is initialized with the total effective stake.
pub fn build_consensus_from_bank_forks(
    bank_forks: BankForks,
    storage_engine: Option<Arc<StorageEngine>>,
    data_dir: Option<&Path>,
    validator_identity: Option<&Pubkey>,
    accounts: Option<Arc<AccountDatabase>>,
) -> ConsensusBundle {
    let working_bank = bank_forks.working_bank();

    // Extract real stake data from the snapshot-initialized bank.
    let (effective_stake, vote_processor_tracker) =
        if let Some(tracker_arc) = working_bank.stake_tracker() {
            let tracker = tracker_arc.read().unwrap();
            let real_stake = tracker.total_stake();
            if real_stake > 0 {
                info!(
                    delegations = tracker.delegation_count(),
                    total_stake = real_stake,
                    "initialized consensus from snapshot stake",
                );
                (real_stake, tracker.clone())
            } else {
                warn!("snapshot has empty stake tracker, using unit stake");
                (1, StakeTracker::new(0))
            }
        } else {
            warn!("no stake tracker on snapshot bank, using unit stake");
            (1, StakeTracker::new(0))
        };

    drop(working_bank);

    let bank_forks = Arc::new(RwLock::new(bank_forks));
    let fork_choice = Arc::new(Mutex::new(ForkChoice::new(effective_stake)));
    let execution_bridge = Arc::new(ExecutionBridge::new());
    let vote_processor = Arc::new(Mutex::new(VoteProcessor::new(
        VoteProcessorConfig::default(),
        vote_processor_tracker,
    )));
    let tower = Arc::new(RwLock::new(try_load_tower(data_dir, validator_identity)));
    let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));

    ConsensusBundle {
        bank_forks,
        fork_choice,
        execution_bridge,
        vote_processor,
        tower,
        commitment_tracker,
        storage_engine,
        accounts,
    }
}

/// Build the replay service for processing assembled blocks through consensus.
///
/// Creates the replay pipeline with an input channel for assembled blocks
/// and returns the shared consensus infrastructure so other services
/// (e.g., pipeline, gossip) can interact with consensus state.
pub fn build_replay_service(config: ReplayServiceConfig, initial_stake: u64) -> ReplayBundle {
    let consensus = build_consensus_infrastructure(initial_stake, None, None)
        .expect("in-memory consensus infrastructure should not fail");

    let channel_depth = config.max_blocks_per_tick.saturating_mul(8).max(64);
    let (block_tx, block_rx) = bounded_link::<paradencer_stages::AssembledBlock>(channel_depth);

    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());
    let service = ReplayService::with_backend(
        config,
        block_rx,
        Arc::clone(&consensus.bank_forks),
        Arc::clone(&consensus.fork_choice),
        Arc::clone(&consensus.execution_bridge),
        backend,
        Arc::clone(&consensus.vote_processor),
        Arc::clone(&consensus.tower),
        Arc::clone(&consensus.commitment_tracker),
    );

    ReplayBundle {
        service: Box::new(service),
        consensus,
        block_input: block_tx,
    }
}

/// Build a replay service connected to an external block source.
///
/// Uses an existing `InPort<AssembledBlock>` from the topology's shred
/// pipeline instead of creating a new internal channel. This connects the
/// TVU receive path (EdgeIntake → ShredFilter → ShredNetworkService →
/// ShredCollector) directly to the replay service for consensus processing.
pub fn build_replay_service_with_block_input(
    config: ReplayServiceConfig,
    block_input: InPort<paradencer_stages::AssembledBlock>,
    initial_stake: u64,
) -> ReplayBundleWithExternalInput {
    let consensus = build_consensus_infrastructure(initial_stake, None, None)
        .expect("in-memory consensus infrastructure should not fail");

    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());
    let service = ReplayService::with_backend(
        config,
        block_input,
        Arc::clone(&consensus.bank_forks),
        Arc::clone(&consensus.fork_choice),
        Arc::clone(&consensus.execution_bridge),
        backend,
        Arc::clone(&consensus.vote_processor),
        Arc::clone(&consensus.tower),
        Arc::clone(&consensus.commitment_tracker),
    );

    let signal_bus = service.signal_bus();

    ReplayBundleWithExternalInput {
        service: Box::new(service),
        consensus,
        signal_bus,
    }
}

/// Result of building a replay service with an external block source.
///
/// Unlike `ReplayBundle`, this does not expose a `block_input` sender
/// because the input comes from the topology's shred pipeline.
pub struct ReplayBundleWithExternalInput {
    /// The replay service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Shared consensus infrastructure for other services to use.
    pub consensus: ConsensusBundle,
    /// Signal bus for subscribing to replay events (slot completed, root advanced, etc.).
    pub signal_bus: Arc<Mutex<paradencer_stages::SignalBus>>,
}

/// Build a replay service using pre-built consensus infrastructure.
///
/// Use this when bootstrapping from a snapshot: the caller runs
/// `restore_from_snapshot_archive` to produce a `ConsensusBundle`, then
/// passes it here along with the shred block input from the topology.
pub fn build_replay_service_with_consensus(
    config: ReplayServiceConfig,
    block_input: InPort<paradencer_stages::AssembledBlock>,
    consensus: ConsensusBundle,
    validator_identity: Option<[u8; 32]>,
) -> ReplayBundleWithExternalInput {
    let backend = Arc::new(SbpfExecutionAdapter::with_defaults());
    let mut service = ReplayService::with_backend(
        config,
        block_input,
        Arc::clone(&consensus.bank_forks),
        Arc::clone(&consensus.fork_choice),
        Arc::clone(&consensus.execution_bridge),
        backend,
        Arc::clone(&consensus.vote_processor),
        Arc::clone(&consensus.tower),
        Arc::clone(&consensus.commitment_tracker),
    );

    if let Some(identity) = validator_identity {
        service.set_validator_identity(identity);
    }

    let signal_bus = service.signal_bus();

    ReplayBundleWithExternalInput {
        service: Box::new(service),
        consensus,
        signal_bus,
    }
}

/// Restore accounts from a Solana snapshot archive and bootstrap consensus.
///
/// Performs the complete snapshot bootstrap sequence:
/// 1. Opens or creates a persistent storage engine at `data_dir`
/// 2. Reads and decompresses the snapshot archive (tar.zst)
/// 3. Populates the account database from AppendVec entries
/// 4. Initializes Bank, stake tracker, vote cache, features, sysvar cache
/// 5. Seeds transaction cache from the status cache
/// 6. Wraps in BankForks with consensus components (ForkChoice, Tower, etc.)
///
/// Returns a `ConsensusBundle` ready for use with `build_replay_service_with_consensus`.
pub fn restore_from_snapshot_archive(
    archive_path: &Path,
    data_dir: Option<&Path>,
    validator_identity: Option<&Pubkey>,
    expected_bank_hash: Option<&str>,
) -> Result<ConsensusBundle> {
    info!(path = %archive_path.display(), "restoring from snapshot archive");

    // Open persistent storage if data_dir is provided.
    let (accounts, storage_engine) = if let Some(dir) = data_dir {
        let engine = StorageEngine::open(dir).map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("failed to open storage engine at {}: {e}", dir.display()),
        })?;
        let db = engine.create_account_database();
        (Arc::new(db), Some(Arc::new(engine)))
    } else {
        (Arc::new(AccountDatabase::new()), None)
    };

    // Read and decompress the snapshot archive.
    let archive_file =
        std::fs::File::open(archive_path).map_err(|e| ControlPlaneError::Bootstrap {
            message: format!(
                "failed to open snapshot archive {}: {e}",
                archive_path.display()
            ),
        })?;
    let reader = std::io::BufReader::new(archive_file);

    let restorer = SnapshotRestorer::new();
    let restore_result = restorer
        .restore_compressed(reader, &accounts)
        .map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("snapshot restore failed: {e}"),
        })?;

    info!(
        accounts_loaded = restore_result.accounts_loaded,
        total_lamports = restore_result.total_lamports,
        slot = restore_result.slot,
        version = restore_result.version,
        "snapshot restore complete",
    );

    if restore_result.bank_state.is_none() {
        return Err(ControlPlaneError::Bootstrap {
            message: "snapshot archive missing bank state metadata — cannot bootstrap consensus"
                .to_string(),
        });
    }

    // Build the initial leader schedule from stake delegations in the snapshot.
    // Scans stake + vote accounts to map validator identities to their
    // delegated stake, then generates a weighted leader schedule for the
    // restored epoch.
    let mut validators = collect_validator_stakes(&accounts);
    if validators.is_empty() {
        // Fallback for snapshots with no delegated stake (e.g., single-node devnet).
        // Use a zeroed pubkey; the replay service will recompute the schedule
        // from live stake data once consensus is running.
        validators.push((Pubkey::zeroed(), 1));
        warn!("no delegated stake found in snapshot, using fallback for leader schedule");
    }
    let leader_schedule = Arc::new(
        LeaderSchedule::new(restore_result.slot, &validators).map_err(|e| {
            ControlPlaneError::Bootstrap {
                message: format!("failed to build leader schedule from snapshot stakes: {e:?}"),
            }
        })?,
    );
    info!(
        validators = validators.len(),
        "leader schedule built from snapshot stake data",
    );

    // Keep a reference for snapshot creation before accounts moves into bootstrap.
    let accounts_for_snapshot = if storage_engine.is_some() {
        Some(Arc::clone(&accounts))
    } else {
        None
    };

    let bootstrap_result = bootstrap_from_snapshot(accounts, &restore_result, leader_schedule)
        .map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("consensus bootstrap from snapshot failed: {e}"),
        })?;

    info!(
        slot = bootstrap_result.slot,
        delegations = bootstrap_result.stake_init.delegations_loaded,
        vote_accounts = bootstrap_result.vote_init.vote_accounts_loaded,
        features_activated = bootstrap_result.feature_init.features_activated,
        features_scanned = bootstrap_result.feature_init.feature_accounts_scanned,
        transactions_seeded = bootstrap_result.transactions_seeded,
        lthash_accounts = bootstrap_result.lthash_accounts,
        bank_hash_verified = bootstrap_result.bank_hash_verified,
        "snapshot bootstrap complete",
    );

    if !bootstrap_result.bank_hash_verified {
        warn!(
            computed = ?&bootstrap_result.computed_bank_hash[..8],
            expected = ?&bootstrap_result.expected_bank_hash[..8],
            "bank hash verification FAILED — consensus may produce incorrect results",
        );
    }

    // Wait-for-supermajority: validate expected bank hash if configured.
    // This is Phase 1 — validate the hash at startup. Phase 2 (gossip-based
    // 80% online tracking before leader promotion) requires gossip integration.
    if let Some(expected_hash_b58) = expected_bank_hash {
        let expected_bytes = bs58::decode(expected_hash_b58).into_vec().map_err(|e| {
            ControlPlaneError::Bootstrap {
                message: format!("invalid wait_for_supermajority_bank_hash base58: {e}"),
            }
        })?;
        if expected_bytes.len() != 32 {
            return Err(ControlPlaneError::Bootstrap {
                message: format!(
                    "wait_for_supermajority_bank_hash must be 32 bytes, got {}",
                    expected_bytes.len()
                ),
            });
        }
        if bootstrap_result.computed_bank_hash[..] != expected_bytes[..] {
            return Err(ControlPlaneError::Bootstrap {
                message: format!(
                    "wait-for-supermajority bank hash mismatch at slot {}: \
                     expected {}, computed {}",
                    bootstrap_result.slot,
                    expected_hash_b58,
                    bs58::encode(&bootstrap_result.computed_bank_hash).into_string(),
                ),
            });
        }
        info!(
            slot = bootstrap_result.slot,
            bank_hash = expected_hash_b58,
            "wait-for-supermajority bank hash validated",
        );
    }

    Ok(build_consensus_from_bank_forks(
        bootstrap_result.bank_forks,
        storage_engine,
        data_dir,
        validator_identity,
        accounts_for_snapshot,
    ))
}

// ---------------------------------------------------------------------------
// Gossip service: cluster peer discovery and state propagation
// ---------------------------------------------------------------------------

/// Handle for the running gossip service.
///
/// Holds a reference to the shared cluster information and manages
/// the background thread that runs the gossip protocol loops. Dropping
/// this handle signals the gossip service to shut down.
pub struct GossipHandle {
    /// The node identity used by gossip (needed by turbine, repair, etc.).
    pub node_id: NodeId,
    /// Shared cluster state — provides other subsystems with peer data.
    pub cluster_info: Arc<ClusterInfo>,
    /// Gossip protocol statistics (atomic counters — safe to read from any thread).
    pub gossip_stats: GossipServiceStats,
    /// Sends shutdown signal to the gossip background thread.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Background thread running the gossip tokio runtime.
    _thread_handle: std::thread::JoinHandle<()>,
}

impl Drop for GossipHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Resolve the validator identity from configuration.
///
/// In Live mode, loads the Ed25519 keypair from the configured file path
/// and verifies that the secret key derives the expected public key.
/// In Dev mode, generates a random keypair for testing.
pub fn resolve_validator_identity(node_config: &NodeConfig) -> Result<ValidatorIdentity> {
    if let Some(ref path) = node_config.identity_keypair_path {
        let identity = paradencer_config::load_identity_keypair(path).map_err(|e| {
            ControlPlaneError::Bootstrap {
                message: format!("failed to load identity keypair: {e}"),
            }
        })?;

        // Verify the public key matches the secret key derivation.
        let derived_pubkey = paradencer_crypto::public_key_from_secret(identity.secret_key());
        if &derived_pubkey != identity.pubkey() {
            return Err(ControlPlaneError::Bootstrap {
                message: "identity keypair public key does not match secret key derivation"
                    .to_string(),
            });
        }

        info!(identity = ?identity, "loaded validator keypair");
        Ok(identity)
    } else {
        let (secret_key, pubkey) = paradencer_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        info!(identity = ?identity, "generated ephemeral keypair (dev mode)");
        Ok(identity)
    }
}

/// Start the gossip service for cluster peer discovery.
///
/// Spawns a background thread with a dedicated tokio runtime that runs
/// the gossip protocol (push, pull, receive, prune loops). The returned
/// handle provides shared access to cluster information and manages the
/// service lifecycle.
///
/// Configured entrypoints from `node_config.live_entrypoints` are seeded
/// into the cluster table so the gossip service can bootstrap peer
/// discovery.
pub fn start_gossip_service(
    node_config: &NodeConfig,
    identity: &ValidatorIdentity,
) -> Result<GossipHandle> {
    let node_id = NodeId::new(*identity.pubkey());

    let gossip_bind_addr = node_config.gossip_bind_addr;
    let shred_version = node_config.expected_shred_version.unwrap_or(0);

    let contact_info = ContactInfo::new(
        node_id,
        gossip_bind_addr,
        node_config.tpu_bind_addr(),
        node_config.tpu_quic_bind_addr(),
        node_config.repair_bind_addr(),
        shred_version,
    );

    let gossip_config = GossipConfig {
        bind_addr: gossip_bind_addr,
        allow_private_addresses: node_config.gossip_allow_private_addresses,
        ..GossipConfig::default()
    };

    let entrypoint_addrs: Vec<std::net::SocketAddr> = node_config.live_entrypoints.to_vec();

    let (cluster_tx, cluster_rx) = std::sync::mpsc::sync_channel::<
        std::result::Result<(Arc<ClusterInfo>, GossipServiceStats), String>,
    >(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let thread_handle = std::thread::Builder::new()
        .name("gossip".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build gossip tokio runtime");

            rt.block_on(async move {
                let mut service =
                    match GossipService::new(node_id, contact_info, gossip_config).await {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = cluster_tx.send(Err(format!("{e}")));
                            return;
                        }
                    };

                let cluster_info = service.cluster_info();
                let gossip_stats = service.stats().clone();

                // Seed entrypoints for bootstrap peer discovery.
                cluster_info.add_entrypoints(&entrypoint_addrs);

                if let Err(e) = service.start().await {
                    let _ = cluster_tx.send(Err(format!("{e}")));
                    return;
                }

                let _ = cluster_tx.send(Ok((cluster_info, gossip_stats)));

                // Park until shutdown signal arrives. The spawned gossip
                // tasks (push/pull/receive/prune) run cooperatively on
                // this single-threaded runtime while we await.
                let _ = shutdown_rx.await;
                service.stop().await;
            });
        })
        .map_err(|e| ControlPlaneError::GossipServiceStartFailed {
            detail: format!("thread spawn failed: {e}"),
        })?;

    let (cluster_info, gossip_stats) = cluster_rx
        .recv()
        .map_err(|_| ControlPlaneError::GossipServiceStartFailed {
            detail: "gossip thread exited before reporting ready".to_string(),
        })?
        .map_err(|detail| ControlPlaneError::GossipServiceStartFailed { detail })?;

    Ok(GossipHandle {
        node_id,
        cluster_info,
        gossip_stats,
        shutdown_tx: Some(shutdown_tx),
        _thread_handle: thread_handle,
    })
}

// ---------------------------------------------------------------------------
// Turbine: shred retransmit and broadcast
// ---------------------------------------------------------------------------

/// Result of building the turbine retransmit service.
///
/// Contains the Service adapter (for the node runtime) and a reference
/// to the underlying retransmit service for cross-service interaction
/// (e.g., submitting shreds for retransmission, requesting missing shreds).
pub struct TurbineBundle {
    /// The service adapter to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Direct access to the retransmit service for cross-service use.
    pub retransmit: Arc<RetransmitService>,
}

/// Service adapter that wraps the poll-driven RetransmitService.
///
/// The retransmit service uses a `service()` call pattern rather than
/// the Service trait. This adapter bridges the two models by calling
/// `service()` on each tick and managing the start/stop lifecycle.
///
/// Periodically rebuilds the turbine tree from gossip ClusterInfo so
/// that retransmit routing reflects current cluster membership.
struct TurbineServiceAdapter {
    retransmit: Arc<RetransmitService>,
    cluster_info: Arc<ClusterInfo>,
    node_id: NodeId,
    turbine_config: TurbineConfig,
    ticks_since_tree_rebuild: u32,
    vote_processor: Arc<Mutex<VoteProcessor>>,
}

impl Service for TurbineServiceAdapter {
    fn name(&self) -> &'static str {
        "turbine-retransmit"
    }

    fn tick_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(2)
    }

    fn on_start(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        self.retransmit.start();
        self.rebuild_tree();
        Ok(())
    }

    fn tick(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        self.retransmit.service();

        // Rebuild the turbine tree every ~500 ticks (~1 second at 2ms tick).
        self.ticks_since_tree_rebuild += 1;
        if self.ticks_since_tree_rebuild >= 500 {
            self.ticks_since_tree_rebuild = 0;
            self.rebuild_tree();
        }

        Ok(())
    }

    fn on_stop(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        self.retransmit.stop();
        Ok(())
    }
}

impl TurbineServiceAdapter {
    fn rebuild_tree(&self) {
        let peers = self.cluster_info.get_all();
        if peers.is_empty() {
            return;
        }

        // Use real stake weights from the vote processor for
        // stake-weighted turbine tree construction.
        let node_stakes = self.vote_processor.lock().unwrap().stake_by_node_identity();

        let validators: Vec<ValidatorInfo> = peers
            .into_iter()
            .map(|ci| {
                let node_pubkey = Pubkey::from(ci.node_id.0);
                let stake = node_stakes.get(&node_pubkey).copied().unwrap_or(1);
                ValidatorInfo::new(ci, stake)
            })
            .collect();

        let self_contact_info = self.cluster_info.self_contact_info();
        let builder = TurbineTreeBuilder::new(self.turbine_config.clone());
        let tree = builder.build(self.node_id, self_contact_info, validators, 0);
        self.retransmit.update_tree(tree);
    }
}

/// Build the turbine retransmit service for shred propagation.
///
/// Creates a UDP transport for sending shreds and wraps the retransmit
/// service in a Service adapter. The turbine tree is periodically rebuilt
/// from the gossip ClusterInfo so routing stays current.
///
/// The returned `TurbineBundle` provides both the runtime Service and
/// direct access to the retransmit service for cross-service use
/// (e.g., the shred pipeline can submit received shreds for retransmit).
pub fn build_turbine_service(
    node_id: NodeId,
    cluster_info: Arc<ClusterInfo>,
    vote_processor: Arc<Mutex<VoteProcessor>>,
) -> Result<TurbineBundle> {
    let transport = Arc::new(
        UdpShredTransport::new("0.0.0.0:0".parse().unwrap()).map_err(|e| {
            ControlPlaneError::GossipServiceStartFailed {
                detail: format!("failed to bind turbine UDP socket: {e}"),
            }
        })?,
    );

    let turbine_config = TurbineConfig::default();
    let turbine_stats = Arc::new(TurbineStats::new());
    let retransmit_stats = RetransmitStats::new(turbine_stats);

    let retransmit = Arc::new(RetransmitService::new(
        node_id,
        transport,
        turbine_config.clone(),
        retransmit_stats,
    ));

    let adapter = TurbineServiceAdapter {
        retransmit: Arc::clone(&retransmit),
        cluster_info,
        node_id,
        turbine_config,
        ticks_since_tree_rebuild: 0,
        vote_processor,
    };

    Ok(TurbineBundle {
        service: Box::new(adapter),
        retransmit,
    })
}

// ---------------------------------------------------------------------------
// Repair: slot recovery via peer-to-peer shred requests
// ---------------------------------------------------------------------------

/// Handle for the background repair I/O (requester + server).
///
/// The repair service uses async tokio for network I/O (sending repair
/// requests, serving repair responses). This handle manages the background
/// thread and provides a shutdown mechanism.
pub struct RepairHandle {
    /// Sends shutdown signal to the repair background thread.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Background thread running the repair tokio runtime.
    _thread_handle: std::thread::JoinHandle<()>,
}

impl Drop for RepairHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Result of building the repair service.
///
/// Contains the poll-driven coordinator service (for the node runtime)
/// and the background I/O handle. The coordinator generates repair
/// requests based on forest state and peer policy; the background
/// service handles the actual UDP send/receive.
pub struct RepairBundle {
    /// The coordinator service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Background I/O handle — must be kept alive.
    pub io_handle: RepairHandle,
    /// Atomic repair coordinator stats for cross-thread metrics access.
    pub repair_stats: Arc<paradencer_stages::AtomicRepairStats>,
}

/// Service adapter that wraps the poll-driven RepairCoordinator.
///
/// Mirrors Firedancer's repair tile architecture: the coordinator runs a
/// synchronous `service()` loop that scans the slot forest for missing
/// shreds, generates repair requests through latency-aware peer selection,
/// and processes responses. The actual network I/O runs on a separate
/// background thread.
///
/// Periodically syncs peers from the gossip ClusterInfo and advances the
/// repair root from consensus.
struct RepairServiceAdapter {
    coordinator: RepairCoordinator,
    cluster_info: Arc<ClusterInfo>,
    vote_processor: Arc<Mutex<VoteProcessor>>,
    bank_forks: Arc<RwLock<BankForks>>,
    /// Channel for forwarding outbound repair requests to the I/O thread.
    outbound_tx: crossbeam_channel::Sender<OutboundRepair>,
    /// Channel for receiving shred arrival notifications from the collector.
    shred_arrival_rx: crossbeam_channel::Receiver<ShredArrival>,
    /// Atomic stats shared with the metrics aggregator.
    atomic_stats: Arc<paradencer_stages::AtomicRepairStats>,
    ticks_since_peer_sync: u32,
    last_root: u64,
}

impl Service for RepairServiceAdapter {
    fn name(&self) -> &'static str {
        "repair-coordinator"
    }

    fn tick_interval(&self) -> std::time::Duration {
        // Match Firedancer's repair tile tick rate: fast polling for
        // responsive slot recovery.
        std::time::Duration::from_millis(5)
    }

    fn on_start(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        self.sync_peers_from_gossip();
        Ok(())
    }

    fn tick(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        // Advance the repair root when consensus root moves forward.
        let current_root = self.bank_forks.read().unwrap().root_slot();
        if current_root > self.last_root {
            self.coordinator.advance_root(current_root);
            self.last_root = current_root;
        }

        // Drain shred arrival notifications from the collector. Each
        // notification tells the forest about a turbine-received shred
        // so it can track slot progress and avoid redundant requests.
        while let Ok(arrival) = self.shred_arrival_rx.try_recv() {
            self.coordinator.receive_turbine_shred(
                arrival.slot,
                arrival.shred_index,
                arrival.is_last_in_slot,
                arrival.parent_slot,
            );
        }

        // Generate repair requests and forward to the I/O thread for
        // actual network transmission via UDP.
        let outbound = self.coordinator.service();
        for repair in outbound {
            let _ = self.outbound_tx.try_send(repair);
        }

        // Periodically sync peers from gossip (~every 1 second at 5ms tick).
        self.ticks_since_peer_sync += 1;
        if self.ticks_since_peer_sync >= 200 {
            self.ticks_since_peer_sync = 0;
            self.sync_peers_from_gossip();

            // Flush coordinator stats to shared atomics for metrics access.
            let s = self.coordinator.stats();
            self.atomic_stats.flush_from(
                s.requests_generated,
                s.requests_deduped,
                s.requests_sent,
                s.responses_accepted,
                s.responses_duplicate,
                s.responses_unknown,
                s.requests_timed_out,
                s.slots_completed,
                s.orphan_requests,
            );
        }

        Ok(())
    }

    fn on_stop(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        Ok(())
    }
}

impl RepairServiceAdapter {
    /// Sync the coordinator's peer list from gossip ClusterInfo.
    ///
    /// Builds a node identity → stake mapping from the vote processor's
    /// registered vote accounts and their delegated stake, then adds
    /// each gossip peer with its real stake weight.  Peers whose
    /// identity does not appear in the stake map receive a fallback
    /// weight of 1 so they still participate in repair.
    fn sync_peers_from_gossip(&mut self) {
        let node_stakes = self.vote_processor.lock().unwrap().stake_by_node_identity();
        let all_peers = self.cluster_info.get_all();
        for contact in all_peers {
            let peer_id = contact.node_id.0;
            let node_key = paradencer_types::Pubkey::new(peer_id);
            let stake = node_stakes.get(&node_key).copied().unwrap_or(1);
            self.coordinator.add_peer(peer_id, stake);
        }
    }
}

/// Adapter that implements `ShredProvider` by reading from a `Blockstore`.
///
/// Delegates shred lookups to the blockstore's persistent storage, so the
/// repair server can serve shreds that survive restarts.
pub struct BlockstoreShredProvider {
    blockstore: Arc<Blockstore>,
}

impl BlockstoreShredProvider {
    pub fn new(blockstore: Arc<Blockstore>) -> Self {
        Self { blockstore }
    }
}

impl ShredProvider for BlockstoreShredProvider {
    fn get_shred(&self, slot: Slot, index: ShredIndex) -> Option<ShredData> {
        let data = self.blockstore.get_data_shred(slot, index).ok()??;
        let is_last = self
            .blockstore
            .get_slot_meta(slot)
            .ok()
            .flatten()
            .and_then(|meta| meta.expected_data_shreds)
            .map(|expected| index + 1 == expected)
            .unwrap_or(false);
        Some(ShredData::new(slot, index, data, is_last))
    }

    fn get_highest_shred_index(&self, slot: Slot) -> Option<ShredIndex> {
        let meta = self.blockstore.get_slot_meta(slot).ok()??;
        if meta.received_data_shreds > 0 {
            Some(meta.received_data_shreds - 1)
        } else {
            None
        }
    }

    fn get_shreds_in_range(&self, start_slot: Slot, end_slot: Slot) -> Vec<ShredData> {
        let mut result = Vec::new();
        for slot in start_slot..=end_slot {
            let meta = match self.blockstore.get_slot_meta(slot) {
                Ok(Some(m)) => m,
                _ => continue,
            };
            for idx in 0..meta.received_data_shreds {
                if let Some(shred) = self.get_shred(slot, idx) {
                    result.push(shred);
                }
            }
        }
        result
    }

    fn get_ancestors(&self, slot: Slot, count: u64) -> Vec<ShredData> {
        let mut result = Vec::new();
        for ancestor_slot in (slot.saturating_sub(count)..slot).rev() {
            let meta = match self.blockstore.get_slot_meta(ancestor_slot) {
                Ok(Some(m)) => m,
                _ => continue,
            };
            for idx in 0..meta.received_data_shreds {
                if let Some(shred) = self.get_shred(ancestor_slot, idx) {
                    result.push(shred);
                }
            }
        }
        result
    }
}

/// Convert a forest-generated `RepairTarget` into a wire `RepairRequest`.
pub(crate) fn convert_repair_target_to_request(
    requester: NodeId,
    target: &RepairTarget,
    nonce: u64,
) -> RepairRequest {
    match *target {
        RepairTarget::Shred { slot, index } => RepairRequest::Shred {
            requester,
            slot,
            index,
            nonce,
        },
        RepairTarget::HighestShred { slot } => RepairRequest::HighestShred {
            requester,
            slot,
            nonce,
        },
        RepairTarget::Orphan { slot } => RepairRequest::Orphan {
            requester,
            slot,
            nonce,
        },
    }
}

/// Build the repair coordinator and background I/O service.
///
/// The repair system has two parts:
/// 1. **Coordinator** (poll-driven Service): generates repair requests by
///    scanning the slot forest, selects peers via latency-aware policy,
///    tracks in-flight requests and timeouts. Runs in the node runtime.
/// 2. **I/O service** (async background thread): handles actual UDP
///    send/receive for repair requests and responses.
///
/// When a `shred_provider` is supplied, the repair server serves shreds
/// from persistent storage. Otherwise falls back to an empty in-memory store.
pub fn build_repair_service(
    node_id: NodeId,
    cluster_info: Arc<ClusterInfo>,
    vote_processor: Arc<Mutex<VoteProcessor>>,
    bank_forks: Arc<RwLock<BankForks>>,
    shred_provider: Option<Arc<dyn ShredProvider>>,
    shred_arrival_rx: crossbeam_channel::Receiver<ShredArrival>,
) -> Result<RepairBundle> {
    let root_slot = bank_forks.read().unwrap().root_slot();
    let coordinator = RepairCoordinator::new(root_slot, RepairCoordinatorConfig::default());

    // Channel for forwarding outbound repair requests to the I/O thread.
    let (outbound_tx, outbound_rx) = crossbeam_channel::bounded::<OutboundRepair>(256);

    let atomic_stats = Arc::new(paradencer_stages::AtomicRepairStats::default());

    let adapter = RepairServiceAdapter {
        coordinator,
        cluster_info: Arc::clone(&cluster_info),
        vote_processor,
        bank_forks,
        outbound_tx,
        shred_arrival_rx,
        atomic_stats: Arc::clone(&atomic_stats),
        ticks_since_peer_sync: 0,
        last_root: root_slot,
    };

    let provider: Arc<dyn ShredProvider> =
        shred_provider.unwrap_or_else(|| Arc::new(InMemoryShredStore::new()));

    // Spawn background thread for repair network I/O.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let io_cluster_info = Arc::clone(&cluster_info);
    let thread_handle = std::thread::Builder::new()
        .name("repair-io".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build repair tokio runtime");

            rt.block_on(async move {
                let config = RepairServiceConfig::default();

                let mut service = match RepairService::new(
                    node_id,
                    Arc::clone(&io_cluster_info),
                    config,
                    provider,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "repair service failed to start");
                        return;
                    }
                };

                if let Err(e) = service.start().await {
                    error!(error = %e, "repair service loops failed to start");
                    return;
                }

                // Spawn a task that forwards outbound repairs from the
                // coordinator (poll-driven) to the requester (async UDP).
                let request_sender = service.requester().get_request_sender();
                let fwd_cluster_info = Arc::clone(&io_cluster_info);
                tokio::spawn(async move {
                    loop {
                        let mut forwarded = 0u32;
                        while let Ok(repair) = outbound_rx.try_recv() {
                            let peer_id = NodeId(repair.peer);
                            if let Some(contact) = fwd_cluster_info.get(&peer_id) {
                                let request = convert_repair_target_to_request(
                                    node_id,
                                    &repair.target,
                                    repair.nonce,
                                );
                                let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
                                let _ = request_sender
                                    .send((request, contact.repair_addr, response_tx))
                                    .await;
                                forwarded += 1;
                            }
                        }
                        if forwarded == 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }
                });

                // Park until shutdown.
                let _ = shutdown_rx.await;
            });
        })
        .map_err(|e| ControlPlaneError::GossipServiceStartFailed {
            detail: format!("repair thread spawn failed: {e}"),
        })?;

    Ok(RepairBundle {
        service: Box::new(adapter),
        io_handle: RepairHandle {
            shutdown_tx: Some(shutdown_tx),
            _thread_handle: thread_handle,
        },
        repair_stats: atomic_stats,
    })
}

// ---------------------------------------------------------------------------
// Vote broadcast: consensus decisions → gossip network
// ---------------------------------------------------------------------------

/// Result of building the vote broadcast service.
pub struct VoteBroadcastBundle {
    /// The poll-driven service for the node runtime.
    pub service: Box<dyn Service>,
}

/// Service adapter that broadcasts new tower votes via gossip.
///
/// Mirrors Firedancer's vote flow: tower tile (decision) → txsend tile
/// (sign + target leaders) → gossip tile (CRDS broadcast). Here the
/// adapter combines the signing and gossip insertion steps — it polls
/// the shared Tower for new vote slots, wraps them in signed CrdsValue
/// entries, and inserts them into ClusterInfo. The gossip service's push
/// loop then automatically propagates votes to cluster peers.
struct VoteBroadcastAdapter {
    tower: Arc<RwLock<paradencer_consensus::Tower>>,
    bank_forks: Arc<RwLock<paradencer_consensus::BankForks>>,
    cluster_info: Arc<ClusterInfo>,
    node_pubkey: [u8; 32],
    /// Ed25519 secret key for signing CRDS values and vote transactions.
    secret_key: [u8; 32],
    /// Vote account address (derived from identity pubkey by convention).
    vote_account: [u8; 32],
    /// Last vote slot we broadcast (avoids duplicate broadcasts).
    last_broadcast_slot: Option<u64>,
    /// Rotating vote index (0..255) for CRDS key differentiation.
    vote_index: u8,
}

impl Service for VoteBroadcastAdapter {
    fn name(&self) -> &'static str {
        "vote-broadcast"
    }

    fn tick_interval(&self) -> std::time::Duration {
        // Check for new votes every 50ms — fast enough for timely
        // broadcast without excessive polling.
        std::time::Duration::from_millis(50)
    }

    fn on_start(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        Ok(())
    }

    fn tick(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        let tower = self.tower.read().map_err(|_| {
            paradencer_runtime::RuntimeError::service_failure(
                "vote-broadcast",
                "tower lock poisoned",
            )
        })?;

        let current_vote_slot = tower.last_vote_slot();

        // Only broadcast if there's a new vote we haven't sent yet.
        if current_vote_slot.is_none() || current_vote_slot == self.last_broadcast_slot {
            return Ok(());
        }

        let vote_slot = current_vote_slot.unwrap();

        // Get the bank hash for the voted slot from BankForks.
        let bank_hash = {
            let forks = self.bank_forks.read().map_err(|_| {
                paradencer_runtime::RuntimeError::service_failure(
                    "vote-broadcast",
                    "bank_forks lock poisoned",
                )
            })?;
            forks.get(vote_slot).map(|b| b.hash())
        };
        let bank_hash = bank_hash.unwrap_or([0u8; 32]);

        // Build a signed TowerSync vote transaction.
        // The tower provides the full vote stack (slots + confirmation counts)
        // and optional root slot.
        let votes = tower.votes();
        let root = tower.root();
        let recent_blockhash = bank_hash; // Use bank hash as the recent blockhash

        let transaction_bytes = build_vote_transaction(
            &self.secret_key,
            &self.node_pubkey,
            &self.vote_account,
            votes,
            root,
            &recent_blockhash,
        );

        self.last_broadcast_slot = Some(vote_slot);

        // Rotate the vote index so each vote gets a unique CRDS key.
        self.vote_index = self.vote_index.wrapping_add(1);

        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        let vote_gossip = paradencer_net::CrdsValueData::Vote(paradencer_net::VoteGossip {
            index: self.vote_index,
            slot: vote_slot,
            hash: bank_hash,
            transaction_bytes,
        });

        let mut crds_value = paradencer_net::CrdsValue {
            origin: self.node_pubkey,
            wallclock_nanos: now_nanos,
            signature: [0u8; 64],
            data: vote_gossip,
        };

        // Sign the CRDS value with the validator's Ed25519 key.
        // The signature covers the full signable payload (type, origin,
        // wallclock, sub_index, and data-specific fields).
        crds_value.sign(&self.secret_key);

        // Insert into CRDS table — the gossip push loop handles broadcast.
        self.cluster_info.insert_crds_value(crds_value, 1);

        Ok(())
    }

    fn on_stop(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        Ok(())
    }
}

/// Build a signed TowerSync vote transaction in Solana wire format.
///
/// The transaction contains a single TowerSync instruction targeting the
/// vote program. It is signed with the validator's Ed25519 identity key.
///
/// Wire format: `[sig_count(1)] [signature(64)] [message]`
/// Message: `[num_required_sigs(1)] [num_readonly_signed(0)] [num_readonly_unsigned(1)]`
///          `[account_keys] [recent_blockhash(32)] [instructions]`
pub fn build_vote_transaction(
    secret_key: &[u8; 32],
    node_pubkey: &[u8; 32],
    vote_account: &[u8; 32],
    votes: &[paradencer_consensus::TowerVote],
    root: Option<u64>,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    // Build TowerSync instruction data
    let mut instr_data = Vec::with_capacity(5 + 9 + votes.len() * 12 + 1);
    instr_data.extend_from_slice(
        &paradencer_constants::vote_program::INSTRUCTION_TOWER_SYNC.to_le_bytes(),
    );
    match root {
        Some(slot) => {
            instr_data.push(1);
            instr_data.extend_from_slice(&slot.to_le_bytes());
        }
        None => instr_data.push(0),
    }
    instr_data.extend_from_slice(&(votes.len() as u32).to_le_bytes());
    for vote in votes {
        instr_data.extend_from_slice(&vote.slot.to_le_bytes());
        instr_data.extend_from_slice(&vote.confirmation_count.to_le_bytes());
    }
    instr_data.push(0); // no timestamp

    // Account keys: [node_pubkey (signer+writable), vote_account (writable), vote_program (readonly)]
    // Vote program address: Vote111111111111111111111111111111111111111
    let vote_program_id: [u8; 32] = [
        7, 97, 72, 29, 53, 116, 116, 187, 124, 77, 118, 36, 235, 211, 189, 179, 216, 53, 94, 115,
        209, 16, 67, 252, 13, 163, 83, 128, 0, 0, 0, 0,
    ];

    // Build legacy message
    let mut message = Vec::with_capacity(128 + instr_data.len());
    // Header: num_required_signatures, num_readonly_signed_accounts, num_readonly_unsigned_accounts
    message.push(1); // 1 signature required (the validator identity)
    message.push(0); // 0 readonly signed accounts
    message.push(1); // 1 readonly unsigned account (vote program)
                     // Account keys (3 accounts)
    message.push(3); // compact-u16 for 3 accounts
    message.extend_from_slice(node_pubkey); // index 0: signer + writable
    message.extend_from_slice(vote_account); // index 1: writable
    message.extend_from_slice(&vote_program_id); // index 2: readonly
                                                 // Recent blockhash
    message.extend_from_slice(recent_blockhash);
    // Instructions (1 instruction)
    message.push(1); // compact-u16: 1 instruction
                     // Instruction: program_id_index, accounts, data
    message.push(2); // program_id_index = 2 (vote program)
    message.push(2); // compact-u16: 2 account indexes
    message.push(0); // account index 0 (node_pubkey)
    message.push(1); // account index 1 (vote_account)
                     // Instruction data length (compact-u16)
    let data_len = instr_data.len();
    if data_len < 128 {
        message.push(data_len as u8);
    } else {
        message.push(((data_len & 0x7F) | 0x80) as u8);
        message.push((data_len >> 7) as u8);
    }
    message.extend_from_slice(&instr_data);

    // Sign the message
    let signature = paradencer_crypto::sign_message(secret_key, &message).unwrap_or([0u8; 64]);

    // Build the full transaction: [sig_count] [signatures] [message]
    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    tx.push(1); // compact-u16: 1 signature
    tx.extend_from_slice(&signature);
    tx.extend_from_slice(&message);

    tx
}

/// Build the vote broadcast service.
///
/// Creates a poll-driven service that monitors the shared Tower for new
/// vote decisions and broadcasts them via gossip. The service reads the
/// Tower lock on each tick, constructs a VoteGossip CRDS value when a
/// new vote is detected, signs it with the validator's keypair, and
/// inserts it into ClusterInfo for the gossip push loop to distribute.
pub fn build_vote_broadcast_service(
    identity: &ValidatorIdentity,
    tower: Arc<RwLock<paradencer_consensus::Tower>>,
    bank_forks: Arc<RwLock<paradencer_consensus::BankForks>>,
    cluster_info: Arc<ClusterInfo>,
) -> VoteBroadcastBundle {
    // By convention, use the identity pubkey as the vote account address.
    // In a full deployment the vote account would be a separate key
    // registered on-chain, but for devnet testing the identity suffices.
    let vote_account = *identity.pubkey();

    let adapter = VoteBroadcastAdapter {
        tower,
        bank_forks,
        cluster_info,
        node_pubkey: *identity.pubkey(),
        secret_key: *identity.secret_key(),
        vote_account,
        last_broadcast_slot: None,
        vote_index: 0,
    };

    VoteBroadcastBundle {
        service: Box::new(adapter),
    }
}

// ---------------------------------------------------------------------------
// Snapshot creation: periodic full and incremental snapshots
// ---------------------------------------------------------------------------

/// Maximum accounts per AppendVec file in Solana-compatible archives.
const SNAPSHOT_MAX_ACCOUNTS_PER_VEC: usize = 10_000;

/// Spawn a background thread that creates snapshots on root advancement.
///
/// Listens for `RootAdvanced` signals from the replay stage and checks
/// the snapshot scheduler to decide whether a full or incremental snapshot
/// is due. Full snapshots capture the complete account state; incremental
/// snapshots capture only accounts modified since the last full snapshot.
///
/// Snapshots are written as Solana-compatible tar.zst archives with the
/// full bank state manifest. This ensures other validators can bootstrap
/// from these snapshots.
///
/// The scheduler automatically manages retention and expiration.
///
/// Returns `None` if accounts database is not available (in-memory mode).
pub fn spawn_snapshot_thread(
    signal_bus: &Arc<Mutex<paradencer_stages::SignalBus>>,
    accounts: Option<Arc<AccountDatabase>>,
    bank_forks: Arc<RwLock<BankForks>>,
    snapshot_dir: std::path::PathBuf,
    config: SnapshotConfig,
) -> Option<std::thread::JoinHandle<()>> {
    spawn_snapshot_thread_with_gossip(signal_bus, accounts, bank_forks, snapshot_dir, config, None)
}

pub fn spawn_snapshot_thread_with_gossip(
    signal_bus: &Arc<Mutex<paradencer_stages::SignalBus>>,
    accounts: Option<Arc<AccountDatabase>>,
    bank_forks: Arc<RwLock<BankForks>>,
    snapshot_dir: std::path::PathBuf,
    config: SnapshotConfig,
    cluster_info: Option<Arc<ClusterInfo>>,
) -> Option<std::thread::JoinHandle<()>> {
    let accounts = accounts?;

    let signal_rx = signal_bus
        .lock()
        .unwrap()
        .subscribe()
        .expect("signal bus subscriber limit not reached");

    let handle = std::thread::Builder::new()
        .name("snapshot-creator".into())
        .spawn(move || {
            let mut scheduler = SnapshotScheduler::new(config.clone());
            let creator = SnapshotCreator::new(config);
            // Track the latest full and incremental snapshot hashes for gossip.
            let mut latest_full: Option<(u64, [u8; 32])> = None;
            let mut latest_incrementals: Vec<(u64, [u8; 32])> = Vec::new();

            // Ensure snapshot directory exists.
            if let Err(e) = std::fs::create_dir_all(&snapshot_dir) {
                error!("failed to create snapshot directory: {e}");
                return;
            }

            while let Ok(signal) = signal_rx.recv() {
                let paradencer_stages::ReplaySignal::RootAdvanced(root_info) = signal else {
                    continue;
                };

                let slot = root_info.new_root;
                match scheduler.check_slot(slot) {
                    SnapshotAction::None => {}
                    SnapshotAction::Full => {
                        info!(slot, "creating full snapshot");
                        // Extract bank state from the root bank for the manifest.
                        let bank_state = extract_bank_state_for_slot(&bank_forks, slot);
                        match creator.create_solana_archive_with_state(
                            &accounts,
                            slot,
                            &snapshot_dir,
                            SNAPSHOT_MAX_ACCOUNTS_PER_VEC,
                            bank_state.as_ref(),
                        ) {
                            Ok(stats) => {
                                let (accounts_hash, _) = accounts.compute_accounts_hash();
                                info!(
                                    slot,
                                    accounts = stats.total_accounts,
                                    lamports = stats.total_lamports,
                                    compressed_bytes = stats.compressed_size,
                                    has_manifest = bank_state.is_some(),
                                    "full snapshot created",
                                );
                                scheduler.record_full(slot, stats.archive_path);
                                latest_full = Some((slot, accounts_hash));
                                latest_incrementals.clear();
                                if let Some(ref ci) = cluster_info {
                                    ci.publish_snapshot_hashes(
                                        (slot, accounts_hash),
                                        Vec::new(),
                                    );
                                }
                            }
                            Err(e) => {
                                error!(slot, error = %e, "full snapshot creation failed");
                            }
                        }
                    }
                    SnapshotAction::Incremental { base_slot } => {
                        info!(slot, base_slot, "creating incremental snapshot");
                        let bank_state = extract_bank_state_for_slot(&bank_forks, slot);
                        match creator.create_incremental_solana_archive(
                            &accounts,
                            slot,
                            base_slot,
                            &snapshot_dir,
                            SNAPSHOT_MAX_ACCOUNTS_PER_VEC,
                            bank_state.as_ref(),
                        ) {
                            Ok((stats, incr_stats)) => {
                                let (accounts_hash, _) = accounts.compute_accounts_hash();
                                info!(
                                    slot,
                                    base_slot,
                                    dirty_tracked = incr_stats.dirty_pubkeys_tracked,
                                    accounts_included = incr_stats.accounts_included,
                                    compressed_bytes = stats.compressed_size,
                                    has_manifest = bank_state.is_some(),
                                    "incremental snapshot created",
                                );
                                scheduler.record_incremental(slot, stats.archive_path);
                                latest_incrementals.push((slot, accounts_hash));
                                if let (Some(ref ci), Some(base)) =
                                    (&cluster_info, latest_full)
                                {
                                    ci.publish_snapshot_hashes(
                                        base,
                                        latest_incrementals.clone(),
                                    );
                                }
                            }
                            Err(e) => {
                                error!(
                                    slot,
                                    base_slot,
                                    error = %e,
                                    "incremental snapshot creation failed",
                                );
                            }
                        }
                    }
                }

                // Clean up expired snapshots after each creation cycle.
                let expired = scheduler.expired_snapshots();
                for path in &expired {
                    if let Err(e) = std::fs::remove_file(path) {
                        warn!(path = %path.display(), error = %e, "failed to remove expired snapshot");
                    }
                }
                if !expired.is_empty() {
                    scheduler.purge_expired();
                }
            }
        })
        .expect("failed to spawn snapshot-creator thread");

    Some(handle)
}

/// Extract bank state for a specific slot from BankForks.
///
/// Looks up the bank at the given slot and calls `to_snapshot_state()`
/// to produce the manifest data. Returns `None` if the bank is not
/// found (already pruned) — the snapshot will still be created but
/// without a manifest, which limits its usefulness for bootstrap.
fn extract_bank_state_for_slot(
    bank_forks: &Arc<RwLock<BankForks>>,
    slot: u64,
) -> Option<paradencer_storage::SnapshotBankState> {
    let forks = bank_forks.read().ok()?;
    let bank = forks.get(slot)?;
    Some(bank.to_snapshot_state())
}

// ---------------------------------------------------------------------------
// Storage maintenance: background compaction and flush
// ---------------------------------------------------------------------------

/// Result of building the storage maintenance service.
pub struct StorageMaintenanceBundle {
    /// The service adapter to add to the node runtime.
    pub service: Box<dyn Service>,
}

/// Service adapter that wraps the poll-driven StorageMaintenanceService.
///
/// Runs periodic compaction and flush operations on the persistent storage
/// engine. The adapter bridges the maintenance service's `tick()` method
/// to the node runtime's Service trait.
struct StorageMaintenanceAdapter {
    inner: StorageMaintenanceService,
}

impl Service for StorageMaintenanceAdapter {
    fn name(&self) -> &'static str {
        "storage-maintenance"
    }

    fn tick_interval(&self) -> std::time::Duration {
        // Check every 5 seconds — the inner service manages its own timers
        // for compaction and flush intervals. This tick rate is fast enough
        // to be responsive while adding negligible overhead (timer checks only).
        std::time::Duration::from_secs(5)
    }

    fn on_start(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        Ok(())
    }

    fn tick(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        let _report = self.inner.tick().map_err(|e| {
            paradencer_runtime::RuntimeError::service_failure(
                "storage-maintenance",
                &format!("maintenance tick failed: {e}"),
            )
        })?;
        Ok(())
    }

    fn on_stop(
        &mut self,
        _context: &paradencer_runtime::ServiceContext,
    ) -> paradencer_runtime::RuntimeResult<()> {
        // Final flush on shutdown to ensure durability.
        let _ = self.inner.force_flush();
        Ok(())
    }
}

/// Build the storage maintenance service for background housekeeping.
///
/// Creates a poll-driven service that periodically compacts column families
/// with accumulated dead space and flushes pending writes to disk. The
/// service runs as part of the node runtime's service loop.
///
/// Use `set_root_slot()` on the inner service (via the returned bundle)
/// to enable blockstore slot compaction as consensus advances.
pub fn build_storage_maintenance_service(
    engine: Arc<StorageEngine>,
    config: MaintenanceConfig,
) -> StorageMaintenanceBundle {
    let inner = StorageMaintenanceService::with_config(engine, config);
    let adapter = StorageMaintenanceAdapter { inner };
    StorageMaintenanceBundle {
        service: Box::new(adapter),
    }
}

// ---------------------------------------------------------------------------
// Blockstore
// ---------------------------------------------------------------------------

/// Open a persistent blockstore for shred storage and serving.
///
/// When `data_dir` is provided, opens a disk-backed blockstore at
/// `<data_dir>/blockstore`. Returns `None` when no data directory is configured
/// (in-memory-only mode). The same `Arc<Blockstore>` should be shared between
/// the shred pipeline (write path) and the repair service (read path).
pub fn build_blockstore(data_dir: Option<&Path>) -> Result<Option<Arc<Blockstore>>> {
    match data_dir {
        Some(dir) => {
            let blockstore_dir = dir.join("blockstore");
            std::fs::create_dir_all(&blockstore_dir).map_err(|e| ControlPlaneError::Bootstrap {
                message: format!(
                    "failed to create blockstore directory {}: {e}",
                    blockstore_dir.display()
                ),
            })?;
            let blockstore =
                Blockstore::open(&blockstore_dir).map_err(|e| ControlPlaneError::Bootstrap {
                    message: format!(
                        "failed to open blockstore at {}: {e}",
                        blockstore_dir.display()
                    ),
                })?;
            Ok(Some(Arc::new(blockstore)))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Shred pipeline: ShredCollector → ReplayService
// ---------------------------------------------------------------------------

/// Result of building the shred collection pipeline.
///
/// The shred collector receives parsed shreds, groups them by slot,
/// assembles complete slots into blocks, and feeds them to the replay service.
pub struct ShredPipelineBundle {
    /// The collector service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// Input channel sender for individual parsed shreds (from ShredFilter).
    pub shred_input: OutPort<paradencer_types::shred::Shred>,
    /// Receiver for assembled blocks (connect to ReplayService).
    pub block_receiver: InPort<paradencer_stages::AssembledBlock>,
}

/// Build a shred collection pipeline.
///
/// Creates a ShredCollector service that receives individual parsed shreds,
/// groups them by slot, detects block boundaries, and emits assembled blocks.
/// The caller should connect `block_receiver` to a ReplayService block input.
pub fn build_shred_pipeline(
    config: ShredCollectorConfig,
    blockstore: Option<Arc<Blockstore>>,
    repair_notifier: Option<crossbeam_channel::Sender<ShredArrival>>,
) -> ShredPipelineBundle {
    let shred_channel_depth = config.max_shreds_per_slot.max(256);
    let block_channel_depth = config.max_buffered_slots.max(64);

    let (shred_tx, shred_rx) = bounded_link::<paradencer_types::shred::Shred>(shred_channel_depth);
    let (block_tx, block_rx) =
        bounded_link::<paradencer_stages::AssembledBlock>(block_channel_depth);

    let mut collector = ShredCollector::with_config(shred_rx, block_tx, config);
    if let Some(bs) = blockstore {
        collector.set_blockstore(bs);
    }
    if let Some(notifier) = repair_notifier {
        collector.set_repair_notifier(notifier);
    }

    ShredPipelineBundle {
        service: Box::new(collector),
        shred_input: shred_tx,
        block_receiver: block_rx,
    }
}

/// Result of building the zero-copy shred pipeline.
///
/// Uses TileLink for zero-copy shred transport between ShredFilter
/// and ShredCollector instead of crossbeam channels.
#[allow(dead_code)]
pub struct ShredPipelineLinkBundle {
    /// The collector service to add to the node runtime.
    pub service: Box<dyn Service>,
    /// TileLink for zero-copy shred transport. The caller must keep this alive
    /// for the entire duration of the pipeline (LinkProducer/LinkConsumer reference it).
    pub shred_link: Box<paradencer_mesh::tile_link::TileLink>,
    /// Receiver for assembled blocks (connect to ReplayService).
    pub block_receiver: InPort<paradencer_stages::AssembledBlock>,
}

/// Build a zero-copy shred collection pipeline using TileLink.
///
/// Creates a ShredCollector that receives shreds via a crossbeam channel
/// (unchanged for now — TileLink on the collector input is Wave W003),
/// but the shred_link field provides the TileLink for the
/// ShredFilter → ShredNetworkService zero-copy path.
///
/// The caller creates LinkProducer/LinkConsumer from the returned
/// `shred_link` and wires them to ShredFilter and ShredNetworkService.
#[allow(dead_code)]
pub fn build_shred_pipeline_with_link(
    config: ShredCollectorConfig,
    blockstore: Option<Arc<Blockstore>>,
    repair_notifier: Option<crossbeam_channel::Sender<ShredArrival>>,
) -> ShredPipelineLinkBundle {
    let shred_channel_depth = config.max_shreds_per_slot.max(256);
    let block_channel_depth = config.max_buffered_slots.max(64);

    // Crossbeam channel for ShredCollector input (to be replaced in W003).
    let (_shred_tx, shred_rx) = bounded_link::<paradencer_types::shred::Shred>(shred_channel_depth);
    let (block_tx, block_rx) =
        bounded_link::<paradencer_stages::AssembledBlock>(block_channel_depth);

    let mut collector = ShredCollector::with_config(shred_rx, block_tx, config);
    if let Some(bs) = blockstore {
        collector.set_blockstore(bs);
    }
    if let Some(notifier) = repair_notifier {
        collector.set_repair_notifier(notifier);
    }

    // TileLink for ShredFilter → ShredNetworkService zero-copy path.
    let shred_link = Box::new(paradencer_stages::shred_link::new_shred_link());

    ShredPipelineLinkBundle {
        service: Box::new(collector),
        shred_link,
        block_receiver: block_rx,
    }
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
    materialize_services_from_config_with_blockstore(node_config, None)
}

/// Materialize topology services with an optional blockstore for shred persistence.
///
/// When a blockstore is provided, the ShredCollector writes every received shred
/// to persistent storage. The same `Arc<Blockstore>` should be shared with the
/// repair service (via `BlockstoreShredProvider`) for serving stored shreds.
pub fn materialize_services_from_config_with_blockstore(
    node_config: &NodeConfig,
    blockstore: Option<Arc<Blockstore>>,
) -> Result<MaterializedTopology> {
    materialize_services_with_blockstore(
        node_config.topology_spec.clone(),
        node_config.ingress_policy.clone(),
        node_config.metrics_output_format,
        node_config.metrics_output_target.clone(),
        node_config.storage_runtime_policy.clone(),
        blockstore,
        node_config.ipc_mode,
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

pub fn maybe_start_metrics_http_bridge(
    node_config: &NodeConfig,
    metrics_content: Option<MetricsContent>,
    health_status: Option<SharedHealthStatus>,
) -> Result<()> {
    if let Some(bind_addr) = node_config.metrics_http_bind {
        match &node_config.metrics_output_target {
            MetricsOutputTarget::File(path) => {
                spawn_metrics_http_bridge(bind_addr, path.clone())?;
            }
            MetricsOutputTarget::Http => {
                let content = metrics_content.ok_or(ControlPlaneError::Bootstrap {
                    message: "Http metrics target requires shared content buffer from topology"
                        .into(),
                })?;
                let mut server = MetricsHttpServer::bind(bind_addr, content).map_err(|e| {
                    ControlPlaneError::Bootstrap {
                        message: format!("failed to bind metrics HTTP server on {bind_addr}: {e}"),
                    }
                })?;
                if let Some(hs) = health_status {
                    server = server.with_health(hs);
                }
                info!(addr = %bind_addr, "starting Prometheus metrics HTTP server");
                std::thread::Builder::new()
                    .name("metrics-http".into())
                    .spawn(move || run_metrics_http_loop(server))
                    .map_err(|e| ControlPlaneError::Bootstrap {
                        message: format!("failed to spawn metrics HTTP thread: {e}"),
                    })?;
            }
            _ => return Err(ControlPlaneError::MetricsHttpRequiresFileTarget),
        }
    }
    Ok(())
}

fn run_metrics_http_loop(mut server: MetricsHttpServer) {
    loop {
        server.poll();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Spawn the QUIC ingress bridge and return a pipeline input channel.
///
/// When the node config enables QUIC ingress (`quic_enabled`), this
/// spawns the NetworkTile + QuicTile bridge on a dedicated thread and
/// starts a forwarder thread that converts completed QUIC transactions
/// into `RawTransaction` pipeline inputs.
///
/// Returns the `InPort<RawTransaction>` that should be added to the
/// pipeline service's inputs, plus the bridge handle (keep alive).
pub fn maybe_spawn_quic_bridge(
    node_config: &NodeConfig,
) -> Result<Option<(InPort<RawTransaction>, BridgeHandle)>> {
    if !node_config.quic_enabled {
        return Ok(None);
    }

    let bridge_config = BridgeConfig::default();
    let handle = paradencer_net::tile::spawn_bridge(bridge_config).map_err(|e| {
        ControlPlaneError::Bootstrap {
            message: format!("failed to spawn QUIC bridge: {e}"),
        }
    })?;

    // Create a pipeline input channel for the forwarder.
    let (pipeline_tx, pipeline_rx) = bounded_link::<RawTransaction>(2048);

    // Forwarder thread: reads QuicTransaction → sends RawTransaction.
    let tx_rx = handle.transaction_rx.clone();
    std::thread::Builder::new()
        .name("quic-pipeline-fwd".into())
        .spawn(move || {
            while let Ok(quic_tx) = tx_rx.recv() {
                let raw_tx = RawTransaction {
                    payload: quic_tx.payload,
                    source: paradencer_stages::TransactionSource::Quic,
                };
                if pipeline_tx.try_send(raw_tx).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| ControlPlaneError::Bootstrap {
            message: format!("failed to spawn QUIC pipeline forwarder: {e}"),
        })?;

    info!("QUIC ingress bridge started");
    Ok(Some((pipeline_rx, handle)))
}

#[cfg(test)]
pub(crate) fn maybe_start_rpc_http_server(node_config: &NodeConfig) -> Result<()> {
    maybe_start_rpc_http_server_with_consensus(node_config, None, None, None, [0u8; 32], None)
}

/// Start the RPC HTTP server with optional live consensus data.
///
/// When `bank_forks` is provided, the RPC server reads real slot, block
/// height, and transaction count data from the consensus layer instead
/// of from a metrics file on disk. This enables RPC methods to return
/// live validator state. The optional `commitment_tracker` enables
/// proper commitment-level resolution so confirmed/finalized queries
/// return data from the correct bank fork.
///
/// When `cluster_info` is provided alongside `bank_forks`, the RPC
/// server can forward `sendTransaction` requests to the current
/// leader's TPU socket via UDP.
pub fn maybe_start_rpc_http_server_with_consensus(
    node_config: &NodeConfig,
    bank_forks: Option<Arc<RwLock<BankForks>>>,
    commitment_tracker: Option<Arc<Mutex<CommitmentTracker>>>,
    cluster_info: Option<Arc<ClusterInfo>>,
    identity_pubkey: [u8; 32],
    blockstore: Option<Arc<Blockstore>>,
) -> Result<()> {
    if !node_config.rpc_enabled {
        return Ok(());
    }
    let bind_addr = node_config.rpc_bind.ok_or(ControlPlaneError::Config(
        paradencer_config::ConfigError::RpcEnabledRequiresBindAddr,
    ))?;

    let (runtime_snapshot_provider, bank_access_provider, tx_submitter) =
        if let Some(ref forks) = bank_forks {
            let snap: Option<Arc<dyn paradencer_rpc::RuntimeSnapshotProvider>> =
                Some(Arc::new(ConsensusSnapshotProvider::new(forks.clone())));
            let bank: Option<Arc<dyn BankAccessProvider>> =
                Some(Arc::new(ConsensusBankAccessProvider::new(
                    forks.clone(),
                    commitment_tracker,
                    identity_pubkey,
                    cluster_info.clone(),
                    blockstore,
                    node_config.expected_genesis_hash.clone(),
                )));
            let submitter: Option<Arc<dyn TransactionSubmitter>> =
                cluster_info.map(|ci| -> Arc<dyn TransactionSubmitter> {
                    Arc::new(ConsensusTransactionSubmitter::new(forks.clone(), ci))
                });
            (snap, bank, submitter)
        } else {
            let snapshot_provider: Option<Arc<dyn paradencer_rpc::RuntimeSnapshotProvider>> =
                match &node_config.metrics_output_target {
                    MetricsOutputTarget::File(path) => Some(metrics_file_provider(path.clone())),
                    _ => None,
                };
            (snapshot_provider, None, None)
        };

    spawn_rpc_http_server(
        bind_addr,
        node_config.rpc_full_api,
        node_config.rpc_private,
        runtime_snapshot_provider,
        bank_access_provider,
        tx_submitter,
    )?;
    Ok(())
}

/// Provides live RPC snapshots from the consensus layer.
///
/// Reads the working bank from BankForks to supply real slot, block
/// height, and transaction count data to the RPC server.
struct ConsensusSnapshotProvider {
    bank_forks: Arc<RwLock<BankForks>>,
}

impl ConsensusSnapshotProvider {
    fn new(bank_forks: Arc<RwLock<BankForks>>) -> Self {
        Self { bank_forks }
    }
}

impl paradencer_rpc::RuntimeSnapshotProvider for ConsensusSnapshotProvider {
    fn latest_snapshot(&self) -> Option<paradencer_rpc::RpcRuntimeSnapshot> {
        let forks = self.bank_forks.read().ok()?;
        let bank = forks.working_bank();
        Some(paradencer_rpc::RpcRuntimeSnapshot {
            slot: bank.slot(),
            block_height: bank.slot(),
            transaction_count: bank.transaction_count(),
            uptime_millis: 0,
            latest_blockhash_seed: bank.slot().wrapping_mul(0x517c_c1b7_2722_0a95),
        })
    }
}

/// Provides access to real account and blockhash data from the consensus layer.
///
/// Resolves commitment levels to the appropriate bank fork:
/// - Processed → working bank (tip of the chain)
/// - Confirmed → highest optimistically confirmed bank (2/3+ stake)
/// - Finalized → root bank (irreversible)
///
/// When the commitment tracker is unavailable, Confirmed falls back to the
/// working bank so the RPC layer degrades gracefully.
struct ConsensusBankAccessProvider {
    bank_forks: Arc<RwLock<BankForks>>,
    commitment_tracker: Option<Arc<Mutex<CommitmentTracker>>>,
    execution_backend: SbpfBackend,
    identity: [u8; 32],
    cluster_info: Option<Arc<ClusterInfo>>,
    blockstore: Option<Arc<Blockstore>>,
    genesis_hash: Option<String>,
}

impl ConsensusBankAccessProvider {
    fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        commitment_tracker: Option<Arc<Mutex<CommitmentTracker>>>,
        identity: [u8; 32],
        cluster_info: Option<Arc<ClusterInfo>>,
        blockstore: Option<Arc<Blockstore>>,
        genesis_hash: Option<String>,
    ) -> Self {
        Self {
            bank_forks,
            commitment_tracker,
            execution_backend: SbpfBackend::new(),
            identity,
            cluster_info,
            blockstore,
            genesis_hash,
        }
    }

    fn bank_for_commitment(&self, commitment: paradencer_rpc::RpcCommitment) -> Option<Arc<Bank>> {
        let forks = self.bank_forks.read().ok()?;
        Some(self.bank_for_commitment_inner(&forks, commitment))
    }

    /// Resolve bank for commitment level using an already-locked BankForks.
    fn bank_for_commitment_inner(
        &self,
        forks: &BankForks,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Arc<Bank> {
        match commitment {
            paradencer_rpc::RpcCommitment::Finalized => {
                forks.root_bank().unwrap_or_else(|| forks.working_bank())
            }
            paradencer_rpc::RpcCommitment::Confirmed => {
                if let Some(ref tracker) = self.commitment_tracker {
                    if let Ok(guard) = tracker.lock() {
                        if let Some(confirmed_slot) =
                            guard.highest_slot_with_commitment(CommitmentLevel::Confirmed)
                        {
                            if let Some(bank) = forks.get(confirmed_slot) {
                                return bank;
                            }
                        }
                    }
                }
                forks.working_bank()
            }
            paradencer_rpc::RpcCommitment::Processed => forks.working_bank(),
        }
    }
}

impl BankAccessProvider for ConsensusBankAccessProvider {
    fn get_account(
        &self,
        pubkey: &paradencer_types::Pubkey,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Option<paradencer_types::Account> {
        let bank = self.bank_for_commitment(commitment)?;
        bank.accounts().get_published_account(pubkey)
    }

    fn get_balance(
        &self,
        pubkey: &paradencer_types::Pubkey,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> u64 {
        self.bank_for_commitment(commitment)
            .and_then(|bank| bank.accounts().get_published_account(pubkey))
            .map(|account| account.meta.lamports)
            .unwrap_or(0)
    }

    fn get_slot(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.slot())
            .unwrap_or(0)
    }

    fn get_block_height(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        // Block height currently equals slot number.
        self.get_slot(commitment)
    }

    fn get_latest_blockhash(&self, commitment: paradencer_rpc::RpcCommitment) -> [u8; 32] {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.last_blockhash())
            .unwrap_or([0u8; 32])
    }

    fn is_blockhash_valid(
        &self,
        blockhash: &[u8; 32],
        commitment: paradencer_rpc::RpcCommitment,
    ) -> bool {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.is_blockhash_valid(blockhash))
            .unwrap_or(false)
    }

    fn get_lamports_per_signature(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.lamports_per_signature())
            .unwrap_or(paradencer_constants::economics::LAMPORTS_PER_SIGNATURE)
    }

    fn get_last_valid_block_height(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        self.get_block_height(commitment)
            .saturating_add(paradencer_constants::ledger::RECENT_BLOCKHASH_VALIDITY_WINDOW)
    }

    fn get_transaction_count(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.transaction_count())
            .unwrap_or(0)
    }

    fn get_capitalization(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.capitalization())
            .unwrap_or(0)
    }

    fn get_accounts_by_owner(
        &self,
        owner: &paradencer_types::Pubkey,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<(paradencer_types::Pubkey, paradencer_types::Account)> {
        self.bank_for_commitment(commitment)
            .map(|bank| bank.accounts().get_accounts_by_owner(owner))
            .unwrap_or_default()
    }

    fn get_slot_leader(
        &self,
        slot: u64,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Option<paradencer_types::Pubkey> {
        let bank = self.bank_for_commitment(commitment)?;
        let epoch_schedule = bank.epoch_schedule();
        let (_, slot_index) = epoch_schedule.get_epoch_and_slot_index(slot);
        bank.leader_schedule().get_leader(slot_index)
    }

    fn get_slot_leaders(
        &self,
        start_slot: u64,
        count: u64,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<(u64, Option<paradencer_types::Pubkey>)> {
        let bank = match self.bank_for_commitment(commitment) {
            Some(bank) => bank,
            None => {
                return (0..count)
                    .map(|i| (start_slot.saturating_add(i), None))
                    .collect();
            }
        };
        let epoch_schedule = bank.epoch_schedule();
        let schedule = bank.leader_schedule();
        (0..count)
            .map(|i| {
                let slot = start_slot.saturating_add(i);
                let (_, slot_index) = epoch_schedule.get_epoch_and_slot_index(slot);
                (slot, schedule.get_leader(slot_index))
            })
            .collect()
    }

    fn get_leader_schedule(
        &self,
        slot: u64,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Option<Vec<(paradencer_types::Pubkey, Vec<u64>)>> {
        let bank = self.bank_for_commitment(commitment)?;
        let epoch_schedule = bank.epoch_schedule();
        let schedule = bank.leader_schedule();
        let (epoch, _) = epoch_schedule.get_epoch_and_slot_index(slot);

        if schedule.get_epoch() != epoch {
            return None;
        }

        let first_slot = epoch_schedule.get_first_slot_in_epoch(epoch);
        let mut by_validator = std::collections::HashMap::new();
        for i in 0..schedule.len() as u64 {
            if let Some(leader) = schedule.get_leader(i) {
                by_validator
                    .entry(leader)
                    .or_insert_with(Vec::new)
                    .push(first_slot + i);
            }
        }
        Some(by_validator.into_iter().collect())
    }

    fn simulate_transaction(
        &self,
        raw_tx: &[u8],
        sig_verify: bool,
        replace_recent_blockhash: bool,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> paradencer_rpc::TransactionSimulationResponse {
        let bank = match self.bank_for_commitment(commitment) {
            Some(bank) => bank,
            None => {
                return paradencer_rpc::TransactionSimulationResponse {
                    error: Some("bank unavailable".to_string()),
                    logs: vec![],
                    units_consumed: 0,
                    accounts: vec![],
                    return_data: None,
                };
            }
        };

        // Deserialize transaction from wire format
        let deserialized = match deserialize_transaction(raw_tx) {
            Ok(d) => d,
            Err(e) => {
                return paradencer_rpc::TransactionSimulationResponse {
                    error: Some(e),
                    logs: vec![],
                    units_consumed: 0,
                    accounts: vec![],
                    return_data: None,
                };
            }
        };

        // Resolve address lookup tables for V0 transactions
        let mut tx = deserialized.tx;
        if !deserialized.address_table_lookups.is_empty() {
            let db = bank.accounts();
            match resolve_address_lookups(&deserialized.address_table_lookups, |key| {
                db.get_published_account(key)
            }) {
                Ok(resolved) => {
                    tx.num_writable_lookup_keys = resolved.writable.len();
                    tx.account_keys.extend(resolved.writable);
                    tx.account_keys.extend(resolved.readonly);
                }
                Err(e) => {
                    return paradencer_rpc::TransactionSimulationResponse {
                        error: Some(format!("{e:?}")),
                        logs: vec![],
                        units_consumed: 0,
                        accounts: vec![],
                        return_data: None,
                    };
                }
            }
        }

        // Run simulation
        let result = bank.simulate_transaction(
            &tx,
            &self.execution_backend,
            sig_verify,
            replace_recent_blockhash,
        );

        // Map return data to base58 program ID
        let return_data = result
            .return_data
            .map(|(program_id, data)| (bs58::encode(program_id.as_bytes()).into_string(), data));

        paradencer_rpc::TransactionSimulationResponse {
            error: result.error,
            logs: result.logs,
            units_consumed: result.compute_units_consumed,
            accounts: vec![], // Populated by the RPC handler per requested addresses
            return_data,
        }
    }

    fn get_identity(&self) -> Option<String> {
        if self.identity == [0u8; 32] {
            None
        } else {
            Some(bs58::encode(self.identity).into_string())
        }
    }

    fn get_cluster_nodes(&self) -> Vec<paradencer_rpc::RpcClusterNode> {
        let ci = match self.cluster_info.as_ref() {
            Some(ci) => ci,
            None => return Vec::new(),
        };
        let table = ci.crds_table().read();
        table
            .contact_info_entries()
            .into_iter()
            .filter_map(|entry| {
                let contact = entry.value.data.as_contact_info()?;
                let pubkey = bs58::encode(contact.pubkey).into_string();
                let gossip = contact
                    .sockets
                    .get(paradencer_constants::gossip::SOCKET_GOSSIP)
                    .copied()
                    .flatten()
                    .map(|a| a.to_string());
                let tpu = contact
                    .sockets
                    .get(paradencer_constants::gossip::SOCKET_TPU)
                    .copied()
                    .flatten()
                    .map(|a| a.to_string());
                let rpc = contact
                    .sockets
                    .get(paradencer_constants::gossip::SOCKET_RPC)
                    .copied()
                    .flatten()
                    .map(|a| a.to_string());
                let version = {
                    let v = &contact.version;
                    if v.major > 0 || v.minor > 0 || v.patch > 0 {
                        Some(format!("{}.{}.{}", v.major, v.minor, v.patch))
                    } else {
                        None
                    }
                };
                Some(paradencer_rpc::RpcClusterNode {
                    pubkey,
                    gossip,
                    tpu,
                    rpc,
                    version,
                })
            })
            .collect()
    }

    fn get_confirmed_blocks(&self, start_slot: u64, end_slot: u64) -> Vec<u64> {
        let bs = match self.blockstore.as_ref() {
            Some(bs) => bs,
            None => return Vec::new(),
        };
        // slot_range returns all slots that have metadata in the range.
        // Filter to only include root (confirmed/finalized) slots.
        bs.slot_range(start_slot, end_slot)
            .unwrap_or_default()
            .into_iter()
            .filter(|slot| bs.is_root(*slot))
            .collect()
    }

    fn get_block_time(&self, slot: u64) -> Option<i64> {
        let bs = self.blockstore.as_ref()?;
        let meta = bs.get_slot_meta(slot).ok()??;
        let ts = meta.first_shred_timestamp;
        if ts > 0 {
            Some(ts)
        } else {
            None
        }
    }

    fn has_slot(&self, slot: u64) -> bool {
        let bs = match self.blockstore.as_ref() {
            Some(bs) => bs,
            None => return false,
        };
        bs.get_slot_meta(slot).ok().flatten().is_some()
    }

    fn get_parent_slot(&self, slot: u64) -> Option<u64> {
        let bs = self.blockstore.as_ref()?;
        let meta = bs.get_slot_meta(slot).ok()??;
        meta.parent_slot
    }

    fn get_genesis_hash(&self) -> Option<String> {
        self.genesis_hash.clone()
    }

    fn get_largest_accounts(
        &self,
        limit: usize,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<(paradencer_types::Pubkey, u64)> {
        let bank = match self.bank_for_commitment(commitment) {
            Some(bank) => bank,
            None => return Vec::new(),
        };
        let db = bank.accounts();
        let mut all_accounts: Vec<(paradencer_types::Pubkey, u64)> = db
            .iter_published_accounts()
            .into_iter()
            .map(|(pubkey, account)| (pubkey, account.meta.lamports))
            .collect();
        all_accounts.sort_by(|a, b| b.1.cmp(&a.1));
        all_accounts.truncate(limit);
        all_accounts
    }

    fn get_first_available_block(&self) -> u64 {
        self.blockstore
            .as_ref()
            .and_then(|bs| {
                let roots = bs.roots();
                roots.into_iter().next()
            })
            .unwrap_or(0)
    }

    fn get_non_circulating_supply(&self, commitment: paradencer_rpc::RpcCommitment) -> u64 {
        let bank = match self.bank_for_commitment(commitment) {
            Some(bank) => bank,
            None => return 0,
        };
        let db = bank.accounts();

        // Non-circulating = lamports in vote accounts + stake accounts.
        let vote_total: u64 = db
            .get_accounts_by_owner(&paradencer_ids::VOTE_PROGRAM_ID)
            .iter()
            .map(|(_, acct)| acct.meta.lamports)
            .sum();
        let stake_total: u64 = db
            .get_accounts_by_owner(&paradencer_ids::STAKE_PROGRAM_ID)
            .iter()
            .map(|(_, acct)| acct.meta.lamports)
            .sum();

        vote_total.saturating_add(stake_total)
    }

    fn get_block_commitment(&self, slot: u64) -> Option<paradencer_rpc::RpcBlockCommitment> {
        let tracker = self.commitment_tracker.as_ref()?;
        let guard = tracker.lock().ok()?;
        let sc = guard.get_commitment(slot)?;

        // Build the 32-entry commitment array: for each depth bucket,
        // the total stake that has confirmed this slot at >= that depth.
        let mut commitment = vec![0_u64; 32];
        let depth = sc.confirmation_depth.min(31);
        commitment[depth] = sc.stake;
        Some(paradencer_rpc::RpcBlockCommitment {
            commitment,
            total_stake: sc.total_stake,
        })
    }

    fn get_epoch_for_slot(&self, slot: u64) -> u64 {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let bank = forks.working_bank();
        let (epoch, _) = bank.epoch_schedule().get_epoch_and_slot_index(slot);
        epoch
    }

    fn get_inflation_rate(&self, epoch: u64) -> Option<(f64, f64, f64)> {
        let forks = self.bank_forks.read().ok()?;
        let bank = forks.working_bank();
        let inflation = bank.inflation();
        let slots_per_epoch = bank.epoch_schedule().config().slots_per_epoch as f64;
        let year = (epoch as f64 * slots_per_epoch)
            / paradencer_constants::economics::DEFAULT_SLOTS_PER_YEAR;
        let total = inflation.total_rate(year);
        let validator = inflation.validator_rate(year);
        let foundation = inflation.foundation_rate(year);
        Some((total, validator, foundation))
    }

    fn get_signature_statuses(
        &self,
        signatures: &[[u8; 64]],
    ) -> Vec<Option<paradencer_rpc::RpcSignatureStatus>> {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return vec![None; signatures.len()],
        };
        let bank = forks.working_bank();
        bank.signature_status_cache()
            .get_batch(signatures)
            .into_iter()
            .map(|opt| {
                opt.map(|s| paradencer_rpc::RpcSignatureStatus {
                    slot: s.slot,
                    succeeded: s.succeeded,
                    error: s.error,
                })
            })
            .collect()
    }

    fn get_transaction(&self, signature: &[u8; 64]) -> Option<paradencer_rpc::RpcTransactionData> {
        // Look up the slot from the signature status cache.
        let forks = self.bank_forks.read().ok()?;
        let bank = forks.working_bank();
        let status = bank.signature_status_cache().get(signature)?;

        // Fetch block data from blockstore to find the matching transaction.
        let bs = self.blockstore.as_ref()?;
        let (_, entries) = bs.get_parsed_block(status.slot).ok()??;

        let sig_b58 = bs58::encode(signature).into_string();
        let block_time = bs.get_slot_meta(status.slot).ok().flatten().and_then(|m| {
            if m.first_shred_timestamp > 0 {
                Some(m.first_shred_timestamp)
            } else {
                None
            }
        });

        // Find the transaction with the matching signature.
        for entry in &entries {
            for tx_bytes in &entry.transactions {
                let sigs = paradencer_storage::extract_signatures(tx_bytes).unwrap_or_default();
                if sigs
                    .first()
                    .map(|s| s == signature.as_slice())
                    .unwrap_or(false)
                {
                    let sig_strings = sigs.iter().map(|s| bs58::encode(s).into_string()).collect();
                    return Some(paradencer_rpc::RpcTransactionData {
                        slot: status.slot,
                        block_time,
                        succeeded: status.succeeded,
                        error: status.error.clone(),
                        signatures: sig_strings,
                        raw_bytes: tx_bytes.clone(),
                    });
                }
            }
        }

        // Signature found in status cache but transaction not found in block data.
        // Return status-only response with the queried signature.
        Some(paradencer_rpc::RpcTransactionData {
            slot: status.slot,
            block_time,
            succeeded: status.succeeded,
            error: status.error,
            signatures: vec![sig_b58],
            raw_bytes: Vec::new(),
        })
    }

    fn get_signatures_for_address(
        &self,
        address: &paradencer_types::Pubkey,
        limit: usize,
        before: Option<&[u8; 64]>,
        until: Option<&[u8; 64]>,
        _commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<paradencer_rpc::RpcAddressSignatureEntry> {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let bank = forks.working_bank();
        let entries = bank
            .signature_status_cache()
            .get_signatures_for_address(address, limit, before, until);

        let bs = self.blockstore.as_ref();
        entries
            .into_iter()
            .map(|e| {
                let block_time = bs.and_then(|store| {
                    store.get_slot_meta(e.slot).ok().flatten().and_then(|m| {
                        if m.first_shred_timestamp > 0 {
                            Some(m.first_shred_timestamp)
                        } else {
                            None
                        }
                    })
                });
                paradencer_rpc::RpcAddressSignatureEntry {
                    signature: bs58::encode(e.signature).into_string(),
                    slot: e.slot,
                    succeeded: e.succeeded,
                    error: e.error,
                    block_time,
                }
            })
            .collect()
    }

    fn get_recent_prioritization_fees(
        &self,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<paradencer_rpc::RpcPrioritizationFee> {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let bank = self.bank_for_commitment_inner(&forks, commitment);
        let current_slot = bank.slot();
        let root_slot = forks
            .root_bank()
            .map(|b| b.slot())
            .unwrap_or(current_slot.saturating_sub(150));

        // Collect priority fees from recent slots (up to 150).
        let start = current_slot.saturating_sub(150).max(root_slot);
        let mut fees = Vec::new();
        for slot in (start..=current_slot).rev() {
            if let Some(slot_bank) = forks.get(slot) {
                fees.push(paradencer_rpc::RpcPrioritizationFee {
                    slot,
                    prioritization_fee: slot_bank.priority_fees(),
                });
            }
            if fees.len() >= 150 {
                break;
            }
        }
        fees
    }

    fn get_recent_performance_samples(
        &self,
        limit: usize,
        commitment: paradencer_rpc::RpcCommitment,
    ) -> Vec<paradencer_rpc::RpcPerformanceSample> {
        let forks = match self.bank_forks.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let bank = self.bank_for_commitment_inner(&forks, commitment);
        let current_slot = bank.slot();
        let root_slot = forks
            .root_bank()
            .map(|b| b.slot())
            .unwrap_or(current_slot.saturating_sub(150));

        // Build samples from recent slots. Each sample represents one slot.
        let start = current_slot.saturating_sub(150).max(root_slot);
        let mut samples = Vec::new();
        for slot in (start..=current_slot).rev() {
            if let Some(slot_bank) = forks.get(slot) {
                samples.push(paradencer_rpc::RpcPerformanceSample {
                    slot,
                    num_transactions: slot_bank.transaction_count(),
                    num_slots: 1,
                    sample_period_secs: 1,
                    num_non_vote_transactions: slot_bank.nonvote_transaction_count(),
                });
            }
            if samples.len() >= limit {
                break;
            }
        }
        samples
    }

    fn get_block_data(&self, slot: u64) -> Option<paradencer_rpc::RpcBlockData> {
        use paradencer_storage::extract_signatures;

        let bs = self.blockstore.as_ref()?;
        let (assembled, entries) = bs.get_parsed_block(slot).ok()??;

        let mut transactions = Vec::new();
        for entry in &entries {
            for tx_bytes in &entry.transactions {
                let sigs = extract_signatures(tx_bytes)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| bs58::encode(s).into_string())
                    .collect();
                transactions.push(paradencer_rpc::RpcBlockTransaction {
                    signatures: sigs,
                    raw_bytes: tx_bytes.clone(),
                });
            }
        }

        let meta = bs.get_slot_meta(slot).ok()??;
        let block_time = if meta.first_shred_timestamp > 0 {
            Some(meta.first_shred_timestamp)
        } else {
            None
        };

        // Fetch blockhash and block height from the bank for this slot.
        let (blockhash, prev_blockhash, block_height) = {
            let forks = self.bank_forks.read().ok()?;
            if let Some(bank) = forks.get(slot) {
                let bh = bs58::encode(bank.last_blockhash()).into_string();
                let parent_hash = meta
                    .parent_slot
                    .and_then(|ps| forks.get(ps))
                    .map(|pb| bs58::encode(pb.last_blockhash()).into_string());
                (Some(bh), parent_hash, Some(bank.slot()))
            } else {
                (None, None, None)
            }
        };

        Some(paradencer_rpc::RpcBlockData {
            slot,
            parent_slot: assembled.parent_slot,
            block_time,
            blockhash,
            previous_blockhash: prev_blockhash,
            block_height,
            transactions,
        })
    }
}

/// Provides leader pubkey lookups for shred signature verification.
///
/// Reads the leader schedule from the working bank in `BankForks` and
/// resolves absolute slot numbers to the 32-byte Ed25519 pubkey of the
/// assigned leader. Used by the shred network stage to verify incoming
/// shreds before accepting them into FEC sets.
pub struct ConsensusLeaderLookup {
    bank_forks: Arc<RwLock<BankForks>>,
}

impl ConsensusLeaderLookup {
    pub fn new(bank_forks: Arc<RwLock<BankForks>>) -> Self {
        Self { bank_forks }
    }
}

impl paradencer_stages::LeaderLookup for ConsensusLeaderLookup {
    fn leader_for_slot(&self, slot: u64) -> Option<[u8; 32]> {
        let forks = self.bank_forks.read().ok()?;
        let bank = forks.working_bank();
        let leader = bank
            .leader_schedule()
            .leader_for_absolute_slot(slot, bank.epoch_schedule())?;
        Some(leader.to_bytes())
    }
}

/// Forwards transactions to the current leader's TPU socket via UDP.
///
/// Resolves the current slot's leader from `BankForks` and looks up
/// their TPU socket address via `ClusterInfo`. The raw transaction
/// bytes are sent as a single UDP datagram. This is the standard
/// Solana transaction forwarding path used by validators and RPC nodes.
struct ConsensusTransactionSubmitter {
    bank_forks: Arc<RwLock<BankForks>>,
    cluster_info: Arc<ClusterInfo>,
    socket: std::net::UdpSocket,
}

impl ConsensusTransactionSubmitter {
    fn new(bank_forks: Arc<RwLock<BankForks>>, cluster_info: Arc<ClusterInfo>) -> Self {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .expect("failed to bind UDP socket for transaction forwarding");
        Self {
            bank_forks,
            cluster_info,
            socket,
        }
    }
}

/// Number of upcoming leader slots to try when forwarding transactions.
/// The current slot leader is tried first, then the next N-1 leaders.
const TPU_FORWARD_LEADER_COUNT: u64 = 4;

impl TransactionSubmitter for ConsensusTransactionSubmitter {
    fn submit_transaction(&self, tx_bytes: &[u8]) -> std::result::Result<[u8; 64], String> {
        // Extract the first signature from the raw transaction.
        // Wire format: [num_signatures: compact-u16] [sig0: 64 bytes] ...
        if tx_bytes.is_empty() {
            return Err("empty transaction".to_string());
        }
        let num_sigs = tx_bytes[0] as usize;
        if num_sigs == 0 {
            return Err("transaction has no signatures".to_string());
        }
        if tx_bytes.len() < 1 + 64 {
            return Err("transaction too short to contain a signature".to_string());
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&tx_bytes[1..65]);

        // Resolve TPU addresses for the current and next leaders.
        // Try multiple leaders so the transaction reaches the network even
        // if the current leader is unresponsive or its TPU is unknown.
        let tpu_addrs = {
            let forks = self
                .bank_forks
                .read()
                .map_err(|e| format!("bank_forks lock poisoned: {e}"))?;
            let bank = forks.working_bank();
            let slot = bank.slot();
            let epoch_schedule = bank.epoch_schedule();
            let leader_schedule = bank.leader_schedule();

            let mut addrs = Vec::with_capacity(TPU_FORWARD_LEADER_COUNT as usize);
            let mut seen_leaders = Vec::with_capacity(TPU_FORWARD_LEADER_COUNT as usize);

            for offset in 0..TPU_FORWARD_LEADER_COUNT {
                let target_slot = slot.saturating_add(offset);
                if let Some(leader) =
                    leader_schedule.leader_for_absolute_slot(target_slot, epoch_schedule)
                {
                    // Skip duplicate leaders (same leader for consecutive slots).
                    if seen_leaders.contains(&leader) {
                        continue;
                    }
                    seen_leaders.push(leader);

                    if let Some(addr) = self
                        .cluster_info
                        .lookup_socket(leader.as_bytes(), paradencer_constants::gossip::SOCKET_TPU)
                    {
                        addrs.push(addr);
                    }
                }
            }

            addrs
        };

        if tpu_addrs.is_empty() {
            return Err("no TPU address found for any upcoming leader".to_string());
        }

        // Forward to all resolved leader TPU addresses. A single success is
        // enough — the transaction will propagate through the network.
        let mut send_ok = 0_usize;
        let mut last_err = None;
        for addr in &tpu_addrs {
            match self.socket.send_to(tx_bytes, addr) {
                Ok(_) => send_ok += 1,
                Err(e) => {
                    last_err = Some(format!("UDP send to {addr} failed: {e}"));
                }
            }
        }

        if send_ok == 0 {
            return Err(last_err.unwrap_or_else(|| "all TPU sends failed".to_string()));
        }

        Ok(sig)
    }
}

pub fn print_preflight_ok() {
    println!("{}", render_preflight_ok_line());
}

pub fn run_runtime_phase(
    node_config: &NodeConfig,
    startup_services: &mut [Box<dyn Service>],
    runtime_bundle: ServiceBundle,
) -> Result<()> {
    run_runtime_phase_with_consensus(
        node_config,
        startup_services,
        runtime_bundle,
        None,
        None,
        None,
        [0u8; 32],
        None,
    )
}

/// Run the main validator runtime with optional live consensus data for RPC.
///
/// When `bank_forks` is provided, the RPC server reads real slot and
/// transaction data from the consensus layer instead of from a metrics
/// file on disk. The optional `commitment_tracker` enables proper
/// commitment-level resolution for confirmed slots. When `cluster_info`
/// is provided, the RPC server can forward transactions to leaders.
#[allow(clippy::too_many_arguments)]
pub fn run_runtime_phase_with_consensus(
    node_config: &NodeConfig,
    startup_services: &mut [Box<dyn Service>],
    runtime_bundle: ServiceBundle,
    bank_forks: Option<Arc<RwLock<BankForks>>>,
    commitment_tracker: Option<Arc<Mutex<CommitmentTracker>>>,
    cluster_info: Option<Arc<ClusterInfo>>,
    identity_pubkey: [u8; 32],
    blockstore: Option<Arc<Blockstore>>,
) -> Result<()> {
    run_startup_checks(node_config, startup_services, "startup", 0)?;
    maybe_start_metrics_http_bridge(
        node_config,
        runtime_bundle.metrics_http_content.clone(),
        runtime_bundle.health_status.clone(),
    )?;
    maybe_start_rpc_http_server_with_consensus(
        node_config,
        bank_forks,
        commitment_tracker,
        cluster_info,
        identity_pubkey,
        blockstore,
    )?;
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
        if node_config.runtime_spec.mode != ExecutionMode::Pinned
            && node_config.runtime_spec.mode != ExecutionMode::Tile
        {
            failed_checks.push(format!(
                "runtime mode is '{}', expected 'pinned' or 'tile'",
                node_config.runtime_spec.mode
            ));
        }
    }
    if node_config.runtime_spec.mode == ExecutionMode::Pinned
        || node_config.runtime_spec.mode == ExecutionMode::Tile
    {
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
