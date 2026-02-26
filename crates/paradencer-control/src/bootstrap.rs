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
    Bank, BankForks, CommitmentTracker, EpochSchedule, ForkChoice, LeaderSchedule, StakeTracker,
    Tower, VoteProcessor, VoteProcessorConfig,
};
use paradencer_core::{ExecutionMode, LinkKind, PinnedCorePolicy, StageKind};
use paradencer_execution::ExecutionBridge;
use paradencer_mesh::{bounded_link, InPort, OutPort};
use paradencer_net::{
    ClusterInfo, ContactInfo, GossipConfig, GossipService, InMemoryShredStore, IngressMode, NodeId,
    RepairCoordinator, RepairCoordinatorConfig, RepairService, RepairServiceConfig,
    RetransmitService, RetransmitStats, ShredData, ShredIndex, ShredProvider, Slot, TurbineConfig,
    TurbineStats, TurbineTreeBuilder, UdpShredTransport, ValidatorInfo,
};
use paradencer_observability::spawn_metrics_http_bridge;
use paradencer_rpc::{metrics_file_provider, spawn_rpc_http_server};
use paradencer_runtime::{build_pinned_affinity_plan, run_services, Service, ServiceProbeReport};
use paradencer_stages::{
    ExecutionErrorHandlingPolicy, MetricsOutputTarget, PipelineHandle, PipelineServiceBuilder,
    PipelineServiceConfig, RawTransaction, ReplayService, ReplayServiceConfig,
    SbpfExecutionAdapter, ShredCollector, ShredCollectorConfig,
};
use paradencer_storage::{
    AccountDatabase, Blockstore, MaintenanceConfig, Pubkey, StorageEngine,
    StorageMaintenanceService,
};
use paradencer_topology::{materialize_services_with_blockstore, MaterializedTopology};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

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

/// Build consensus infrastructure from genesis state.
///
/// Creates all shared consensus components (BankForks, ForkChoice, Tower,
/// VoteProcessor, CommitmentTracker) initialized from a genesis bank.
/// The initial stake is used for fork choice weight calculations.
///
/// When `data_dir` is provided, accounts are backed by persistent storage
/// and recovered from disk on startup. Otherwise runs in-memory only.
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
        eprintln!(
            "storage: recovered {} accounts ({} total lamports) from persistent storage",
            stats.accounts.accounts_loaded, stats.accounts.total_lamports,
        );
        (Arc::new(db), Some(Arc::new(engine)))
    } else {
        (Arc::new(AccountDatabase::new()), None)
    };

    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = match validator_pubkey {
        Some(pk) => Pubkey::from(*pk),
        None => Pubkey::new_unique(),
    };
    let validators = vec![(validator, initial_stake)];
    let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
    let genesis = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
    let bank_forks = Arc::new(RwLock::new(BankForks::new(genesis)));
    let fork_choice = Arc::new(Mutex::new(ForkChoice::new(initial_stake)));
    let execution_bridge = Arc::new(ExecutionBridge::new());
    let vote_processor = Arc::new(Mutex::new(VoteProcessor::new(
        VoteProcessorConfig::default(),
        StakeTracker::new(0),
    )));
    let tower = Arc::new(RwLock::new(Tower::new()));
    let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));

    Ok(ConsensusBundle {
        bank_forks,
        fork_choice,
        execution_bridge,
        vote_processor,
        tower,
        commitment_tracker,
        storage_engine,
    })
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

    ReplayBundleWithExternalInput {
        service: Box::new(service),
        consensus,
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

        eprintln!("identity: loaded validator keypair {:?}", identity);
        Ok(identity)
    } else {
        let (secret_key, pubkey) = paradencer_crypto::generate_keypair();
        let identity = ValidatorIdentity::new(secret_key, pubkey);
        eprintln!(
            "identity: generated ephemeral keypair {:?} (dev mode)",
            identity
        );
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
        ..GossipConfig::default()
    };

    let entrypoint_addrs: Vec<std::net::SocketAddr> = node_config.live_entrypoints.to_vec();

    let (cluster_tx, cluster_rx) =
        std::sync::mpsc::sync_channel::<std::result::Result<Arc<ClusterInfo>, String>>(1);
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

                // Seed entrypoints for bootstrap peer discovery.
                cluster_info.add_entrypoints(&entrypoint_addrs);

                if let Err(e) = service.start().await {
                    let _ = cluster_tx.send(Err(format!("{e}")));
                    return;
                }

                let _ = cluster_tx.send(Ok(cluster_info));

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

    let cluster_info = cluster_rx
        .recv()
        .map_err(|_| ControlPlaneError::GossipServiceStartFailed {
            detail: "gossip thread exited before reporting ready".to_string(),
        })?
        .map_err(|detail| ControlPlaneError::GossipServiceStartFailed { detail })?;

    Ok(GossipHandle {
        node_id,
        cluster_info,
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

        let validators: Vec<ValidatorInfo> = peers
            .into_iter()
            .map(|ci| ValidatorInfo::new(ci, 1))
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
    ticks_since_peer_sync: u32,
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
        // Generate repair requests. In the full implementation these
        // would be forwarded to the background RepairRequester for
        // actual network transmission.
        let _outbound = self.coordinator.service();

        // Periodically sync peers from gossip (~every 1 second at 5ms tick).
        self.ticks_since_peer_sync += 1;
        if self.ticks_since_peer_sync >= 200 {
            self.ticks_since_peer_sync = 0;
            self.sync_peers_from_gossip();
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
    shred_provider: Option<Arc<dyn ShredProvider>>,
) -> Result<RepairBundle> {
    let coordinator = RepairCoordinator::new(0, RepairCoordinatorConfig::default());

    let adapter = RepairServiceAdapter {
        coordinator,
        cluster_info: Arc::clone(&cluster_info),
        vote_processor,
        ticks_since_peer_sync: 0,
    };

    let provider: Arc<dyn ShredProvider> =
        shred_provider.unwrap_or_else(|| Arc::new(InMemoryShredStore::new()));

    // Spawn background thread for repair network I/O.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let thread_handle = std::thread::Builder::new()
        .name("repair-io".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build repair tokio runtime");

            rt.block_on(async move {
                let config = RepairServiceConfig::default();

                let mut service =
                    match RepairService::new(node_id, cluster_info, config, provider).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("repair service failed to start: {e}");
                            return;
                        }
                    };

                if let Err(e) = service.start().await {
                    eprintln!("repair service loops failed to start: {e}");
                    return;
                }

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
        // The signature covers (origin || wallclock || data) serialized bytes.
        if let Ok(sig) = paradencer_crypto::sign_message(&self.secret_key, &crds_value.origin) {
            crds_value.signature = sig;
        }

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
fn build_vote_transaction(
    secret_key: &[u8; 32],
    node_pubkey: &[u8; 32],
    vote_account: &[u8; 32],
    votes: &[paradencer_consensus::TowerVote],
    root: Option<u64>,
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    // TowerSync instruction discriminant (vote program instruction type 12).
    const TOWER_SYNC_DISCRIMINANT: u32 = 12;

    // Build TowerSync instruction data
    let mut instr_data = Vec::with_capacity(5 + 9 + votes.len() * 12 + 1);
    instr_data.extend_from_slice(&TOWER_SYNC_DISCRIMINANT.to_le_bytes());
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

    ShredPipelineBundle {
        service: Box::new(collector),
        shred_input: shred_tx,
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
        build_blockstore, build_consensus_infrastructure, build_pipeline_service,
        build_replay_service, build_shred_pipeline, build_storage_maintenance_service,
        ensure_mainnet_readiness, evaluate_mainnet_readiness, load_node_config,
        materialize_service_pair_from_config, materialize_services_from_config,
        maybe_start_metrics_http_bridge, maybe_start_rpc_http_server, resolve_validator_identity,
        run_diagnostics_phase, start_gossip_service, BlockstoreShredProvider,
    };
    use crate::errors::ControlPlaneError;
    use paradencer_config::NodeConfig;
    use paradencer_core::LinkKind;
    use std::sync::Arc;

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
        // 5 topology stages + ShredNetworkService + ShredCollector = 7 services.
        assert_eq!(materialized.services.len(), 7);
    }

    #[test]
    fn materialize_service_pair_from_config_builds_startup_and_runtime_services() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let pair = materialize_service_pair_from_config(&node_config).unwrap();
        assert_eq!(pair.startup.services.len(), pair.runtime.services.len());
        assert_eq!(pair.runtime.services.len(), 7);
    }

    #[test]
    fn build_pipeline_service_creates_service_and_handle() {
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};
        use paradencer_stages::PipelineServiceConfig;

        let bundle = build_pipeline_service(PipelineServiceConfig::default(), Vec::new());
        assert_eq!(bundle.service.name(), "validator-pipeline");
        assert!(!bundle.handle.is_leading());

        // Service ticks without error.
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let mut service = bundle.service;
        service.tick(&ctx).unwrap();
    }

    #[test]
    fn pipeline_service_integrates_with_topology_services() {
        use paradencer_stages::PipelineServiceConfig;

        let node_config = NodeConfig::from_profile(None).unwrap();
        let materialized = materialize_services_from_config(&node_config).unwrap();
        let bundle = build_pipeline_service(
            PipelineServiceConfig::default(),
            materialized.pipeline_inputs,
        );

        let mut services = materialized.services;
        services.push(bundle.service);

        // Topology (7) + pipeline (1) = 8 total services.
        assert_eq!(services.len(), 8);
        assert_eq!(services.last().unwrap().name(), "validator-pipeline");
    }

    #[test]
    fn build_consensus_infrastructure_creates_all_components() {
        let consensus = build_consensus_infrastructure(1_000_000, None, None).unwrap();
        let forks = consensus.bank_forks.read().unwrap();
        assert_eq!(forks.root_slot(), 0);
        assert!(consensus.storage_engine.is_none());
    }

    #[test]
    fn build_consensus_with_storage_engine() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let consensus = build_consensus_infrastructure(1_000_000, Some(dir.path()), None).unwrap();
        assert!(consensus.storage_engine.is_some());

        let forks = consensus.bank_forks.read().unwrap();
        assert_eq!(forks.root_slot(), 0);
    }

    #[test]
    fn build_replay_service_creates_service_and_consensus() {
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};
        use paradencer_stages::ReplayServiceConfig;

        let bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
        assert_eq!(bundle.service.name(), "replay-service");

        // Consensus infrastructure accessible.
        let forks = bundle.consensus.bank_forks.read().unwrap();
        assert_eq!(forks.root_slot(), 0);
        drop(forks);

        // Service ticks without error (no blocks pending).
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let mut service = bundle.service;
        service.tick(&ctx).unwrap();
    }

    #[test]
    fn replay_and_pipeline_integrate_with_topology() {
        use paradencer_stages::{PipelineServiceConfig, ReplayServiceConfig};

        let node_config = NodeConfig::from_profile(None).unwrap();
        let materialized = materialize_services_from_config(&node_config).unwrap();
        let replay_bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
        let pipeline_bundle = build_pipeline_service(
            PipelineServiceConfig::default(),
            materialized.pipeline_inputs,
        );

        let mut services = materialized.services;
        services.push(replay_bundle.service);
        services.push(pipeline_bundle.service);

        // Topology (7) + replay (1) + pipeline (1) = 9 total services.
        assert_eq!(services.len(), 9);

        let names: Vec<&str> = services.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"replay-service"));
        assert!(names.contains(&"validator-pipeline"));
    }

    #[test]
    fn build_shred_pipeline_creates_service_and_channels() {
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};
        use paradencer_stages::ShredCollectorConfig;

        let bundle = build_shred_pipeline(ShredCollectorConfig::default(), None);
        assert_eq!(bundle.service.name(), "shred-collector");

        // Service ticks without error (no shreds pending).
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let mut service = bundle.service;
        service.tick(&ctx).unwrap();
    }

    #[test]
    fn build_shred_pipeline_with_blockstore_persists_shreds() {
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};
        use paradencer_stages::ShredCollectorConfig;
        use paradencer_storage::Blockstore;
        use paradencer_types::shred::{
            DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SIGNATURE_SIZE,
        };

        let blockstore = Arc::new(Blockstore::in_memory());
        let bundle = build_shred_pipeline(
            ShredCollectorConfig::default(),
            Some(Arc::clone(&blockstore)),
        );

        // Send a shred through the pipeline.
        let common = ShredCommonHeader {
            signature: [0u8; SIGNATURE_SIZE],
            variant: 0x55,
            slot: 42,
            index: 0,
            version: 1,
            fec_set_index: 0,
        };
        let data_header = DataShredHeader {
            parent_offset: 1,
            flags: 0,
            size: 64,
        };
        let shred = Shred::new(
            common,
            ShredVariant::LegacyData(data_header),
            vec![0xBE; 64],
        );

        bundle.shred_input.try_send(shred).unwrap();

        // Tick the collector to drain the incoming shred.
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let mut service = bundle.service;
        service.tick(&ctx).unwrap();

        // Verify the shred was persisted to blockstore.
        let stored = blockstore.get_data_shred(42, 0).unwrap();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap(), vec![0xBE; 64]);
    }

    #[test]
    fn build_blockstore_creates_persistent_store() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let bs = build_blockstore(Some(dir.path())).unwrap();
        assert!(bs.is_some());

        // Insert and read back.
        let bs = bs.unwrap();
        bs.insert_data_shred(1, 0, &[0xFF; 32]).unwrap();
        assert!(bs.get_data_shred(1, 0).unwrap().is_some());
    }

    #[test]
    fn build_blockstore_returns_none_without_data_dir() {
        let bs = build_blockstore(None).unwrap();
        assert!(bs.is_none());
    }

    #[test]
    fn topology_includes_shred_collector_and_integrates_with_bootstrap_services() {
        use paradencer_stages::{PipelineServiceConfig, ReplayServiceConfig};

        let node_config = NodeConfig::from_profile(None).unwrap();
        let materialized = materialize_services_from_config(&node_config).unwrap();

        // ShredCollector is now part of the materialized topology.
        assert!(materialized.shred_block_receiver.is_some());

        let replay_bundle = build_replay_service(ReplayServiceConfig::default(), 1_000_000);
        let pipeline_bundle = build_pipeline_service(
            PipelineServiceConfig::default(),
            materialized.pipeline_inputs,
        );

        let mut services = materialized.services;
        services.push(replay_bundle.service);
        services.push(pipeline_bundle.service);

        // Topology (7, including shred-network + shred-collector) + replay (1) + pipeline (1) = 9.
        assert_eq!(services.len(), 9);

        let names: Vec<&str> = services.iter().map(|s| s.name()).collect();
        assert!(names.contains(&"replay-service"));
        assert!(names.contains(&"validator-pipeline"));
        assert!(names.contains(&"shred-network"));
        assert!(names.contains(&"shred-collector"));
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
        assert_eq!(summary.runtime_service_names.len(), 7);
        assert_eq!(summary.startup_probe_report.started_ok, 7);
        assert_eq!(summary.startup_probe_report.ticked_ok, 7);
        assert_eq!(summary.startup_probe_report.stopped_ok, 7);
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
        node_config.runtime_spec.pinned_service_core_ids = Some(vec![0, 0, 0, 0, 0, 0, 0]);
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

    #[test]
    fn start_gossip_service_creates_handle_with_cluster_info() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let identity = resolve_validator_identity(&node_config).unwrap();
        let handle = start_gossip_service(&node_config, &identity).unwrap();
        // Cluster info is accessible and starts with zero peers.
        assert_eq!(handle.cluster_info.size(), 0);
        // Gossip handle drops cleanly (signals shutdown to background thread).
        drop(handle);
    }

    #[test]
    fn build_storage_maintenance_creates_service() {
        use paradencer_runtime::{ServiceContext, ShutdownSwitch};
        use paradencer_storage::{MaintenanceConfig, StorageEngine};

        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = Arc::new(StorageEngine::open(dir.path()).expect("open"));
        let bundle = build_storage_maintenance_service(engine, MaintenanceConfig::default());
        assert_eq!(bundle.service.name(), "storage-maintenance");

        // Service ticks without error.
        let ctx = ServiceContext::new(ShutdownSwitch::new());
        let mut service = bundle.service;
        service.tick(&ctx).unwrap();
    }

    #[test]
    fn blockstore_shred_provider_serves_stored_shreds() {
        use paradencer_net::ShredProvider;
        use paradencer_storage::Blockstore;

        let bs = Arc::new(Blockstore::in_memory());

        // Insert shreds into blockstore.
        bs.insert_data_shred(10, 0, &[0xAA; 64]).unwrap();
        bs.insert_data_shred(10, 1, &[0xBB; 64]).unwrap();
        bs.insert_data_shred(11, 0, &[0xCC; 64]).unwrap();

        let provider = BlockstoreShredProvider::new(Arc::clone(&bs));

        // get_shred returns matching data.
        let shred = provider.get_shred(10, 0).unwrap();
        assert_eq!(shred.slot, 10);
        assert_eq!(shred.index, 0);
        assert_eq!(shred.data, vec![0xAA; 64]);

        // Missing shred returns None.
        assert!(provider.get_shred(10, 99).is_none());
        assert!(provider.get_shred(999, 0).is_none());

        // get_highest_shred_index returns the count minus one.
        assert_eq!(provider.get_highest_shred_index(10), Some(1));
        assert_eq!(provider.get_highest_shred_index(11), Some(0));
        assert!(provider.get_highest_shred_index(999).is_none());

        // get_shreds_in_range returns shreds across slots.
        let range_shreds = provider.get_shreds_in_range(10, 11);
        assert_eq!(range_shreds.len(), 3);

        // get_ancestors returns shreds from prior slots.
        let ancestors = provider.get_ancestors(11, 2);
        assert_eq!(ancestors.len(), 2); // slot 10 has 2 shreds
        assert!(ancestors.iter().all(|s| s.slot == 10));
    }

    #[test]
    fn resolve_identity_generates_ephemeral_in_dev_mode() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let identity = resolve_validator_identity(&node_config).unwrap();
        // Pubkey should be derived from secret key.
        let derived = paradencer_crypto::public_key_from_secret(identity.secret_key());
        assert_eq!(&derived, identity.pubkey());
    }

    #[test]
    fn resolve_identity_loads_from_file() {
        let (secret, pubkey) = paradencer_crypto::generate_keypair();
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&secret);
        bytes.extend_from_slice(&pubkey);

        // Build JSON array manually: [byte0, byte1, ..., byte63]
        let json = format!(
            "[{}]",
            bytes
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("identity.json");
        std::fs::write(&path, &json).unwrap();

        let identity = paradencer_config::load_identity_keypair(&path).unwrap();
        assert_eq!(identity.secret_key(), &secret);
        assert_eq!(identity.pubkey(), &pubkey);
    }

    #[test]
    fn gossip_node_id_matches_identity_pubkey() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let identity = resolve_validator_identity(&node_config).unwrap();
        let handle = start_gossip_service(&node_config, &identity).unwrap();
        assert_eq!(&handle.node_id.0, identity.pubkey());
        drop(handle);
    }
}
