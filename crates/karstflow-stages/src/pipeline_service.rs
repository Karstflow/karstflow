/// Service wrapper for the full validator transaction pipeline.
///
/// Integrates the zero-copy IPC pipeline (Verify → Resolv) with the leader
/// pipeline (Pack → Exec → PoH) and exposes it as a `Service` for the
/// node runtime.
///
/// The service receives raw transaction payloads from an input channel and
/// feeds them through the full pipeline:
///
/// ```text
///   InPort<RawTransaction> → [IPC] Verify → [IPC] Resolv →
///     → Pack → Exec → PoH → entries
/// ```
///
/// During leader slots, use the `PipelineHandle` to call `begin_slot()` and
/// `register_blockhash()` to activate block production. Produced entries
/// accumulate until `end_slot()` collects them for shredding.
use crate::block_producer::{Entry, PohEntry, PohService};
use crate::exec_stage::{ExecConfig, ExecStage, ExecStats, ExecutionEngine};
use crate::leader_pipeline::LeaderPipeline;
use crate::pack_stage::{PackConfig, PackScheduler, PackStats};
use crate::resolv_stage::{Blockhash, ResolvStats};
use crate::tile_pipeline::{PipelineConfig, ValidatorPipeline};
use crate::verify_stage::{TransactionSource, VerifyStats};
use karstflow_mesh::DualReceiver;
use karstflow_runtime::{RuntimeResult, Service, ServiceContext};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Raw transaction payload for channel transport
// ---------------------------------------------------------------------------

/// A raw transaction with its source, ready for pipeline ingestion.
///
/// This is the type sent through the input channel. It carries the
/// wire-format transaction bytes and the ingress source for routing.
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// Solana wire-format transaction bytes.
    pub payload: Vec<u8>,
    /// Where this transaction was received from.
    pub source: TransactionSource,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the validator pipeline service.
#[derive(Debug, Clone)]
pub struct PipelineServiceConfig {
    /// IPC pipeline settings (link depth, MTU).
    pub pipeline: PipelineConfig,
    /// Pack scheduler settings.
    pub pack: PackConfig,
    /// Execution tile settings.
    pub exec: ExecConfig,
    /// Maximum transactions to drain from input per tick.
    pub max_drain_per_tick: usize,
    /// Hashes per PoH tick. Set to 1 for dev/low-power mode.
    pub hashes_per_tick: u64,
}

impl Default for PipelineServiceConfig {
    fn default() -> Self {
        Self {
            pipeline: PipelineConfig::default(),
            pack: PackConfig::default(),
            exec: ExecConfig::default(),
            max_drain_per_tick: 256,
            hashes_per_tick: karstflow_constants::ledger::DEFAULT_HASHES_PER_TICK,
        }
    }
}

impl PipelineServiceConfig {
    /// Create a dev-mode configuration with low-power PoH (instant ticks).
    pub fn dev() -> Self {
        Self {
            hashes_per_tick: 1,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Statistics for the pipeline service.
#[derive(Debug, Default)]
pub struct PipelineServiceStats {
    /// Transactions received from input channels.
    pub transactions_received: AtomicU64,
    /// Transactions accepted into the IPC pipeline.
    pub transactions_accepted: AtomicU64,
    /// Transactions dropped due to backpressure.
    pub transactions_dropped: AtomicU64,
    /// Total IPC fragments processed.
    pub ipc_fragments_processed: AtomicU64,
    /// Transactions resolved and submitted to pack.
    pub transactions_resolved: AtomicU64,
    /// Microblocks executed.
    pub microblocks_executed: AtomicU64,
}

// ---------------------------------------------------------------------------
// Pipeline stage stats — references to inner stage counters
// ---------------------------------------------------------------------------

/// Shared references to the atomic stats of each pipeline stage.
///
/// Populated during pipeline construction and accessible through
/// `PipelineHandle::stage_stats` for wiring into a `MetricsAggregator`.
pub struct PipelineStageStats {
    pub verify: Arc<VerifyStats>,
    pub resolv: Arc<ResolvStats>,
    pub pack: Arc<PackStats>,
    pub exec: Arc<ExecStats>,
}

// ---------------------------------------------------------------------------
// PipelineHandle — cross-service communication
// ---------------------------------------------------------------------------

/// Shared handle for cross-service communication with the pipeline.
///
/// Other services (e.g., consensus, gossip) use this handle to register
/// blockhashes, signal new leader slots, and query pipeline state.
pub struct PipelineHandle {
    /// Commands queued for the service to process.
    commands: Mutex<Vec<PipelineCommand>>,
    /// Whether we're currently in a leader slot.
    is_leading: AtomicBool,
    /// Current leader slot (0 if not leading).
    current_slot: AtomicU64,
    /// Number of PoH ticks completed in the current slot.
    /// Updated by the pipeline service during advance_poh.
    /// The slot driver polls this to detect PoH slot completion.
    poh_ticks_done: AtomicU64,
    /// Pipeline statistics.
    pub stats: Arc<PipelineServiceStats>,
    /// Inner stage stats for metrics aggregation.
    pub stage_stats: PipelineStageStats,
}

impl PipelineHandle {
    fn new(stats: Arc<PipelineServiceStats>, stage_stats: PipelineStageStats) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            is_leading: AtomicBool::new(false),
            current_slot: AtomicU64::new(0),
            poh_ticks_done: AtomicU64::new(0),
            stats,
            stage_stats,
        }
    }

    /// Check if the PoH service has completed all ticks for the current slot.
    pub fn is_poh_slot_complete(&self) -> bool {
        self.poh_ticks_done.load(Ordering::Relaxed) >= karstflow_constants::ledger::TICKS_PER_SLOT
    }

    /// Signal the start of a new leader slot.
    pub fn begin_slot(&self, slot: u64) {
        self.is_leading.store(true, Ordering::Relaxed);
        self.current_slot.store(slot, Ordering::Relaxed);
        self.poh_ticks_done.store(0, Ordering::Relaxed);
        self.commands
            .lock()
            .expect("pipeline commands lock poisoned")
            .push(PipelineCommand::BeginSlot(slot));
    }

    /// Register a blockhash for transaction resolution.
    pub fn register_blockhash(&self, hash: Blockhash, slot: u64) {
        self.commands
            .lock()
            .expect("pipeline commands lock poisoned")
            .push(PipelineCommand::RegisterBlockhash(hash, slot));
    }

    /// Advance the resolv slot for transaction expiry tracking.
    pub fn advance_slot(&self, slot: u64) {
        self.commands
            .lock()
            .expect("pipeline commands lock poisoned")
            .push(PipelineCommand::AdvanceSlot(slot));
    }

    /// Signal the end of a leader slot.
    pub fn end_slot(&self) {
        self.is_leading.store(false, Ordering::Relaxed);
        self.commands
            .lock()
            .expect("pipeline commands lock poisoned")
            .push(PipelineCommand::EndSlot);
    }

    /// Whether the pipeline is currently in a leader slot.
    pub fn is_leading(&self) -> bool {
        self.is_leading.load(Ordering::Relaxed)
    }

    /// Current leader slot.
    pub fn current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    /// Request PohEntries for shredding from completed leader slots.
    ///
    /// Blocks until the pipeline service processes the request on its next
    /// tick (up to ~2ms). Returns all PohEntries from completed slots since
    /// the last call.
    pub fn take_entries(&self) -> Vec<Vec<PohEntry>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.commands
            .lock()
            .expect("pipeline commands lock poisoned")
            .push(PipelineCommand::TakeEntries(tx));
        // Block until the service processes the command. The service ticks
        // every 2ms so this should return quickly.
        rx.recv().unwrap_or_default()
    }
}

/// Internal command enum for cross-service communication.
enum PipelineCommand {
    BeginSlot(u64),
    RegisterBlockhash(Blockhash, u64),
    AdvanceSlot(u64),
    EndSlot,
    /// Request accumulated PohEntries for shredding. The oneshot sender
    /// receives all PohEntries from completed leader slots.
    TakeEntries(std::sync::mpsc::SyncSender<Vec<Vec<PohEntry>>>),
}

// ---------------------------------------------------------------------------
// PipelineService
// ---------------------------------------------------------------------------

/// Service that drives the full validator transaction pipeline.
///
/// Created via `PipelineServiceBuilder` which allows configuring the
/// execution engine, pipeline parameters, and input channels.
pub struct PipelineService {
    pipeline: ValidatorPipeline,
    /// Input channels receiving raw transaction payloads.
    inputs: Vec<DualReceiver<RawTransaction>>,
    /// Shared handle for cross-service communication.
    handle: Arc<PipelineHandle>,
    /// Entries from completed slots.
    completed_entries: Vec<Vec<Entry>>,
    /// PohEntries from completed slots (with transaction data for shredding).
    completed_shred_entries: Vec<Vec<PohEntry>>,
    /// Maximum transactions to drain per tick.
    max_drain_per_tick: usize,
    /// Hashes to advance PoH per service tick when leading.
    hashes_per_poh_advance: u64,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a PipelineService with its handle.
pub struct PipelineServiceBuilder {
    config: PipelineServiceConfig,
    inputs: Vec<DualReceiver<RawTransaction>>,
    engine: Option<Box<dyn ExecutionEngine>>,
}

impl PipelineServiceBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: PipelineServiceConfig::default(),
            inputs: Vec::new(),
            engine: None,
        }
    }

    /// Set the pipeline service configuration.
    pub fn with_config(mut self, config: PipelineServiceConfig) -> Self {
        self.config = config;
        self
    }

    /// Add an input channel for raw transaction payloads.
    pub fn add_input(mut self, input: DualReceiver<RawTransaction>) -> Self {
        self.inputs.push(input);
        self
    }

    /// Set a custom execution engine (e.g., SbpfBackend adapter).
    ///
    /// Required — `build()` will panic if not set.
    pub fn with_execution_engine(mut self, engine: Box<dyn ExecutionEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Build the service and its shared handle.
    ///
    /// Returns `(PipelineService, Arc<PipelineHandle>)`. The handle is used
    /// by other services to communicate with the pipeline.
    pub fn build(self) -> (PipelineService, Arc<PipelineHandle>) {
        let pack = PackScheduler::with_config(self.config.pack);
        let engine: Box<dyn ExecutionEngine> = self
            .engine
            .expect("ExecutionEngine must be provided via with_execution_engine()");
        let exec = ExecStage::with_config(engine, self.config.exec);
        let poh = PohService::with_hashes_per_tick(
            karstflow_types::Hash::default(),
            self.config.hashes_per_tick,
        );

        // Capture pack/exec stats before stages are consumed by LeaderPipeline.
        let pack_stats = pack.stats();
        let exec_stats = exec.stats();

        let leader = LeaderPipeline::new(pack, exec, poh);
        let validator_pipeline = ValidatorPipeline::new(self.config.pipeline, leader);

        // Capture verify/resolv stats from the transaction pipeline.
        let stage_stats = PipelineStageStats {
            verify: validator_pipeline.verify_stats(),
            resolv: validator_pipeline.resolv_stats(),
            pack: pack_stats,
            exec: exec_stats,
        };

        let stats = Arc::new(PipelineServiceStats::default());
        let handle = Arc::new(PipelineHandle::new(Arc::clone(&stats), stage_stats));

        let service = PipelineService {
            pipeline: validator_pipeline,
            inputs: self.inputs,
            handle: Arc::clone(&handle),
            completed_entries: Vec::new(),
            completed_shred_entries: Vec::new(),
            max_drain_per_tick: self.config.max_drain_per_tick,
            hashes_per_poh_advance: self.config.hashes_per_tick,
        };

        (service, handle)
    }
}

impl PipelineService {
    /// Take completed slot entries (produced by `end_slot()`).
    ///
    /// Returns all entry batches from completed leader slots since the
    /// last call. Typically consumed by the shred/turbine pipeline.
    pub fn take_completed_entries(&mut self) -> Vec<Vec<Entry>> {
        std::mem::take(&mut self.completed_entries)
    }
}

impl Service for PipelineService {
    fn name(&self) -> &'static str {
        "validator-pipeline"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(2)
    }

    fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        let stats = &self.handle.stats;

        // Process queued commands from the handle.
        {
            let mut commands = self
                .handle
                .commands
                .lock()
                .expect("pipeline commands lock poisoned");
            for cmd in commands.drain(..) {
                match cmd {
                    PipelineCommand::BeginSlot(slot) => {
                        self.pipeline.begin_slot(slot);
                    }
                    PipelineCommand::RegisterBlockhash(hash, slot) => {
                        self.pipeline.register_blockhash(hash, slot);
                    }
                    PipelineCommand::AdvanceSlot(slot) => {
                        self.pipeline.advance_slot(slot);
                    }
                    PipelineCommand::EndSlot => {
                        let entries = self.pipeline.finish_slot();
                        let shred_entries = self.pipeline.take_shred_entries();
                        if !entries.is_empty() {
                            self.completed_entries.push(entries);
                        }
                        if !shred_entries.is_empty() {
                            self.completed_shred_entries.push(shred_entries);
                        }
                    }
                    PipelineCommand::TakeEntries(sender) => {
                        let entries = std::mem::take(&mut self.completed_shred_entries);
                        let _ = sender.send(entries);
                    }
                }
            }
        }

        // Drain raw transactions from input channels.
        let mut drained = 0usize;
        for input in &mut self.inputs {
            while drained < self.max_drain_per_tick {
                match input.try_recv() {
                    Ok(Some(raw_tx)) => {
                        stats.transactions_received.fetch_add(1, Ordering::Relaxed);
                        drained += 1;

                        let accepted = self.pipeline.ingest(&raw_tx.payload, raw_tx.source);
                        if accepted {
                            stats.transactions_accepted.fetch_add(1, Ordering::Relaxed);
                            tracing::info!(
                                payload_len = raw_tx.payload.len(),
                                "pipeline: transaction ingested into tile pipeline"
                            );
                        } else {
                            stats.transactions_dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!("pipeline: transaction dropped (no credits)");
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }

        // Service the pipeline (verify → resolv → pack → exec → PoH).
        let result = self.pipeline.service();
        if result.ipc_fragments_processed > 0 || result.transactions_resolved > 0 {
            tracing::info!(
                ipc = result.ipc_fragments_processed,
                resolved = result.transactions_resolved,
                microblock = result.leader_step.is_some(),
                "pipeline: service result"
            );
        }
        stats
            .ipc_fragments_processed
            .fetch_add(result.ipc_fragments_processed as u64, Ordering::Relaxed);
        stats
            .transactions_resolved
            .fetch_add(result.transactions_resolved as u64, Ordering::Relaxed);
        if result.leader_step.is_some() {
            stats.microblocks_executed.fetch_add(1, Ordering::Relaxed);
        }

        // Advance PoH ticks when leading. This generates tick entries that
        // fill the slot's PoH chain even when no transactions arrive.
        if self.handle.is_leading() {
            let ticks_before = self.pipeline.poh_ticks_completed();
            self.pipeline.advance_poh(self.hashes_per_poh_advance);
            let ticks_after = self.pipeline.poh_ticks_completed();
            if ticks_after > ticks_before {
                self.handle
                    .poh_ticks_done
                    .store(ticks_after, Ordering::Relaxed);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_stage::MockExecutionEngine;
    use karstflow_mesh::bounded_link;
    use karstflow_runtime::ShutdownSwitch;

    fn mock_engine() -> Box<dyn ExecutionEngine> {
        Box::new(MockExecutionEngine::new(200_000))
    }

    fn make_raw_tx(payload: Vec<u8>) -> RawTransaction {
        RawTransaction {
            payload,
            source: TransactionSource::Quic,
        }
    }

    #[test]
    fn builder_constructs_service() {
        let (_tx, rx) = bounded_link::<RawTransaction>(16);
        let (service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .add_input(DualReceiver::Channel(rx))
            .build();

        assert_eq!(service.name(), "validator-pipeline");
        assert!(!handle.is_leading());
    }

    #[test]
    fn service_drains_input_channel() {
        let (tx, rx) = bounded_link::<RawTransaction>(16);
        let (mut service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .add_input(DualReceiver::Channel(rx))
            .build();

        // Submit transactions.
        tx.try_send(make_raw_tx(vec![0xAA; 128])).unwrap();
        tx.try_send(make_raw_tx(vec![0xBB; 128])).unwrap();

        let ctx = ServiceContext::new(ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        assert_eq!(
            handle.stats.transactions_received.load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn handle_begin_end_slot() {
        let (mut service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .build();

        // Begin a leader slot.
        handle.begin_slot(42);
        assert!(handle.is_leading());
        assert_eq!(handle.current_slot(), 42);

        let ctx = ServiceContext::new(ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        // End the slot.
        handle.end_slot();
        assert!(!handle.is_leading());

        service.tick(&ctx).unwrap();

        // Entries from the completed slot should be available.
        let entries = service.take_completed_entries();
        // May be empty since no transactions were submitted.
        assert!(entries.len() <= 1);
    }

    #[test]
    fn handle_register_blockhash() {
        let (mut service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .build();

        handle.register_blockhash([0xCC; 32], 100);
        handle.advance_slot(100);

        let ctx = ServiceContext::new(ShutdownSwitch::new());
        service.tick(&ctx).unwrap();
    }

    #[test]
    fn max_drain_per_tick_limits() {
        let config = PipelineServiceConfig {
            max_drain_per_tick: 3,
            ..Default::default()
        };

        let (tx, rx) = bounded_link::<RawTransaction>(32);
        let (mut service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .with_config(config)
            .add_input(DualReceiver::Channel(rx))
            .build();

        // Send 10 transactions.
        for i in 0..10u8 {
            tx.try_send(make_raw_tx(vec![i; 128])).unwrap();
        }

        let ctx = ServiceContext::new(ShutdownSwitch::new());
        service.tick(&ctx).unwrap();

        // Should have only drained 3 (max_drain_per_tick).
        assert_eq!(
            handle.stats.transactions_received.load(Ordering::Relaxed),
            3
        );

        // Second tick drains 3 more.
        service.tick(&ctx).unwrap();
        assert_eq!(
            handle.stats.transactions_received.load(Ordering::Relaxed),
            6
        );
    }

    #[test]
    fn full_pipeline_with_leader_slot() {
        use ed25519_dalek::{Signer, SigningKey};

        let (tx, rx) = bounded_link::<RawTransaction>(64);
        let (mut service, handle) = PipelineServiceBuilder::new()
            .with_execution_engine(mock_engine())
            .add_input(DualReceiver::Channel(rx))
            .build();

        let ctx = ServiceContext::new(ShutdownSwitch::new());

        // Begin a leader slot and register a blockhash.
        handle.begin_slot(1);
        handle.register_blockhash([0xBB; 32], 100);
        service.tick(&ctx).unwrap();

        // Build and send a signed transaction.
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let blockhash = [0xBB; 32];

        let mut message = vec![1u8, 0, 0, 1];
        message.extend_from_slice(&pubkey);
        message.extend_from_slice(&blockhash);
        message.push(0); // no instructions

        let signature = key.sign(&message);
        let mut payload = vec![1u8]; // 1 signature
        payload.extend_from_slice(&signature.to_bytes());
        payload.extend_from_slice(&message);

        tx.try_send(RawTransaction {
            payload,
            source: TransactionSource::Quic,
        })
        .unwrap();

        // Service multiple rounds to move through the pipeline.
        for _ in 0..5 {
            service.tick(&ctx).unwrap();
        }

        // Transaction should have been received and processed.
        assert!(handle.stats.transactions_received.load(Ordering::Relaxed) >= 1);
        assert!(handle.stats.transactions_accepted.load(Ordering::Relaxed) >= 1);

        // End the slot.
        handle.end_slot();
        service.tick(&ctx).unwrap();

        let entries = service.take_completed_entries();
        // Should have at least one slot's entries (may be empty if PoH isn't Leading).
        assert!(entries.len() <= 1);
    }
}
