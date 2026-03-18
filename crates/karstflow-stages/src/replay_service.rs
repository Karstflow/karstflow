/// Service wrapper for the replay pipeline.
///
/// Receives assembled blocks from the shred assembly pipeline and feeds them
/// to `ReplayStage` for deterministic block processing. Each tick drains up
/// to `max_blocks_per_tick` blocks from the input channel, replays them in
/// slot order, and updates consensus state.
///
/// The service also owns a `ShredAssembler` so that raw shred batches can be
/// assembled into blocks inline before replay, eliminating an extra hop.
use crate::codec_impls::ShredBatch;
use crate::replay_stage::{ReplayConfig, ReplayStage, ReplayStats, SignalBus};
use crate::shred_assembler::{AssembledBlock, ShredAssembler, ShredAssemblyStats};
use crate::StageError;
use karstflow_consensus::{
    BankForks, CommitmentTracker, ExecutionBackend, ForkChoice, Tower, VoteProcessor,
};
use karstflow_execution::ExecutionBridge;
use karstflow_mesh::DualReceiver;
use karstflow_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use karstflow_types::shred::Shred;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default maximum orphaned blocks across all parent slots.
const DEFAULT_ORPHAN_MAX_TOTAL: usize = 256;
/// Default maximum orphaned blocks per parent slot.
const DEFAULT_ORPHAN_MAX_PER_PARENT: usize = 8;

/// Configuration for the replay service.
#[derive(Debug, Clone)]
pub struct ReplayServiceConfig {
    /// Maximum blocks to replay per tick.
    pub max_blocks_per_tick: usize,
    /// Maximum total orphaned blocks buffered.
    pub orphan_max_total: usize,
    /// Maximum orphaned blocks per parent slot.
    pub orphan_max_per_parent: usize,
    /// Replay stage configuration.
    pub replay_config: ReplayConfig,
}

impl Default for ReplayServiceConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_tick: 4,
            orphan_max_total: DEFAULT_ORPHAN_MAX_TOTAL,
            orphan_max_per_parent: DEFAULT_ORPHAN_MAX_PER_PARENT,
            replay_config: ReplayConfig::default(),
        }
    }
}

/// Bounded buffer for blocks whose parent slot hasn't been replayed yet.
///
/// When a block arrives but its parent is not yet in BankForks, the block is
/// held here. Once the parent is successfully replayed, all waiting children
/// are released and replayed in cascade.
pub struct OrphanBuffer {
    /// Blocks waiting on a parent, keyed by the parent_slot they depend on.
    orphans: HashMap<u64, Vec<AssembledBlock>>,
    /// Total number of buffered blocks across all parents.
    total_buffered: usize,
    /// Maximum total blocks to buffer.
    max_total: usize,
    /// Maximum blocks waiting on a single parent.
    max_per_parent: usize,
    /// Running count of blocks inserted.
    inserts: u64,
    /// Running count of blocks evicted due to capacity.
    evictions: u64,
    /// Running count of blocks released via cascade replay.
    cascade_releases: u64,
}

impl OrphanBuffer {
    pub fn new(max_total: usize, max_per_parent: usize) -> Self {
        Self {
            orphans: HashMap::new(),
            total_buffered: 0,
            max_total,
            max_per_parent,
            inserts: 0,
            evictions: 0,
            cascade_releases: 0,
        }
    }

    /// Insert a block into the orphan buffer, keyed by its parent_slot.
    ///
    /// Returns `true` if the block was accepted, `false` if the buffer is
    /// full or the per-parent limit is reached.
    pub fn insert(&mut self, block: AssembledBlock) -> bool {
        if self.total_buffered >= self.max_total {
            self.evictions += 1;
            return false;
        }

        let parent_slot = block.parent_slot;
        let children = self.orphans.entry(parent_slot).or_default();

        if children.len() >= self.max_per_parent {
            self.evictions += 1;
            return false;
        }

        // Avoid duplicate slots.
        if children.iter().any(|b| b.slot == block.slot) {
            return false;
        }

        children.push(block);
        self.total_buffered += 1;
        self.inserts += 1;
        true
    }

    /// Remove and return all blocks waiting on `parent_slot`.
    ///
    /// The returned blocks are sorted by slot for deterministic replay order.
    pub fn take_children(&mut self, parent_slot: u64) -> Vec<AssembledBlock> {
        if let Some(mut children) = self.orphans.remove(&parent_slot) {
            let count = children.len();
            self.total_buffered = self.total_buffered.saturating_sub(count);
            self.cascade_releases += count as u64;
            children.sort_by_key(|b| b.slot);
            children
        } else {
            Vec::new()
        }
    }

    /// Remove all orphaned blocks whose parent_slot is below `root_slot`.
    ///
    /// These blocks can never be replayed because their parent is already
    /// finalized and pruned from BankForks.
    pub fn prune_below(&mut self, root_slot: u64) {
        let mut pruned = 0_usize;
        self.orphans.retain(|&parent, children| {
            if parent < root_slot {
                pruned += children.len();
                false
            } else {
                true
            }
        });
        self.total_buffered = self.total_buffered.saturating_sub(pruned);
        self.evictions += pruned as u64;
    }

    /// Total number of buffered orphan blocks.
    pub fn len(&self) -> usize {
        self.total_buffered
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.total_buffered == 0
    }

    /// Number of distinct parent slots being waited on.
    pub fn parent_count(&self) -> usize {
        self.orphans.len()
    }

    /// Total inserts since creation.
    pub fn inserts(&self) -> u64 {
        self.inserts
    }

    /// Total evictions since creation.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Total cascade releases since creation.
    pub fn cascade_releases(&self) -> u64 {
        self.cascade_releases
    }
}

/// Running service that drives the ShredAssembler → ReplayStage pipeline.
pub struct ReplayService {
    config: ReplayServiceConfig,
    replay_stage: ReplayStage,
    assembler: ShredAssembler,
    /// Channel receiving assembled blocks from external producers.
    block_input: Option<DualReceiver<AssembledBlock>>,
    /// Channel receiving raw shred batches for inline assembly.
    shred_input: Option<DualReceiver<ShredBatch>>,
    /// Channel receiving completed slot numbers for consensus processing.
    /// Leader-produced slots that bypass replay_block still need consensus
    /// decisions (voting + root advancement).
    consensus_slot_rx: Option<crossbeam_channel::Receiver<u64>>,
    /// Blocks waiting to be replayed (buffered across ticks).
    pending_blocks: Vec<AssembledBlock>,
    /// Assembly statistics.
    assembly_stats: ShredAssemblyStats,
    /// Buffer for blocks whose parent hasn't been replayed yet.
    orphan_buffer: OrphanBuffer,
    /// BankForks reference for root slot lookups during orphan pruning.
    bank_forks: Arc<RwLock<BankForks>>,
}

impl ReplayService {
    /// Create a replay service with block input channel.
    ///
    /// Blocks arrive pre-assembled from an upstream shred assembler.
    pub fn with_block_input(
        config: ReplayServiceConfig,
        block_input: DualReceiver<AssembledBlock>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let orphan_buffer =
            OrphanBuffer::new(config.orphan_max_total, config.orphan_max_per_parent);
        let replay_stage = ReplayStage::with_config(
            config.replay_config.clone(),
            bank_forks.clone(),
            fork_choice,
            execution_bridge,
            vote_processor,
            tower,
            commitment_tracker,
        );

        Self {
            config,
            replay_stage,
            assembler: ShredAssembler::new(),
            block_input: Some(block_input),
            shred_input: None,
            consensus_slot_rx: None,
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
            orphan_buffer,
            bank_forks,
        }
    }

    /// Set the consensus slot receiver for leader-produced slots.
    pub fn set_consensus_slot_receiver(&mut self, rx: crossbeam_channel::Receiver<u64>) {
        self.consensus_slot_rx = Some(rx);
    }

    /// Create a replay service with shred input channel.
    ///
    /// Raw shred batches are assembled into blocks inline before replay.
    pub fn with_shred_input(
        config: ReplayServiceConfig,
        shred_input: DualReceiver<ShredBatch>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let orphan_buffer =
            OrphanBuffer::new(config.orphan_max_total, config.orphan_max_per_parent);
        let replay_stage = ReplayStage::with_config(
            config.replay_config.clone(),
            bank_forks.clone(),
            fork_choice,
            execution_bridge,
            vote_processor,
            tower,
            commitment_tracker,
        );

        Self {
            config,
            replay_stage,
            assembler: ShredAssembler::new(),
            block_input: None,
            shred_input: Some(shred_input),
            consensus_slot_rx: None,
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
            orphan_buffer,
            bank_forks,
        }
    }

    /// Create a replay service with a custom execution backend.
    pub fn with_backend(
        config: ReplayServiceConfig,
        block_input: DualReceiver<AssembledBlock>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        backend: Arc<dyn ExecutionBackend>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let orphan_buffer =
            OrphanBuffer::new(config.orphan_max_total, config.orphan_max_per_parent);
        let replay_stage = ReplayStage::with_backend(
            config.replay_config.clone(),
            bank_forks.clone(),
            fork_choice,
            execution_bridge,
            backend,
            vote_processor,
            tower,
            commitment_tracker,
        );

        Self {
            config,
            replay_stage,
            assembler: ShredAssembler::new(),
            block_input: Some(block_input),
            shred_input: None,
            consensus_slot_rx: None,
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
            orphan_buffer,
            bank_forks,
        }
    }

    /// Drain blocks from input channels into the pending buffer.
    fn drain_inputs(&mut self) {
        // Drain assembled blocks.
        if let Some(ref mut block_input) = self.block_input {
            while let Ok(Some(block)) = block_input.try_recv() {
                self.pending_blocks.push(block);
            }
        }

        // Drain shred batches and assemble into blocks.
        if let Some(ref mut shred_input) = self.shred_input {
            while let Ok(Some(batch)) = shred_input.try_recv() {
                match self.assembler.assemble_block(batch.0) {
                    Ok(block) => {
                        self.assembly_stats.blocks_assembled += 1;
                        self.assembly_stats.entries_extracted += block.entries.len() as u64;
                        self.assembly_stats.transactions_extracted +=
                            block.transaction_count as u64;
                        self.pending_blocks.push(block);
                    }
                    Err(_) => {
                        // Assembly failure — skip this batch.
                    }
                }
            }
        }

        // Sort pending blocks by slot for deterministic processing order.
        self.pending_blocks.sort_by_key(|b| b.slot);
    }

    /// Replay stats from the underlying stage.
    pub fn replay_stats(&self) -> ReplayStats {
        self.replay_stage.stats()
    }

    /// Assembly stats.
    pub fn assembly_stats(&self) -> &ShredAssemblyStats {
        &self.assembly_stats
    }

    /// Number of blocks waiting to be replayed.
    pub fn pending_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Number of orphaned blocks buffered (waiting for parent).
    pub fn orphan_count(&self) -> usize {
        self.orphan_buffer.len()
    }

    /// Reference to the orphan buffer for inspection.
    pub fn orphan_buffer(&self) -> &OrphanBuffer {
        &self.orphan_buffer
    }

    /// Access the signal bus for subscribing to replay signals.
    ///
    /// Returns a shared reference to the signal bus. Callers should
    /// lock and call `subscribe()` to get their own receiving channel.
    pub fn signal_bus(&self) -> Arc<Mutex<SignalBus>> {
        self.replay_stage.signal_bus()
    }

    /// Set the validator identity for leader schedule detection.
    ///
    /// When set, the replay stage will emit BecameLeader signals after
    /// each completed slot if the next slot belongs to this validator.
    pub fn set_validator_identity(&mut self, identity: [u8; 32]) {
        self.replay_stage.set_validator_identity(identity);
    }
}

impl Service for ReplayService {
    fn name(&self) -> &'static str {
        "replay-service"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(10)
    }

    fn tick(&mut self, _context: &ServiceContext) -> RuntimeResult<()> {
        self.drain_inputs();

        // Process consensus decisions for leader-produced slots that
        // bypassed replay_block. This drives voting and root advancement.
        if let Some(ref rx) = self.consensus_slot_rx {
            while let Ok(slot) = rx.try_recv() {
                self.replay_stage.run_consensus_for_slot(slot);
            }
        }

        let limit = self
            .config
            .max_blocks_per_tick
            .min(self.pending_blocks.len());
        let blocks: Vec<AssembledBlock> = self.pending_blocks.drain(..limit).collect();

        // Collect successfully replayed slots for cascade release.
        let mut replayed_slots: Vec<u64> = Vec::new();

        for block in blocks {
            let slot = block.slot;
            let parent_slot = block.parent_slot;
            match self.replay_stage.replay_block(block.clone()) {
                Ok(_outcome) => {
                    replayed_slots.push(slot);
                }
                Err(StageError::ReplayError(ref msg))
                    if msg.contains("ParentNotFound") || msg.contains("Bank creation failed") =>
                {
                    // Parent not yet available — buffer as orphan instead of dropping.
                    if self.orphan_buffer.insert(block) {
                        debug!(
                            slot,
                            parent_slot,
                            orphan_count = self.orphan_buffer.len(),
                            "block buffered as orphan (parent not yet replayed)"
                        );
                    } else {
                        warn!(
                            slot,
                            parent_slot,
                            orphan_count = self.orphan_buffer.len(),
                            "orphan buffer full, block dropped"
                        );
                    }
                }
                Err(StageError::ReplayError(msg)) => {
                    warn!(slot, error = %msg, "replay failed");
                }
                Err(e) => {
                    return Err(RuntimeError::service_failure(
                        self.name(),
                        &format!("Fatal replay error at slot {}: {:?}", slot, e),
                    ));
                }
            }
        }

        // Cascade: release orphaned children of successfully replayed slots.
        // Use a work queue to handle multi-level cascades (child → grandchild).
        let mut cascade_queue: Vec<u64> = replayed_slots;
        let mut cascade_depth = 0_u32;
        const MAX_CASCADE_DEPTH: u32 = 16;

        while !cascade_queue.is_empty() && cascade_depth < MAX_CASCADE_DEPTH {
            cascade_depth += 1;
            let mut next_queue: Vec<u64> = Vec::new();

            for parent_slot in cascade_queue.drain(..) {
                let children = self.orphan_buffer.take_children(parent_slot);
                if !children.is_empty() {
                    info!(
                        parent_slot,
                        child_count = children.len(),
                        cascade_depth,
                        "releasing orphaned children for cascade replay"
                    );
                    for child in children {
                        let child_slot = child.slot;
                        match self.replay_stage.replay_block(child) {
                            Ok(_) => {
                                next_queue.push(child_slot);
                            }
                            Err(StageError::ReplayError(msg)) => {
                                warn!(slot = child_slot, error = %msg, "cascade replay failed");
                            }
                            Err(e) => {
                                return Err(RuntimeError::service_failure(
                                    self.name(),
                                    &format!(
                                        "Fatal cascade replay error at slot {}: {:?}",
                                        child_slot, e
                                    ),
                                ));
                            }
                        }
                    }
                }
            }

            cascade_queue = next_queue;
        }

        // Prune orphans below current root (they can never be replayed).
        if let Ok(forks) = self.bank_forks.read() {
            self.orphan_buffer.prune_below(forks.root_slot());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shred_assembler::Entry;
    use karstflow_consensus::{
        Bank, EpochSchedule, LeaderSchedule, StakeTracker, VoteProcessorConfig,
    };
    use karstflow_mesh::{bounded_link, DualReceiver};
    use karstflow_storage::{AccountDatabase, Pubkey};

    type TestInfra = (
        Arc<RwLock<BankForks>>,
        Arc<Mutex<ForkChoice>>,
        Arc<ExecutionBridge>,
        Arc<Mutex<VoteProcessor>>,
        Arc<RwLock<Tower>>,
        Arc<Mutex<CommitmentTracker>>,
    );

    fn create_test_infrastructure() -> TestInfra {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
        let genesis = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        let bank_forks = Arc::new(RwLock::new(BankForks::new(genesis)));
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let execution_bridge = Arc::new(ExecutionBridge::new());
        let config = VoteProcessorConfig::default();
        let stake_tracker = StakeTracker::new(0);
        let vote_processor = Arc::new(Mutex::new(VoteProcessor::new(config, stake_tracker)));
        let tower = Arc::new(RwLock::new(Tower::new()));
        let commitment_tracker = Arc::new(Mutex::new(CommitmentTracker::default()));

        (
            bank_forks,
            fork_choice,
            execution_bridge,
            vote_processor,
            tower,
            commitment_tracker,
        )
    }

    fn create_test_block(slot: u64, parent_slot: u64) -> AssembledBlock {
        AssembledBlock {
            slot,
            parent_slot,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32],
                transactions: vec![],
            }],
            transaction_count: 0,
            total_bytes: 0,
            shred_count: 1,
        }
    }

    #[test]
    fn service_constructs_with_block_input() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        assert_eq!(service.name(), "replay-service");
        assert_eq!(service.pending_count(), 0);
    }

    #[test]
    fn service_drains_block_input() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);

        let mut service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        // Send blocks.
        block_tx.try_send(create_test_block(1, 0)).unwrap();
        block_tx.try_send(create_test_block(2, 1)).unwrap();

        service.drain_inputs();
        assert_eq!(service.pending_count(), 2);
    }

    #[test]
    fn pending_blocks_sorted_by_slot() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);

        let mut service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        // Send out of order.
        block_tx.try_send(create_test_block(5, 4)).unwrap();
        block_tx.try_send(create_test_block(3, 2)).unwrap();
        block_tx.try_send(create_test_block(4, 3)).unwrap();

        service.drain_inputs();
        assert_eq!(service.pending_blocks[0].slot, 3);
        assert_eq!(service.pending_blocks[1].slot, 4);
        assert_eq!(service.pending_blocks[2].slot, 5);
    }

    #[test]
    fn max_blocks_per_tick_respected() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);

        let config = ReplayServiceConfig {
            max_blocks_per_tick: 2,
            ..Default::default()
        };

        let mut service = ReplayService::with_block_input(
            config,
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        // Send 4 blocks.
        for slot in 1..=4 {
            block_tx
                .try_send(create_test_block(slot, slot - 1))
                .unwrap();
        }

        service.drain_inputs();
        assert_eq!(service.pending_count(), 4);

        // Only 2 should be drained per tick.
        let limit = service
            .config
            .max_blocks_per_tick
            .min(service.pending_blocks.len());
        let _drained: Vec<AssembledBlock> = service.pending_blocks.drain(..limit).collect();
        assert_eq!(service.pending_count(), 2);
    }

    #[test]
    fn default_config_values() {
        let config = ReplayServiceConfig::default();
        assert_eq!(config.max_blocks_per_tick, 4);
        assert_eq!(config.orphan_max_total, DEFAULT_ORPHAN_MAX_TOTAL);
        assert_eq!(config.orphan_max_per_parent, DEFAULT_ORPHAN_MAX_PER_PARENT);
        assert!(config.replay_config.strict_ancestry_check);
        assert!(config.replay_config.process_votes);
    }

    // --- OrphanBuffer unit tests ---

    #[test]
    fn orphan_buffer_insert_and_take() {
        let mut buf = OrphanBuffer::new(64, 8);

        // Insert blocks waiting on parent slot 10.
        assert!(buf.insert(create_test_block(11, 10)));
        assert!(buf.insert(create_test_block(12, 10)));
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.parent_count(), 1);

        // Insert block waiting on different parent.
        assert!(buf.insert(create_test_block(21, 20)));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.parent_count(), 2);

        // Take children of slot 10.
        let children = buf.take_children(10);
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].slot, 11); // sorted by slot
        assert_eq!(children[1].slot, 12);
        assert_eq!(buf.len(), 1); // only the slot 21 block remains
        assert_eq!(buf.parent_count(), 1);

        // Take non-existent parent returns empty.
        let empty = buf.take_children(99);
        assert!(empty.is_empty());
    }

    #[test]
    fn orphan_buffer_rejects_duplicates() {
        let mut buf = OrphanBuffer::new(64, 8);

        assert!(buf.insert(create_test_block(11, 10)));
        // Same slot again should be rejected.
        assert!(!buf.insert(create_test_block(11, 10)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn orphan_buffer_max_total_capacity() {
        let mut buf = OrphanBuffer::new(3, 8);

        assert!(buf.insert(create_test_block(11, 10)));
        assert!(buf.insert(create_test_block(12, 10)));
        assert!(buf.insert(create_test_block(21, 20)));
        // Buffer is full.
        assert!(!buf.insert(create_test_block(22, 20)));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.evictions(), 1);
    }

    #[test]
    fn orphan_buffer_per_parent_limit() {
        let mut buf = OrphanBuffer::new(64, 2);

        assert!(buf.insert(create_test_block(11, 10)));
        assert!(buf.insert(create_test_block(12, 10)));
        // Per-parent limit reached for parent 10.
        assert!(!buf.insert(create_test_block(13, 10)));
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.evictions(), 1);

        // Different parent still works.
        assert!(buf.insert(create_test_block(21, 20)));
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn orphan_buffer_prune_below_root() {
        let mut buf = OrphanBuffer::new(64, 8);

        buf.insert(create_test_block(6, 5));
        buf.insert(create_test_block(11, 10));
        buf.insert(create_test_block(21, 20));
        assert_eq!(buf.len(), 3);

        // Prune everything below root=15.
        buf.prune_below(15);
        assert_eq!(buf.len(), 1); // only parent=20 survives
        assert_eq!(buf.parent_count(), 1);

        let children = buf.take_children(20);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].slot, 21);
    }

    #[test]
    fn orphan_buffer_take_returns_sorted() {
        let mut buf = OrphanBuffer::new(64, 8);

        // Insert in reverse order.
        buf.insert(create_test_block(15, 10));
        buf.insert(create_test_block(13, 10));
        buf.insert(create_test_block(11, 10));

        let children = buf.take_children(10);
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].slot, 11);
        assert_eq!(children[1].slot, 13);
        assert_eq!(children[2].slot, 15);
    }

    #[test]
    fn orphan_buffer_metrics() {
        let mut buf = OrphanBuffer::new(2, 8);

        buf.insert(create_test_block(11, 10));
        buf.insert(create_test_block(12, 10));
        assert_eq!(buf.inserts(), 2);

        // Full — eviction.
        buf.insert(create_test_block(21, 20));
        assert_eq!(buf.evictions(), 1);

        // Cascade release.
        let children = buf.take_children(10);
        assert_eq!(children.len(), 2);
        assert_eq!(buf.cascade_releases(), 2);
    }

    #[test]
    fn service_has_orphan_buffer() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        assert_eq!(service.orphan_count(), 0);
        assert!(service.orphan_buffer().is_empty());
    }

    #[test]
    fn signal_bus_accessible_from_service() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        let bus = service.signal_bus();
        let rx = bus.lock().unwrap().subscribe();
        assert!(rx.is_some(), "should be able to subscribe via signal_bus");
    }

    #[test]
    fn signal_bus_receives_emitted_signals() {
        use crate::replay_stage::{ReplaySignal, RootAdvancedInfo};

        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        // Subscribe via the service's signal bus.
        let bus = service.signal_bus();
        let rx = bus.lock().unwrap().subscribe().unwrap();

        // Emit a signal through the bus and verify receipt.
        bus.lock()
            .unwrap()
            .emit(ReplaySignal::RootAdvanced(RootAdvancedInfo {
                new_root: 42,
                previous_root: 10,
                pruned_slot_count: 30,
            }));

        let received = rx.try_recv();
        assert!(
            received.is_ok(),
            "should receive signal emitted through the bus"
        );

        match received.unwrap() {
            ReplaySignal::RootAdvanced(info) => {
                assert_eq!(info.new_root, 42);
                assert_eq!(info.previous_root, 10);
                assert_eq!(info.pruned_slot_count, 30);
            }
            _ => panic!("Expected RootAdvanced signal"),
        }
    }

    #[test]
    fn multiple_subscribers_via_service() {
        use crate::replay_stage::ReplaySignal;

        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            DualReceiver::Channel(block_rx),
            bank_forks,
            fork_choice,
            bridge,
            vote_proc,
            tower,
            commitment,
        );

        let bus = service.signal_bus();
        let rx1 = bus.lock().unwrap().subscribe().unwrap();
        let rx2 = bus.lock().unwrap().subscribe().unwrap();

        // Emit directly via the bus to verify both receive.
        bus.lock().unwrap().emit(ReplaySignal::RootAdvanced(
            crate::replay_stage::RootAdvancedInfo {
                new_root: 100,
                previous_root: 50,
                pruned_slot_count: 45,
            },
        ));

        let r1 = rx1.try_recv();
        let r2 = rx2.try_recv();
        assert!(r1.is_ok(), "subscriber 1 should receive signal");
        assert!(r2.is_ok(), "subscriber 2 should receive signal");
    }
}
