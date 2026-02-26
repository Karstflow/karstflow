/// Service wrapper for the replay pipeline.
///
/// Receives assembled blocks from the shred assembly pipeline and feeds them
/// to `ReplayStage` for deterministic block processing. Each tick drains up
/// to `max_blocks_per_tick` blocks from the input channel, replays them in
/// slot order, and updates consensus state.
///
/// The service also owns a `ShredAssembler` so that raw shred batches can be
/// assembled into blocks inline before replay, eliminating an extra hop.
use crate::replay_stage::{ReplayConfig, ReplayStage, ReplayStats, SignalBus};
use crate::shred_assembler::{AssembledBlock, ShredAssembler, ShredAssemblyStats};
use crate::StageError;
use paradencer_consensus::{
    BankForks, CommitmentTracker, ExecutionBackend, ForkChoice, Tower, VoteProcessor,
};
use paradencer_execution::ExecutionBridge;
use paradencer_mesh::InPort;
use paradencer_runtime::{RuntimeError, RuntimeResult, Service, ServiceContext};
use paradencer_types::shred::Shred;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::warn;

/// Configuration for the replay service.
#[derive(Debug, Clone)]
pub struct ReplayServiceConfig {
    /// Maximum blocks to replay per tick.
    pub max_blocks_per_tick: usize,
    /// Replay stage configuration.
    pub replay_config: ReplayConfig,
}

impl Default for ReplayServiceConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_tick: 4,
            replay_config: ReplayConfig::default(),
        }
    }
}

/// Running service that drives the ShredAssembler → ReplayStage pipeline.
pub struct ReplayService {
    config: ReplayServiceConfig,
    replay_stage: ReplayStage,
    assembler: ShredAssembler,
    /// Channel receiving assembled blocks from external producers.
    block_input: Option<InPort<AssembledBlock>>,
    /// Channel receiving raw shred batches for inline assembly.
    shred_input: Option<InPort<Vec<Shred>>>,
    /// Blocks waiting to be replayed (buffered across ticks).
    pending_blocks: Vec<AssembledBlock>,
    /// Assembly statistics.
    assembly_stats: ShredAssemblyStats,
}

impl ReplayService {
    /// Create a replay service with block input channel.
    ///
    /// Blocks arrive pre-assembled from an upstream shred assembler.
    pub fn with_block_input(
        config: ReplayServiceConfig,
        block_input: InPort<AssembledBlock>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let replay_stage = ReplayStage::with_config(
            config.replay_config.clone(),
            bank_forks,
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
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
        }
    }

    /// Create a replay service with shred input channel.
    ///
    /// Raw shred batches are assembled into blocks inline before replay.
    pub fn with_shred_input(
        config: ReplayServiceConfig,
        shred_input: InPort<Vec<Shred>>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let replay_stage = ReplayStage::with_config(
            config.replay_config.clone(),
            bank_forks,
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
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
        }
    }

    /// Create a replay service with a custom execution backend.
    pub fn with_backend(
        config: ReplayServiceConfig,
        block_input: InPort<AssembledBlock>,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        backend: Arc<dyn ExecutionBackend>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let replay_stage = ReplayStage::with_backend(
            config.replay_config.clone(),
            bank_forks,
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
            pending_blocks: Vec::new(),
            assembly_stats: ShredAssemblyStats::default(),
        }
    }

    /// Drain blocks from input channels into the pending buffer.
    fn drain_inputs(&mut self) {
        // Drain assembled blocks.
        if let Some(ref block_input) = self.block_input {
            while let Ok(Some(block)) = block_input.try_recv() {
                self.pending_blocks.push(block);
            }
        }

        // Drain shred batches and assemble into blocks.
        if let Some(ref shred_input) = self.shred_input {
            while let Ok(Some(shreds)) = shred_input.try_recv() {
                match self.assembler.assemble_block(shreds) {
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

    fn tick(&mut self, context: &ServiceContext) -> RuntimeResult<()> {
        self.drain_inputs();

        let limit = self
            .config
            .max_blocks_per_tick
            .min(self.pending_blocks.len());
        let blocks: Vec<AssembledBlock> = self.pending_blocks.drain(..limit).collect();

        for block in blocks {
            let slot = block.slot;
            match self.replay_stage.replay_block(block) {
                Ok(_outcome) => {}
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shred_assembler::Entry;
    use paradencer_consensus::{
        Bank, EpochSchedule, LeaderSchedule, StakeTracker, VoteProcessorConfig,
    };
    use paradencer_mesh::bounded_link;
    use paradencer_storage::{AccountDatabase, Pubkey};

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
            block_rx,
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
            block_rx,
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
            block_rx,
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
            block_rx,
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
        assert!(config.replay_config.strict_ancestry_check);
        assert!(config.replay_config.process_votes);
    }

    #[test]
    fn signal_bus_accessible_from_service() {
        let (bank_forks, fork_choice, bridge, vote_proc, tower, commitment) =
            create_test_infrastructure();
        let (_, block_rx) = bounded_link::<AssembledBlock>(16);

        let service = ReplayService::with_block_input(
            ReplayServiceConfig::default(),
            block_rx,
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
            block_rx,
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
            block_rx,
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
