mod ancestry_verifier;
mod bank_transition;
mod block_processor;
mod replay_pipeline;
mod slot_metrics;
#[cfg(test)]
mod tests;
mod vote_integration;

pub use ancestry_verifier::{
    AncestryError, AncestryStats, AncestryVerifier, ForkDetector, ForkPoint,
};
pub use bank_transition::{BankTransition, BankTransitionError};
pub use block_processor::{BlockOutcome, BlockProcessor, BlockProcessorError, TransactionResult};
pub use replay_pipeline::{
    BatchReplayResult, ConfirmationInfo, ConfirmationStats, CoordinatorStats,
    ForkReplayCoordinator, OptimisticConfirmationTracker, ReplayBatchProcessor, ReplayOptimizer,
    SlotReplayInfo,
};
pub use slot_metrics::{
    AggregateMetrics, AlertSeverity, AlertType, AnomalyType, MetricsTracker, PerformanceAlert,
    PerformanceAnomaly, PerformanceMonitor, PerformanceThresholds, SlotMetrics,
};
pub use vote_integration::{VoteIntegration, VoteIntegrationError};

use crate::{AssembledBlock, StageError};
use paradencer_consensus::{
    BankForks, CommitmentTracker, ExecutionBackend, ForkChoice, Tower, VoteProcessor,
};
use paradencer_execution::ExecutionBridge;
use std::sync::{Arc, Mutex, RwLock};

/// Statistics for replay stage operations
#[derive(Debug, Clone, Default)]
pub struct ReplayStats {
    /// Total blocks replayed
    pub blocks_replayed: u64,
    /// Total transactions replayed
    pub transactions_replayed: u64,
    /// Total votes processed
    pub votes_processed: u64,
    /// Total bank transitions (freezes + creations)
    pub bank_transitions: u64,
    /// Total root progressions
    pub root_progressions: u64,
    /// Failed block replays
    pub failed_blocks: u64,
    /// Failed transactions
    pub failed_transactions: u64,
    /// Average transactions per block
    pub avg_transactions_per_block: f64,
}

impl ReplayStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_block_replay(&mut self, transaction_count: usize, success: bool) {
        if success {
            self.blocks_replayed += 1;
            self.transactions_replayed += transaction_count as u64;

            // Update average
            if self.blocks_replayed > 0 {
                self.avg_transactions_per_block =
                    self.transactions_replayed as f64 / self.blocks_replayed as f64;
            }
        } else {
            self.failed_blocks += 1;
        }
    }

    pub fn record_vote_processed(&mut self) {
        self.votes_processed += 1;
    }

    pub fn record_bank_transition(&mut self) {
        self.bank_transitions += 1;
    }

    pub fn record_root_progression(&mut self) {
        self.root_progressions += 1;
    }

    pub fn record_transaction_failure(&mut self) {
        self.failed_transactions += 1;
    }
}

/// Configuration for replay stage
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Enable strict ancestry verification
    pub strict_ancestry_check: bool,
    /// Enable PoH entry chain verification during block replay.
    /// Should be true in production. Can be disabled during
    /// initial snapshot catchup or in test scenarios.
    pub verify_poh: bool,
    /// Enable vote processing
    pub process_votes: bool,
    /// Enable automatic bank freezing
    pub auto_freeze_banks: bool,
    /// Enable root progression
    pub enable_root_progression: bool,
    /// Maximum blocks to process before yielding
    pub max_blocks_per_iteration: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            strict_ancestry_check: true,
            verify_poh: true,
            process_votes: true,
            auto_freeze_banks: true,
            enable_root_progression: true,
            max_blocks_per_iteration: 32,
        }
    }
}

/// Main replay stage for deterministic block processing
///
/// Orchestrates the replay of assembled blocks by:
/// - Selecting target banks using fork choice
/// - Verifying block ancestry
/// - Creating child banks at slot boundaries
/// - Applying transactions via ExecutionBridge
/// - Processing ticks and slot metadata
/// - Freezing banks at end of slot
/// - Updating fork choice with outcomes
/// - Checking for root progression
pub struct ReplayStage {
    /// Configuration
    config: ReplayConfig,
    /// Bank transition manager
    bank_transition: BankTransition,
    /// Block processor
    block_processor: BlockProcessor,
    /// Vote integration
    vote_integration: VoteIntegration,
    /// Statistics
    stats: Arc<Mutex<ReplayStats>>,
}

impl ReplayStage {
    pub fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        Self::with_config(
            ReplayConfig::default(),
            bank_forks,
            fork_choice,
            execution_bridge,
            vote_processor,
            tower,
            commitment_tracker,
        )
    }

    pub fn with_config(
        config: ReplayConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let bank_transition = BankTransition::new(bank_forks.clone(), fork_choice.clone());
        let mut block_processor = BlockProcessor::new(execution_bridge, commitment_tracker);
        block_processor.verify_poh = config.verify_poh;
        let vote_integration = VoteIntegration::new(vote_processor, tower, fork_choice);

        Self {
            config,
            bank_transition,
            block_processor,
            vote_integration,
            stats: Arc::new(Mutex::new(ReplayStats::new())),
        }
    }

    /// Create a replay stage with a real execution backend for instruction
    /// processing. In production, pass `SbpfExecutionAdapter` here.
    pub fn with_backend(
        config: ReplayConfig,
        bank_forks: Arc<RwLock<BankForks>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
        execution_bridge: Arc<ExecutionBridge>,
        backend: Arc<dyn ExecutionBackend>,
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        commitment_tracker: Arc<Mutex<CommitmentTracker>>,
    ) -> Self {
        let bank_transition = BankTransition::new(bank_forks.clone(), fork_choice.clone());
        let mut block_processor =
            BlockProcessor::with_backend(execution_bridge, commitment_tracker, backend);
        block_processor.verify_poh = config.verify_poh;
        let vote_integration = VoteIntegration::new(vote_processor, tower, fork_choice);

        Self {
            config,
            bank_transition,
            block_processor,
            vote_integration,
            stats: Arc::new(Mutex::new(ReplayStats::new())),
        }
    }

    /// Process a single assembled block through replay
    pub fn replay_block(&mut self, block: AssembledBlock) -> Result<BlockOutcome, StageError> {
        // Step 1: Get or create working bank for this slot
        let bank = if let Ok(existing_bank) = self.bank_transition.get_working_bank(block.slot) {
            existing_bank
        } else {
            // Need to create child bank from parent
            self.bank_transition
                .create_child_bank(block.parent_slot, block.slot)
                .map_err(|e| StageError::ReplayError(format!("Bank creation failed: {:?}", e)))?;

            self.stats.lock().unwrap().record_bank_transition();

            self.bank_transition
                .get_working_bank(block.slot)
                .map_err(|e| StageError::ReplayError(format!("Failed to get new bank: {:?}", e)))?
        };

        // Step 2: Verify ancestry if strict checking enabled
        if self.config.strict_ancestry_check {
            self.verify_block_ancestry(&block, &bank)?;
        }

        // Step 3: Process votes from block if enabled
        if self.config.process_votes {
            if let Err(e) = self.vote_integration.process_votes_from_block(&block) {
                // Vote processing failures are non-fatal
                eprintln!("Vote processing warning for slot {}: {:?}", block.slot, e);
            } else {
                self.stats.lock().unwrap().record_vote_processed();
            }
        }

        // Step 4: Apply transactions and process block
        let outcome = self
            .block_processor
            .process_block(block.clone(), bank.clone())
            .map_err(|e| StageError::ReplayError(format!("Block processing failed: {:?}", e)))?;

        // Step 4b: Feed vote updates from executed transactions into ForkChoice
        if self.config.process_votes && !outcome.vote_updates.is_empty() {
            if let Err(e) = self
                .vote_integration
                .process_vote_updates(&outcome.vote_updates)
            {
                eprintln!(
                    "Vote update processing warning for slot {}: {:?}",
                    block.slot, e
                );
            }
        }

        // Step 5: Finalize slot if complete (distribute fees, update sysvars, freeze)
        if self.config.auto_freeze_banks && bank.is_complete() {
            let finalization = self
                .bank_transition
                .freeze_bank(block.slot)
                .map_err(|e| StageError::ReplayError(format!("Bank freeze failed: {:?}", e)))?;

            self.stats.lock().unwrap().record_bank_transition();

            if finalization.epoch_boundary {
                println!(
                    "Epoch boundary at slot {} (epoch {})",
                    finalization.slot, finalization.epoch
                );
            }
        }

        // Step 6: Run consensus decision (vote + root progression)
        if self.config.process_votes {
            let bank_forks = self.bank_transition.bank_forks.clone();
            let is_ancestor = |a: u64, b: u64| {
                let bf = bank_forks.read().unwrap();
                bf.is_ancestor(a, b)
            };

            match self
                .vote_integration
                .run_consensus_decision(block.slot, is_ancestor)
            {
                Ok(decision) => {
                    if decision.vote_slot.is_some() {
                        self.stats.lock().unwrap().record_vote_processed();
                    }

                    // Handle root progression
                    if let Some(new_root) = decision.new_root {
                        if self.config.enable_root_progression {
                            let mut bank_forks = self.bank_transition.bank_forks.write().unwrap();
                            if new_root > bank_forks.root_slot() {
                                if let Err(e) = bank_forks.set_root(new_root) {
                                    eprintln!("Root progression failed: {:?}", e);
                                } else {
                                    drop(bank_forks);
                                    // Prune old vote data
                                    let mut vote_processor =
                                        self.vote_integration.vote_processor.lock().unwrap();
                                    vote_processor.prune_below_root(new_root);

                                    self.block_processor
                                        .commitment_tracker
                                        .lock()
                                        .unwrap()
                                        .update_root(new_root);

                                    // Flush account storage at root boundary for
                                    // crash-consistent durability checkpoint.
                                    let bank_forks_r =
                                        self.bank_transition.bank_forks.read().unwrap();
                                    if let Some(root_bank) = bank_forks_r.root_bank() {
                                        if let Err(e) =
                                            root_bank.accounts().notify_root_advanced(new_root)
                                        {
                                            eprintln!(
                                                "Storage flush at root {} failed: {:?}",
                                                new_root, e
                                            );
                                        }
                                    }
                                    drop(bank_forks_r);

                                    self.stats.lock().unwrap().record_root_progression();
                                    println!("Root progressed to slot {}", new_root);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Consensus decision warning for slot {}: {:?}",
                        block.slot, e
                    );
                }
            }
        }

        // Record statistics
        let success = outcome.executed_count > 0 || outcome.transactions.is_empty();
        self.stats
            .lock()
            .unwrap()
            .record_block_replay(outcome.transactions.len(), success);

        Ok(outcome)
    }

    /// Verify that block's parent hash matches expected parent bank
    fn verify_block_ancestry(
        &self,
        block: &AssembledBlock,
        bank: &Arc<paradencer_consensus::Bank>,
    ) -> Result<(), StageError> {
        // Check parent slot matches
        if let Some(parent_slot) = bank.parent_slot() {
            if parent_slot != block.parent_slot {
                return Err(StageError::ReplayError(format!(
                    "Parent slot mismatch: bank has parent {}, block has parent {}",
                    parent_slot, block.parent_slot
                )));
            }

            // Verify parent hash
            if bank.parent_hash() != [0u8; 32] {
                // Parent hash verification would go here
                // For now we trust the block's parent_slot
            }
        }

        Ok(())
    }

    /// Get current statistics
    pub fn stats(&self) -> ReplayStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        *self.stats.lock().unwrap() = ReplayStats::new();
    }

    /// Get configuration
    pub fn config(&self) -> &ReplayConfig {
        &self.config
    }
}
