mod ancestry_verifier;
mod bank_transition;
mod block_processor;
mod replay_pipeline;
pub mod signals;
mod slot_metrics;
#[cfg(test)]
mod tests;
mod transaction_dispatcher;
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
pub use signals::{
    BecameLeaderInfo, OptimisticConfirmationInfo, PohResetInfo, ReplaySignal, RootAdvancedInfo,
    SignalBus, SlotCompletedInfo, SlotDeadInfo, SlotDeadReason,
};
pub use slot_metrics::{
    AggregateMetrics, AlertSeverity, AlertType, AnomalyType, MetricsTracker, PerformanceAlert,
    PerformanceAnomaly, PerformanceMonitor, PerformanceThresholds, SlotMetrics,
};
pub use transaction_dispatcher::{
    DependencyGraph, DispatchProgress, DispatchState, DispatcherStats, TransactionDispatcher,
};
pub use vote_integration::{VoteIntegration, VoteIntegrationError};

use crate::{AssembledBlock, StageError};
use karstflow_consensus::{
    BankForks, CommitmentTracker, ExecutionBackend, ForkChoice, Tower, VoteProcessor,
};
use karstflow_execution::ExecutionBridge;
use std::sync::{Arc, Mutex, RwLock};
use tracing::{error, info, warn};

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
    /// Signal bus for structured replay event broadcast.
    signal_bus: Arc<Mutex<SignalBus>>,
    /// Validator identity for leader schedule detection.
    /// When set, the replay stage emits BecameLeader signals.
    validator_identity: Option<[u8; 32]>,
    /// Last leader slot range end we emitted (avoids duplicate signals).
    last_leader_signal_end: Option<u64>,
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
        let mut block_processor = BlockProcessor::new(execution_bridge, commitment_tracker.clone());
        block_processor.verify_poh = config.verify_poh;
        let vote_integration =
            VoteIntegration::new(vote_processor, tower, fork_choice, commitment_tracker);

        Self {
            config,
            bank_transition,
            block_processor,
            vote_integration,
            stats: Arc::new(Mutex::new(ReplayStats::new())),
            signal_bus: Arc::new(Mutex::new(SignalBus::new())),
            validator_identity: None,
            last_leader_signal_end: None,
        }
    }

    /// Set the validator identity for leader schedule detection.
    ///
    /// When set, the replay stage will emit BecameLeader signals whenever
    /// a completed slot is followed by a leader range for this validator.
    pub fn set_validator_identity(&mut self, identity: [u8; 32]) {
        self.validator_identity = Some(identity);
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
            BlockProcessor::with_backend(execution_bridge, commitment_tracker.clone(), backend);
        block_processor.verify_poh = config.verify_poh;
        let vote_integration =
            VoteIntegration::new(vote_processor, tower, fork_choice, commitment_tracker);

        Self {
            config,
            bank_transition,
            block_processor,
            vote_integration,
            stats: Arc::new(Mutex::new(ReplayStats::new())),
            signal_bus: Arc::new(Mutex::new(SignalBus::new())),
            validator_identity: None,
            last_leader_signal_end: None,
        }
    }

    /// Get a shared reference to the signal bus.
    ///
    /// Use `signal_bus().lock().expect("...").subscribe()` to register a
    /// new consumer of replay signals.
    pub fn signal_bus(&self) -> Arc<Mutex<SignalBus>> {
        Arc::clone(&self.signal_bus)
    }

    /// Emit a replay signal and log when subscribers drop messages.
    fn emit_signal(&self, signal: ReplaySignal) {
        let drops = self
            .signal_bus
            .lock()
            .expect("signal_bus lock poisoned")
            .emit(signal);
        if drops > 0 {
            warn!(
                signal_drops = drops,
                "replay signal dropped for overloaded subscribers"
            );
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

            self.stats
                .lock()
                .expect("replay_stats lock poisoned")
                .record_bank_transition();

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
                warn!(slot = block.slot, error = ?e, "vote processing warning");
            } else {
                self.stats
                    .lock()
                    .expect("replay_stats lock poisoned")
                    .record_vote_processed();
            }
        }

        // Step 4: Apply transactions and process block
        let outcome = match self
            .block_processor
            .process_block(block.clone(), bank.clone())
        {
            Ok(outcome) => outcome,
            Err(e) => {
                // Mark the slot dead and evict it from the fork tree.
                let evicted = self.bank_transition.mark_slot_dead(block.slot);
                if evicted > 0 {
                    info!(
                        slot = block.slot,
                        evicted, "dead bank evicted after block processing failure",
                    );
                }

                // Emit SlotDead signal on block processing failure.
                self.emit_signal(ReplaySignal::SlotDead(SlotDeadInfo {
                    slot: block.slot,
                    parent_slot: block.parent_slot,
                    reason: SlotDeadReason::ExecutionFailed(format!("{:?}", e)),
                }));
                return Err(StageError::ReplayError(format!(
                    "Block processing failed: {:?}",
                    e
                )));
            }
        };

        // Step 4b: Feed vote updates from executed transactions into ForkChoice
        // and CommitmentTracker for threshold-based confirmation events.
        if self.config.process_votes && !outcome.vote_updates.is_empty() {
            if let Err(e) = self
                .vote_integration
                .process_vote_updates(&outcome.vote_updates)
            {
                warn!(
                    slot = block.slot,
                    vote_count = outcome.vote_updates.len(),
                    error = ?e,
                    "failed to incorporate vote updates into fork choice"
                );
            }

            // Emit OptimisticConfirmation signals for slots that crossed
            // the 2/3+ stake threshold during vote processing.
            for event in self.vote_integration.drain_confirmation_events() {
                if event.status >= karstflow_consensus::ConfirmationStatus::OptimisticallyConfirmed
                {
                    self.emit_signal(ReplaySignal::OptimisticConfirmation(
                        OptimisticConfirmationInfo {
                            slot: event.slot,
                            stake_percentage: event.stake_ratio * 100.0,
                        },
                    ));
                }
            }
        }

        // Step 5: Finalize slot if complete (distribute fees, update sysvars, freeze)
        if self.config.auto_freeze_banks && bank.is_complete() {
            let finalization = match self.bank_transition.freeze_bank(block.slot) {
                Ok(f) => f,
                Err(e) => {
                    // Mark the slot dead and evict it from the fork tree.
                    let evicted = self.bank_transition.mark_slot_dead(block.slot);
                    if evicted > 0 {
                        info!(
                            slot = block.slot,
                            evicted, "dead bank evicted after freeze failure",
                        );
                    }

                    self.emit_signal(ReplaySignal::SlotDead(SlotDeadInfo {
                        slot: block.slot,
                        parent_slot: block.parent_slot,
                        reason: SlotDeadReason::BankFreezeError,
                    }));
                    return Err(StageError::ReplayError(format!(
                        "Bank freeze failed: {:?}",
                        e
                    )));
                }
            };

            self.stats
                .lock()
                .expect("replay_stats lock poisoned")
                .record_bank_transition();

            if finalization.epoch_boundary {
                info!(
                    slot = finalization.slot,
                    epoch = finalization.epoch,
                    "epoch boundary reached",
                );
            }

            // Emit SlotCompleted signal after successful freeze.
            let timestamp = bank
                .sysvar_cache()
                .map(|c| c.clock().unix_timestamp)
                .unwrap_or(0);
            let parent_blockhash = self
                .bank_transition
                .bank_forks
                .read()
                .expect("bank_forks lock poisoned")
                .get(block.parent_slot)
                .map(|parent_bank| parent_bank.last_blockhash())
                .unwrap_or([0u8; 32]);
            self.emit_signal(ReplaySignal::SlotCompleted(SlotCompletedInfo {
                slot: block.slot,
                parent_slot: block.parent_slot,
                bank_hash: bank.hash(),
                block_hash: bank.last_blockhash(),
                parent_blockhash,
                epoch: finalization.epoch,
                is_epoch_boundary: finalization.epoch_boundary,
                transaction_count: outcome.transactions.len() as u64,
                executed_count: outcome.executed_count as u64,
                fee_lamports_collected: bank.execution_fees() + bank.priority_fees(),
                capitalization: bank.capitalization(),
                timestamp,
            }));

            // Step 5b: Check if this validator is the leader for upcoming slots.
            // Emit BecameLeader so the pipeline activates block production.
            if let Some(identity) = self.validator_identity {
                let next_slot = block.slot + 1;
                let identity_pubkey = karstflow_storage::Pubkey::new(identity);
                let schedule = bank.leader_schedule();
                let epoch_schedule = bank.epoch_schedule();
                let is_our_slot = schedule
                    .leader_for_absolute_slot(next_slot, epoch_schedule)
                    .map(|leader| leader == identity_pubkey)
                    .unwrap_or(false);
                if is_our_slot {
                    // Scan forward for contiguous leader range.
                    let mut end_slot = next_slot;
                    while schedule
                        .leader_for_absolute_slot(end_slot + 1, epoch_schedule)
                        .map(|leader| leader == identity_pubkey)
                        .unwrap_or(false)
                    {
                        end_slot += 1;
                    }
                    // Only emit if we haven't already signaled this range.
                    if self.last_leader_signal_end != Some(end_slot) {
                        self.last_leader_signal_end = Some(end_slot);
                        self.emit_signal(ReplaySignal::BecameLeader(BecameLeaderInfo {
                            start_slot: next_slot,
                            end_slot,
                            epoch: finalization.epoch,
                            identity_pubkey: identity,
                        }));
                    }
                }
            }
        }

        // Step 6: Run consensus decision (vote + root progression)
        if self.config.process_votes {
            let bank_forks = self.bank_transition.bank_forks.clone();
            let is_ancestor = |a: u64, b: u64| {
                let bf = bank_forks.read().expect("bank_forks lock poisoned");
                bf.is_ancestor(a, b)
            };

            match self
                .vote_integration
                .run_consensus_decision(block.slot, is_ancestor)
            {
                Ok(decision) => {
                    if decision.vote_slot.is_some() {
                        self.stats
                            .lock()
                            .expect("replay_stats lock poisoned")
                            .record_vote_processed();
                    }

                    // Handle root progression
                    if let Some(new_root) = decision.new_root {
                        if self.config.enable_root_progression {
                            let mut bank_forks = self
                                .bank_transition
                                .bank_forks
                                .write()
                                .expect("bank_forks lock poisoned");
                            if new_root > bank_forks.root_slot() {
                                let previous_root = bank_forks.root_slot();
                                match bank_forks.set_root(new_root) {
                                    Err(e) => {
                                        error!(error = ?e, "root progression failed");
                                    }
                                    Ok(eviction_report) => {
                                        let pruned_count = eviction_report.total_evicted() as u64;
                                        drop(bank_forks);
                                        // Prune old vote data
                                        let mut vote_processor = self
                                            .vote_integration
                                            .vote_processor
                                            .lock()
                                            .expect("vote_processor lock poisoned");
                                        vote_processor.prune_below_root(new_root);

                                        self.block_processor
                                            .commitment_tracker
                                            .lock()
                                            .expect("commitment_tracker lock poisoned")
                                            .update_root(new_root);

                                        // Flush account storage at root boundary for
                                        // crash-consistent durability checkpoint.
                                        let bank_forks_r = self
                                            .bank_transition
                                            .bank_forks
                                            .read()
                                            .expect("bank_forks lock poisoned");
                                        if let Some(root_bank) = bank_forks_r.root_bank() {
                                            if let Err(e) =
                                                root_bank.accounts().notify_root_advanced(new_root)
                                            {
                                                error!(root = new_root, error = ?e, "storage flush at root failed");
                                            }
                                        }
                                        drop(bank_forks_r);

                                        self.stats
                                            .lock()
                                            .expect("replay_stats lock poisoned")
                                            .record_root_progression();

                                        // Emit RootAdvanced signal.
                                        self.emit_signal(ReplaySignal::RootAdvanced(
                                            RootAdvancedInfo {
                                                new_root,
                                                previous_root,
                                                pruned_slot_count: pruned_count,
                                            },
                                        ));

                                        info!(new_root, "root progressed");
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(slot = block.slot, error = ?e, "consensus decision failed");
                }
            }
        }

        // Record statistics
        let success = outcome.executed_count > 0 || outcome.transactions.is_empty();
        self.stats
            .lock()
            .expect("replay_stats lock poisoned")
            .record_block_replay(outcome.transactions.len(), success);

        Ok(outcome)
    }

    /// Verify that block's parent hash matches expected parent bank
    fn verify_block_ancestry(
        &self,
        block: &AssembledBlock,
        bank: &Arc<karstflow_consensus::Bank>,
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
        self.stats
            .lock()
            .expect("replay_stats lock poisoned")
            .clone()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        *self.stats.lock().expect("replay_stats lock poisoned") = ReplayStats::new();
    }

    /// Get configuration
    pub fn config(&self) -> &ReplayConfig {
        &self.config
    }
}
