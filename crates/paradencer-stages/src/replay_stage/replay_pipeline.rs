/// Advanced replay pipeline utilities for batch processing and optimization
///
/// Provides higher-level abstractions for common replay patterns including:
/// - Batch block processing with parallelization
/// - Fork selection and switching
/// - Optimistic confirmation tracking
/// - Performance optimization helpers
use super::{BlockOutcome, ReplayStage, ReplayStats};
use crate::{AssembledBlock, StageError};
use std::collections::{HashMap, VecDeque};

/// Result of processing a batch of blocks
#[derive(Debug, Clone)]
pub struct BatchReplayResult {
    /// Number of blocks successfully replayed
    pub successful_blocks: usize,
    /// Number of blocks that failed
    pub failed_blocks: usize,
    /// Outcomes for each block (in order)
    pub outcomes: Vec<Result<BlockOutcome, String>>,
    /// Total transactions processed
    pub total_transactions: usize,
    /// Total compute units consumed
    pub total_compute_units: u64,
    /// Elapsed time in milliseconds
    pub elapsed_millis: u64,
}

impl BatchReplayResult {
    pub fn new() -> Self {
        Self {
            successful_blocks: 0,
            failed_blocks: 0,
            outcomes: Vec::new(),
            total_transactions: 0,
            total_compute_units: 0,
            elapsed_millis: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.successful_blocks + self.failed_blocks;
        if total == 0 {
            return 0.0;
        }
        self.successful_blocks as f64 / total as f64
    }

    pub fn throughput_tps(&self) -> f64 {
        if self.elapsed_millis == 0 {
            return 0.0;
        }
        let seconds = self.elapsed_millis as f64 / 1000.0;
        self.total_transactions as f64 / seconds
    }

    pub fn average_compute_per_tx(&self) -> u64 {
        if self.total_transactions == 0 {
            return 0;
        }
        self.total_compute_units / self.total_transactions as u64
    }
}

/// Helper for batch processing blocks with performance optimization
pub struct ReplayBatchProcessor {
    /// Maximum blocks to process in one batch
    batch_size: usize,
    /// Whether to stop on first error
    fail_fast: bool,
    /// Track performance metrics
    enable_metrics: bool,
}

impl ReplayBatchProcessor {
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            fail_fast: false,
            enable_metrics: true,
        }
    }

    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.enable_metrics = enable;
        self
    }

    /// Process a batch of blocks through the replay stage
    pub fn process_batch(
        &self,
        replay_stage: &mut ReplayStage,
        blocks: Vec<AssembledBlock>,
    ) -> Result<BatchReplayResult, StageError> {
        let start = std::time::Instant::now();
        let mut result = BatchReplayResult::new();

        for block in blocks.into_iter().take(self.batch_size) {
            let tx_count = block.transaction_count;

            match replay_stage.replay_block(block) {
                Ok(outcome) => {
                    result.successful_blocks += 1;
                    result.total_transactions += tx_count;
                    result.total_compute_units += outcome.total_compute_units;
                    result.outcomes.push(Ok(outcome));
                }
                Err(e) => {
                    result.failed_blocks += 1;
                    let error_msg = format!("{:?}", e);
                    result.outcomes.push(Err(error_msg));

                    if self.fail_fast {
                        return Err(e);
                    }
                }
            }
        }

        if self.enable_metrics {
            result.elapsed_millis = start.elapsed().as_millis() as u64;
        }

        Ok(result)
    }
}

/// Manager for handling fork selection and replay coordination
pub struct ForkReplayCoordinator {
    /// Track which forks we've replayed
    replayed_slots: HashMap<u64, SlotReplayInfo>,
    /// Queue of pending blocks to replay
    pending_blocks: VecDeque<AssembledBlock>,
    /// Maximum pending queue size
    max_pending: usize,
}

impl ForkReplayCoordinator {
    pub fn new(max_pending: usize) -> Self {
        Self {
            replayed_slots: HashMap::new(),
            pending_blocks: VecDeque::new(),
            max_pending,
        }
    }

    /// Add a block to the pending queue
    pub fn enqueue_block(&mut self, block: AssembledBlock) -> Result<(), String> {
        if self.pending_blocks.len() >= self.max_pending {
            return Err("Pending queue full".to_string());
        }

        self.pending_blocks.push_back(block);
        Ok(())
    }

    /// Process pending blocks in order
    pub fn process_pending(
        &mut self,
        replay_stage: &mut ReplayStage,
    ) -> Result<Vec<BlockOutcome>, StageError> {
        let mut outcomes = Vec::new();

        while let Some(block) = self.pending_blocks.pop_front() {
            let slot = block.slot;
            let outcome = replay_stage.replay_block(block)?;

            // Track replay info
            self.replayed_slots.insert(
                slot,
                SlotReplayInfo {
                    slot,
                    outcome: outcome.clone(),
                    timestamp: current_timestamp(),
                },
            );

            outcomes.push(outcome);
        }

        Ok(outcomes)
    }

    /// Get replay info for a slot
    pub fn get_replay_info(&self, slot: u64) -> Option<&SlotReplayInfo> {
        self.replayed_slots.get(&slot)
    }

    /// Check if slot has been replayed
    pub fn has_replayed(&self, slot: u64) -> bool {
        self.replayed_slots.contains_key(&slot)
    }

    /// Get pending block count
    pub fn pending_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Clear old replay info below a slot
    pub fn prune_below_slot(&mut self, slot: u64) {
        self.replayed_slots.retain(|&s, _| s >= slot);
    }

    /// Get statistics about replayed slots
    pub fn replay_stats(&self) -> CoordinatorStats {
        let total_replayed = self.replayed_slots.len();
        let avg_success_rate = if total_replayed > 0 {
            let sum: f64 = self
                .replayed_slots
                .values()
                .map(|info| info.outcome.success_rate())
                .sum();
            sum / total_replayed as f64
        } else {
            0.0
        };

        CoordinatorStats {
            total_replayed,
            pending_blocks: self.pending_blocks.len(),
            avg_success_rate,
        }
    }
}

/// Information about a replayed slot
#[derive(Debug, Clone)]
pub struct SlotReplayInfo {
    pub slot: u64,
    pub outcome: BlockOutcome,
    pub timestamp: u64,
}

/// Statistics from the fork coordinator
#[derive(Debug, Clone)]
pub struct CoordinatorStats {
    pub total_replayed: usize,
    pub pending_blocks: usize,
    pub avg_success_rate: f64,
}

/// Helper for optimistic confirmation tracking
pub struct OptimisticConfirmationTracker {
    /// Slots with optimistic confirmation
    confirmed_slots: HashMap<u64, ConfirmationInfo>,
    /// Minimum depth for optimistic confirmation
    min_depth: usize,
    /// Minimum stake ratio for confirmation
    min_stake_ratio: f64,
}

impl OptimisticConfirmationTracker {
    pub fn new(min_depth: usize, min_stake_ratio: f64) -> Self {
        Self {
            confirmed_slots: HashMap::new(),
            min_depth,
            min_stake_ratio,
        }
    }

    /// Check if a slot meets optimistic confirmation criteria
    pub fn check_confirmation(
        &mut self,
        slot: u64,
        stake_ratio: f64,
        descendant_depth: usize,
    ) -> bool {
        let is_confirmed =
            stake_ratio >= self.min_stake_ratio && descendant_depth >= self.min_depth;

        if is_confirmed {
            self.confirmed_slots.insert(
                slot,
                ConfirmationInfo {
                    slot,
                    stake_ratio,
                    depth: descendant_depth,
                    confirmed_at: current_timestamp(),
                },
            );
        }

        is_confirmed
    }

    /// Check if slot is optimistically confirmed
    pub fn is_confirmed(&self, slot: u64) -> bool {
        self.confirmed_slots.contains_key(&slot)
    }

    /// Get confirmation info for slot
    pub fn get_confirmation_info(&self, slot: u64) -> Option<&ConfirmationInfo> {
        self.confirmed_slots.get(&slot)
    }

    /// Get all confirmed slots
    pub fn confirmed_slots(&self) -> Vec<u64> {
        self.confirmed_slots.keys().copied().collect()
    }

    /// Prune confirmed slots below a root
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.confirmed_slots.retain(|&slot, _| slot >= root_slot);
    }

    /// Get statistics
    pub fn stats(&self) -> ConfirmationStats {
        let avg_depth = if !self.confirmed_slots.is_empty() {
            let sum: usize = self.confirmed_slots.values().map(|c| c.depth).sum();
            sum as f64 / self.confirmed_slots.len() as f64
        } else {
            0.0
        };

        let avg_stake_ratio = if !self.confirmed_slots.is_empty() {
            let sum: f64 = self.confirmed_slots.values().map(|c| c.stake_ratio).sum();
            sum / self.confirmed_slots.len() as f64
        } else {
            0.0
        };

        ConfirmationStats {
            total_confirmed: self.confirmed_slots.len(),
            avg_depth,
            avg_stake_ratio,
        }
    }
}

/// Information about an optimistically confirmed slot
#[derive(Debug, Clone)]
pub struct ConfirmationInfo {
    pub slot: u64,
    pub stake_ratio: f64,
    pub depth: usize,
    pub confirmed_at: u64,
}

/// Statistics about optimistic confirmations
#[derive(Debug, Clone)]
pub struct ConfirmationStats {
    pub total_confirmed: usize,
    pub avg_depth: f64,
    pub avg_stake_ratio: f64,
}

/// Performance optimizer for replay operations
pub struct ReplayOptimizer {
    /// Recent block processing times (in microseconds)
    recent_times: VecDeque<u64>,
    /// Maximum samples to track
    max_samples: usize,
}

impl ReplayOptimizer {
    pub fn new(max_samples: usize) -> Self {
        Self {
            recent_times: VecDeque::new(),
            max_samples,
        }
    }

    /// Record a block processing time
    pub fn record_processing_time(&mut self, micros: u64) {
        if self.recent_times.len() >= self.max_samples {
            self.recent_times.pop_front();
        }
        self.recent_times.push_back(micros);
    }

    /// Get average processing time
    pub fn avg_processing_time(&self) -> Option<u64> {
        if self.recent_times.is_empty() {
            return None;
        }

        let sum: u64 = self.recent_times.iter().sum();
        Some(sum / self.recent_times.len() as u64)
    }

    /// Get median processing time
    pub fn median_processing_time(&self) -> Option<u64> {
        if self.recent_times.is_empty() {
            return None;
        }

        let mut sorted: Vec<u64> = self.recent_times.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    /// Get 95th percentile processing time
    pub fn p95_processing_time(&self) -> Option<u64> {
        if self.recent_times.is_empty() {
            return None;
        }

        let mut sorted: Vec<u64> = self.recent_times.iter().copied().collect();
        sorted.sort_unstable();
        let index = (sorted.len() as f64 * 0.95) as usize;
        Some(sorted[index.min(sorted.len() - 1)])
    }

    /// Suggest optimal batch size based on timing
    pub fn suggest_batch_size(&self, target_latency_ms: u64) -> usize {
        match self.avg_processing_time() {
            Some(avg_micros) => {
                let target_micros = target_latency_ms * 1000;
                let suggested = target_micros / avg_micros.max(1);
                suggested.max(1).min(128) as usize
            }
            None => 32, // Default
        }
    }

    /// Check if performance is degrading
    pub fn is_degrading(&self, threshold_percent: f64) -> bool {
        if self.recent_times.len() < 2 {
            return false;
        }

        let half = self.recent_times.len() / 2;
        let first_half: Vec<_> = self.recent_times.iter().take(half).copied().collect();
        let second_half: Vec<_> = self.recent_times.iter().skip(half).copied().collect();

        if first_half.is_empty() || second_half.is_empty() {
            return false;
        }

        let avg_first: u64 = first_half.iter().sum::<u64>() / first_half.len() as u64;
        let avg_second: u64 = second_half.iter().sum::<u64>() / second_half.len() as u64;

        let percent_increase = (avg_second as f64 - avg_first as f64) / avg_first as f64 * 100.0;

        percent_increase > threshold_percent
    }
}

/// Helper to get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_replay_result_calculates_rates() {
        let mut result = BatchReplayResult::new();
        result.successful_blocks = 8;
        result.failed_blocks = 2;
        result.total_transactions = 1000;
        result.total_compute_units = 500000;
        result.elapsed_millis = 1000;

        assert_eq!(result.success_rate(), 0.8);
        assert_eq!(result.throughput_tps(), 1000.0);
        assert_eq!(result.average_compute_per_tx(), 500);
    }

    #[test]
    fn batch_processor_initializes() {
        let processor = ReplayBatchProcessor::new(32)
            .with_fail_fast(true)
            .with_metrics(false);

        assert_eq!(processor.batch_size, 32);
        assert!(processor.fail_fast);
        assert!(!processor.enable_metrics);
    }

    #[test]
    fn fork_coordinator_manages_queue() {
        let mut coordinator = ForkReplayCoordinator::new(10);

        // Create test block
        use crate::Entry;
        let block = AssembledBlock {
            slot: 1,
            parent_slot: 0,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32],
                transactions: vec![],
            }],
            transaction_count: 0,
            total_bytes: 0,
            shred_count: 1,
        };

        coordinator.enqueue_block(block).unwrap();
        assert_eq!(coordinator.pending_count(), 1);

        let stats = coordinator.replay_stats();
        assert_eq!(stats.pending_blocks, 1);
    }

    #[test]
    fn optimistic_confirmation_tracks_slots() {
        let mut tracker = OptimisticConfirmationTracker::new(8, 0.67);

        // Low stake - not confirmed
        assert!(!tracker.check_confirmation(100, 0.5, 10));

        // Insufficient depth - not confirmed
        assert!(!tracker.check_confirmation(101, 0.7, 5));

        // Meets criteria - confirmed
        assert!(tracker.check_confirmation(102, 0.7, 10));
        assert!(tracker.is_confirmed(102));

        let stats = tracker.stats();
        assert_eq!(stats.total_confirmed, 1);
    }

    #[test]
    fn optimistic_confirmation_prunes_old_slots() {
        let mut tracker = OptimisticConfirmationTracker::new(8, 0.67);

        tracker.check_confirmation(100, 0.7, 10);
        tracker.check_confirmation(101, 0.7, 10);
        tracker.check_confirmation(102, 0.7, 10);

        assert_eq!(tracker.confirmed_slots().len(), 3);

        tracker.prune_below_root(101);
        assert_eq!(tracker.confirmed_slots().len(), 2);
        assert!(!tracker.is_confirmed(100));
        assert!(tracker.is_confirmed(101));
        assert!(tracker.is_confirmed(102));
    }

    #[test]
    fn replay_optimizer_tracks_performance() {
        let mut optimizer = ReplayOptimizer::new(10);

        optimizer.record_processing_time(1000);
        optimizer.record_processing_time(2000);
        optimizer.record_processing_time(1500);

        assert_eq!(optimizer.avg_processing_time(), Some(1500));
        assert_eq!(optimizer.median_processing_time(), Some(1500));
    }

    #[test]
    fn replay_optimizer_suggests_batch_size() {
        let mut optimizer = ReplayOptimizer::new(10);

        // Record 1ms per block average
        for _ in 0..5 {
            optimizer.record_processing_time(1000);
        }

        // Target 50ms latency
        let suggested = optimizer.suggest_batch_size(50);
        assert_eq!(suggested, 50);
    }

    #[test]
    fn replay_optimizer_detects_degradation() {
        let mut optimizer = ReplayOptimizer::new(10);

        // First half: fast
        for _ in 0..5 {
            optimizer.record_processing_time(1000);
        }

        // Second half: slow (50% slower)
        for _ in 0..5 {
            optimizer.record_processing_time(1500);
        }

        // Should detect degradation > 25%
        assert!(optimizer.is_degrading(25.0));
        assert!(!optimizer.is_degrading(75.0));
    }

    #[test]
    fn fork_coordinator_tracks_replay_info() {
        let mut coordinator = ForkReplayCoordinator::new(10);

        assert!(!coordinator.has_replayed(100));
        assert_eq!(coordinator.get_replay_info(100), None);

        coordinator.prune_below_slot(50);
        assert_eq!(coordinator.replay_stats().total_replayed, 0);
    }

    #[test]
    fn confirmation_info_stores_metadata() {
        let info = ConfirmationInfo {
            slot: 100,
            stake_ratio: 0.75,
            depth: 12,
            confirmed_at: 1000,
        };

        assert_eq!(info.slot, 100);
        assert_eq!(info.depth, 12);
        assert!((info.stake_ratio - 0.75).abs() < 0.01);
    }

    #[test]
    fn confirmation_stats_calculates_averages() {
        let mut tracker = OptimisticConfirmationTracker::new(8, 0.67);

        tracker.check_confirmation(100, 0.70, 10);
        tracker.check_confirmation(101, 0.75, 12);
        tracker.check_confirmation(102, 0.80, 14);

        let stats = tracker.stats();
        assert_eq!(stats.total_confirmed, 3);
        assert!((stats.avg_depth - 12.0).abs() < 0.01);
        assert!((stats.avg_stake_ratio - 0.75).abs() < 0.01);
    }

    #[test]
    fn batch_result_handles_empty_batch() {
        let result = BatchReplayResult::new();
        assert_eq!(result.success_rate(), 0.0);
        assert_eq!(result.throughput_tps(), 0.0);
        assert_eq!(result.average_compute_per_tx(), 0);
    }
}
