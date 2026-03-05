//! Transaction packing and block scheduling.
//!
//! Selects and orders pending transactions for block inclusion, maximizing
//! fee revenue while respecting compute unit limits, per-account write-lock
//! costs, and data size constraints.

pub mod cost_model;
pub mod priority;
pub mod scheduler;

#[cfg(test)]
mod tests;

pub use cost_model::{
    compute_transaction_cost, CostRebateTracker, InstructionView,
    TransactionCost as PackTransactionCost,
};
pub use priority::{PendingTransaction, PriorityQueue};
pub use scheduler::{
    BlockLimits, BlockScheduler, BlockUsage, MicroblockSchedule, ScheduledTransaction,
};

use karstflow_constants::block_limits::DEFAULT_PENDING_POOL_CAPACITY;

// ---------------------------------------------------------------------------
// Transaction pack (top-level API)
// ---------------------------------------------------------------------------

/// High-level transaction packing engine.
///
/// Combines a priority queue of pending transactions with a block scheduler
/// that selects non-conflicting transactions for microblock production.
pub struct TransactionPack {
    /// Pool of pending transactions ordered by priority.
    queue: PriorityQueue,
    /// Block-level scheduler with conflict detection.
    scheduler: BlockScheduler,
    /// Fraction of each microblock reserved for vote transactions.
    vote_fraction: f64,
}

impl TransactionPack {
    /// Create a new pack engine with the given capacity and limits.
    pub fn new(capacity: usize, limits: BlockLimits) -> Self {
        Self {
            queue: PriorityQueue::new(capacity),
            scheduler: BlockScheduler::new(limits),
            vote_fraction: 0.75,
        }
    }

    /// Create a pack engine with default settings.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_PENDING_POOL_CAPACITY, BlockLimits::default())
    }

    /// Set the fraction of microblock capacity reserved for votes.
    pub fn set_vote_fraction(&mut self, fraction: f64) {
        self.vote_fraction = fraction.clamp(0.0, 1.0);
    }

    /// Insert a transaction into the pending pool.
    ///
    /// Returns the assigned ID on success, or `None` if rejected.
    pub fn insert(&mut self, entry: PendingTransaction) -> Option<u64> {
        self.queue.insert(entry)
    }

    /// Produce the next microblock of scheduled transactions.
    pub fn schedule_microblock(&mut self) -> MicroblockSchedule {
        self.scheduler
            .schedule_microblock(&mut self.queue, self.vote_fraction)
    }

    /// Notify the scheduler that a transaction has completed execution.
    ///
    /// Releases any write/read locks held by this transaction, potentially
    /// unblocking deferred transactions for the next microblock.
    pub fn complete_transaction(&mut self, tx_id: u64) {
        self.scheduler.release_locks(tx_id);
    }

    /// Remove expired transactions from the pending pool.
    pub fn expire_before(&mut self, slot: u64) -> usize {
        self.queue.expire_before(slot)
    }

    /// Signal that the current block is finished. Resets per-block state.
    pub fn end_block(&mut self) {
        self.scheduler.end_block();
    }

    /// Update block limits for the next block.
    pub fn set_block_limits(&mut self, limits: BlockLimits) {
        self.scheduler.set_limits(limits);
    }

    /// Number of transactions currently in the pending pool.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Number of non-vote transactions in the pending pool.
    pub fn pending_non_vote_count(&self) -> usize {
        self.queue.pending_count()
    }

    /// Number of vote transactions in the pending pool.
    pub fn pending_vote_count(&self) -> usize {
        self.queue.vote_count()
    }

    /// Current block resource usage.
    pub fn block_usage(&self) -> &BlockUsage {
        self.scheduler.usage()
    }

    /// Clear all pending transactions.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}
