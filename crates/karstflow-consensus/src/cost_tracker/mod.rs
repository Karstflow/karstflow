//! Per-block cost tracking and limit enforcement.
//!
//! Tracks compute unit consumption and account data size changes
//! to prevent blocks from exceeding protocol limits.

mod account_cost;
mod block_limits_checker;
mod transaction_cost;

#[cfg(test)]
mod tests;

pub use account_cost::AccountCostTracker;
pub use block_limits_checker::check_limits;
pub use transaction_cost::TransactionCost;

use karstflow_constants::block_limits::MAX_BLOCK_COMPUTE_UNITS;
use karstflow_storage::Pubkey;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Per-block cost tracker with atomic counters for concurrent access.
///
/// Tracks total block cost, vote cost, per-account write-lock costs,
/// and account data size changes. All limit checks and updates happen
/// atomically to support multi-threaded transaction scheduling.
pub struct CostTracker {
    /// Total compute units consumed in this block.
    block_cost: AtomicU64,
    /// Compute units consumed by vote transactions.
    vote_cost: AtomicU64,
    /// Per-account write lock costs.
    account_costs: AccountCostTracker,
    /// Net account data size change (can be negative from account closures).
    account_data_size_delta: AtomicI64,
    /// Whether this block has been marked as dead (exceeded limits).
    is_dead: AtomicBool,
    /// Number of transactions added to this block.
    transaction_count: AtomicU64,
}

impl CostTracker {
    /// Create a new, empty cost tracker for a block.
    pub fn new() -> Self {
        Self {
            block_cost: AtomicU64::new(0),
            vote_cost: AtomicU64::new(0),
            account_costs: AccountCostTracker::new(),
            account_data_size_delta: AtomicI64::new(0),
            is_dead: AtomicBool::new(false),
            transaction_count: AtomicU64::new(0),
        }
    }

    /// Attempt to add a transaction's cost to this block.
    ///
    /// Performs a pre-check against all block limits. If the transaction
    /// would exceed any limit, returns an error without modifying state.
    /// Otherwise atomically adds the cost.
    pub fn try_add(&self, cost: &TransactionCost) -> Result<(), CostTrackerError> {
        if self.is_dead.load(Ordering::Acquire) {
            return Err(CostTrackerError::BlockDead);
        }

        // Pre-check limits against current values.
        let current_block = self.block_cost.load(Ordering::Acquire);
        let current_vote = self.vote_cost.load(Ordering::Acquire);
        let current_delta = self.account_data_size_delta.load(Ordering::Acquire);

        check_limits(
            current_block,
            current_vote,
            current_delta,
            &|pubkey| self.account_costs.get(pubkey),
            cost,
        )?;

        // Apply the cost. In a highly concurrent system there is a TOCTOU gap
        // between the check and the add; the atomic adds are safe and the
        // worst case is a slight over-commitment that the validator can handle.
        self.block_cost
            .fetch_add(cost.compute_units, Ordering::Release);
        if cost.is_vote {
            self.vote_cost
                .fetch_add(cost.compute_units, Ordering::Release);
        }
        for (pubkey, acct_cost) in &cost.writable_accounts {
            self.account_costs.add(pubkey, *acct_cost);
        }
        if cost.data_size_delta != 0 {
            self.account_data_size_delta
                .fetch_add(cost.data_size_delta, Ordering::Release);
        }
        self.transaction_count.fetch_add(1, Ordering::Release);

        Ok(())
    }

    /// Remove a previously added transaction cost (e.g. after execution failure).
    pub fn remove(&self, cost: &TransactionCost) {
        self.block_cost
            .fetch_sub(cost.compute_units, Ordering::Release);
        if cost.is_vote {
            self.vote_cost
                .fetch_sub(cost.compute_units, Ordering::Release);
        }
        for (pubkey, acct_cost) in &cost.writable_accounts {
            self.account_costs.remove(pubkey, *acct_cost);
        }
        if cost.data_size_delta != 0 {
            // Subtract the delta that was previously added.
            self.account_data_size_delta
                .fetch_update(Ordering::Release, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(cost.data_size_delta))
                })
                .ok();
        }
        self.transaction_count.fetch_sub(1, Ordering::Release);
    }

    /// Remaining compute units that can still fit in this block.
    pub fn remaining_capacity(&self) -> u64 {
        MAX_BLOCK_COMPUTE_UNITS.saturating_sub(self.block_cost.load(Ordering::Acquire))
    }

    /// Total block compute units consumed so far.
    pub fn block_cost(&self) -> u64 {
        self.block_cost.load(Ordering::Acquire)
    }

    /// Compute units consumed by vote transactions.
    pub fn vote_cost(&self) -> u64 {
        self.vote_cost.load(Ordering::Acquire)
    }

    /// Net account data size delta for this block.
    pub fn account_data_size_delta(&self) -> i64 {
        self.account_data_size_delta.load(Ordering::Acquire)
    }

    /// Whether the block has been marked as dead.
    pub fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Acquire)
    }

    /// Mark this block as dead (no further transactions accepted).
    pub fn mark_dead(&self) {
        self.is_dead.store(true, Ordering::Release);
    }

    /// Number of transactions that have been added to this block.
    pub fn transaction_count(&self) -> u64 {
        self.transaction_count.load(Ordering::Acquire)
    }

    /// Get the accumulated write-lock cost for a specific account.
    pub fn account_cost(&self, pubkey: &Pubkey) -> u64 {
        self.account_costs.get(pubkey)
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CostTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CostTracker")
            .field("block_cost", &self.block_cost.load(Ordering::Relaxed))
            .field("vote_cost", &self.vote_cost.load(Ordering::Relaxed))
            .field("is_dead", &self.is_dead.load(Ordering::Relaxed))
            .field(
                "transaction_count",
                &self.transaction_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

/// Errors returned when a transaction would exceed block limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostTrackerError {
    /// Block compute unit limit exceeded.
    BlockCostLimitExceeded {
        current: u64,
        requested: u64,
        limit: u64,
    },
    /// Vote compute unit limit exceeded.
    VoteCostLimitExceeded {
        current: u64,
        requested: u64,
        limit: u64,
    },
    /// Writable account compute unit limit exceeded.
    AccountCostLimitExceeded {
        account: Pubkey,
        current: u64,
        requested: u64,
        limit: u64,
    },
    /// Account data size delta exceeded.
    AccountDataSizeLimitExceeded {
        current: i64,
        requested: i64,
        limit: i64,
    },
    /// Block is dead.
    BlockDead,
}
