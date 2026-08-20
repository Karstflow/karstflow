//! Per-block cost tracking and limit enforcement.
//!
//! Tracks compute unit consumption and account data size changes
//! to prevent blocks from exceeding protocol limits.

mod account_cost;
mod allocated_data;
mod block_limits_checker;
mod transaction_cost;

#[cfg(test)]
mod tests;

pub use account_cost::AccountCostTracker;
pub use allocated_data::calculate_allocated_accounts_data_size;
pub use block_limits_checker::check_limits;
pub use transaction_cost::TransactionCost;

use karstflow_constants::block_limits::{
    ACCOUNT_CU_LIMIT_RATIO_PERCENT, MAX_ACCOUNT_DATA_SIZE_DELTA, MAX_BLOCK_ACCOUNTS_DATA_SIZE,
    MAX_BLOCK_COMPUTE_UNITS, MAX_BLOCK_COMPUTE_UNITS_SIMD_0256, MAX_BLOCK_COMPUTE_UNITS_SIMD_0286,
    MAX_VOTE_COMPUTE_UNITS, MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
};
use karstflow_storage::Pubkey;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Resolved block cost limits for a specific slot.
///
/// At each slot boundary, feature flags are consulted to determine
/// which SIMD-level limits are active. This struct stores the resolved
/// values so they can be used throughout the slot without repeated
/// feature checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostLimits {
    /// Maximum total compute units per block.
    pub block_cost_limit: u64,
    /// Maximum compute units for vote transactions per block.
    pub vote_cost_limit: u64,
    /// Maximum compute units per writable account per block.
    pub account_cost_limit: u64,
    /// Maximum account data size delta per block (bytes).
    pub account_data_size_limit: i64,
    /// Maximum total account data the block may allocate (bytes), enforced from
    /// the pre-execution system-program allocation estimate.
    pub block_accounts_data_size_limit: u64,
}

impl CostLimits {
    /// Resolve cost limits based on active feature flags.
    ///
    /// Feature flags:
    /// - `raise_block_limits_to_100m` → SIMD-0286 (100M CU)
    /// - `raise_block_limits_to_60m`  → SIMD-0256 (60M CU)
    /// - `raise_account_cu_limit`     → SIMD-0306 (account limit = 40% of block limit)
    ///
    /// Falls back to SIMD-0207 (50M CU) when neither raise feature is active.
    pub fn from_features(
        raise_to_100m: bool,
        raise_to_60m: bool,
        raise_account_limit: bool,
    ) -> Self {
        let block_cost_limit = if raise_to_100m {
            MAX_BLOCK_COMPUTE_UNITS_SIMD_0286
        } else if raise_to_60m {
            MAX_BLOCK_COMPUTE_UNITS_SIMD_0256
        } else {
            MAX_BLOCK_COMPUTE_UNITS
        };

        let account_cost_limit = if raise_account_limit {
            block_cost_limit * ACCOUNT_CU_LIMIT_RATIO_PERCENT / 100
        } else {
            MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS
        };

        Self {
            block_cost_limit,
            vote_cost_limit: MAX_VOTE_COMPUTE_UNITS,
            account_cost_limit,
            account_data_size_limit: MAX_ACCOUNT_DATA_SIZE_DELTA,
            block_accounts_data_size_limit: MAX_BLOCK_ACCOUNTS_DATA_SIZE,
        }
    }
}

impl Default for CostLimits {
    fn default() -> Self {
        Self {
            block_cost_limit: MAX_BLOCK_COMPUTE_UNITS,
            vote_cost_limit: MAX_VOTE_COMPUTE_UNITS,
            account_cost_limit: MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS,
            account_data_size_limit: MAX_ACCOUNT_DATA_SIZE_DELTA,
            block_accounts_data_size_limit: MAX_BLOCK_ACCOUNTS_DATA_SIZE,
        }
    }
}

/// Per-block cost tracker with atomic counters for concurrent access.
///
/// Tracks total block cost, vote cost, per-account write-lock costs,
/// and account data size changes. All limit checks and updates happen
/// atomically to support multi-threaded transaction scheduling.
pub struct CostTracker {
    /// Resolved limits for this block.
    limits: CostLimits,
    /// Total compute units consumed in this block.
    block_cost: AtomicU64,
    /// Compute units consumed by vote transactions.
    vote_cost: AtomicU64,
    /// Per-account write lock costs.
    account_costs: AccountCostTracker,
    /// Net account data size change (can be negative from account closures).
    account_data_size_delta: AtomicI64,
    /// Cumulative pre-execution allocated account data size for this block.
    allocated_accounts_data_size: AtomicU64,
    /// Whether this block has been marked as dead (exceeded limits).
    is_dead: AtomicBool,
    /// Number of transactions added to this block.
    transaction_count: AtomicU64,
    /// When true, simple votes are no longer tracked separately in the
    /// vote cost bucket — they use the full cost model instead.
    remove_simple_vote_from_cost_model: bool,
}

impl CostTracker {
    /// Create a new, empty cost tracker with default limits.
    pub fn new() -> Self {
        Self::with_limits(CostLimits::default())
    }

    /// Create a new, empty cost tracker with specific limits.
    pub fn with_limits(limits: CostLimits) -> Self {
        Self {
            limits,
            block_cost: AtomicU64::new(0),
            vote_cost: AtomicU64::new(0),
            account_costs: AccountCostTracker::new(),
            account_data_size_delta: AtomicI64::new(0),
            allocated_accounts_data_size: AtomicU64::new(0),
            is_dead: AtomicBool::new(false),
            transaction_count: AtomicU64::new(0),
            remove_simple_vote_from_cost_model: false,
        }
    }

    /// Create a new cost tracker with the `remove_simple_vote_from_cost_model` feature.
    pub fn with_limits_and_features(limits: CostLimits, remove_simple_vote: bool) -> Self {
        Self {
            limits,
            block_cost: AtomicU64::new(0),
            vote_cost: AtomicU64::new(0),
            account_costs: AccountCostTracker::new(),
            account_data_size_delta: AtomicI64::new(0),
            allocated_accounts_data_size: AtomicU64::new(0),
            is_dead: AtomicBool::new(false),
            transaction_count: AtomicU64::new(0),
            remove_simple_vote_from_cost_model: remove_simple_vote,
        }
    }

    /// Get the resolved cost limits for this block.
    pub fn limits(&self) -> &CostLimits {
        &self.limits
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
        let current_allocated = self.allocated_accounts_data_size.load(Ordering::Acquire);

        let check_vote_limit = cost.is_vote && !self.remove_simple_vote_from_cost_model;
        check_limits(
            current_block,
            current_vote,
            current_delta,
            current_allocated,
            &|pubkey| self.account_costs.get(pubkey),
            cost,
            &self.limits,
            check_vote_limit,
        )?;

        // Apply the cost. In a highly concurrent system there is a TOCTOU gap
        // between the check and the add; the atomic adds are safe and the
        // worst case is a slight over-commitment that the validator can handle.
        self.block_cost
            .fetch_add(cost.total_cost, Ordering::Release);
        if cost.is_vote && !self.remove_simple_vote_from_cost_model {
            self.vote_cost.fetch_add(cost.total_cost, Ordering::Release);
        }
        for pubkey in &cost.writable_accounts {
            self.account_costs.add(pubkey, cost.total_cost);
        }
        if cost.data_size_delta != 0 {
            self.account_data_size_delta
                .fetch_add(cost.data_size_delta, Ordering::Release);
        }
        if cost.allocated_accounts_data_size != 0 {
            self.allocated_accounts_data_size
                .fetch_add(cost.allocated_accounts_data_size, Ordering::Release);
        }
        self.transaction_count.fetch_add(1, Ordering::Release);

        Ok(())
    }

    /// Reconcile a reserved cost against what the transaction actually did.
    ///
    /// The block reserves capacity from the compute budget a transaction
    /// *requests*. That request is routinely far larger than the work — asking
    /// for too little is fatal and asking for too much is free, provided the
    /// difference is given back here. Block, vote and every write-locked
    /// account move together, because all three were charged the same figure.
    pub fn update_execution_cost(&self, cost: &TransactionCost, actual_execution_and_loaded: u64) {
        let estimated = cost.execution_and_loaded_cost;
        if actual_execution_and_loaded == estimated {
            return;
        }

        if actual_execution_and_loaded > estimated {
            let extra = actual_execution_and_loaded - estimated;
            self.block_cost.fetch_add(extra, Ordering::Release);
            if cost.is_vote && !self.remove_simple_vote_from_cost_model {
                self.vote_cost.fetch_add(extra, Ordering::Release);
            }
            for pubkey in &cost.writable_accounts {
                self.account_costs.add(pubkey, extra);
            }
        } else {
            let refund = estimated - actual_execution_and_loaded;
            self.block_cost.fetch_sub(refund, Ordering::Release);
            if cost.is_vote && !self.remove_simple_vote_from_cost_model {
                self.vote_cost.fetch_sub(refund, Ordering::Release);
            }
            for pubkey in &cost.writable_accounts {
                self.account_costs.remove(pubkey, refund);
            }
        }
    }

    /// Remove a previously added transaction cost (e.g. after execution failure).
    pub fn remove(&self, cost: &TransactionCost) {
        self.block_cost
            .fetch_sub(cost.total_cost, Ordering::Release);
        if cost.is_vote && !self.remove_simple_vote_from_cost_model {
            self.vote_cost.fetch_sub(cost.total_cost, Ordering::Release);
        }
        for pubkey in &cost.writable_accounts {
            self.account_costs.remove(pubkey, cost.total_cost);
        }
        if cost.data_size_delta != 0 {
            // Subtract the delta that was previously added.
            self.account_data_size_delta
                .fetch_update(Ordering::Release, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(cost.data_size_delta))
                })
                .ok();
        }
        if cost.allocated_accounts_data_size != 0 {
            self.allocated_accounts_data_size
                .fetch_sub(cost.allocated_accounts_data_size, Ordering::Release);
        }
        self.transaction_count.fetch_sub(1, Ordering::Release);
    }

    /// Remaining compute units that can still fit in this block.
    pub fn remaining_capacity(&self) -> u64 {
        self.limits
            .block_cost_limit
            .saturating_sub(self.block_cost.load(Ordering::Acquire))
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
    /// Per-block allocated account data size limit exceeded.
    BlockAccountsDataSizeLimitExceeded {
        current: u64,
        requested: u64,
        limit: u64,
    },
    /// Block is dead.
    BlockDead,
}
