/// Execution status recorded alongside a transaction in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Transaction executed successfully.
    Success,
    /// Transaction failed with an execution error.
    Failed,
}

/// Tracks where a transaction has been seen across forks.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The slot in which this transaction was first observed.
    pub slot: u64,
    /// Fork identifiers on which this transaction has appeared.
    pub forks: Vec<u64>,
    /// Execution result of the transaction.
    pub status: TransactionStatus,
}

impl CacheEntry {
    /// Create a new cache entry for a transaction first seen on the given slot and fork.
    pub fn new(slot: u64, fork: u64, status: TransactionStatus) -> Self {
        Self {
            slot,
            forks: vec![fork],
            status,
        }
    }

    /// Record this transaction as also appearing on an additional fork.
    pub fn add_fork(&mut self, fork: u64) {
        if !self.forks.contains(&fork) {
            self.forks.push(fork);
        }
    }

    /// Check whether this transaction has been observed on the given fork.
    pub fn seen_on_fork(&self, fork: u64) -> bool {
        self.forks.contains(&fork)
    }
}
