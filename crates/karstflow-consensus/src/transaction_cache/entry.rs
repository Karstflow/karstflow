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

    /// Remove a fork from this entry. Returns `true` if the entry
    /// has no remaining forks and should be evicted.
    pub fn remove_fork(&mut self, fork: u64) -> bool {
        self.forks.retain(|&f| f != fork);
        self.forks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_entry_has_single_fork() {
        let entry = CacheEntry::new(100, 1, TransactionStatus::Success);
        assert_eq!(entry.slot, 100);
        assert_eq!(entry.forks, vec![1]);
        assert_eq!(entry.status, TransactionStatus::Success);
    }

    #[test]
    fn add_fork_extends_list() {
        let mut entry = CacheEntry::new(100, 1, TransactionStatus::Success);
        entry.add_fork(2);
        assert_eq!(entry.forks, vec![1, 2]);
    }

    #[test]
    fn add_fork_deduplicates() {
        let mut entry = CacheEntry::new(100, 1, TransactionStatus::Success);
        entry.add_fork(1);
        assert_eq!(entry.forks, vec![1]);
    }

    #[test]
    fn seen_on_fork_returns_true_for_known() {
        let entry = CacheEntry::new(100, 5, TransactionStatus::Failed);
        assert!(entry.seen_on_fork(5));
    }

    #[test]
    fn seen_on_fork_returns_false_for_unknown() {
        let entry = CacheEntry::new(100, 5, TransactionStatus::Failed);
        assert!(!entry.seen_on_fork(99));
    }

    #[test]
    fn failed_status_preserved() {
        let entry = CacheEntry::new(0, 0, TransactionStatus::Failed);
        assert_eq!(entry.status, TransactionStatus::Failed);
    }
}
