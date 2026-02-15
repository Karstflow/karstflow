/// Tracks where a transaction has been seen across forks.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The slot in which this transaction was first observed.
    pub slot: u64,
    /// Fork identifiers on which this transaction has appeared.
    pub forks: Vec<u64>,
}

impl CacheEntry {
    /// Create a new cache entry for a transaction first seen on the given slot and fork.
    pub fn new(slot: u64, fork: u64) -> Self {
        Self {
            slot,
            forks: vec![fork],
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
