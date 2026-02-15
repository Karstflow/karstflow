//! Fork-aware transaction deduplication cache.
//!
//! Uses sharded concurrent storage to allow lock-free reads and
//! minimal-contention writes during transaction processing.

mod entry;
mod nonce;
mod shard;

#[cfg(test)]
mod tests;

pub use entry::CacheEntry;
pub use nonce::{extract_nonce_key_index, is_nonce_instruction};

use paradencer_constants::block_limits::{
    DEFAULT_TRANSACTION_CACHE_MAX_ENTRIES, TRANSACTION_CACHE_SHARDS,
};
use shard::CacheShard;
use std::sync::RwLock;

/// Sharded, fork-aware transaction deduplication cache.
///
/// Transactions are distributed across shards by hashing the first 8 bytes
/// of the blockhash. Each shard is independently locked so that concurrent
/// insertions from different scheduling threads rarely contend.
pub struct TransactionCache {
    shards: Vec<RwLock<CacheShard>>,
    max_entries: usize,
}

impl TransactionCache {
    /// Create a cache with the default maximum entry count.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_TRANSACTION_CACHE_MAX_ENTRIES)
    }

    /// Create a cache with a specific maximum entry count.
    pub fn with_capacity(max_entries: usize) -> Self {
        let mut shards = Vec::with_capacity(TRANSACTION_CACHE_SHARDS);
        for _ in 0..TRANSACTION_CACHE_SHARDS {
            shards.push(RwLock::new(CacheShard::new()));
        }
        Self {
            shards,
            max_entries,
        }
    }

    /// Insert a transaction into the cache.
    ///
    /// Returns `true` if the transaction was newly accepted (not a duplicate
    /// on this fork). Returns `false` if it is a duplicate.
    pub fn insert(
        &self,
        blockhash: &[u8; 32],
        message_hash: &[u8; 32],
        slot: u64,
        fork: u64,
    ) -> bool {
        // Capacity check: if we are already at the limit, reject.
        if self.entry_count() >= self.max_entries {
            return false;
        }

        let idx = self.shard_for_hash(blockhash);
        let mut shard = self.shards[idx]
            .write()
            .expect("transaction cache shard lock poisoned");
        shard.insert(blockhash, message_hash, slot, fork)
    }

    /// Check whether a transaction already exists on a particular fork.
    pub fn contains(&self, blockhash: &[u8; 32], message_hash: &[u8; 32], fork: u64) -> bool {
        let idx = self.shard_for_hash(blockhash);
        let shard = self.shards[idx]
            .read()
            .expect("transaction cache shard lock poisoned");
        shard.contains(blockhash, message_hash, fork)
    }

    /// Remove all entries for a specific slot across every shard.
    pub fn purge_slot(&self, slot: u64) {
        for shard_lock in &self.shards {
            let mut shard = shard_lock
                .write()
                .expect("transaction cache shard lock poisoned");
            shard.purge_slot(slot);
        }
    }

    /// Remove all entries with a slot strictly less than `min_slot`.
    pub fn purge_before_slot(&self, min_slot: u64) {
        for shard_lock in &self.shards {
            let mut shard = shard_lock
                .write()
                .expect("transaction cache shard lock poisoned");
            shard.purge_before_slot(min_slot);
        }
    }

    /// Total number of cached transaction entries across all shards.
    pub fn entry_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.read()
                    .expect("transaction cache shard lock poisoned")
                    .entry_count()
            })
            .sum()
    }

    /// Determine the shard index for a given 32-byte hash.
    ///
    /// Uses the first 8 bytes of the hash interpreted as a little-endian u64,
    /// modulo the shard count.
    pub fn shard_for_hash(&self, hash: &[u8; 32]) -> usize {
        let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
        (val as usize) % self.shards.len()
    }
}

impl Default for TransactionCache {
    fn default() -> Self {
        Self::new()
    }
}
