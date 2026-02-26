use std::collections::HashMap;

use paradencer_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES;

use super::entry::CacheEntry;

/// A single shard of the transaction deduplication cache.
///
/// Each shard owns an independent hash map, keyed by blockhash then message hash prefix,
/// so that concurrent readers and writers on different shards do not contend.
pub struct CacheShard {
    /// blockhash -> (message_hash_prefix -> CacheEntry)
    entries: HashMap<[u8; 32], HashMap<[u8; MESSAGE_HASH_PREFIX_BYTES], CacheEntry>>,
    entry_count: usize,
}

impl CacheShard {
    /// Create an empty shard.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            entry_count: 0,
        }
    }

    /// Insert a transaction into the shard.
    ///
    /// Returns `true` if the transaction was newly inserted.
    /// Returns `false` if the transaction already exists on the given fork (duplicate).
    pub fn insert(
        &mut self,
        blockhash: &[u8; 32],
        message_hash: &[u8; MESSAGE_HASH_PREFIX_BYTES],
        slot: u64,
        fork: u64,
        status: super::entry::TransactionStatus,
    ) -> bool {
        let message_map = self.entries.entry(*blockhash).or_default();

        if let Some(existing) = message_map.get_mut(message_hash) {
            if existing.seen_on_fork(fork) {
                // Duplicate on the same fork.
                return false;
            }
            // Same transaction on a different fork is allowed.
            existing.add_fork(fork);
            true
        } else {
            message_map.insert(*message_hash, CacheEntry::new(slot, fork, status));
            self.entry_count += 1;
            true
        }
    }

    /// Check whether a transaction exists on the given fork.
    pub fn contains(
        &self,
        blockhash: &[u8; 32],
        message_hash: &[u8; MESSAGE_HASH_PREFIX_BYTES],
        fork: u64,
    ) -> bool {
        self.entries
            .get(blockhash)
            .and_then(|m| m.get(message_hash))
            .is_some_and(|entry| entry.seen_on_fork(fork))
    }

    /// Look up the cache entry for a transaction on a given fork.
    pub fn get(
        &self,
        blockhash: &[u8; 32],
        message_hash: &[u8; MESSAGE_HASH_PREFIX_BYTES],
        fork: u64,
    ) -> Option<&CacheEntry> {
        self.entries
            .get(blockhash)
            .and_then(|m| m.get(message_hash))
            .filter(|entry| entry.seen_on_fork(fork))
    }

    /// Remove all entries for a specific slot.
    pub fn purge_slot(&mut self, slot: u64) {
        let mut removed = 0usize;
        self.entries.retain(|_blockhash, message_map| {
            let before = message_map.len();
            message_map.retain(|_msg_hash, entry| entry.slot != slot);
            removed += before - message_map.len();
            !message_map.is_empty()
        });
        self.entry_count = self.entry_count.saturating_sub(removed);
    }

    /// Remove all entries with a slot strictly less than `min_slot`.
    pub fn purge_before_slot(&mut self, min_slot: u64) {
        let mut removed = 0usize;
        self.entries.retain(|_blockhash, message_map| {
            let before = message_map.len();
            message_map.retain(|_msg_hash, entry| entry.slot >= min_slot);
            removed += before - message_map.len();
            !message_map.is_empty()
        });
        self.entry_count = self.entry_count.saturating_sub(removed);
    }

    /// Total number of unique transaction entries in this shard.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}
