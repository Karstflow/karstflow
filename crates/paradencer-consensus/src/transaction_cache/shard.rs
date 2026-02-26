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

#[cfg(test)]
mod tests {
    use super::super::entry::TransactionStatus;
    use super::*;

    fn blockhash(b: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    fn msg_hash(b: u8) -> [u8; MESSAGE_HASH_PREFIX_BYTES] {
        let mut h = [0u8; MESSAGE_HASH_PREFIX_BYTES];
        h[0] = b;
        h
    }

    #[test]
    fn empty_shard() {
        let shard = CacheShard::new();
        assert_eq!(shard.entry_count(), 0);
        assert!(!shard.contains(&blockhash(1), &msg_hash(1), 0));
    }

    #[test]
    fn insert_and_lookup() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);
        let mh = msg_hash(1);

        let inserted = shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        assert!(inserted);
        assert_eq!(shard.entry_count(), 1);
        assert!(shard.contains(&bh, &mh, 0));
    }

    #[test]
    fn duplicate_on_same_fork_rejected() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);
        let mh = msg_hash(1);

        shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        let dup = shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        assert!(!dup);
        assert_eq!(shard.entry_count(), 1);
    }

    #[test]
    fn same_tx_on_different_fork_allowed() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);
        let mh = msg_hash(1);

        shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        let ok = shard.insert(&bh, &mh, 100, 1, TransactionStatus::Success);
        assert!(ok);
        // Entry count doesn't increase — same entry, different fork
        assert_eq!(shard.entry_count(), 1);
        assert!(shard.contains(&bh, &mh, 0));
        assert!(shard.contains(&bh, &mh, 1));
    }

    #[test]
    fn contains_returns_false_for_different_fork() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);
        let mh = msg_hash(1);

        shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        assert!(!shard.contains(&bh, &mh, 1));
    }

    #[test]
    fn get_returns_entry_on_correct_fork() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);
        let mh = msg_hash(1);

        shard.insert(&bh, &mh, 100, 0, TransactionStatus::Success);
        let entry = shard.get(&bh, &mh, 0).unwrap();
        assert_eq!(entry.slot, 100);
        assert!(matches!(entry.status, TransactionStatus::Success));

        assert!(shard.get(&bh, &mh, 1).is_none());
    }

    #[test]
    fn purge_slot_removes_matching_entries() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);

        shard.insert(&bh, &msg_hash(1), 100, 0, TransactionStatus::Success);
        shard.insert(&bh, &msg_hash(2), 200, 0, TransactionStatus::Success);
        shard.insert(&bh, &msg_hash(3), 100, 0, TransactionStatus::Failed);
        assert_eq!(shard.entry_count(), 3);

        shard.purge_slot(100);
        assert_eq!(shard.entry_count(), 1);
        assert!(!shard.contains(&bh, &msg_hash(1), 0));
        assert!(shard.contains(&bh, &msg_hash(2), 0));
    }

    #[test]
    fn purge_before_slot_removes_older() {
        let mut shard = CacheShard::new();
        let bh = blockhash(1);

        shard.insert(&bh, &msg_hash(1), 50, 0, TransactionStatus::Success);
        shard.insert(&bh, &msg_hash(2), 100, 0, TransactionStatus::Success);
        shard.insert(&bh, &msg_hash(3), 150, 0, TransactionStatus::Success);

        shard.purge_before_slot(100);
        assert_eq!(shard.entry_count(), 2);
        assert!(!shard.contains(&bh, &msg_hash(1), 0));
        assert!(shard.contains(&bh, &msg_hash(2), 0));
        assert!(shard.contains(&bh, &msg_hash(3), 0));
    }

    #[test]
    fn multiple_blockhashes() {
        let mut shard = CacheShard::new();

        shard.insert(
            &blockhash(1),
            &msg_hash(1),
            100,
            0,
            TransactionStatus::Success,
        );
        shard.insert(
            &blockhash(2),
            &msg_hash(1),
            100,
            0,
            TransactionStatus::Success,
        );

        assert_eq!(shard.entry_count(), 2);
        assert!(shard.contains(&blockhash(1), &msg_hash(1), 0));
        assert!(shard.contains(&blockhash(2), &msg_hash(1), 0));
        // Same msg_hash under different blockhash — different entries
        assert!(!shard.contains(&blockhash(1), &msg_hash(2), 0));
    }
}
