/// Transaction deduplication stage.
///
/// Provides O(1) amortized duplicate detection using a ring buffer paired
/// with an open-addressing (linear probing) hash map. When the ring is full,
/// the oldest entry is evicted and removed from the map using backward-shift
/// deletion to maintain probe-chain invariants.
///
/// Transactions are identified by a 64-bit tag (typically the first 8 bytes
/// of the Ed25519 signature). The sentinel value 0 is reserved for empty
/// map slots and is always treated as unique.
use paradencer_constants::dedup::{DEFAULT_CACHE_DEPTH, NULL_TAG, SPARSE_FACTOR};

/// O(1) amortized transaction dedup cache.
///
/// Combines a fixed-size ring buffer (recording insertion order for FIFO
/// eviction) with a sparse open-addressing hash map (for O(1) lookups).
///
/// - **Insert**: probe map → if found, duplicate. Otherwise evict oldest
///   from ring, remove from map via backward-shift, write new tag to ring
///   and map.
/// - **Evict**: O(1) amortized. The ring cursor advances, and the evicted
///   tag is removed from the map with backward-shift deletion (no tombstones).
pub struct TransactionCache {
    /// Ring buffer of tags in insertion order. Length = depth.
    ring: Vec<u64>,
    /// Current write position in the ring (wraps at depth).
    ring_cursor: usize,
    /// Number of entries currently stored (up to depth).
    ring_count: usize,
    /// Open-addressing hash map with linear probing. Length = depth * sparse_factor.
    /// Empty slots contain NULL_TAG (0).
    map: Vec<u64>,
    /// Bitmask for map index: map.len() - 1.
    map_mask: usize,
    /// Maximum entries in the ring buffer.
    depth: usize,
}

impl TransactionCache {
    /// Create a new transaction cache with the given depth.
    ///
    /// `depth` must be a power of 2. The hash map is allocated with
    /// `depth * SPARSE_FACTOR` slots.
    ///
    /// # Panics
    ///
    /// Panics if `depth` is not a power of 2 or is zero.
    pub fn new(depth: usize) -> Self {
        assert!(
            depth > 0 && depth.is_power_of_two(),
            "depth must be a power of 2"
        );

        let map_capacity = depth * SPARSE_FACTOR as usize;
        // map_capacity is also a power of 2 since depth is and SPARSE_FACTOR is 2
        debug_assert!(map_capacity.is_power_of_two());

        Self {
            ring: vec![NULL_TAG; depth],
            ring_cursor: 0,
            ring_count: 0,
            map: vec![NULL_TAG; map_capacity],
            map_mask: map_capacity - 1,
            depth,
        }
    }

    /// Create a cache with the default depth from constants.
    pub fn with_default_depth() -> Self {
        Self::new(DEFAULT_CACHE_DEPTH)
    }

    /// Check whether `tag` is a duplicate and insert it if unique.
    ///
    /// Returns `true` if the tag was already present (duplicate),
    /// `false` if it was newly inserted (unique).
    ///
    /// The sentinel value `NULL_TAG` (0) is always treated as unique
    /// and is never stored in the cache.
    pub fn insert(&mut self, tag: u64) -> bool {
        // Sentinel tags are never cached — always unique
        if tag == NULL_TAG {
            return false;
        }

        // Probe the map for this tag
        let mut slot = self.slot_for(tag);
        loop {
            let existing = self.map[slot];
            if existing == tag {
                // Found — duplicate
                return true;
            }
            if existing == NULL_TAG {
                // Empty slot — tag is unique, proceed to insert
                break;
            }
            // Linear probe
            slot = (slot + 1) & self.map_mask;
        }

        // Evict oldest entry if ring is full
        if self.ring_count == self.depth {
            let evicted = self.ring[self.ring_cursor];
            if evicted != NULL_TAG {
                self.remove_from_map(evicted);
            }
        } else {
            self.ring_count += 1;
        }

        // Write to ring
        self.ring[self.ring_cursor] = tag;
        self.ring_cursor = (self.ring_cursor + 1) % self.depth;

        // Insert into map (find first empty slot from the natural position)
        let mut slot = self.slot_for(tag);
        loop {
            if self.map[slot] == NULL_TAG {
                self.map[slot] = tag;
                break;
            }
            slot = (slot + 1) & self.map_mask;
        }

        false
    }

    /// Query whether `tag` is present in the cache without inserting.
    pub fn query(&self, tag: u64) -> bool {
        if tag == NULL_TAG {
            return false;
        }

        let mut slot = self.slot_for(tag);
        loop {
            let existing = self.map[slot];
            if existing == tag {
                return true;
            }
            if existing == NULL_TAG {
                return false;
            }
            slot = (slot + 1) & self.map_mask;
        }
    }

    /// Clear the cache, removing all entries.
    pub fn reset(&mut self) {
        self.ring.fill(NULL_TAG);
        self.ring_cursor = 0;
        self.ring_count = 0;
        self.map.fill(NULL_TAG);
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.ring_count
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.ring_count == 0
    }

    /// Maximum capacity of the cache.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Compute the natural map slot for a tag using a fast hash.
    #[inline]
    fn slot_for(&self, tag: u64) -> usize {
        // Fibonacci hashing for good distribution
        let hash = tag.wrapping_mul(0x9E3779B97F4A7C15);
        (hash as usize) & self.map_mask
    }

    /// Remove a tag from the map using backward-shift deletion.
    ///
    /// This maintains the invariant that all tags in a probe chain are
    /// contiguous from their natural slot. No tombstones needed.
    fn remove_from_map(&mut self, tag: u64) {
        // Find the tag in the map
        let mut slot = self.slot_for(tag);
        loop {
            if self.map[slot] == tag {
                break;
            }
            if self.map[slot] == NULL_TAG {
                // Tag not found (shouldn't happen if ring/map are consistent)
                return;
            }
            slot = (slot + 1) & self.map_mask;
        }

        // Backward-shift deletion: shift subsequent entries backward
        // to fill the gap, as long as they would benefit from being
        // closer to their natural slot.
        let mut empty = slot;
        loop {
            let next = (empty + 1) & self.map_mask;
            let next_tag = self.map[next];

            if next_tag == NULL_TAG {
                // End of probe chain
                break;
            }

            let natural = self.slot_for(next_tag);

            // Should we shift? The entry at `next` belongs to `natural`.
            // It should be shifted backward if `natural` is at or before
            // the empty slot in the circular probe sequence.
            if self.should_shift(empty, next, natural) {
                self.map[empty] = next_tag;
                empty = next;
            } else {
                // This entry is in its correct cluster — stop shifting
                // past entries that are correctly placed.
                // We need to continue scanning in case there are more
                // entries further along that could benefit from shifting.
                let scan = (next + 1) & self.map_mask;
                if self.map[scan] == NULL_TAG {
                    break;
                }
                // Continue scanning without moving empty
                empty = next;
                continue;
            }
        }

        // Clear the final empty slot
        self.map[empty] = NULL_TAG;
    }

    /// Determine whether the entry at `candidate` should be shifted backward
    /// to fill the `empty` slot, given that its natural slot is `natural`.
    ///
    /// In a circular array, we shift if `natural` is "between" `empty` and
    /// `candidate` in the circular order (i.e., the entry would benefit from
    /// being closer to its natural position).
    #[inline]
    fn should_shift(&self, empty: usize, candidate: usize, natural: usize) -> bool {
        if empty <= candidate {
            // No wrap: natural must be in [natural..=empty] or after candidate
            // Actually: shift if natural <= empty OR natural > candidate
            natural <= empty || natural > candidate
        } else {
            // Wraps: shift if natural is in the wrapped range
            natural <= empty && natural > candidate
        }
    }
}

/// Outcome of a deduplication check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupOutcome {
    /// Transaction tag was not seen before — proceed with processing.
    Unique,
    /// Transaction tag was already seen — discard.
    Duplicate,
}

/// Statistics for dedup stage operations.
#[derive(Debug, Clone, Default)]
pub struct DedupStats {
    /// Total tags checked.
    pub total_checked: u64,
    /// Tags identified as duplicates.
    pub duplicates_found: u64,
    /// Tags that passed as unique.
    pub unique_passed: u64,
}

/// Deduplication stage wrapping a `TransactionCache` with metrics.
///
/// Call `check(tag)` for each incoming transaction signature fingerprint.
/// Duplicates are silently dropped (counted in stats).
pub struct DedupStage {
    cache: TransactionCache,
    stats: DedupStats,
}

impl DedupStage {
    /// Create a new dedup stage with the given cache depth.
    pub fn new(depth: usize) -> Self {
        Self {
            cache: TransactionCache::new(depth),
            stats: DedupStats::default(),
        }
    }

    /// Create a dedup stage with the default cache depth.
    pub fn with_default_depth() -> Self {
        Self {
            cache: TransactionCache::with_default_depth(),
            stats: DedupStats::default(),
        }
    }

    /// Check a transaction tag for duplicates.
    ///
    /// Returns `DedupOutcome::Unique` if the tag is new (and inserts it),
    /// or `DedupOutcome::Duplicate` if it was already seen.
    pub fn check(&mut self, tag: u64) -> DedupOutcome {
        self.stats.total_checked += 1;

        if self.cache.insert(tag) {
            self.stats.duplicates_found += 1;
            DedupOutcome::Duplicate
        } else {
            self.stats.unique_passed += 1;
            DedupOutcome::Unique
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &DedupStats {
        &self.stats
    }

    /// Reset statistics counters (cache contents are preserved).
    pub fn reset_stats(&mut self) {
        self.stats = DedupStats::default();
    }

    /// Reset both the cache and statistics.
    pub fn reset_all(&mut self) {
        self.cache.reset();
        self.stats = DedupStats::default();
    }

    /// Access the underlying cache (for advanced queries).
    pub fn cache(&self) -> &TransactionCache {
        &self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_returns_unique() {
        let mut cache = TransactionCache::new(16);
        assert!(!cache.insert(42));
        assert!(!cache.insert(100));
        assert!(!cache.insert(999));
    }

    #[test]
    fn duplicate_detection() {
        let mut cache = TransactionCache::new(16);
        assert!(!cache.insert(42)); // unique
        assert!(cache.insert(42)); // duplicate
        assert!(cache.insert(42)); // still duplicate
    }

    #[test]
    fn eviction_after_depth() {
        let depth = 8;
        let mut cache = TransactionCache::new(depth);

        // Fill cache with tags 1..=8
        for i in 1..=depth as u64 {
            assert!(!cache.insert(i), "tag {} should be unique", i);
        }

        // All should be queryable
        for i in 1..=depth as u64 {
            assert!(cache.query(i), "tag {} should be present", i);
        }

        // Insert one more — tag 1 should be evicted
        assert!(!cache.insert(100));
        assert!(!cache.query(1), "tag 1 should have been evicted");
        assert!(cache.query(2), "tag 2 should still be present");
        assert!(cache.query(100), "tag 100 should be present");

        // Insert more to evict 2..=4
        assert!(!cache.insert(101));
        assert!(!cache.insert(102));
        assert!(!cache.insert(103));
        assert!(!cache.query(2));
        assert!(!cache.query(3));
        assert!(!cache.query(4));
        assert!(cache.query(5), "tag 5 should still be present");
    }

    #[test]
    fn null_tag_always_unique() {
        let mut cache = TransactionCache::new(16);
        // NULL_TAG is never stored, always returns unique
        assert!(!cache.insert(NULL_TAG));
        assert!(!cache.insert(NULL_TAG));
        assert!(!cache.insert(NULL_TAG));
        assert!(!cache.query(NULL_TAG));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn backward_shift_deletion_correct() {
        // Use a small cache to force many evictions and test probe chain integrity
        let depth = 16;
        let mut cache = TransactionCache::new(depth);

        // Insert tags that will hash to nearby slots (collision testing)
        let tags: Vec<u64> = (1..=32).collect();

        // Fill and overfill — each eviction triggers backward-shift deletion
        for &tag in &tags {
            cache.insert(tag);
        }

        // Only the last `depth` tags should remain
        for &tag in &tags[..16] {
            assert!(!cache.query(tag), "tag {} should have been evicted", tag);
        }
        for &tag in &tags[16..] {
            assert!(cache.query(tag), "tag {} should still be present", tag);
        }

        // Verify no false positives for tags never inserted
        for tag in 1000..1100u64 {
            assert!(!cache.query(tag), "tag {} was never inserted", tag);
        }
    }

    #[test]
    fn large_batch_no_false_positives() {
        let depth = 1024;
        let mut cache = TransactionCache::new(depth);

        // Insert 1024 unique tags
        for i in 1..=depth as u64 {
            assert!(
                !cache.insert(i),
                "tag {} should be unique on first insert",
                i
            );
        }

        // All should be found
        for i in 1..=depth as u64 {
            assert!(cache.query(i), "tag {} should be queryable", i);
        }

        // None of these should be false positives
        for i in (depth as u64 + 1)..=(depth as u64 + 500) {
            assert!(!cache.query(i), "tag {} was never inserted", i);
        }
    }

    #[test]
    fn stats_tracking() {
        let mut stage = DedupStage::new(16);

        assert_eq!(stage.check(1), DedupOutcome::Unique);
        assert_eq!(stage.check(2), DedupOutcome::Unique);
        assert_eq!(stage.check(1), DedupOutcome::Duplicate);
        assert_eq!(stage.check(3), DedupOutcome::Unique);
        assert_eq!(stage.check(2), DedupOutcome::Duplicate);

        let stats = stage.stats();
        assert_eq!(stats.total_checked, 5);
        assert_eq!(stats.unique_passed, 3);
        assert_eq!(stats.duplicates_found, 2);
    }

    #[test]
    fn reset_clears_all() {
        let mut stage = DedupStage::new(16);

        stage.check(1);
        stage.check(2);
        stage.check(3);
        assert_eq!(stage.cache().len(), 3);

        stage.reset_all();
        assert_eq!(stage.cache().len(), 0);
        assert_eq!(stage.stats().total_checked, 0);

        // Previously-inserted tags should now be unique again
        assert_eq!(stage.check(1), DedupOutcome::Unique);
        assert_eq!(stage.check(2), DedupOutcome::Unique);
    }

    #[test]
    fn stress_eviction_integrity() {
        // Stress test: insert many tags, verify cache never reports
        // false positives or misses for tags within the window.
        let depth = 64;
        let mut cache = TransactionCache::new(depth);

        for i in 1..=10_000u64 {
            let is_dup = cache.insert(i);
            assert!(!is_dup, "first insert of {} should be unique", i);

            // The tag we just inserted should be queryable
            assert!(cache.query(i), "just-inserted tag {} should be found", i);

            // Tags more than `depth` ago should be gone
            if i > depth as u64 {
                let old = i - depth as u64;
                assert!(
                    !cache.query(old),
                    "tag {} should have been evicted (current={})",
                    old,
                    i
                );
            }
        }
    }
}
