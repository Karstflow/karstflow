//! Fixed-depth deduplication cache for 64-bit tags.
//!
//! Tracks the most recently observed unique tags using a circular ring
//! buffer (FIFO eviction) backed by a sparse open-addressing hash map
//! for O(1) lookup. Designed for high-throughput per-tile deduplication
//! of transaction signature hashes.
//!
//! The ring stores tags in insertion order. When the ring is full
//! (after `depth` unique inserts), the oldest tag is evicted from both
//! the ring and the map on each new unique insert.
//!
//! Duplicates are detected but NOT promoted (no LRU). A tag that was
//! inserted long ago will still be evicted at its scheduled time, even
//! if it was queried recently. This is intentional — deduplication only
//! needs "was this seen in the last N?" semantics.
//!
//! The hash map uses linear probing with identity-mod hashing (low bits
//! of the tag). This works well when tags are uniformly distributed
//! (e.g., signature hashes). The map's fill ratio is kept at 25–50%
//! (with default sparsity), ensuring short probe chains.
//!
//! Single-threaded. Not `Sync`. Intended for use within a single tile's
//! service loop where blocking and contention are not allowed.

/// Sentinel value for empty slots. Tag 0 must never be inserted.
pub const TAG_NULL: u64 = 0;

/// Default sparsity exponent. The map has `2^(ceil_log2(depth+1) + SPARSE_DEFAULT)`
/// slots, giving a fill ratio between 25% and 50%.
const SPARSE_DEFAULT: u32 = 2;

/// A fixed-depth cache of unique 64-bit tags.
///
/// Cache-line aligned to avoid false sharing when allocated adjacent
/// to other per-tile structures.
#[repr(C, align(128))]
pub struct TagCache {
    /// Circular ring of the last `depth` unique tags seen.
    /// During startup (fewer than `depth` inserts), unfilled slots
    /// contain `TAG_NULL`.
    ring: Vec<u64>,
    /// Sparse open-addressing hash map. Slot count is a power of 2.
    /// Empty slots contain `TAG_NULL`.
    map: Vec<u64>,
    /// Number of unique tags to retain.
    depth: usize,
    /// Bitmask for map indexing: `map.len() - 1`.
    map_mask: usize,
    /// Index of the oldest entry in the ring (next to be evicted).
    oldest: usize,
}

impl TagCache {
    /// Create a new tag cache with the given depth.
    ///
    /// `depth` must be >= 1. The map size is computed automatically
    /// using the default sparsity (4x depth).
    ///
    /// # Panics
    ///
    /// Panics if `depth` is 0.
    pub fn new(depth: usize) -> Self {
        assert!(depth >= 1, "TagCache depth must be >= 1");
        let map_cnt = map_cnt_default(depth);
        Self::with_map_cnt(depth, map_cnt)
    }

    /// Create a new tag cache with explicit depth and map size.
    ///
    /// `map_cnt` must be a power of 2 and >= `depth + 2`.
    ///
    /// # Panics
    ///
    /// Panics if constraints are violated.
    pub fn with_map_cnt(depth: usize, map_cnt: usize) -> Self {
        assert!(depth >= 1, "TagCache depth must be >= 1");
        assert!(map_cnt.is_power_of_two(), "map_cnt must be a power of 2");
        assert!(
            map_cnt >= depth + 2,
            "map_cnt ({map_cnt}) must be >= depth + 2 ({})",
            depth + 2
        );

        Self {
            ring: vec![TAG_NULL; depth],
            map: vec![TAG_NULL; map_cnt],
            depth,
            map_mask: map_cnt - 1,
            oldest: 0,
        }
    }

    /// Cache depth (number of unique tags retained).
    #[inline]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Map slot count.
    #[inline]
    pub fn map_cnt(&self) -> usize {
        self.map_mask + 1
    }

    /// Query whether a tag is in the cache.
    ///
    /// Returns `true` if the tag was seen within the last `depth` unique inserts.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `tag != TAG_NULL`.
    #[inline]
    pub fn contains(&self, tag: u64) -> bool {
        debug_assert_ne!(tag, TAG_NULL, "cannot query TAG_NULL");
        let (found, _) = self.probe(tag);
        found
    }

    /// Insert a tag into the cache.
    ///
    /// Returns `true` if the tag was already present (duplicate).
    /// Returns `false` if the tag is new (was inserted, possibly
    /// evicting the oldest tag).
    ///
    /// # Panics
    ///
    /// Debug-asserts that `tag != TAG_NULL`.
    #[inline]
    pub fn insert(&mut self, tag: u64) -> bool {
        debug_assert_ne!(tag, TAG_NULL, "cannot insert TAG_NULL");

        let (found, slot) = self.probe(tag);

        if found {
            return true;
        }

        // Insert into map at the empty slot found by probe.
        self.map[slot] = tag;

        // Read the tag being evicted from the ring.
        let evicted = self.ring[self.oldest];

        // Write new tag into the ring at the oldest position.
        self.ring[self.oldest] = tag;

        // Advance oldest pointer.
        self.oldest += 1;
        if self.oldest >= self.depth {
            self.oldest = 0;
        }

        // Remove the evicted tag from the map.
        // During startup, evicted == TAG_NULL and remove is a no-op.
        if evicted != TAG_NULL {
            self.remove(evicted);
        }

        false
    }

    /// Reset the cache to empty state.
    ///
    /// All tags are cleared. Equivalent to creating a new cache with
    /// the same depth and map size.
    pub fn reset(&mut self) {
        self.ring.fill(TAG_NULL);
        self.map.fill(TAG_NULL);
        self.oldest = 0;
    }

    /// Number of tags currently in the cache.
    ///
    /// During startup this may be less than `depth`. At steady state
    /// it equals `depth`.
    pub fn len(&self) -> usize {
        // Count non-null entries in the ring.
        self.ring.iter().filter(|&&t| t != TAG_NULL).count()
    }

    /// Whether the cache is empty (no tags inserted yet).
    pub fn is_empty(&self) -> bool {
        self.ring[0] == TAG_NULL && self.oldest == 0
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// Linear-probe query. Returns (found, slot_index).
    ///
    /// If found: slot_index is where the tag lives.
    /// If not found: slot_index is the first empty slot (valid insertion point).
    #[inline]
    fn probe(&self, tag: u64) -> (bool, usize) {
        let mut idx = (tag as usize) & self.map_mask;
        loop {
            let slot_tag = self.map[idx];
            if slot_tag == tag {
                return (true, idx);
            }
            if slot_tag == TAG_NULL {
                return (false, idx);
            }
            idx = (idx + 1) & self.map_mask;
        }
    }

    /// Remove a tag from the map using backward-shift deletion.
    ///
    /// Maintains the linear-probing invariant: after removal, all
    /// tags reachable by probing from their natural start slot remain
    /// reachable.
    fn remove(&mut self, tag: u64) {
        let (found, mut slot) = self.probe(tag);
        if !found {
            return;
        }

        // Backward-shift deletion for open-addressing linear probe.
        loop {
            self.map[slot] = TAG_NULL;
            let hole = slot;

            loop {
                slot = (slot + 1) & self.map_mask;
                let displaced = self.map[slot];

                if displaced == TAG_NULL {
                    // Hit empty — deletion complete.
                    return;
                }

                // Check if `displaced` needs to move back to fill the hole.
                // Its natural start slot is `displaced & map_mask`.
                let start = (displaced as usize) & self.map_mask;

                // `displaced` needs to move if `start` is NOT in the
                // half-open circular range (hole, slot].
                if !in_circular_range(hole, start, slot, self.map_mask) {
                    // Move displaced to fill the hole.
                    self.map[hole] = displaced;
                    break;
                }
            }
        }
    }
}

/// Check if `x` is in the half-open circular range `(a, b]` on a ring
/// of size `mask + 1`.
///
/// Returns true if `x` is strictly after `a` and at-or-before `b` in
/// the circular sense.
#[inline]
fn in_circular_range(a: usize, x: usize, b: usize, _mask: usize) -> bool {
    if a < b {
        // No wrap: range is (a, b] in normal order.
        a < x && x <= b
    } else {
        // Wrap: range spans the boundary.
        // x is in range if x > a OR x <= b.
        a < x || x <= b
    }
}

/// Compute the default map size for a given depth.
///
/// Returns a power of 2 such that the steady-state fill ratio is 25–50%.
/// Formula: `1 << (floor(log2(depth + 1)) + SPARSE_DEFAULT)`.
pub fn map_cnt_default(depth: usize) -> usize {
    if depth == 0 {
        return 0;
    }
    // floor(log2(depth + 1)) = MSB position of (depth + 1)
    let dp1 = (depth + 1) as u64;
    let lg = (63 - dp1.leading_zeros()) + SPARSE_DEFAULT;
    1usize << lg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cache_is_empty() {
        let cache = TagCache::new(16);
        assert_eq!(cache.depth(), 16);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn map_cnt_default_values() {
        // Verify sparsity: map_cnt should be roughly 4x depth.
        assert_eq!(map_cnt_default(1), 8);
        assert_eq!(map_cnt_default(2), 8);
        assert_eq!(map_cnt_default(3), 16);
        assert_eq!(map_cnt_default(7), 32);
        assert_eq!(map_cnt_default(15), 64);
        assert_eq!(map_cnt_default(16), 64);

        // All results are powers of 2.
        for d in 1..=1000 {
            let mc = map_cnt_default(d);
            assert!(mc.is_power_of_two(), "map_cnt_default({d}) = {mc} not pow2");
            assert!(mc >= d + 2, "map_cnt_default({d}) = {mc} < depth+2");
        }
    }

    #[test]
    fn insert_and_query() {
        let mut cache = TagCache::new(8);

        // Insert unique tags.
        assert!(!cache.insert(100)); // new
        assert!(!cache.insert(200)); // new
        assert!(!cache.insert(300)); // new

        assert!(cache.contains(100));
        assert!(cache.contains(200));
        assert!(cache.contains(300));
        assert!(!cache.contains(400));

        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn duplicate_detection() {
        let mut cache = TagCache::new(8);

        assert!(!cache.insert(42));
        assert!(cache.insert(42)); // duplicate
        assert!(cache.insert(42)); // still duplicate

        // Duplicate does not increase count.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eviction_after_depth_exceeded() {
        let mut cache = TagCache::new(4);

        // Fill to depth.
        for tag in 1..=4u64 {
            assert!(!cache.insert(tag));
        }
        assert_eq!(cache.len(), 4);

        // All 4 should be present.
        for tag in 1..=4u64 {
            assert!(cache.contains(tag));
        }

        // Insert 5th — should evict tag 1 (the oldest).
        assert!(!cache.insert(5));
        assert!(!cache.contains(1), "tag 1 should have been evicted");
        assert!(cache.contains(2));
        assert!(cache.contains(5));
        assert_eq!(cache.len(), 4);

        // Insert 6th — should evict tag 2.
        assert!(!cache.insert(6));
        assert!(!cache.contains(2), "tag 2 should have been evicted");
        assert!(cache.contains(3));
        assert!(cache.contains(6));
    }

    #[test]
    fn eviction_wraps_ring() {
        let depth = 4;
        let mut cache = TagCache::new(depth);

        // Insert depth * 3 unique tags — wraps the ring multiple times.
        for tag in 1..=(depth as u64 * 3) {
            cache.insert(tag);
        }

        // Only the last `depth` tags should be present.
        for tag in 1..=(depth as u64 * 2) {
            assert!(!cache.contains(tag), "tag {tag} should have been evicted");
        }
        for tag in (depth as u64 * 2 + 1)..=(depth as u64 * 3) {
            assert!(cache.contains(tag), "tag {tag} should be present");
        }
        assert_eq!(cache.len(), depth);
    }

    #[test]
    fn reset_clears_everything() {
        let mut cache = TagCache::new(8);
        for tag in 1..=8u64 {
            cache.insert(tag);
        }
        assert_eq!(cache.len(), 8);

        cache.reset();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        // Previous tags should not be found.
        for tag in 1..=8u64 {
            assert!(!cache.contains(tag));
        }

        // Can insert again after reset.
        assert!(!cache.insert(42));
        assert!(cache.contains(42));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn minimum_depth() {
        let mut cache = TagCache::new(1);
        assert_eq!(cache.depth(), 1);

        assert!(!cache.insert(10));
        assert!(cache.contains(10));

        // Second insert evicts the first.
        assert!(!cache.insert(20));
        assert!(!cache.contains(10));
        assert!(cache.contains(20));

        // Duplicate still works.
        assert!(cache.insert(20));
    }

    #[test]
    fn map_probe_chains() {
        // Use a small map to force probe chains.
        let mut cache = TagCache::with_map_cnt(4, 8);

        // Tags that hash to the same slot (low 3 bits all 0).
        let tags: Vec<u64> = vec![8, 16, 24, 32]; // all & 7 == 0
        for &tag in &tags {
            cache.insert(tag);
        }

        // All should be findable despite probe chains.
        for &tag in &tags {
            assert!(cache.contains(tag), "tag {tag} should be in cache");
        }

        // Insert one more — evicts oldest (8).
        cache.insert(40); // also maps to slot 0
        assert!(!cache.contains(8));
        assert!(cache.contains(40));
    }

    #[test]
    fn backward_shift_deletion_correctness() {
        // After eviction, remaining tags must still be findable.
        // This tests the backward-shift delete on probe chains.
        let mut cache = TagCache::with_map_cnt(3, 8);

        // Insert 3 tags that all hash to slot 0 (low 3 bits = 0).
        cache.insert(8); // slot 0
        cache.insert(16); // slot 1 (probe)
        cache.insert(24); // slot 2 (probe)

        // Now insert a 4th — evicts 8 from slot 0.
        // The backward-shift delete must fix slots 1 and 2.
        cache.insert(32); // evicts 8, inserts 32

        assert!(!cache.contains(8));
        assert!(cache.contains(16));
        assert!(cache.contains(24));
        assert!(cache.contains(32));
    }

    #[test]
    fn large_depth_stress() {
        let depth = 1024;
        let mut cache = TagCache::new(depth);

        // Insert 10x depth unique tags.
        for tag in 1..=(depth as u64 * 10) {
            let was_dup = cache.insert(tag);
            assert!(!was_dup, "tag {tag} should be new");
        }

        assert_eq!(cache.len(), depth);

        // Only the last `depth` tags should be present.
        let first_present = depth as u64 * 10 - depth as u64 + 1;
        for tag in first_present..=(depth as u64 * 10) {
            assert!(cache.contains(tag), "tag {tag} should be present");
        }

        // Tags before that should be evicted.
        for tag in 1..first_present {
            assert!(!cache.contains(tag), "tag {tag} should be evicted");
        }
    }

    #[test]
    fn duplicate_does_not_promote() {
        let mut cache = TagCache::new(3);

        cache.insert(1);
        cache.insert(2);
        cache.insert(3);

        // Re-insert 1 (duplicate, NOT promoted).
        assert!(cache.insert(1));

        // Insert new tag — should evict 1, not 2.
        cache.insert(4);
        assert!(
            !cache.contains(1),
            "tag 1 should be evicted (not promoted by dup)"
        );
        assert!(cache.contains(2));
        assert!(cache.contains(3));
        assert!(cache.contains(4));
    }

    #[test]
    fn mixed_duplicates_and_new() {
        let mut cache = TagCache::new(4);

        // Interleave new inserts and duplicate queries.
        assert!(!cache.insert(10));
        assert!(!cache.insert(20));
        assert!(cache.insert(10)); // dup
        assert!(!cache.insert(30));
        assert!(cache.insert(20)); // dup
        assert!(!cache.insert(40));
        assert!(cache.insert(30)); // dup

        assert_eq!(cache.len(), 4);
        assert!(cache.contains(10));
        assert!(cache.contains(20));
        assert!(cache.contains(30));
        assert!(cache.contains(40));

        // Now overflow — 10 should be evicted first.
        assert!(!cache.insert(50));
        assert!(!cache.contains(10));
    }

    #[test]
    #[should_panic(expected = "TagCache depth must be >= 1")]
    fn zero_depth_panics() {
        TagCache::new(0);
    }

    #[test]
    fn with_explicit_map_cnt() {
        let cache = TagCache::with_map_cnt(10, 16);
        assert_eq!(cache.depth(), 10);
        assert_eq!(cache.map_cnt(), 16);
    }

    #[test]
    #[should_panic(expected = "map_cnt must be a power of 2")]
    fn non_power_of_two_map_panics() {
        TagCache::with_map_cnt(4, 7);
    }

    #[test]
    #[should_panic(expected = "map_cnt")]
    fn too_small_map_panics() {
        TagCache::with_map_cnt(4, 4); // needs >= 6, but must be pow2, so >= 8
    }
}
