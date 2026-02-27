/// In-memory cache for completed FEC sets.
///
/// Stores completed FEC set data shreds indexed by (slot, fec_set_index)
/// for retrieval by the replay stage. The cache is bounded by slot count
/// and evicts entries when the root slot advances.
///
/// This serves a similar role to a store tile's FEC data cache, providing
/// fast access to recently completed FEC sets without disk I/O.
use std::collections::{BTreeMap, HashMap};

/// Key for a cached FEC set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FecCacheKey {
    pub slot: u64,
    pub fec_set_index: u32,
}

/// A cached completed FEC set with its data shreds.
#[derive(Debug, Clone)]
pub struct CachedFecSet {
    /// Slot this FEC set belongs to.
    pub slot: u64,
    /// FEC set index within the slot.
    pub fec_set_index: u32,
    /// Assembled data shred payloads in index order.
    pub data_payloads: Vec<Vec<u8>>,
    /// Whether this FEC set was recovered via Reed-Solomon.
    pub was_recovered: bool,
}

/// Statistics for the FEC cache.
#[derive(Debug, Default, Clone)]
pub struct FecCacheStats {
    /// Total FEC sets inserted.
    pub inserts: u64,
    /// Cache hits (successful lookups).
    pub hits: u64,
    /// Cache misses (failed lookups).
    pub misses: u64,
    /// FEC sets evicted by root advancement.
    pub evictions: u64,
    /// Current number of cached FEC sets.
    pub cached_count: usize,
    /// Current number of cached slots.
    pub slot_count: usize,
}

/// Configuration for the FEC cache.
#[derive(Debug, Clone)]
pub struct FecCacheConfig {
    /// Maximum number of slots to retain in the cache.
    /// Older slots are evicted when this limit is exceeded.
    pub max_slots: usize,
    /// Maximum total FEC sets across all slots.
    /// When exceeded, the oldest slot's sets are evicted.
    pub max_total_sets: usize,
}

impl Default for FecCacheConfig {
    fn default() -> Self {
        Self {
            max_slots: 64,
            max_total_sets: 4096,
        }
    }
}

/// Bounded in-memory cache for completed FEC sets.
///
/// The cache tracks FEC sets by slot and fec_set_index, supporting
/// fast lookups and automatic eviction based on root advancement
/// or capacity limits.
pub struct FecSetCache {
    /// FEC sets indexed by cache key.
    entries: HashMap<FecCacheKey, CachedFecSet>,
    /// Slot → set of FEC set indices for that slot (for eviction).
    slot_index: BTreeMap<u64, Vec<u32>>,
    /// Minimum slot (root). Entries below this are evicted.
    root_slot: u64,
    /// Configuration.
    config: FecCacheConfig,
    /// Running statistics.
    stats: FecCacheStats,
}

impl FecSetCache {
    /// Create a new FEC cache with default configuration.
    pub fn new() -> Self {
        Self::with_config(FecCacheConfig::default())
    }

    /// Create a new FEC cache with custom configuration.
    pub fn with_config(config: FecCacheConfig) -> Self {
        Self {
            entries: HashMap::new(),
            slot_index: BTreeMap::new(),
            root_slot: 0,
            config,
            stats: FecCacheStats::default(),
        }
    }

    /// Insert a completed FEC set into the cache.
    ///
    /// If the slot is below the root, the insertion is silently ignored.
    /// If the cache is at capacity, the oldest slot's entries are evicted.
    pub fn insert(&mut self, fec_set: CachedFecSet) {
        if fec_set.slot < self.root_slot {
            return;
        }

        let key = FecCacheKey {
            slot: fec_set.slot,
            fec_set_index: fec_set.fec_set_index,
        };

        // Enforce capacity limits before inserting.
        self.enforce_limits();

        // Track in slot index.
        self.slot_index
            .entry(fec_set.slot)
            .or_default()
            .push(fec_set.fec_set_index);

        self.entries.insert(key, fec_set);
        self.stats.inserts += 1;
        self.update_stats();
    }

    /// Look up a cached FEC set by slot and fec_set_index.
    pub fn get(&mut self, slot: u64, fec_set_index: u32) -> Option<&CachedFecSet> {
        let key = FecCacheKey {
            slot,
            fec_set_index,
        };
        let result = self.entries.get(&key);
        if result.is_some() {
            self.stats.hits += 1;
        } else {
            self.stats.misses += 1;
        }
        result
    }

    /// Check if a FEC set is cached.
    pub fn contains(&self, slot: u64, fec_set_index: u32) -> bool {
        let key = FecCacheKey {
            slot,
            fec_set_index,
        };
        self.entries.contains_key(&key)
    }

    /// Get all cached FEC sets for a given slot, sorted by fec_set_index.
    pub fn get_slot_sets(&self, slot: u64) -> Vec<&CachedFecSet> {
        let mut sets: Vec<&CachedFecSet> = self
            .entries
            .values()
            .filter(|fec| fec.slot == slot)
            .collect();
        sets.sort_by_key(|fec| fec.fec_set_index);
        sets
    }

    /// Advance the root slot. Evicts all entries for slots below the new root.
    pub fn advance_root(&mut self, new_root: u64) {
        if new_root <= self.root_slot {
            return;
        }
        self.root_slot = new_root;

        // Collect slots to evict (below new root).
        let slots_to_evict: Vec<u64> = self
            .slot_index
            .range(..new_root)
            .map(|(&slot, _)| slot)
            .collect();

        for slot in slots_to_evict {
            self.evict_slot(slot);
        }
        self.update_stats();
    }

    /// Get the current root slot.
    pub fn root_slot(&self) -> u64 {
        self.root_slot
    }

    /// Get current cache statistics.
    pub fn stats(&self) -> &FecCacheStats {
        &self.stats
    }

    /// Number of cached FEC sets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of slots with cached data.
    pub fn slot_count(&self) -> usize {
        self.slot_index.len()
    }

    /// Evict all entries for a specific slot.
    fn evict_slot(&mut self, slot: u64) {
        if let Some(indices) = self.slot_index.remove(&slot) {
            for fec_set_index in indices {
                let key = FecCacheKey {
                    slot,
                    fec_set_index,
                };
                self.entries.remove(&key);
                self.stats.evictions += 1;
            }
        }
    }

    /// Enforce capacity limits by evicting the oldest slots.
    fn enforce_limits(&mut self) {
        // Evict oldest slot if too many slots.
        while self.slot_index.len() >= self.config.max_slots {
            if let Some((&oldest_slot, _)) = self.slot_index.iter().next() {
                self.evict_slot(oldest_slot);
            } else {
                break;
            }
        }

        // Evict oldest slot if too many total entries.
        while self.entries.len() >= self.config.max_total_sets {
            if let Some((&oldest_slot, _)) = self.slot_index.iter().next() {
                self.evict_slot(oldest_slot);
            } else {
                break;
            }
        }
    }

    /// Update running stats counters.
    fn update_stats(&mut self) {
        self.stats.cached_count = self.entries.len();
        self.stats.slot_count = self.slot_index.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fec_set(slot: u64, fec_set_index: u32, num_data: usize) -> CachedFecSet {
        CachedFecSet {
            slot,
            fec_set_index,
            data_payloads: (0..num_data)
                .map(|i| vec![(i as u8).wrapping_mul(7); 64])
                .collect(),
            was_recovered: false,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = FecSetCache::new();
        cache.insert(make_fec_set(100, 0, 4));

        assert!(cache.contains(100, 0));
        assert!(!cache.contains(100, 1));
        assert!(!cache.contains(101, 0));

        let fec = cache.get(100, 0);
        assert!(fec.is_some());
        assert_eq!(fec.unwrap().data_payloads.len(), 4);
    }

    #[test]
    fn advance_root_evicts_old_slots() {
        let mut cache = FecSetCache::new();
        cache.insert(make_fec_set(10, 0, 2));
        cache.insert(make_fec_set(20, 0, 2));
        cache.insert(make_fec_set(30, 0, 2));
        assert_eq!(cache.len(), 3);

        cache.advance_root(25);
        assert_eq!(cache.len(), 1);
        assert!(!cache.contains(10, 0));
        assert!(!cache.contains(20, 0));
        assert!(cache.contains(30, 0));
    }

    #[test]
    fn insert_below_root_ignored() {
        let mut cache = FecSetCache::new();
        cache.advance_root(50);
        cache.insert(make_fec_set(10, 0, 2));
        assert!(cache.is_empty());
    }

    #[test]
    fn slot_capacity_eviction() {
        let config = FecCacheConfig {
            max_slots: 3,
            max_total_sets: 1000,
        };
        let mut cache = FecSetCache::with_config(config);

        cache.insert(make_fec_set(1, 0, 2));
        cache.insert(make_fec_set(2, 0, 2));
        cache.insert(make_fec_set(3, 0, 2));
        assert_eq!(cache.slot_count(), 3);

        // Fourth slot evicts the oldest (slot 1).
        cache.insert(make_fec_set(4, 0, 2));
        assert_eq!(cache.slot_count(), 3);
        assert!(!cache.contains(1, 0));
        assert!(cache.contains(4, 0));
    }

    #[test]
    fn total_sets_capacity_eviction() {
        let config = FecCacheConfig {
            max_slots: 100,
            max_total_sets: 3,
        };
        let mut cache = FecSetCache::with_config(config);

        cache.insert(make_fec_set(1, 0, 2));
        cache.insert(make_fec_set(1, 1, 2));
        cache.insert(make_fec_set(1, 2, 2));
        assert_eq!(cache.len(), 3);

        // Fourth insert evicts oldest slot's entries.
        cache.insert(make_fec_set(2, 0, 2));
        assert!(cache.contains(2, 0));
    }

    #[test]
    fn get_slot_sets_sorted() {
        let mut cache = FecSetCache::new();
        cache.insert(make_fec_set(100, 4, 2));
        cache.insert(make_fec_set(100, 0, 3));
        cache.insert(make_fec_set(100, 2, 1));

        let sets = cache.get_slot_sets(100);
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0].fec_set_index, 0);
        assert_eq!(sets[1].fec_set_index, 2);
        assert_eq!(sets[2].fec_set_index, 4);
    }

    #[test]
    fn stats_tracking() {
        let mut cache = FecSetCache::new();
        cache.insert(make_fec_set(10, 0, 2));
        cache.insert(make_fec_set(20, 0, 2));

        assert_eq!(cache.stats().inserts, 2);

        cache.get(10, 0); // hit
        cache.get(99, 0); // miss

        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);

        cache.advance_root(15);
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn multiple_fec_sets_per_slot() {
        let mut cache = FecSetCache::new();
        for i in 0..8 {
            cache.insert(make_fec_set(100, i * 4, 2));
        }
        assert_eq!(cache.len(), 8);
        assert_eq!(cache.slot_count(), 1);

        // Evicting the slot removes all its FEC sets.
        cache.advance_root(101);
        assert!(cache.is_empty());
    }

    #[test]
    fn advance_root_is_monotonic() {
        let mut cache = FecSetCache::new();
        cache.insert(make_fec_set(10, 0, 2));
        cache.advance_root(50);
        assert_eq!(cache.root_slot(), 50);

        // Advancing to a lower root has no effect.
        cache.advance_root(30);
        assert_eq!(cache.root_slot(), 50);
    }

    #[test]
    fn recovered_flag_preserved() {
        let mut cache = FecSetCache::new();
        let mut fec = make_fec_set(100, 0, 4);
        fec.was_recovered = true;
        cache.insert(fec);

        let cached = cache.get(100, 0).unwrap();
        assert!(cached.was_recovered);
    }
}
