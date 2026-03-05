//! Compiled program cache with LRU eviction.
//!
//! Caches parsed/compiled program representations to avoid repeated
//! deserialization of program account data. Thread-safe and designed
//! for high-frequency concurrent reads.

mod entry;
mod eviction;

#[cfg(test)]
mod tests;

pub use entry::{CachedProgram, ProgramType};
pub use eviction::EvictionPolicy;

use karstflow_constants::program_cache::DEFAULT_MAX_CACHE_ENTRIES;
use karstflow_types::Pubkey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Thread-safe program cache with LRU eviction.
pub struct ProgramCache {
    entries: RwLock<HashMap<Pubkey, CacheSlot>>,
    max_entries: usize,
    stats: CacheStats,
}

/// Entry in the cache, versioned by slot to handle redeployments.
#[allow(dead_code)]
pub(crate) struct CacheSlot {
    pub(crate) program: Arc<CachedProgram>,
    pub(crate) last_accessed: u64,
    pub(crate) deployment_slot: u64,
    pub(crate) ref_count: u64,
}

/// Cache hit/miss statistics.
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub insertions: AtomicU64,
}

impl CacheStats {
    /// Get hit count.
    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get miss count.
    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get eviction count.
    pub fn eviction_count(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Get insertion count.
    pub fn insertion_count(&self) -> u64 {
        self.insertions.load(Ordering::Relaxed)
    }
}

impl ProgramCache {
    /// Create a new program cache with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_CACHE_ENTRIES)
    }

    /// Create a new program cache with a specific maximum entry count.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(max_entries)),
            max_entries,
            stats: CacheStats::default(),
        }
    }

    /// Get a cached program by its pubkey.
    ///
    /// Updates the last-accessed slot for LRU tracking and increments
    /// the hit or miss counter.
    pub fn get(&self, program_id: &Pubkey, current_slot: u64) -> Option<Arc<CachedProgram>> {
        let mut entries = self.entries.write().expect("cache lock poisoned");
        if let Some(slot) = entries.get_mut(program_id) {
            slot.last_accessed = current_slot;
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(Arc::clone(&slot.program))
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert or update a program in the cache.
    ///
    /// Triggers LRU eviction if the cache exceeds capacity.
    pub fn insert(&self, program_id: Pubkey, program: CachedProgram, deployment_slot: u64) {
        let mut entries = self.entries.write().expect("cache lock poisoned");

        entries.insert(
            program_id,
            CacheSlot {
                program: Arc::new(program),
                last_accessed: deployment_slot,
                deployment_slot,
                ref_count: 0,
            },
        );
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);

        self.evict_if_needed(&mut entries);
    }

    /// Insert a builtin program that should not be evicted.
    ///
    /// Builtin programs have ref_count > 0, which protects them from eviction.
    pub fn insert_builtin(&self, program_id: Pubkey, program: CachedProgram, deployment_slot: u64) {
        let mut entries = self.entries.write().expect("cache lock poisoned");

        entries.insert(
            program_id,
            CacheSlot {
                program: Arc::new(program),
                last_accessed: deployment_slot,
                deployment_slot,
                ref_count: 1, // Protected from eviction
            },
        );
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Invalidate a cached program (e.g., on redeployment).
    pub fn invalidate(&self, program_id: &Pubkey) {
        let mut entries = self.entries.write().expect("cache lock poisoned");
        entries.remove(program_id);
    }

    /// Get cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get number of cached programs.
    pub fn len(&self) -> usize {
        self.entries.read().expect("cache lock poisoned").len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().expect("cache lock poisoned").is_empty()
    }

    /// Clear all cached programs.
    pub fn clear(&self) {
        self.entries.write().expect("cache lock poisoned").clear();
    }

    /// Evict least recently used entries to stay within capacity.
    fn evict_if_needed(&self, entries: &mut HashMap<Pubkey, CacheSlot>) {
        if entries.len() <= self.max_entries {
            return;
        }

        let to_evict = EvictionPolicy::select_evictions(entries, self.max_entries);
        let evicted_count = to_evict.len() as u64;

        for key in to_evict {
            entries.remove(&key);
        }

        self.stats
            .evictions
            .fetch_add(evicted_count, Ordering::Relaxed);
    }
}

impl Default for ProgramCache {
    fn default() -> Self {
        Self::new()
    }
}
