// LRU read cache for hot key-value data.
//
// Sits in front of the durable file store, caching recently accessed
// values in memory. Cache-through on reads, invalidation on writes.
//
// Inspired by Firedancer's vinyl line cache: fixed-capacity, LRU eviction,
// single-writer invalidation semantics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use karstflow_constants::durable_store::DEFAULT_CACHE_SIZE_BYTES;

/// A single cached value with LRU tracking metadata.
struct CacheEntry {
    value: Vec<u8>,
    /// Approximate size in bytes (key + value).
    size: usize,
    /// Access timestamp for LRU ordering.
    last_access: u64,
}

/// Per-column-family LRU read cache.
pub(crate) struct ReadCache {
    /// Maximum cache size in bytes.
    max_bytes: u64,
    /// Current total cached bytes.
    current_bytes: u64,
    /// Cache entries keyed by (cf, key).
    entries: HashMap<(String, Vec<u8>), CacheEntry>,
    /// Monotonic counter for LRU ordering.
    access_counter: u64,
    /// Cache hit count.
    hits: AtomicU64,
    /// Cache miss count.
    misses: AtomicU64,
}

/// Cache statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub bytes_used: u64,
    pub max_bytes: u64,
}

impl ReadCache {
    /// Create a new cache with the given maximum size in bytes.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            entries: HashMap::new(),
            access_counter: 0,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Create a cache with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CACHE_SIZE_BYTES)
    }

    /// Look up a cached value. Returns `Some(value)` on hit, `None` on miss.
    pub fn get(&mut self, cf: &str, key: &[u8]) -> Option<Vec<u8>> {
        let cache_key = (cf.to_owned(), key.to_vec());
        if let Some(entry) = self.entries.get_mut(&cache_key) {
            self.access_counter += 1;
            entry.last_access = self.access_counter;
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.value.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert a value into the cache. Evicts LRU entries if necessary.
    pub fn insert(&mut self, cf: &str, key: &[u8], value: &[u8]) {
        let cache_key = (cf.to_owned(), key.to_vec());
        let entry_size = cf.len() + key.len() + value.len();

        // Don't cache entries larger than half the max capacity.
        if entry_size as u64 > self.max_bytes / 2 {
            return;
        }

        // Remove existing entry for this key (if any).
        if let Some(old) = self.entries.remove(&cache_key) {
            self.current_bytes -= old.size as u64;
        }

        // Evict LRU entries until we have space.
        while self.current_bytes + entry_size as u64 > self.max_bytes && !self.entries.is_empty() {
            self.evict_lru();
        }

        self.access_counter += 1;
        self.entries.insert(
            cache_key,
            CacheEntry {
                value: value.to_vec(),
                size: entry_size,
                last_access: self.access_counter,
            },
        );
        self.current_bytes += entry_size as u64;
    }

    /// Invalidate a cached entry.
    pub fn invalidate(&mut self, cf: &str, key: &[u8]) {
        let cache_key = (cf.to_owned(), key.to_vec());
        if let Some(entry) = self.entries.remove(&cache_key) {
            self.current_bytes -= entry.size as u64;
        }
    }

    /// Invalidate all entries for a column family.
    pub fn invalidate_cf(&mut self, cf: &str) {
        let keys_to_remove: Vec<_> = self
            .entries
            .keys()
            .filter(|(entry_cf, _)| entry_cf == cf)
            .cloned()
            .collect();
        for key in keys_to_remove {
            if let Some(entry) = self.entries.remove(&key) {
                self.current_bytes -= entry.size as u64;
            }
        }
    }

    /// Clear the entire cache.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_bytes = 0;
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: self.entries.len() as u64,
            bytes_used: self.current_bytes,
            max_bytes: self.max_bytes,
        }
    }

    /// Evict the least recently used entry.
    fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        // Find the entry with the lowest last_access.
        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            if let Some(entry) = self.entries.remove(&key) {
                self.current_bytes -= entry.size as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_miss_returns_none() {
        let mut cache = ReadCache::new(1024);
        assert!(cache.get("cf", b"missing").is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf", b"key", b"value");
        let val = cache.get("cf", b"key").expect("should hit");
        assert_eq!(val, b"value");
    }

    #[test]
    fn hit_miss_stats() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf", b"k", b"v");

        cache.get("cf", b"k"); // hit
        cache.get("cf", b"missing"); // miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn invalidate_removes_entry() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf", b"k", b"v");
        cache.invalidate("cf", b"k");
        assert!(cache.get("cf", b"k").is_none());
    }

    #[test]
    fn invalidate_cf_removes_all_entries_for_cf() {
        let mut cache = ReadCache::new(4096);
        cache.insert("cf_a", b"k1", b"v1");
        cache.insert("cf_a", b"k2", b"v2");
        cache.insert("cf_b", b"k1", b"v3");

        cache.invalidate_cf("cf_a");
        assert!(cache.get("cf_a", b"k1").is_none());
        assert!(cache.get("cf_a", b"k2").is_none());
        assert!(cache.get("cf_b", b"k1").is_some()); // unaffected
    }

    #[test]
    fn eviction_when_full() {
        // Cache with very small capacity.
        let mut cache = ReadCache::new(50);

        // Insert entries that together exceed capacity.
        cache.insert("cf", b"key1", b"val1"); // ~12 bytes
        cache.insert("cf", b"key2", b"val2"); // ~12 bytes
        cache.insert("cf", b"key3", b"val3"); // ~12 bytes
        cache.insert("cf", b"key4", b"val4"); // should evict oldest
        cache.insert("cf", b"key5", b"val5"); // should evict more

        // At least some entries should exist but not all.
        let stats = cache.stats();
        assert!(stats.bytes_used <= 50);
    }

    #[test]
    fn lru_eviction_order() {
        // Each entry is 6 bytes (cf=2 + key=1 + value=3). Capacity fits 3 entries.
        let mut cache = ReadCache::new(20);

        cache.insert("cf", b"a", b"111"); // oldest
        cache.insert("cf", b"b", b"222");
        cache.insert("cf", b"c", b"333"); // newest

        // Access 'a' to make it recent.
        cache.get("cf", b"a");

        // Insert a new entry — should evict 'b' (LRU).
        cache.insert("cf", b"d", b"444");

        assert!(cache.get("cf", b"a").is_some(), "'a' was recently accessed");
        assert!(cache.get("cf", b"b").is_none(), "'b' should be evicted");
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = ReadCache::new(100);
        // Entry larger than half max capacity (50 bytes) should not be cached.
        let big = vec![0u8; 60];
        cache.insert("cf", b"big", &big);
        assert!(cache.get("cf", b"big").is_none());
    }

    #[test]
    fn overwrite_existing_key() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf", b"k", b"old");
        cache.insert("cf", b"k", b"new");
        assert_eq!(cache.get("cf", b"k").unwrap(), b"new");
        assert_eq!(cache.stats().entries, 1);
    }

    #[test]
    fn clear_empties_cache() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf", b"k1", b"v1");
        cache.insert("cf", b"k2", b"v2");
        cache.clear();
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().bytes_used, 0);
    }

    #[test]
    fn different_cfs_are_separate() {
        let mut cache = ReadCache::new(1024);
        cache.insert("cf_a", b"key", b"val_a");
        cache.insert("cf_b", b"key", b"val_b");
        assert_eq!(cache.get("cf_a", b"key").unwrap(), b"val_a");
        assert_eq!(cache.get("cf_b", b"key").unwrap(), b"val_b");
    }
}
