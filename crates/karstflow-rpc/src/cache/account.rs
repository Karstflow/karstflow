use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::{CacheEntry, CacheStats};
use crate::state::RpcCommitment;
use karstflow_types::Account;

/// Account cache with LRU eviction
#[derive(Clone)]
pub struct AccountCache {
    cache: Arc<DashMap<CacheKey, CacheEntry<Account>>>,
    stats: Arc<RwLock<CacheStats>>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    pubkey: String,
    commitment: RpcCommitment,
}

impl AccountCache {
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            max_entries,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get account from cache
    pub fn get(&self, pubkey: &str, commitment: RpcCommitment) -> Option<Account> {
        let key = CacheKey {
            pubkey: pubkey.to_string(),
            commitment,
        };

        let mut stats = self.stats.write();

        if let Some(mut entry) = self.cache.get_mut(&key) {
            if entry.is_expired(self.ttl) {
                drop(entry);
                self.cache.remove(&key);
                stats.misses += 1;
                None
            } else {
                entry.touch();
                stats.hits += 1;
                Some(entry.value.clone())
            }
        } else {
            stats.misses += 1;
            None
        }
    }

    /// Insert account into cache
    pub fn insert(&self, pubkey: String, account: Account, _slot: u64, commitment: RpcCommitment) {
        let key = CacheKey { pubkey, commitment };

        // Evict if at capacity
        if self.cache.len() >= self.max_entries {
            self.evict_lru();
        }

        self.cache.insert(key, CacheEntry::new(account));

        let mut stats = self.stats.write();
        stats.inserts += 1;
    }

    /// Remove account from cache
    pub fn remove(&self, pubkey: &str, commitment: RpcCommitment) {
        let key = CacheKey {
            pubkey: pubkey.to_string(),
            commitment,
        };
        self.cache.remove(&key);
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Evict least recently used entry
    fn evict_lru(&self) {
        let mut oldest_key = None;
        let mut oldest_time = Instant::now();

        for entry in self.cache.iter() {
            if entry.value().timestamp < oldest_time {
                oldest_time = entry.value().timestamp;
                oldest_key = Some(entry.key().clone());
            }
        }

        if let Some(key) = oldest_key {
            self.cache.remove(&key);
            let mut stats = self.stats.write();
            stats.evictions += 1;
        }
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) {
        let keys_to_remove: Vec<_> = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired(self.ttl))
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.cache.remove(&key);
        }
    }

    /// Get current cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;
    use std::thread;

    fn create_test_account(lamports: u64) -> Account {
        Account::new(lamports, vec![1, 2, 3], Pubkey::zeroed())
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = AccountCache::new(100, 60);
        let account = create_test_account(1000);

        cache.insert(
            "test_pubkey".to_string(),
            account.clone(),
            100,
            RpcCommitment::Confirmed,
        );

        let retrieved = cache.get("test_pubkey", RpcCommitment::Confirmed);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().meta.lamports, 1000);
    }

    #[test]
    fn test_cache_miss() {
        let cache = AccountCache::new(100, 60);
        let result = cache.get("nonexistent", RpcCommitment::Confirmed);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_commitment_separation() {
        let cache = AccountCache::new(100, 60);
        let account = create_test_account(1000);

        cache.insert(
            "test_pubkey".to_string(),
            account.clone(),
            100,
            RpcCommitment::Confirmed,
        );

        // Should not find with different commitment
        let result = cache.get("test_pubkey", RpcCommitment::Finalized);
        assert!(result.is_none());

        // Should find with same commitment
        let result = cache.get("test_pubkey", RpcCommitment::Confirmed);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_eviction() {
        let cache = AccountCache::new(3, 60);

        // Fill cache to capacity
        for i in 0..3 {
            let account = create_test_account(1000 + i);
            cache.insert(
                format!("pubkey_{}", i),
                account,
                100 + i,
                RpcCommitment::Confirmed,
            );
        }

        assert_eq!(cache.len(), 3);

        // Insert one more - should evict oldest
        let account = create_test_account(2000);
        cache.insert(
            "pubkey_new".to_string(),
            account,
            200,
            RpcCommitment::Confirmed,
        );

        assert_eq!(cache.len(), 3);

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = AccountCache::new(100, 0); // 0 second TTL
        let account = create_test_account(1000);

        cache.insert(
            "test_pubkey".to_string(),
            account,
            100,
            RpcCommitment::Confirmed,
        );

        thread::sleep(Duration::from_millis(10));

        // Should be expired
        let result = cache.get("test_pubkey", RpcCommitment::Confirmed);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_remove() {
        let cache = AccountCache::new(100, 60);
        let account = create_test_account(1000);

        cache.insert(
            "test_pubkey".to_string(),
            account,
            100,
            RpcCommitment::Confirmed,
        );

        assert!(cache.get("test_pubkey", RpcCommitment::Confirmed).is_some());

        cache.remove("test_pubkey", RpcCommitment::Confirmed);

        assert!(cache.get("test_pubkey", RpcCommitment::Confirmed).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = AccountCache::new(100, 60);

        for i in 0..5 {
            let account = create_test_account(1000 + i);
            cache.insert(
                format!("pubkey_{}", i),
                account,
                100,
                RpcCommitment::Confirmed,
            );
        }

        assert_eq!(cache.len(), 5);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache = AccountCache::new(100, 60);
        let account = create_test_account(1000);

        cache.insert(
            "test_pubkey".to_string(),
            account,
            100,
            RpcCommitment::Confirmed,
        );

        // Hit
        let _ = cache.get("test_pubkey", RpcCommitment::Confirmed);

        // Miss
        let _ = cache.get("nonexistent", RpcCommitment::Confirmed);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.inserts, 1);
        assert_eq!(stats.hit_rate(), 0.5);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = AccountCache::new(100, 0); // 0 second TTL

        for i in 0..5 {
            let account = create_test_account(1000 + i);
            cache.insert(
                format!("pubkey_{}", i),
                account,
                100,
                RpcCommitment::Confirmed,
            );
        }

        thread::sleep(Duration::from_millis(10));

        assert_eq!(cache.len(), 5);
        cache.cleanup_expired();
        assert_eq!(cache.len(), 0);
    }
}
