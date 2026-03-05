use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::{CacheEntry, CacheStats};
use crate::state::RpcCommitment;

/// Signature information for caching
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub commitment: RpcCommitment,
    pub err: Option<String>,
    pub confirmation_status: ConfirmationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationStatus {
    Processed,
    Confirmed,
    Finalized,
}

impl From<RpcCommitment> for ConfirmationStatus {
    fn from(commitment: RpcCommitment) -> Self {
        match commitment {
            RpcCommitment::Processed => ConfirmationStatus::Processed,
            RpcCommitment::Confirmed => ConfirmationStatus::Confirmed,
            RpcCommitment::Finalized => ConfirmationStatus::Finalized,
        }
    }
}

/// Signature cache with LRU eviction
#[derive(Clone)]
pub struct SignatureCache {
    cache: Arc<DashMap<String, CacheEntry<SignatureInfo>>>,
    stats: Arc<RwLock<CacheStats>>,
    max_entries: usize,
    ttl: Duration,
}

impl SignatureCache {
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            max_entries,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get signature from cache
    pub fn get(&self, signature: &str) -> Option<SignatureInfo> {
        let mut stats = self.stats.write();

        if let Some(mut entry) = self.cache.get_mut(signature) {
            if entry.is_expired(self.ttl) {
                drop(entry);
                self.cache.remove(signature);
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

    /// Insert signature into cache
    pub fn insert(&self, signature: String, slot: u64, commitment: RpcCommitment) {
        // Evict if at capacity
        if self.cache.len() >= self.max_entries {
            self.evict_lru();
        }

        let info = SignatureInfo {
            signature: signature.clone(),
            slot,
            commitment,
            err: None,
            confirmation_status: commitment.into(),
        };

        self.cache.insert(signature, CacheEntry::new(info));

        let mut stats = self.stats.write();
        stats.inserts += 1;
    }

    /// Insert signature with error
    pub fn insert_with_error(
        &self,
        signature: String,
        slot: u64,
        commitment: RpcCommitment,
        err: String,
    ) {
        if self.cache.len() >= self.max_entries {
            self.evict_lru();
        }

        let info = SignatureInfo {
            signature: signature.clone(),
            slot,
            commitment,
            err: Some(err),
            confirmation_status: commitment.into(),
        };

        self.cache.insert(signature, CacheEntry::new(info));

        let mut stats = self.stats.write();
        stats.inserts += 1;
    }

    /// Remove signature from cache
    pub fn remove(&self, signature: &str) {
        self.cache.remove(signature);
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

    /// Get all signatures for a slot
    pub fn get_by_slot(&self, slot: u64) -> Vec<SignatureInfo> {
        self.cache
            .iter()
            .filter(|entry| entry.value().value.slot == slot)
            .map(|entry| entry.value().value.clone())
            .collect()
    }

    /// Batch get signatures
    pub fn get_batch(&self, signatures: &[String]) -> Vec<Option<SignatureInfo>> {
        signatures.iter().map(|sig| self.get(sig)).collect()
    }

    /// Update confirmation status
    pub fn update_confirmation(&self, signature: &str, commitment: RpcCommitment) {
        if let Some(mut entry) = self.cache.get_mut(signature) {
            let mut info = entry.value.clone();
            info.commitment = commitment;
            info.confirmation_status = commitment.into();
            entry.value = info;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = SignatureCache::new(100, 60);

        cache.insert("sig123".to_string(), 1000, RpcCommitment::Confirmed);

        let retrieved = cache.get("sig123");
        assert!(retrieved.is_some());
        let info = retrieved.unwrap();
        assert_eq!(info.signature, "sig123");
        assert_eq!(info.slot, 1000);
        assert_eq!(info.commitment, RpcCommitment::Confirmed);
    }

    #[test]
    fn test_cache_miss() {
        let cache = SignatureCache::new(100, 60);
        let result = cache.get("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_insert_with_error() {
        let cache = SignatureCache::new(100, 60);

        cache.insert_with_error(
            "sig_error".to_string(),
            1000,
            RpcCommitment::Confirmed,
            "InsufficientFunds".to_string(),
        );

        let retrieved = cache.get("sig_error");
        assert!(retrieved.is_some());
        let info = retrieved.unwrap();
        assert_eq!(info.err, Some("InsufficientFunds".to_string()));
    }

    #[test]
    fn test_cache_eviction() {
        let cache = SignatureCache::new(3, 60);

        // Fill cache to capacity
        for i in 0..3 {
            cache.insert(format!("sig{}", i), 1000 + i, RpcCommitment::Confirmed);
        }

        assert_eq!(cache.len(), 3);

        // Insert one more - should evict oldest
        cache.insert("sig_new".to_string(), 2000, RpcCommitment::Confirmed);

        assert_eq!(cache.len(), 3);

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = SignatureCache::new(100, 0); // 0 second TTL

        cache.insert("sig_expire".to_string(), 1000, RpcCommitment::Confirmed);

        thread::sleep(Duration::from_millis(10));

        // Should be expired
        let result = cache.get("sig_expire");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_slot() {
        let cache = SignatureCache::new(100, 60);

        cache.insert("sig1".to_string(), 1000, RpcCommitment::Confirmed);
        cache.insert("sig2".to_string(), 1000, RpcCommitment::Confirmed);
        cache.insert("sig3".to_string(), 1001, RpcCommitment::Confirmed);

        let sigs = cache.get_by_slot(1000);
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_get_batch() {
        let cache = SignatureCache::new(100, 60);

        cache.insert("sig1".to_string(), 1000, RpcCommitment::Confirmed);
        cache.insert("sig2".to_string(), 1001, RpcCommitment::Confirmed);

        let signatures = vec!["sig1".to_string(), "sig2".to_string(), "sig3".to_string()];
        let results = cache.get_batch(&signatures);

        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert!(results[1].is_some());
        assert!(results[2].is_none());
    }

    #[test]
    fn test_update_confirmation() {
        let cache = SignatureCache::new(100, 60);

        cache.insert("sig_update".to_string(), 1000, RpcCommitment::Processed);

        cache.update_confirmation("sig_update", RpcCommitment::Finalized);

        let info = cache.get("sig_update").unwrap();
        assert_eq!(info.commitment, RpcCommitment::Finalized);
        assert_eq!(info.confirmation_status, ConfirmationStatus::Finalized);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = SignatureCache::new(100, 0); // 0 second TTL

        for i in 0..5 {
            cache.insert(format!("sig{}", i), 1000 + i, RpcCommitment::Confirmed);
        }

        thread::sleep(Duration::from_millis(10));

        assert_eq!(cache.len(), 5);
        cache.cleanup_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_confirmation_status_conversion() {
        assert_eq!(
            ConfirmationStatus::from(RpcCommitment::Processed),
            ConfirmationStatus::Processed
        );
        assert_eq!(
            ConfirmationStatus::from(RpcCommitment::Confirmed),
            ConfirmationStatus::Confirmed
        );
        assert_eq!(
            ConfirmationStatus::from(RpcCommitment::Finalized),
            ConfirmationStatus::Finalized
        );
    }
}
