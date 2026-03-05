use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::{CacheEntry, CacheStats};
use crate::state::RpcCommitment;

/// Block information for caching
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub slot: u64,
    pub blockhash: String,
    pub parent_slot: u64,
    pub block_time: Option<i64>,
    pub block_height: u64,
    pub transaction_count: u64,
    pub rewards: Vec<Reward>,
}

#[derive(Debug, Clone)]
pub struct Reward {
    pub pubkey: String,
    pub lamports: i64,
    pub post_balance: u64,
    pub reward_type: RewardType,
    pub commission: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardType {
    Fee,
    Rent,
    Staking,
    Voting,
}

/// Block cache with LRU eviction
#[derive(Clone)]
pub struct BlockCache {
    cache: Arc<DashMap<CacheKey, CacheEntry<BlockInfo>>>,
    stats: Arc<RwLock<CacheStats>>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    slot: u64,
    commitment: RpcCommitment,
}

impl BlockCache {
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            max_entries,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get block from cache
    pub fn get(&self, slot: u64, commitment: RpcCommitment) -> Option<BlockInfo> {
        let key = CacheKey { slot, commitment };

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

    /// Insert block into cache
    pub fn insert(&self, block: BlockInfo, commitment: RpcCommitment) {
        let key = CacheKey {
            slot: block.slot,
            commitment,
        };

        // Evict if at capacity
        if self.cache.len() >= self.max_entries {
            self.evict_lru();
        }

        self.cache.insert(key, CacheEntry::new(block));

        let mut stats = self.stats.write();
        stats.inserts += 1;
    }

    /// Remove block from cache
    pub fn remove(&self, slot: u64, commitment: RpcCommitment) {
        let key = CacheKey { slot, commitment };
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

    /// Get blocks in slot range
    pub fn get_range(
        &self,
        start_slot: u64,
        end_slot: u64,
        commitment: RpcCommitment,
    ) -> Vec<BlockInfo> {
        let mut blocks = Vec::new();
        for slot in start_slot..=end_slot {
            if let Some(block) = self.get(slot, commitment) {
                blocks.push(block);
            }
        }
        blocks
    }

    /// Prefetch blocks for a range
    pub fn prefetch_range(&self, start_slot: u64, count: usize, commitment: RpcCommitment) {
        for i in 0..count {
            let slot = start_slot + i as u64;
            let key = CacheKey { slot, commitment };

            if !self.cache.contains_key(&key) {
                // Generate synthetic block
                let block = generate_synthetic_block(slot);
                self.insert(block, commitment);
            }
        }
    }
}

/// Generate synthetic block for testing/demo
fn generate_synthetic_block(slot: u64) -> BlockInfo {
    let blockhash = format!("{:064x}", slot);
    let parent_slot = slot.saturating_sub(1);
    let block_time = Some((slot * 400) as i64);
    let transaction_count = (slot % 100) + 10;

    let mut rewards = Vec::new();
    for i in 0..5 {
        rewards.push(Reward {
            pubkey: format!("Validator{:02}11111111111111111111111111111", i),
            lamports: 50000 + (slot as i64 % 10000),
            post_balance: 1000000000 + (slot + i) * 1000,
            reward_type: if i == 0 {
                RewardType::Staking
            } else {
                RewardType::Voting
            },
            commission: Some(10),
        });
    }

    BlockInfo {
        slot,
        blockhash,
        parent_slot,
        block_time,
        block_height: slot,
        transaction_count,
        rewards,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = BlockCache::new(100, 60);
        let block = generate_synthetic_block(1000);

        cache.insert(block.clone(), RpcCommitment::Confirmed);

        let retrieved = cache.get(1000, RpcCommitment::Confirmed);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().slot, 1000);
    }

    #[test]
    fn test_cache_miss() {
        let cache = BlockCache::new(100, 60);
        let result = cache.get(999, RpcCommitment::Confirmed);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_commitment_separation() {
        let cache = BlockCache::new(100, 60);
        let block = generate_synthetic_block(1000);

        cache.insert(block, RpcCommitment::Confirmed);

        // Should not find with different commitment
        let result = cache.get(1000, RpcCommitment::Finalized);
        assert!(result.is_none());

        // Should find with same commitment
        let result = cache.get(1000, RpcCommitment::Confirmed);
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_eviction() {
        let cache = BlockCache::new(3, 60);

        // Fill cache to capacity
        for i in 0..3 {
            let block = generate_synthetic_block(1000 + i);
            cache.insert(block, RpcCommitment::Confirmed);
        }

        assert_eq!(cache.len(), 3);

        // Insert one more - should evict oldest
        let block = generate_synthetic_block(2000);
        cache.insert(block, RpcCommitment::Confirmed);

        assert_eq!(cache.len(), 3);

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = BlockCache::new(100, 0); // 0 second TTL
        let block = generate_synthetic_block(1000);

        cache.insert(block, RpcCommitment::Confirmed);

        thread::sleep(Duration::from_millis(10));

        // Should be expired
        let result = cache.get(1000, RpcCommitment::Confirmed);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_range() {
        let cache = BlockCache::new(100, 60);

        // Insert blocks
        for slot in 1000..1010 {
            let block = generate_synthetic_block(slot);
            cache.insert(block, RpcCommitment::Confirmed);
        }

        let blocks = cache.get_range(1000, 1005, RpcCommitment::Confirmed);
        assert_eq!(blocks.len(), 6); // Inclusive range
    }

    #[test]
    fn test_prefetch_range() {
        let cache = BlockCache::new(100, 60);

        cache.prefetch_range(1000, 10, RpcCommitment::Confirmed);

        assert_eq!(cache.len(), 10);

        // Verify blocks are accessible
        for slot in 1000..1010 {
            assert!(cache.get(slot, RpcCommitment::Confirmed).is_some());
        }
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = BlockCache::new(100, 0); // 0 second TTL

        for slot in 1000..1005 {
            let block = generate_synthetic_block(slot);
            cache.insert(block, RpcCommitment::Confirmed);
        }

        thread::sleep(Duration::from_millis(10));

        assert_eq!(cache.len(), 5);
        cache.cleanup_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_generate_synthetic_block() {
        let block = generate_synthetic_block(1000);

        assert_eq!(block.slot, 1000);
        assert_eq!(block.parent_slot, 999);
        assert!(block.transaction_count > 0);
        assert!(!block.rewards.is_empty());
    }
}
