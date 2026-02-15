pub mod account;
pub mod block;
pub mod signature;

pub use account::AccountCache;
pub use block::{BlockCache, BlockInfo, Reward, RewardType};
pub use signature::{ConfirmationStatus, SignatureCache, SignatureInfo};

use std::time::{Duration, Instant};

/// LRU cache entry with timestamp
#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    pub value: T,
    pub timestamp: Instant,
    pub access_count: u64,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            timestamp: Instant::now(),
            access_count: 0,
        }
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp.elapsed() > ttl
    }

    pub fn touch(&mut self) {
        self.access_count += 1;
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub inserts: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn miss_rate(&self) -> f64 {
        1.0 - self.hit_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new(42);
        assert!(!entry.is_expired(Duration::from_secs(1)));

        thread::sleep(Duration::from_millis(100));
        assert!(!entry.is_expired(Duration::from_secs(1)));
        assert!(entry.is_expired(Duration::from_millis(50)));
    }

    #[test]
    fn test_cache_entry_touch() {
        let mut entry = CacheEntry::new(42);
        assert_eq!(entry.access_count, 0);

        entry.touch();
        assert_eq!(entry.access_count, 1);

        entry.touch();
        assert_eq!(entry.access_count, 2);
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let mut stats = CacheStats::default();
        assert_eq!(stats.hit_rate(), 0.0);

        stats.hits = 80;
        stats.misses = 20;
        assert_eq!(stats.hit_rate(), 0.8);

        stats.hits = 0;
        stats.misses = 100;
        assert_eq!(stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_stats_miss_rate() {
        let mut stats = CacheStats::default();
        stats.hits = 75;
        stats.misses = 25;

        assert_eq!(stats.miss_rate(), 0.25);
    }
}
