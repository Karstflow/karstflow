//! Signature-indexed transaction status cache.
//!
//! Tracks recent transaction signatures and their execution status
//! (slot, success/failure, optional error message). Used by the RPC
//! layer to serve `getSignatureStatuses` queries.
//!
//! The cache is bounded and uses LRU-style eviction when capacity
//! is exceeded. It is shared across bank forks via `Arc`.

use std::collections::HashMap;
use std::sync::RwLock;

/// Maximum number of signature entries retained in the cache.
const DEFAULT_CAPACITY: usize = 1_048_576; // ~1M entries

/// Status of a single transaction identified by its signature.
#[derive(Debug, Clone)]
pub struct SignatureStatus {
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Whether the transaction executed successfully.
    pub succeeded: bool,
    /// Error description for failed transactions.
    pub error: Option<String>,
}

/// Thread-safe, bounded cache mapping Ed25519 signatures to transaction status.
///
/// Shared across the fork tree via `Arc<SignatureStatusCache>`.
#[derive(Debug)]
pub struct SignatureStatusCache {
    entries: RwLock<HashMap<[u8; 64], SignatureStatus>>,
    capacity: usize,
}

impl SignatureStatusCache {
    /// Create a new cache with default capacity.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            capacity: DEFAULT_CAPACITY,
        }
    }

    /// Record a successful transaction.
    pub fn insert_success(&self, signature: [u8; 64], slot: u64) {
        let mut map = self.entries.write().unwrap();
        self.evict_if_needed(&mut map);
        map.insert(
            signature,
            SignatureStatus {
                slot,
                succeeded: true,
                error: None,
            },
        );
    }

    /// Record a failed transaction with an error description.
    pub fn insert_failure(&self, signature: [u8; 64], slot: u64, error: String) {
        let mut map = self.entries.write().unwrap();
        self.evict_if_needed(&mut map);
        map.insert(
            signature,
            SignatureStatus {
                slot,
                succeeded: false,
                error: Some(error),
            },
        );
    }

    /// Look up the status of a transaction by its first signature.
    pub fn get(&self, signature: &[u8; 64]) -> Option<SignatureStatus> {
        self.entries.read().unwrap().get(signature).cloned()
    }

    /// Look up statuses for multiple signatures at once.
    pub fn get_batch(&self, signatures: &[[u8; 64]]) -> Vec<Option<SignatureStatus>> {
        let map = self.entries.read().unwrap();
        signatures.iter().map(|sig| map.get(sig).cloned()).collect()
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Evict oldest entries when at capacity. Removes entries from the
    /// lowest slot numbers first.
    fn evict_if_needed(&self, map: &mut HashMap<[u8; 64], SignatureStatus>) {
        if map.len() < self.capacity {
            return;
        }
        // Find the minimum slot and remove all entries from that slot.
        if let Some(min_slot) = map.values().map(|s| s.slot).min() {
            map.retain(|_, status| status.slot > min_slot);
        }
    }
}

impl Default for SignatureStatusCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_success() {
        let cache = SignatureStatusCache::new();
        let sig = [0xAA; 64];
        cache.insert_success(sig, 42);

        let status = cache.get(&sig).unwrap();
        assert_eq!(status.slot, 42);
        assert!(status.succeeded);
        assert!(status.error.is_none());
    }

    #[test]
    fn insert_and_get_failure() {
        let cache = SignatureStatusCache::new();
        let sig = [0xBB; 64];
        cache.insert_failure(sig, 100, "InstructionError".to_string());

        let status = cache.get(&sig).unwrap();
        assert_eq!(status.slot, 100);
        assert!(!status.succeeded);
        assert_eq!(status.error.as_deref(), Some("InstructionError"));
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = SignatureStatusCache::new();
        let sig = [0xCC; 64];
        assert!(cache.get(&sig).is_none());
    }

    #[test]
    fn batch_query() {
        let cache = SignatureStatusCache::new();
        let sig1 = [0x11; 64];
        let sig2 = [0x22; 64];
        let sig3 = [0x33; 64];

        cache.insert_success(sig1, 10);
        cache.insert_failure(sig2, 20, "err".to_string());

        let results = cache.get_batch(&[sig1, sig2, sig3]);
        assert!(results[0].is_some());
        assert!(results[1].is_some());
        assert!(results[2].is_none());
        assert!(results[0].as_ref().unwrap().succeeded);
        assert!(!results[1].as_ref().unwrap().succeeded);
    }
}
