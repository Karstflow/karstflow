//! Signature-indexed transaction status cache.
//!
//! Tracks recent transaction signatures and their execution status
//! (slot, success/failure, optional error message). Used by the RPC
//! layer to serve `getSignatureStatuses` and `getSignaturesForAddress`
//! queries.
//!
//! The cache is bounded and uses LRU-style eviction when capacity
//! is exceeded. It is shared across bank forks via `Arc`.

use std::collections::HashMap;
use std::sync::RwLock;

use paradencer_types::Pubkey;

/// Maximum number of signature entries retained in the cache.
const DEFAULT_CAPACITY: usize = 1_048_576; // ~1M entries

/// Maximum address index entries per address.
const MAX_SIGS_PER_ADDRESS: usize = 1_000;

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

/// A signature entry in the address index, referencing a transaction
/// that touched a specific address.
#[derive(Debug, Clone)]
pub struct AddressSignatureEntry {
    /// First signature of the transaction.
    pub signature: [u8; 64],
    /// Slot in which the transaction was processed.
    pub slot: u64,
    /// Whether the transaction succeeded.
    pub succeeded: bool,
    /// Error description for failed transactions.
    pub error: Option<String>,
}

/// Thread-safe, bounded cache mapping Ed25519 signatures to transaction status.
///
/// Also maintains a secondary index from account addresses to recent
/// transaction signatures, enabling `getSignaturesForAddress` queries.
///
/// Shared across the fork tree via `Arc<SignatureStatusCache>`.
#[derive(Debug)]
pub struct SignatureStatusCache {
    entries: RwLock<HashMap<[u8; 64], SignatureStatus>>,
    /// Secondary index: address → list of (signature, slot, succeeded, error)
    /// sorted by slot descending (most recent first).
    address_index: RwLock<HashMap<Pubkey, Vec<AddressSignatureEntry>>>,
    capacity: usize,
}

impl SignatureStatusCache {
    /// Create a new cache with default capacity.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            address_index: RwLock::new(HashMap::new()),
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

    /// Record the address associations for a processed transaction.
    ///
    /// For each account key involved in the transaction, adds an entry to
    /// the address index so `getSignaturesForAddress` can find it.
    pub fn index_transaction_addresses(
        &self,
        signature: [u8; 64],
        slot: u64,
        account_keys: &[Pubkey],
        succeeded: bool,
        error: Option<String>,
    ) {
        let mut index = self.address_index.write().unwrap();
        let entry = AddressSignatureEntry {
            signature,
            slot,
            succeeded,
            error,
        };
        for key in account_keys {
            let list = index.entry(*key).or_default();
            list.push(entry.clone());
            // Keep sorted by slot descending — newest first.
            // Since we typically insert in slot order, just check if last
            // two are out of order and swap if needed.
            let len = list.len();
            if len >= 2 && list[len - 1].slot > list[len - 2].slot {
                list.swap(len - 1, len - 2);
            }
            // Trim to max per address.
            if list.len() > MAX_SIGS_PER_ADDRESS {
                list.truncate(MAX_SIGS_PER_ADDRESS);
            }
        }
    }

    /// Query signatures for a given address with pagination.
    ///
    /// Returns up to `limit` entries, optionally filtered by:
    /// - `before_signature`: only return entries before this signature (exclusive)
    /// - `until_signature`: only return entries until this signature (exclusive)
    ///
    /// Results are ordered most-recent-first (descending slot).
    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        limit: usize,
        before_signature: Option<&[u8; 64]>,
        until_signature: Option<&[u8; 64]>,
    ) -> Vec<AddressSignatureEntry> {
        let index = self.address_index.read().unwrap();
        let list = match index.get(address) {
            Some(list) => list,
            None => return Vec::new(),
        };

        // Find the starting position based on `before` cursor.
        let start = if let Some(before_sig) = before_signature {
            // Find the entry with this signature and start after it.
            list.iter()
                .position(|e| &e.signature == before_sig)
                .map(|pos| pos + 1)
                .unwrap_or(0)
        } else {
            0
        };

        // Collect entries up to limit, stopping at `until` cursor.
        let mut results = Vec::with_capacity(limit.min(list.len()));
        for entry in list.iter().skip(start) {
            if results.len() >= limit {
                break;
            }
            if let Some(until_sig) = until_signature {
                if &entry.signature == until_sig {
                    break;
                }
            }
            results.push(entry.clone());
        }
        results
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
            let evicted_sigs: Vec<[u8; 64]> = map
                .iter()
                .filter(|(_, status)| status.slot <= min_slot)
                .map(|(sig, _)| *sig)
                .collect();
            map.retain(|_, status| status.slot > min_slot);
            // Also clean evicted signatures from address index.
            self.evict_address_entries(&evicted_sigs);
        }
    }

    /// Remove evicted signatures from the address index.
    fn evict_address_entries(&self, evicted_sigs: &[[u8; 64]]) {
        if evicted_sigs.is_empty() {
            return;
        }
        let mut index = self.address_index.write().unwrap();
        index.retain(|_, entries| {
            entries.retain(|e| !evicted_sigs.contains(&e.signature));
            !entries.is_empty()
        });
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

    #[test]
    fn address_index_basic() {
        let cache = SignatureStatusCache::new();
        let sig1 = [0x01; 64];
        let sig2 = [0x02; 64];
        let addr_a = Pubkey::from([0xAA; 32]);
        let addr_b = Pubkey::from([0xBB; 32]);

        cache.insert_success(sig1, 10);
        cache.index_transaction_addresses(sig1, 10, &[addr_a, addr_b], true, None);

        cache.insert_success(sig2, 20);
        cache.index_transaction_addresses(sig2, 20, &[addr_a], true, None);

        // addr_a has 2 sigs, addr_b has 1
        let result_a = cache.get_signatures_for_address(&addr_a, 100, None, None);
        assert_eq!(result_a.len(), 2);
        // Most recent first
        assert_eq!(result_a[0].slot, 20);
        assert_eq!(result_a[1].slot, 10);

        let result_b = cache.get_signatures_for_address(&addr_b, 100, None, None);
        assert_eq!(result_b.len(), 1);
        assert_eq!(result_b[0].slot, 10);
    }

    #[test]
    fn address_index_pagination_before() {
        let cache = SignatureStatusCache::new();
        let sig1 = [0x01; 64];
        let sig2 = [0x02; 64];
        let sig3 = [0x03; 64];
        let addr = Pubkey::from([0xAA; 32]);

        for (sig, slot) in [(sig1, 30), (sig2, 20), (sig3, 10)] {
            cache.insert_success(sig, slot);
            cache.index_transaction_addresses(sig, slot, &[addr], true, None);
        }

        // Get entries before sig1 (slot 30) — should return sig2, sig3
        let result = cache.get_signatures_for_address(&addr, 100, Some(&sig1), None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].slot, 20);
        assert_eq!(result[1].slot, 10);
    }

    #[test]
    fn address_index_pagination_limit() {
        let cache = SignatureStatusCache::new();
        let addr = Pubkey::from([0xAA; 32]);

        for i in 0_u8..10 {
            let mut sig = [0u8; 64];
            sig[0] = i;
            cache.insert_success(sig, u64::from(10 - i));
            cache.index_transaction_addresses(sig, u64::from(10 - i), &[addr], true, None);
        }

        let result = cache.get_signatures_for_address(&addr, 3, None, None);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn address_index_unknown_address() {
        let cache = SignatureStatusCache::new();
        let unknown = Pubkey::from([0xFF; 32]);
        let result = cache.get_signatures_for_address(&unknown, 100, None, None);
        assert!(result.is_empty());
    }
}
