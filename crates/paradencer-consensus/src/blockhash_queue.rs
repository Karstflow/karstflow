/// Blockhash queue for recent blockhash tracking and transaction validation.
///
/// This module implements a consensus-critical data structure that tracks recently
/// produced blockhashes. It serves multiple purposes:
/// - Transaction validation: Ensures transactions reference recent blockhashes
/// - Fee calculation: Associates each blockhash with fee rates
/// - Nonce validation: Supports durable transaction nonces
use paradencer_storage::Pubkey;

/// Type alias for blockhash (32-byte value, same as Pubkey)
pub type Hash = Pubkey;
use std::collections::{HashMap, VecDeque};

/// Maximum number of blockhashes to track in the queue.
/// Matches Solana's MAX_RECENT_BLOCKHASHES constant.
pub const MAX_RECENT_BLOCKHASHES: usize = 300;

/// Information associated with each blockhash in the queue.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockhashInfo {
    /// The blockhash
    pub hash: Hash,
    /// Fee rate in lamports per signature at this blockhash
    pub lamports_per_signature: u64,
    /// Slot when this blockhash was produced
    pub slot: u64,
}

impl BlockhashInfo {
    pub fn new(hash: Hash, lamports_per_signature: u64, slot: u64) -> Self {
        Self {
            hash,
            lamports_per_signature,
            slot,
        }
    }
}

/// Queue of recent blockhashes for transaction validation.
///
/// Maintains a FIFO queue of recent blockhashes with fast lookup via hash map.
/// New blockhashes are added to the back, oldest are evicted from the front
/// when capacity is reached.
#[derive(Debug, Clone)]
pub struct BlockhashQueue {
    /// Ordered queue of blockhash info (newest at back)
    queue: VecDeque<BlockhashInfo>,
    /// Hash map for O(1) lookup of blockhash age
    index: HashMap<Hash, usize>,
    /// Maximum age (in slots) for a blockhash to be considered valid
    max_age: usize,
}

impl BlockhashQueue {
    /// Create a new blockhash queue with default max age.
    pub fn new(max_age: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(MAX_RECENT_BLOCKHASHES),
            index: HashMap::with_capacity(MAX_RECENT_BLOCKHASHES),
            max_age,
        }
    }

    /// Register a new blockhash in the queue.
    ///
    /// Adds the blockhash to the back of the queue. If the queue is full,
    /// evicts the oldest blockhash from the front.
    pub fn register_hash(&mut self, info: BlockhashInfo) {
        // Check for duplicate (should never happen in valid chain)
        if self.index.contains_key(&info.hash) {
            // In production this would be a critical error
            // For now, just skip the duplicate
            return;
        }

        // Evict oldest if at capacity
        if self.queue.len() >= MAX_RECENT_BLOCKHASHES {
            if let Some(old_info) = self.queue.pop_front() {
                self.index.remove(&old_info.hash);
            }
        }

        // Add new blockhash to back
        let position = self.queue.len();
        self.queue.push_back(info.clone());
        self.index.insert(info.hash, position);

        // Rebuild index since positions changed
        self.rebuild_index();
    }

    /// Check if a blockhash is in the queue and within max age.
    ///
    /// Returns true if the blockhash exists and its age (distance from tail)
    /// is less than or equal to max_age.
    pub fn check_hash_age(&self, hash: &Hash, max_age: usize) -> bool {
        if let Some(&position) = self.index.get(hash) {
            let age = self.queue.len().saturating_sub(1).saturating_sub(position);
            age <= max_age
        } else {
            false
        }
    }

    /// Check if a blockhash is valid (exists and within default max age).
    pub fn is_hash_valid(&self, hash: &Hash) -> bool {
        self.check_hash_age(hash, self.max_age)
    }

    /// Get fee rate (lamports per signature) for a given blockhash.
    pub fn get_lamports_per_signature(&self, hash: &Hash) -> Option<u64> {
        self.index
            .get(hash)
            .and_then(|&pos| self.queue.get(pos))
            .map(|info| info.lamports_per_signature)
    }

    /// Get the most recent blockhash.
    pub fn last_blockhash(&self) -> Option<&Hash> {
        self.queue.back().map(|info| &info.hash)
    }

    /// Get the most recent blockhash info.
    pub fn last_blockhash_info(&self) -> Option<&BlockhashInfo> {
        self.queue.back()
    }

    /// Get age of a blockhash (distance from most recent).
    ///
    /// Returns None if blockhash not found, otherwise returns age where
    /// 0 means most recent, 1 means second most recent, etc.
    pub fn get_hash_age(&self, hash: &Hash) -> Option<usize> {
        self.index
            .get(hash)
            .map(|&position| self.queue.len().saturating_sub(1).saturating_sub(position))
    }

    /// Get number of blockhashes in queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get maximum age for blockhash validity.
    pub fn max_age(&self) -> usize {
        self.max_age
    }

    /// Rebuild the index after queue modifications.
    ///
    /// Called after adding entries to ensure position mapping is correct.
    fn rebuild_index(&mut self) {
        self.index.clear();
        for (pos, info) in self.queue.iter().enumerate() {
            self.index.insert(info.hash, pos);
        }
    }

    /// Return a snapshot of all entries in the queue (oldest-first order).
    ///
    /// Each entry contains the blockhash, fee rate, and originating slot.
    /// Used for serializing blockhash queue state into snapshot manifests.
    pub fn entries(&self) -> impl Iterator<Item = &BlockhashInfo> {
        self.queue.iter()
    }

    /// Clear all blockhashes from the queue.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.index.clear();
    }
}

impl Default for BlockhashQueue {
    fn default() -> Self {
        Self::new(MAX_RECENT_BLOCKHASHES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockhash_queue_registers_new_hash() {
        let mut queue = BlockhashQueue::new(150);
        let hash = Hash::new_unique();
        let info = BlockhashInfo::new(hash, 5000, 100);

        queue.register_hash(info.clone());

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.last_blockhash(), Some(&hash));
        assert_eq!(queue.get_lamports_per_signature(&hash), Some(5000));
    }

    #[test]
    fn blockhash_queue_validates_recent_hash() {
        let mut queue = BlockhashQueue::new(150);
        let hash = Hash::new_unique();
        let info = BlockhashInfo::new(hash, 5000, 100);

        queue.register_hash(info);

        assert!(queue.is_hash_valid(&hash));
        assert!(queue.check_hash_age(&hash, 150));
    }

    #[test]
    fn blockhash_queue_rejects_old_hash() {
        let mut queue = BlockhashQueue::new(1); // max_age = 1

        // Add 3 hashes
        let hash1 = Hash::new_unique();
        let hash2 = Hash::new_unique();
        let hash3 = Hash::new_unique();

        queue.register_hash(BlockhashInfo::new(hash1, 5000, 100));
        queue.register_hash(BlockhashInfo::new(hash2, 5000, 101));
        queue.register_hash(BlockhashInfo::new(hash3, 5000, 102));

        // hash3 is age 0 (most recent), valid
        assert!(queue.is_hash_valid(&hash3));
        // hash2 is age 1, valid with max_age=1
        assert!(queue.is_hash_valid(&hash2));
        // hash1 is age 2, invalid with max_age=1
        assert!(!queue.is_hash_valid(&hash1));
    }

    #[test]
    fn blockhash_queue_calculates_age_correctly() {
        let mut queue = BlockhashQueue::new(150);

        let hash1 = Hash::new_unique();
        let hash2 = Hash::new_unique();
        let hash3 = Hash::new_unique();

        queue.register_hash(BlockhashInfo::new(hash1, 5000, 100));
        queue.register_hash(BlockhashInfo::new(hash2, 5000, 101));
        queue.register_hash(BlockhashInfo::new(hash3, 5000, 102));

        // hash3 is most recent (age 0)
        assert_eq!(queue.get_hash_age(&hash3), Some(0));
        // hash2 is second most recent (age 1)
        assert_eq!(queue.get_hash_age(&hash2), Some(1));
        // hash1 is oldest (age 2)
        assert_eq!(queue.get_hash_age(&hash1), Some(2));
    }

    #[test]
    fn blockhash_queue_respects_max_age() {
        let mut queue = BlockhashQueue::new(1);

        let hash1 = Hash::new_unique();
        let hash2 = Hash::new_unique();

        queue.register_hash(BlockhashInfo::new(hash1, 5000, 100));
        queue.register_hash(BlockhashInfo::new(hash2, 5000, 101));

        // hash2 is age 0, should be valid
        assert!(queue.check_hash_age(&hash2, 1));
        // hash1 is age 1, should be valid with max_age=1
        assert!(queue.check_hash_age(&hash1, 1));
        // hash1 is age 1, should be invalid with max_age=0
        assert!(!queue.check_hash_age(&hash1, 0));
    }

    #[test]
    fn blockhash_queue_evicts_when_full() {
        let mut queue = BlockhashQueue::new(150);

        // Fill queue to MAX_RECENT_BLOCKHASHES
        let mut hashes = Vec::new();
        for i in 0..MAX_RECENT_BLOCKHASHES {
            let hash = Hash::new_unique();
            queue.register_hash(BlockhashInfo::new(hash, 5000, i as u64));
            hashes.push(hash);
        }

        assert_eq!(queue.len(), MAX_RECENT_BLOCKHASHES);

        // Add one more, should evict the first
        let new_hash = Hash::new_unique();
        queue.register_hash(BlockhashInfo::new(
            new_hash,
            5000,
            MAX_RECENT_BLOCKHASHES as u64,
        ));

        // First hash should be gone
        assert!(!queue.is_hash_valid(&hashes[0]));
        // New hash should be present
        assert!(queue.is_hash_valid(&new_hash));
        // Size should still be MAX_RECENT_BLOCKHASHES
        assert_eq!(queue.len(), MAX_RECENT_BLOCKHASHES);
    }

    #[test]
    fn blockhash_queue_rejects_duplicates() {
        let mut queue = BlockhashQueue::new(150);
        let hash = Hash::new_unique();

        queue.register_hash(BlockhashInfo::new(hash, 5000, 100));
        assert_eq!(queue.len(), 1);

        // Try to register same hash again
        queue.register_hash(BlockhashInfo::new(hash, 6000, 101));

        // Should still be only 1 entry
        assert_eq!(queue.len(), 1);
        // Original fee should remain
        assert_eq!(queue.get_lamports_per_signature(&hash), Some(5000));
    }

    #[test]
    fn blockhash_queue_clears_all() {
        let mut queue = BlockhashQueue::new(150);

        let hash1 = Hash::new_unique();
        let hash2 = Hash::new_unique();

        queue.register_hash(BlockhashInfo::new(hash1, 5000, 100));
        queue.register_hash(BlockhashInfo::new(hash2, 5000, 101));

        assert_eq!(queue.len(), 2);

        queue.clear();

        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        assert!(!queue.is_hash_valid(&hash1));
        assert!(!queue.is_hash_valid(&hash2));
    }

    #[test]
    fn blockhash_queue_handles_empty() {
        let queue = BlockhashQueue::new(150);

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.last_blockhash(), None);
        assert_eq!(queue.last_blockhash_info(), None);

        let hash = Hash::new_unique();
        assert!(!queue.is_hash_valid(&hash));
        assert_eq!(queue.get_hash_age(&hash), None);
        assert_eq!(queue.get_lamports_per_signature(&hash), None);
    }
}
