//! Proof of History (PoH) Hash Chain
//!
//! This module implements a cryptographic hash chain that provides a verifiable
//! passage of time and ordering for transactions in Paradencer. PoH is a fundamental
//! component of the Solana architecture.
//!
//! # Overview
//!
//! PoH works by continuously hashing the previous hash output, creating a sequence
//! that can only be generated sequentially. Transactions are "mixed in" to the hash
//! chain at specific points, proving they occurred at that moment in the sequence.
//!
//! # Hash Chain Properties
//!
//! - **Sequential**: Each hash depends on the previous one
//! - **Deterministic**: Same inputs always produce same outputs
//! - **Verifiable**: Anyone can verify the chain by re-hashing
//! - **Time-stamped**: Position in chain proves relative time ordering

use blake3;
use paradencer_consensus::Hash;
use serde::{Deserialize, Serialize};

/// Default number of hashes per tick
pub const DEFAULT_HASHES_PER_TICK: u64 = 12_500;

/// Maximum transactions per entry
pub const MAX_TRANSACTIONS_PER_ENTRY: usize = 64;

/// A record in the PoH hash chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohRecord {
    /// The hash value at this point in the chain
    pub hash: Hash,

    /// Number of hashes since the last record
    pub num_hashes: u64,

    /// Optional transaction data mixed into the chain
    pub mixin: Option<Vec<u8>>,
}

/// A complete entry in the PoH chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohEntry {
    /// Number of hashes since previous entry
    pub num_hashes: u64,

    /// Hash of this entry
    pub hash: Hash,

    /// Transactions in this entry (serialized)
    pub transactions: Vec<Vec<u8>>,
}

/// Statistics for PoH service
#[derive(Debug, Clone, Default)]
pub struct PohStats {
    /// Total hashes computed
    pub total_hashes: u64,

    /// Total ticks generated
    pub total_ticks: u64,

    /// Total transaction entries recorded
    pub total_entries: u64,

    /// Total transactions recorded
    pub total_transactions: u64,
}

/// Proof of History service maintaining a hash chain
pub struct PohService {
    /// Current hash at the head of the chain
    current_hash: Hash,

    /// Number of ticks generated in current sequence
    tick_count: u64,

    /// Number of hashes since last tick
    hashes_since_tick: u64,

    /// Number of hashes per tick
    hashes_per_tick: u64,

    /// Accumulated entries waiting to be flushed
    pending_entries: Vec<PohEntry>,

    /// Statistics
    stats: PohStats,
}

impl PohService {
    /// Create a new PoH service with the given starting hash
    pub fn new(starting_hash: Hash) -> Self {
        Self {
            current_hash: starting_hash,
            tick_count: 0,
            hashes_since_tick: 0,
            hashes_per_tick: DEFAULT_HASHES_PER_TICK,
            pending_entries: Vec::new(),
            stats: PohStats::default(),
        }
    }

    /// Create a new PoH service with a random starting hash
    pub fn new_random() -> Self {
        Self::new(Hash::new_unique())
    }

    /// Create a new PoH service with custom hashes per tick
    pub fn with_hashes_per_tick(starting_hash: Hash, hashes_per_tick: u64) -> Self {
        Self {
            current_hash: starting_hash,
            tick_count: 0,
            hashes_since_tick: 0,
            hashes_per_tick: hashes_per_tick.max(1),
            pending_entries: Vec::new(),
            stats: PohStats::default(),
        }
    }

    /// Hash a single iteration
    ///
    /// Computes: hash = Blake3(current_hash || data)
    pub fn hash(&mut self, data: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.current_hash.as_ref());
        hasher.update(data);
        let hash_bytes = hasher.finalize();

        let hash = Hash::new(*hash_bytes.as_bytes());

        self.current_hash = hash;
        self.stats.total_hashes += 1;
        self.hashes_since_tick += 1;

        hash
    }

    /// Hash without mixing in data
    pub fn tick_hash(&mut self) -> Hash {
        self.hash(&[])
    }

    /// Generate a tick entry
    ///
    /// A tick is a special entry with no transactions that marks passage of time
    pub fn tick(&mut self) -> PohEntry {
        // Hash to the next tick boundary
        let hashes_needed = self.hashes_per_tick - self.hashes_since_tick;
        for _ in 0..hashes_needed {
            self.tick_hash();
        }

        let entry = PohEntry {
            num_hashes: self.hashes_per_tick,
            hash: self.current_hash,
            transactions: Vec::new(),
        };

        self.tick_count += 1;
        self.hashes_since_tick = 0;
        self.stats.total_ticks += 1;

        entry
    }

    /// Record transactions into a new entry
    ///
    /// Mixes transaction data into the hash chain and creates an entry
    pub fn record(&mut self, transactions: Vec<Vec<u8>>) -> PohEntry {
        if transactions.is_empty() {
            return self.tick();
        }

        // Hash to advance the chain before mixing in transactions
        let num_preamble_hashes = self.hashes_since_tick.max(1);

        // Mix in all transaction data
        for tx in &transactions {
            self.hash(tx);
        }

        let entry = PohEntry {
            num_hashes: num_preamble_hashes,
            hash: self.current_hash,
            transactions,
        };

        self.stats.total_entries += 1;
        self.stats.total_transactions += entry.transactions.len() as u64;

        entry
    }

    /// Record a single transaction
    pub fn record_one(&mut self, transaction: Vec<u8>) -> PohEntry {
        self.record(vec![transaction])
    }

    /// Get current hash
    pub fn current_hash(&self) -> Hash {
        self.current_hash
    }

    /// Get tick count
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Get statistics
    pub fn stats(&self) -> &PohStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = PohStats::default();
    }

    /// Get hashes per tick setting
    pub fn hashes_per_tick(&self) -> u64 {
        self.hashes_per_tick
    }

    /// Reset the PoH service with a new starting hash
    pub fn reset(&mut self, starting_hash: Hash) {
        self.current_hash = starting_hash;
        self.tick_count = 0;
        self.hashes_since_tick = 0;
        self.pending_entries.clear();
        self.stats = PohStats::default();
    }
}

impl Default for PohService {
    fn default() -> Self {
        Self::new_random()
    }
}

impl PohEntry {
    /// Create a new entry
    pub fn new(num_hashes: u64, hash: Hash, transactions: Vec<Vec<u8>>) -> Self {
        Self {
            num_hashes,
            hash,
            transactions,
        }
    }

    /// Check if this is a tick entry (no transactions)
    pub fn is_tick(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Serialize entry to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // num_hashes (8 bytes)
        bytes.extend_from_slice(&self.num_hashes.to_le_bytes());

        // hash (32 bytes)
        bytes.extend_from_slice(self.hash.as_ref());

        // num_transactions (8 bytes)
        bytes.extend_from_slice(&(self.transactions.len() as u64).to_le_bytes());

        // transactions
        for tx in &self.transactions {
            bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
            bytes.extend_from_slice(tx);
        }

        bytes
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> usize {
        let mut size = 8 + 32 + 8; // num_hashes + hash + num_transactions
        for tx in &self.transactions {
            size += 8 + tx.len(); // length prefix + tx data
        }
        size
    }
}

impl PohRecord {
    /// Create a new PoH record
    pub fn new(hash: Hash, num_hashes: u64, mixin: Option<Vec<u8>>) -> Self {
        Self {
            hash,
            num_hashes,
            mixin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poh_service_creation() {
        let hash = Hash::new_unique();
        let poh = PohService::new(hash);

        assert_eq!(poh.current_hash(), hash);
        assert_eq!(poh.tick_count(), 0);
        assert_eq!(poh.hashes_per_tick(), DEFAULT_HASHES_PER_TICK);
    }

    #[test]
    fn test_poh_hash_chain() {
        let mut poh = PohService::new_random();
        let initial_hash = poh.current_hash();

        let hash1 = poh.hash(b"test data");
        assert_ne!(hash1, initial_hash);

        let hash2 = poh.hash(b"more data");
        assert_ne!(hash2, hash1);

        assert_eq!(poh.current_hash(), hash2);
        assert_eq!(poh.stats().total_hashes, 2);
    }

    #[test]
    fn test_poh_tick() {
        let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 10);

        let entry = poh.tick();

        assert!(entry.is_tick());
        assert_eq!(entry.num_hashes, 10);
        assert_eq!(poh.tick_count(), 1);
        assert_eq!(poh.stats().total_ticks, 1);
    }

    #[test]
    fn test_poh_record_transactions() {
        let mut poh = PohService::new_random();

        let tx1 = vec![1, 2, 3, 4];
        let tx2 = vec![5, 6, 7, 8];

        let entry = poh.record(vec![tx1.clone(), tx2.clone()]);

        assert!(!entry.is_tick());
        assert_eq!(entry.transactions.len(), 2);
        assert_eq!(entry.transactions[0], tx1);
        assert_eq!(entry.transactions[1], tx2);
        assert_eq!(poh.stats().total_entries, 1);
        assert_eq!(poh.stats().total_transactions, 2);
    }

    #[test]
    fn test_poh_empty_transactions_creates_tick() {
        let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 10);

        let entry = poh.record(vec![]);

        assert!(entry.is_tick());
        assert_eq!(poh.tick_count(), 1);
    }

    #[test]
    fn test_poh_hash_deterministic() {
        let start_hash = Hash::new_unique();

        let mut poh1 = PohService::new(start_hash);
        let mut poh2 = PohService::new(start_hash);

        let hash1 = poh1.hash(b"test");
        let hash2 = poh2.hash(b"test");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poh_entry_serialization() {
        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6, 7, 8];
        let entry = PohEntry::new(100, Hash::new_unique(), vec![tx1, tx2]);

        let bytes = entry.to_bytes();

        // Check size calculation
        let expected_size = 8 + 32 + 8 + (8 + 3) + (8 + 5);
        assert_eq!(entry.size_bytes(), expected_size);
        assert_eq!(bytes.len(), expected_size);
    }

    #[test]
    fn test_poh_entry_is_tick() {
        let tick_entry = PohEntry::new(100, Hash::new_unique(), vec![]);
        assert!(tick_entry.is_tick());

        let tx_entry = PohEntry::new(100, Hash::new_unique(), vec![vec![1, 2, 3]]);
        assert!(!tx_entry.is_tick());
    }

    #[test]
    fn test_poh_reset() {
        let mut poh = PohService::new_random();

        poh.hash(b"data");
        poh.tick();

        let new_hash = Hash::new_unique();
        poh.reset(new_hash);

        assert_eq!(poh.current_hash(), new_hash);
        assert_eq!(poh.tick_count(), 0);
        assert_eq!(poh.stats().total_hashes, 0);
    }

    #[test]
    fn test_poh_stats() {
        let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 5);

        poh.tick();
        poh.record(vec![vec![1], vec![2]]);
        poh.tick();

        let stats = poh.stats();
        assert_eq!(stats.total_ticks, 2);
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_transactions, 2);
        assert!(stats.total_hashes >= 10); // At least 2 ticks worth
    }

    #[test]
    fn test_poh_record_one() {
        let mut poh = PohService::new_random();

        let tx = vec![1, 2, 3, 4, 5];
        let entry = poh.record_one(tx.clone());

        assert_eq!(entry.transactions.len(), 1);
        assert_eq!(entry.transactions[0], tx);
    }

    #[test]
    fn test_poh_custom_hashes_per_tick() {
        let custom_hpt = 42;
        let poh = PohService::with_hashes_per_tick(Hash::new_unique(), custom_hpt);

        assert_eq!(poh.hashes_per_tick(), custom_hpt);
    }

    #[test]
    fn test_poh_minimum_hashes_per_tick() {
        let poh = PohService::with_hashes_per_tick(Hash::new_unique(), 0);
        assert_eq!(poh.hashes_per_tick(), 1); // Should be clamped to minimum of 1
    }
}
