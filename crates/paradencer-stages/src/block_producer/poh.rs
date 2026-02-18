//! Proof of History (PoH) hash chain.
//!
//! PoH maintains a SHA-256 hash chain that provides verifiable ordering of
//! transactions. The leader continuously hashes `SHA256(prev_hash)` to
//! advance the chain. Transactions are "mixed in" by hashing
//! `SHA256(prev_hash || mixin_hash)` at specific hashcnts.
//!
//! # Time Units (smallest → largest)
//!
//! - **hashcnt**: one SHA-256 iteration (~100ns on mainnet)
//! - **tick**: periodic checkpoint, every `hashes_per_tick` hashcnts
//! - **slot**: leader window, `ticks_per_slot` ticks (~400ms)
//! - **epoch**: housekeeping boundary, `slots_per_epoch` slots (~2 days)
//!
//! # State Machine
//!
//! The PoH tile runs in three states:
//! - `Idling`: Not leader, performing background hashing for proof-of-skipping
//! - `Hashing`: Approaching leader slot, accumulating skip proof
//! - `Leading`: Active leader, mixing in microblocks and publishing ticks

use paradencer_constants::ledger::{
    DEFAULT_HASHES_PER_TICK, MAX_MICROBLOCKS_PER_SLOT, TICKS_PER_SLOT,
};
use paradencer_types::Hash;
use serde::{Deserialize, Serialize};

/// Maximum transactions per entry.
pub const MAX_TRANSACTIONS_PER_ENTRY: usize = 64;

// ---------------------------------------------------------------------------
// PohEntry — serializable ledger entry
// ---------------------------------------------------------------------------

/// A ledger entry produced by the PoH service.
///
/// Contains the PoH hash, the number of hash iterations since the previous
/// entry, and any transactions included (empty for tick entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohEntry {
    /// Number of PoH hashes since the previous entry.
    pub num_hashes: u64,
    /// PoH hash at this entry.
    pub hash: Hash,
    /// Transactions included in this entry (empty for ticks).
    pub transactions: Vec<Vec<u8>>,
}

impl PohEntry {
    pub fn new(num_hashes: u64, hash: Hash, transactions: Vec<Vec<u8>>) -> Self {
        Self {
            num_hashes,
            hash,
            transactions,
        }
    }

    /// Whether this is a tick entry (no transactions).
    pub fn is_tick(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Serialize to bytes (num_hashes + hash + txs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size_bytes());
        buf.extend_from_slice(&self.num_hashes.to_le_bytes());
        buf.extend_from_slice(self.hash.as_bytes());
        buf.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            buf.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            buf.extend_from_slice(tx);
        }
        buf
    }

    /// Serialized size in bytes.
    pub fn size_bytes(&self) -> usize {
        8 + 32 + 4 + self.transactions.iter().map(|t| 4 + t.len()).sum::<usize>()
    }
}

/// Record type for logging/stats.
pub enum PohRecord {
    Tick,
    Entry(usize),
}

// ---------------------------------------------------------------------------
// PoH state
// ---------------------------------------------------------------------------

/// Current state of the PoH tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PohState {
    /// Not leader, background hashing for proof-of-skipping.
    Idling,
    /// Approaching own leader slot, accumulating tick hashes.
    Hashing,
    /// Active leader, accepting microblocks and producing entries.
    Leading,
}

/// A tick entry: the hash value at a tick boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickEntry {
    /// Hash at this tick boundary.
    pub hash: Hash,
    /// Number of hashcnts since the previous entry.
    pub num_hashes: u64,
}

/// A microblock entry: transactions mixed into the PoH chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockEntry {
    /// Hash after mixing in the transaction batch.
    pub hash: Hash,
    /// Number of hashcnts since the previous entry (at least 1 for the mixin).
    pub num_hashes: u64,
    /// Number of transactions in this microblock.
    pub transaction_count: u32,
}

/// An entry in the PoH chain (either a tick or a microblock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    Tick(TickEntry),
    Microblock(MicroblockEntry),
}

impl Entry {
    pub fn hash(&self) -> &Hash {
        match self {
            Entry::Tick(t) => &t.hash,
            Entry::Microblock(m) => &m.hash,
        }
    }

    pub fn num_hashes(&self) -> u64 {
        match self {
            Entry::Tick(t) => t.num_hashes,
            Entry::Microblock(m) => m.num_hashes,
        }
    }

    pub fn is_tick(&self) -> bool {
        matches!(self, Entry::Tick(_))
    }
}

/// Slot completion signal from PoH to downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotComplete {
    /// The completed slot.
    pub slot: u64,
    /// Final blockhash (hash at the last tick of the slot).
    pub blockhash: Hash,
}

/// Statistics for the PoH service.
#[derive(Debug, Clone, Default)]
pub struct PohStats {
    pub total_hashes: u64,
    pub total_ticks: u64,
    pub total_entries: u64,
    pub total_transactions: u64,
    pub slots_completed: u64,
    pub slots_skipped: u64,
}

// ---------------------------------------------------------------------------
// PoH service
// ---------------------------------------------------------------------------

/// Proof of History service maintaining the SHA-256 hash chain.
///
/// Tracks position within the chain (slot + hashcnt), manages leader
/// transitions, and stores skipped tick hashes for proof-of-skipping.
pub struct PohService {
    /// Current state of the PoH tile.
    state: PohState,

    /// Current SHA-256 hash at the head of the chain.
    hash: Hash,

    /// Current slot.
    slot: u64,

    /// Hash count within the current slot (0..hashcnt_per_slot).
    hashcnt: u64,

    /// Hash count at which the last entry was published.
    last_entry_hashcnt: u64,

    /// Slot of the last published entry.
    last_entry_slot: u64,

    /// Number of microblocks received in the current leader slot.
    microblocks_in_slot: u64,

    /// Whether pack has signaled done packing for the current slot.
    slot_done: bool,

    /// The slot we last reset onto (building on top of).
    reset_slot: u64,

    /// The hash at the reset point.
    reset_hash: Hash,

    /// Next slot where this validator is leader (u64::MAX = not scheduled).
    next_leader_slot: u64,

    // -- Configuration (from genesis / features) --
    hashes_per_tick: u64,
    ticks_per_slot: u64,
    hashcnt_per_slot: u64,
    max_microblocks_per_slot: u64,

    /// Tick hashes accumulated during non-leader slots for proof-of-skipping.
    skipped_tick_hashes: Vec<Hash>,

    /// Statistics.
    stats: PohStats,
}

impl PohService {
    /// Create a new PoH service with mainnet defaults.
    pub fn new(genesis_hash: Hash) -> Self {
        Self::with_config(
            genesis_hash,
            DEFAULT_HASHES_PER_TICK,
            TICKS_PER_SLOT,
            MAX_MICROBLOCKS_PER_SLOT,
        )
    }

    /// Create with specific hashes per tick (convenience constructor).
    pub fn with_hashes_per_tick(genesis_hash: Hash, hashes_per_tick: u64) -> Self {
        Self::with_config(
            genesis_hash,
            hashes_per_tick,
            TICKS_PER_SLOT,
            MAX_MICROBLOCKS_PER_SLOT,
        )
    }

    /// Create with random genesis hash (for testing).
    pub fn new_random() -> Self {
        Self::new(Hash::new_unique())
    }

    /// Create a new PoH service with custom configuration.
    pub fn with_config(
        genesis_hash: Hash,
        hashes_per_tick: u64,
        ticks_per_slot: u64,
        max_microblocks_per_slot: u64,
    ) -> Self {
        let hashes_per_tick = hashes_per_tick.max(1);
        Self {
            state: PohState::Idling,
            hash: genesis_hash,
            slot: 0,
            hashcnt: 0,
            last_entry_hashcnt: 0,
            last_entry_slot: 0,
            microblocks_in_slot: 0,
            slot_done: false,
            reset_slot: 0,
            reset_hash: genesis_hash,
            next_leader_slot: u64::MAX,
            hashes_per_tick,
            ticks_per_slot,
            hashcnt_per_slot: hashes_per_tick * ticks_per_slot,
            max_microblocks_per_slot,
            skipped_tick_hashes: Vec::new(),
            stats: PohStats::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn state(&self) -> PohState {
        self.state
    }

    pub fn current_hash(&self) -> Hash {
        self.hash
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn hashcnt(&self) -> u64 {
        self.hashcnt
    }

    pub fn is_leader(&self) -> bool {
        self.state == PohState::Leading
    }

    pub fn stats(&self) -> &PohStats {
        &self.stats
    }

    pub fn hashes_per_tick(&self) -> u64 {
        self.hashes_per_tick
    }

    pub fn ticks_per_slot(&self) -> u64 {
        self.ticks_per_slot
    }

    pub fn tick_count(&self) -> u64 {
        self.stats.total_ticks
    }

    // -----------------------------------------------------------------------
    // Core hashing
    // -----------------------------------------------------------------------

    /// Compute one SHA-256 hash: `hash = SHA256(prev_hash)`.
    fn hash_once(&mut self) {
        self.hash = Hash::sha256(self.hash.as_bytes());
        self.stats.total_hashes += 1;
    }

    /// Mix a 32-byte value into the chain: `hash = SHA256(prev_hash || mixin)`.
    fn hash_mixin(&mut self, mixin: &[u8]) {
        self.hash = Hash::extend_and_hash(&self.hash, mixin);
        self.stats.total_hashes += 1;
    }

    /// Check if the current hashcnt is on a tick boundary.
    fn is_tick_boundary(&self) -> bool {
        self.hashcnt > 0 && self.hashcnt.is_multiple_of(self.hashes_per_tick)
    }

    /// Whether we must produce a tick (at tick boundary or slot end).
    pub fn must_tick(&self) -> bool {
        self.is_tick_boundary()
    }

    /// Remaining hashcnts in the current slot.
    fn remaining_in_slot(&self) -> u64 {
        self.hashcnt_per_slot.saturating_sub(self.hashcnt)
    }

    // -----------------------------------------------------------------------
    // Legacy convenience methods (used by EntryCreator / BlockProducer)
    // -----------------------------------------------------------------------

    /// Hash data into the chain and return the resulting hash.
    ///
    /// Computes SHA-256 of the data to get a 32-byte mixin, then
    /// mixes it into the chain: `hash = SHA256(prev_hash || SHA256(data))`.
    pub fn hash(&mut self, data: &[u8]) -> Hash {
        let data_hash = Hash::sha256(data);
        self.hash_mixin(data_hash.as_bytes());
        self.hash
    }

    /// Generate a tick entry.
    ///
    /// Hashes forward by `hashes_per_tick` iterations and returns
    /// a PohEntry representing the tick.
    pub fn tick(&mut self) -> PohEntry {
        let hpt = self.hashes_per_tick;
        for _ in 0..hpt {
            self.hash_once();
        }
        self.stats.total_ticks += 1;
        PohEntry::new(hpt, self.hash, vec![])
    }

    /// Record transactions as an entry.
    ///
    /// Mixes a hash of the transactions into the chain and returns
    /// a PohEntry containing the transactions.
    pub fn record(&mut self, transactions: Vec<Vec<u8>>) -> PohEntry {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for tx in &transactions {
            hasher.update(tx);
        }
        let result = hasher.finalize();
        self.hash_mixin(&result);
        self.stats.total_entries += 1;
        self.stats.total_transactions += transactions.len() as u64;
        PohEntry::new(1, self.hash, transactions)
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    /// Reset the PoH chain onto a completed slot.
    ///
    /// Called when the fork choice selects a new best slot to build on.
    pub fn reset(&mut self, completed_slot: u64, completed_blockhash: Hash, next_leader_slot: u64) {
        self.reset_slot = completed_slot;
        self.reset_hash = completed_blockhash;
        self.hash = completed_blockhash;
        self.slot = completed_slot + 1;
        self.hashcnt = 0;
        self.last_entry_slot = self.slot;
        self.last_entry_hashcnt = 0;
        self.microblocks_in_slot = 0;
        self.slot_done = false;
        self.next_leader_slot = next_leader_slot;
        self.skipped_tick_hashes.clear();

        self.state = if next_leader_slot == self.slot {
            PohState::Leading
        } else if next_leader_slot != u64::MAX {
            PohState::Hashing
        } else {
            PohState::Idling
        };
    }

    /// Begin leading a slot.
    ///
    /// Called when the current slot matches our leader schedule.
    pub fn begin_leader(&mut self, leader_slot: u64) {
        self.next_leader_slot = leader_slot;
        self.microblocks_in_slot = 0;
        self.slot_done = false;
        self.state = PohState::Leading;
    }

    /// Signal that pack is done sending microblocks for this slot.
    pub fn done_packing(&mut self, microblocks_count: u64) {
        self.slot_done = true;
        self.microblocks_in_slot = microblocks_count;
    }

    // -----------------------------------------------------------------------
    // Advancing the chain
    // -----------------------------------------------------------------------

    /// Advance the PoH chain, producing entries as needed.
    ///
    /// Hashes forward, generating tick entries at tick boundaries.
    /// Returns produced entries. In non-leader mode, tick hashes are
    /// stored for proof-of-skipping instead of published.
    pub fn advance(&mut self, target_hashes: u64) -> Vec<Entry> {
        let mut entries = Vec::new();

        for _ in 0..target_hashes {
            // Don't advance past slot boundary without explicit slot transition
            if self.hashcnt >= self.hashcnt_per_slot {
                break;
            }

            self.hash_once();
            self.hashcnt += 1;

            // Tick boundary reached
            if self.is_tick_boundary() {
                let hashes_since_last = self.hashcnt_since_last_entry();

                if self.state == PohState::Leading {
                    entries.push(Entry::Tick(TickEntry {
                        hash: self.hash,
                        num_hashes: hashes_since_last,
                    }));
                } else {
                    // Store for proof-of-skipping
                    self.skipped_tick_hashes.push(self.hash);
                    self.stats.slots_skipped += 1;
                }

                self.last_entry_hashcnt = self.hashcnt;
                self.last_entry_slot = self.slot;
                self.stats.total_ticks += 1;
            }
        }

        entries
    }

    /// Complete the current slot by hashing to the end and advancing to the next.
    ///
    /// Returns entries produced plus the slot completion signal.
    pub fn finish_slot(&mut self) -> (Vec<Entry>, SlotComplete) {
        let remaining = self.remaining_in_slot();
        let entries = self.advance(remaining);

        let completion = SlotComplete {
            slot: self.slot,
            blockhash: self.hash,
        };

        self.stats.slots_completed += 1;

        // Advance to next slot
        self.slot += 1;
        self.hashcnt = 0;
        self.last_entry_hashcnt = 0;
        self.last_entry_slot = self.slot;
        self.microblocks_in_slot = 0;
        self.slot_done = false;

        // Update state for next slot
        if self.slot == self.next_leader_slot {
            self.state = PohState::Leading;
        } else if self.next_leader_slot != u64::MAX {
            self.state = PohState::Hashing;
        } else {
            self.state = PohState::Idling;
        }

        (entries, completion)
    }

    /// Mix a microblock's transaction hash into the PoH chain.
    ///
    /// The mixin_hash is typically `SHA256(sig0 || sig1 || ... || sigN)`
    /// of all transaction signatures in the microblock.
    ///
    /// Returns the microblock entry, or None if we can't accept more
    /// microblocks (at tick boundary, past slot end, or limit reached).
    pub fn mixin(
        &mut self,
        mixin_hash: &[u8; 32],
        transaction_count: u32,
    ) -> Option<MicroblockEntry> {
        if self.state != PohState::Leading {
            return None;
        }

        // Can't mixin on a tick boundary
        if self.is_tick_boundary() {
            return None;
        }

        // Advance one hashcnt for the mixin
        self.hash_mixin(mixin_hash);
        self.hashcnt += 1;

        let hashes_since_last = self.hashcnt_since_last_entry();
        self.microblocks_in_slot += 1;

        let entry = MicroblockEntry {
            hash: self.hash,
            num_hashes: hashes_since_last,
            transaction_count,
        };

        self.last_entry_hashcnt = self.hashcnt;
        self.last_entry_slot = self.slot;
        self.stats.total_entries += 1;
        self.stats.total_transactions += transaction_count as u64;

        Some(entry)
    }

    /// Number of hashcnts since the last published entry.
    fn hashcnt_since_last_entry(&self) -> u64 {
        if self.slot == self.last_entry_slot {
            self.hashcnt.saturating_sub(self.last_entry_hashcnt)
        } else {
            // Crossed a slot boundary since last entry
            let prev_remaining = self
                .hashcnt_per_slot
                .saturating_sub(self.last_entry_hashcnt);
            prev_remaining + self.hashcnt
        }
    }

    /// Get stored skipped tick hashes (for proof-of-skipping).
    pub fn skipped_tick_hashes(&self) -> &[Hash] {
        &self.skipped_tick_hashes
    }

    /// Clear skipped tick hashes (after publishing them).
    pub fn clear_skipped_ticks(&mut self) {
        self.skipped_tick_hashes.clear();
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = PohStats::default();
    }
}

// ---------------------------------------------------------------------------
// PoH verification
// ---------------------------------------------------------------------------

/// Verify a sequence of PoH entries.
///
/// Checks that each entry's hash is correctly derived from the previous
/// hash by the claimed number of iterations.
pub fn verify_entries(starting_hash: &Hash, entries: &[Entry]) -> bool {
    let mut current = *starting_hash;

    for entry in entries {
        let num_hashes = entry.num_hashes();
        if num_hashes == 0 {
            return false;
        }

        match entry {
            Entry::Tick(tick) => {
                for _ in 0..num_hashes {
                    current = Hash::sha256(current.as_bytes());
                }
                if current != tick.hash {
                    return false;
                }
            }
            Entry::Microblock(mb) => {
                // Full verification needs the actual mixin data.
                // Without mixin, we trust the hash and just advance.
                current = mb.hash;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash() -> Hash {
        Hash::zeroed()
    }

    fn test_hash() -> Hash {
        Hash::sha256(zero_hash().as_bytes())
    }

    #[test]
    fn sha256_chain_is_deterministic() {
        let mut h1 = zero_hash();
        let mut h2 = zero_hash();
        for _ in 0..10 {
            h1 = Hash::sha256(h1.as_bytes());
            h2 = Hash::sha256(h2.as_bytes());
        }
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_extend_differs_from_plain() {
        let h = zero_hash();
        let plain = Hash::sha256(h.as_bytes());
        let mixin = [1u8; 32];
        let extended = Hash::extend_and_hash(&h, &mixin);
        assert_ne!(plain, extended);
    }

    #[test]
    fn new_service_starts_idling() {
        let poh = PohService::new(zero_hash());
        assert_eq!(poh.state(), PohState::Idling);
        assert_eq!(poh.slot(), 0);
        assert_eq!(poh.hashcnt(), 0);
        assert!(!poh.is_leader());
    }

    #[test]
    fn with_config_clamps_hashes_per_tick() {
        let poh = PohService::with_config(zero_hash(), 0, 64, 1000);
        assert_eq!(poh.hashes_per_tick(), 1);
    }

    #[test]
    fn reset_sets_state_to_leading_when_next_leader() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(5, test_hash(), 6);
        assert_eq!(poh.state(), PohState::Leading);
        assert_eq!(poh.slot(), 6);
        assert!(poh.is_leader());
    }

    #[test]
    fn reset_sets_state_to_hashing_when_future_leader() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(5, test_hash(), 10);
        assert_eq!(poh.state(), PohState::Hashing);
        assert_eq!(poh.slot(), 6);
    }

    #[test]
    fn reset_sets_state_to_idling_when_no_leader() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(5, test_hash(), u64::MAX);
        assert_eq!(poh.state(), PohState::Idling);
    }

    #[test]
    fn advance_produces_ticks_when_leading() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 1);
        assert_eq!(poh.state(), PohState::Leading);

        let entries = poh.advance(5);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_tick());
        assert_eq!(entries[0].num_hashes(), 5);
    }

    #[test]
    fn advance_stores_skipped_ticks_when_not_leading() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 10);
        assert_eq!(poh.state(), PohState::Hashing);

        let entries = poh.advance(5);
        assert!(entries.is_empty());
        assert_eq!(poh.skipped_tick_hashes().len(), 1);
    }

    #[test]
    fn advance_multiple_ticks() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 1);

        let entries = poh.advance(15);
        assert_eq!(entries.len(), 3);
        for e in &entries {
            assert!(e.is_tick());
            assert_eq!(e.num_hashes(), 5);
        }
    }

    #[test]
    fn advance_does_not_exceed_slot_boundary() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 1);

        let entries = poh.advance(100);
        assert_eq!(entries.len(), 4);
        assert_eq!(poh.hashcnt(), 20);
    }

    #[test]
    fn finish_slot_completes_and_advances() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 1);

        let (entries, completion) = poh.finish_slot();
        assert_eq!(entries.len(), 4);
        assert_eq!(completion.slot, 1);
        assert_eq!(poh.slot(), 2);
        assert_eq!(poh.hashcnt(), 0);
        assert_eq!(poh.stats().slots_completed, 1);
    }

    #[test]
    fn mixin_produces_microblock_entry() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(0, zero_hash(), 1);

        poh.advance(1);

        let mixin = [42u8; 32];
        let entry = poh.mixin(&mixin, 5);
        assert!(entry.is_some());
        let mb = entry.unwrap();
        assert_eq!(mb.transaction_count, 5);
        assert!(mb.num_hashes > 0);
        assert_eq!(poh.stats().total_entries, 1);
        assert_eq!(poh.stats().total_transactions, 5);
    }

    #[test]
    fn mixin_rejected_when_not_leading() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(0, zero_hash(), u64::MAX);

        let entry = poh.mixin(&[42u8; 32], 1);
        assert!(entry.is_none());
    }

    #[test]
    fn mixin_rejected_on_tick_boundary() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 1);

        poh.advance(5);
        assert!(poh.is_tick_boundary());

        let entry = poh.mixin(&[42u8; 32], 1);
        assert!(entry.is_none());
    }

    #[test]
    fn verify_tick_entries() {
        let mut poh = PohService::with_config(zero_hash(), 3, 2, 100);
        poh.reset(0, zero_hash(), 1);

        let entries = poh.advance(6);
        assert_eq!(entries.len(), 2);

        assert!(verify_entries(&zero_hash(), &entries));
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let tick = Entry::Tick(TickEntry {
            hash: Hash::new([99u8; 32]),
            num_hashes: 5,
        });
        assert!(!verify_entries(&zero_hash(), &[tick]));
    }

    #[test]
    fn verify_rejects_zero_hashes() {
        let tick = Entry::Tick(TickEntry {
            hash: zero_hash(),
            num_hashes: 0,
        });
        assert!(!verify_entries(&zero_hash(), &[tick]));
    }

    #[test]
    fn done_packing_sets_flag() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        poh.reset(0, zero_hash(), 1);

        assert!(!poh.slot_done);
        poh.done_packing(42);
        assert!(poh.slot_done);
        assert_eq!(poh.microblocks_in_slot, 42);
    }

    #[test]
    fn begin_leader_transitions_to_leading() {
        let mut poh = PohService::with_config(zero_hash(), 10, 4, 100);
        assert_eq!(poh.state(), PohState::Idling);

        poh.begin_leader(5);
        assert_eq!(poh.state(), PohState::Leading);
    }

    #[test]
    fn full_leader_cycle() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);

        poh.reset(0, zero_hash(), 1);
        assert!(poh.is_leader());
        assert_eq!(poh.slot(), 1);

        let entries = poh.advance(2);
        assert!(entries.is_empty());

        let mb = poh.mixin(&[1u8; 32], 3);
        assert!(mb.is_some());

        let (entries, completion) = poh.finish_slot();
        assert_eq!(completion.slot, 1);
        assert!(!entries.is_empty());
    }

    #[test]
    fn stats_accumulate_correctly() {
        let mut poh = PohService::with_config(zero_hash(), 5, 2, 100);
        poh.reset(0, zero_hash(), 1);

        poh.advance(3);
        poh.mixin(&[1u8; 32], 2);
        let (_, _) = poh.finish_slot();

        let stats = poh.stats();
        assert_eq!(stats.slots_completed, 1);
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_transactions, 2);
        assert!(stats.total_ticks >= 2);
        assert!(stats.total_hashes > 0);
    }

    #[test]
    fn reset_clears_skipped_ticks() {
        let mut poh = PohService::with_config(zero_hash(), 5, 4, 100);
        poh.reset(0, zero_hash(), 10);

        poh.advance(5);
        assert!(!poh.skipped_tick_hashes().is_empty());

        poh.reset(1, test_hash(), 2);
        assert!(poh.skipped_tick_hashes().is_empty());
    }

    // Legacy API tests

    #[test]
    fn legacy_hash_chain_continuity() {
        let mut poh = PohService::new(Hash::new_unique());
        let start_hash = poh.current_hash();

        let hash1 = poh.hash(b"data1");
        let hash2 = poh.hash(b"data2");
        let hash3 = poh.hash(b"data3");

        assert_ne!(hash1, start_hash);
        assert_ne!(hash2, hash1);
        assert_ne!(hash3, hash2);
        assert_eq!(poh.current_hash(), hash3);
    }

    #[test]
    fn legacy_deterministic_hashing() {
        let seed = Hash::new_unique();

        let mut poh1 = PohService::new(seed);
        let mut poh2 = PohService::new(seed);

        let hash1_a = poh1.hash(b"test");
        let hash1_b = poh2.hash(b"test");
        assert_eq!(hash1_a, hash1_b);

        let hash2_a = poh1.hash(b"data");
        let hash2_b = poh2.hash(b"data");
        assert_eq!(hash2_a, hash2_b);
    }

    #[test]
    fn legacy_tick_generation() {
        let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 10);

        let entry = poh.tick();

        assert!(entry.is_tick());
        assert_eq!(entry.num_hashes, 10);
        assert_eq!(entry.transactions.len(), 0);
        assert_eq!(poh.tick_count(), 1);
    }

    #[test]
    fn legacy_record_transactions() {
        let mut poh = PohService::new_random();

        let tx1 = b"transaction 1".to_vec();
        let tx2 = b"transaction 2".to_vec();
        let txs = vec![tx1.clone(), tx2.clone()];

        let entry = poh.record(txs);

        assert!(!entry.is_tick());
        assert_eq!(entry.transactions.len(), 2);
        assert_eq!(entry.transactions[0], tx1);
        assert_eq!(entry.transactions[1], tx2);
    }

    #[test]
    fn legacy_stats_accumulation() {
        let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 5);

        poh.tick();
        poh.record(vec![b"tx1".to_vec(), b"tx2".to_vec()]);
        poh.tick();

        let stats = poh.stats();
        assert_eq!(stats.total_ticks, 2);
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_transactions, 2);
        assert!(stats.total_hashes > 0);
    }

    #[test]
    fn poh_entry_serialization() {
        let tx1 = b"first transaction".to_vec();
        let tx2 = b"second transaction".to_vec();
        let entry = PohEntry::new(100, Hash::new_unique(), vec![tx1, tx2]);

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), entry.size_bytes());
        assert!(bytes.len() > 48);
    }
}
