//! CRDS table entry with multi-index metadata.
//!
//! Each entry in the CRDS table wraps a CrdsValue with additional
//! metadata used by the various indexes: stake weight for eviction,
//! reception timestamp for expiration, value hash for bloom filter
//! queries, and duplicate tracking.

use super::key::CrdsKey;
use super::value::CrdsValue;

/// How a CRDS entry was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryOrigin {
    /// Received via push gossip.
    Push,
    /// Received via pull response.
    PullResponse,
    /// Locally generated.
    Local,
}

/// A CRDS table entry with multi-index metadata.
///
/// This struct holds the value along with metadata needed by the
/// five concurrent indexes (lookup map, eviction treap, expiration
/// lists, hash-prefix treap, contact info side table).
#[derive(Debug, Clone)]
pub struct CrdsEntry {
    // --- Core data ---
    /// The CRDS key (value type + origin + sub-index).
    pub key: CrdsKey,
    /// The signed CRDS value.
    pub value: CrdsValue,

    // --- Index metadata ---
    /// SHA-256 hash of the serialized value.
    pub value_hash: [u8; 32],
    /// First 8 bytes of value_hash (big-endian), used as hash-prefix treap key.
    pub hash_prefix: u64,
    /// Originator's stake weight (for eviction ordering).
    pub stake: u64,
    /// Local reception timestamp (nanoseconds since epoch).
    pub received_at_nanos: i64,
    /// Number of times this exact hash was received (duplicate tracking).
    pub duplicate_count: u64,
    /// How this entry was received.
    pub origin: EntryOrigin,

    // --- Contact info metadata ---
    /// If this is a contact info entry, index into the contact info side table.
    pub contact_info_index: Option<usize>,
    /// Whether the associated peer has responded to pings.
    pub is_active: bool,
    /// Index into the weighted peer sampler array.
    pub sampler_index: Option<usize>,
    /// Whether this contact info is in the fresh list (updated within threshold).
    pub is_fresh: bool,
    /// Monotonically increasing insertion ordinal assigned by the table.
    /// Used by the push loop to efficiently find new/updated entries since
    /// a given cursor without scanning the entire table.
    pub ordinal: u64,
}

impl CrdsEntry {
    /// Create a new entry from a CRDS value.
    pub fn new(value: CrdsValue, stake: u64, now_nanos: i64, origin: EntryOrigin) -> Self {
        let key = value.key();
        let value_hash = value.compute_hash();
        let hash_prefix = hash_prefix_from_bytes(&value_hash);

        Self {
            key,
            value,
            value_hash,
            hash_prefix,
            stake,
            received_at_nanos: now_nanos,
            duplicate_count: 0,
            origin,
            contact_info_index: None,
            is_active: false,
            sampler_index: None,
            is_fresh: true,
            ordinal: 0, // assigned by CrdsTable on insert
        }
    }

    /// Whether this entry is from a staked node (stake > 0).
    pub fn is_staked(&self) -> bool {
        self.stake > 0
    }

    /// Whether this entry has expired based on the current time.
    pub fn is_expired(&self, now_nanos: i64, staked_duration: i64, unstaked_duration: i64) -> bool {
        let duration = if self.is_staked() {
            staked_duration
        } else {
            unstaked_duration
        };
        now_nanos.saturating_sub(self.received_at_nanos) >= duration
    }

    /// Whether this contact info entry is stale (not refreshed within threshold).
    pub fn is_stale(&self, now_nanos: i64, fresh_threshold: i64) -> bool {
        now_nanos.saturating_sub(self.received_at_nanos) >= fresh_threshold
    }

    /// Compute peer score for the weighted sampler.
    ///
    /// Score = base_weight + stake. Stale peers are downweighted.
    pub fn peer_score(&self, now_nanos: i64, fresh_threshold: i64) -> u64 {
        let base = paradencer_constants::gossip::PEER_SCORE_BASE_WEIGHT.saturating_add(self.stake);
        if self.is_stale(now_nanos, fresh_threshold) {
            base / paradencer_constants::gossip::OFFLINE_PEER_DOWNWEIGHT_FACTOR
        } else {
            base
        }
    }
}

/// Extract the hash prefix (first 8 bytes, big-endian) from a 32-byte hash.
///
/// The prefix is stored in big-endian order so that numerical comparison
/// matches lexicographic byte order, enabling efficient range queries
/// in the hash-prefix treap.
fn hash_prefix_from_bytes(hash: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::crds::value::{CrdsContactInfo, CrdsValueData};

    fn make_test_value(origin: [u8; 32], wallclock: i64) -> CrdsValue {
        CrdsValue {
            origin,
            wallclock_nanos: wallclock,
            signature: [0u8; 64],
            data: CrdsValueData::ContactInfo(CrdsContactInfo {
                pubkey: origin,
                shred_version: 1,
                instance_creation_nanos: 1000,
                wallclock_nanos: wallclock,
                sockets: Default::default(),
                version: Default::default(),
            }),
        }
    }

    #[test]
    fn test_entry_creation() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 500, 2000, EntryOrigin::Push);

        assert_eq!(entry.key.origin, origin);
        assert_eq!(entry.stake, 500);
        assert_eq!(entry.received_at_nanos, 2000);
        assert!(entry.is_staked());
        assert!(entry.is_fresh);
    }

    #[test]
    fn test_entry_unstaked() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 0, 2000, EntryOrigin::PullResponse);

        assert!(!entry.is_staked());
    }

    #[test]
    fn test_entry_expiration_staked() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 500, 1000, EntryOrigin::Push);

        let staked_ttl = paradencer_constants::gossip::STAKED_EXPIRE_DURATION_NANOS;
        let unstaked_ttl = paradencer_constants::gossip::UNSTAKED_EXPIRE_DURATION_NANOS;

        // Not expired yet
        assert!(!entry.is_expired(1000 + staked_ttl - 1, staked_ttl, unstaked_ttl));
        // Expired
        assert!(entry.is_expired(1000 + staked_ttl, staked_ttl, unstaked_ttl));
    }

    #[test]
    fn test_entry_expiration_unstaked() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 0, 1000, EntryOrigin::Push);

        let staked_ttl = paradencer_constants::gossip::STAKED_EXPIRE_DURATION_NANOS;
        let unstaked_ttl = paradencer_constants::gossip::UNSTAKED_EXPIRE_DURATION_NANOS;

        // Not expired yet
        assert!(!entry.is_expired(1000 + unstaked_ttl - 1, staked_ttl, unstaked_ttl));
        // Expired
        assert!(entry.is_expired(1000 + unstaked_ttl, staked_ttl, unstaked_ttl));
    }

    #[test]
    fn test_peer_score_fresh() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 500, 1000, EntryOrigin::Push);

        let threshold = paradencer_constants::gossip::FRESH_THRESHOLD_NANOS;
        let score = entry.peer_score(1000 + threshold - 1, threshold);
        assert_eq!(score, 100 + 500); // base + stake
    }

    #[test]
    fn test_peer_score_stale() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let entry = CrdsEntry::new(value, 500, 1000, EntryOrigin::Push);

        let threshold = paradencer_constants::gossip::FRESH_THRESHOLD_NANOS;
        let score = entry.peer_score(1000 + threshold, threshold);
        assert_eq!(score, (100 + 500) / 100); // downweighted by 100x
    }

    #[test]
    fn test_hash_prefix_deterministic() {
        let origin = [1u8; 32];
        let value = make_test_value(origin, 1000);
        let e1 = CrdsEntry::new(value.clone(), 0, 1000, EntryOrigin::Push);
        let e2 = CrdsEntry::new(value, 0, 1000, EntryOrigin::Push);
        assert_eq!(e1.hash_prefix, e2.hash_prefix);
        assert_eq!(e1.value_hash, e2.value_hash);
    }
}
