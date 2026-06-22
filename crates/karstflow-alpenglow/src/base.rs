//! Common base for the Alpenglow consensus port — types, constants, and
//! quorum/window helpers.
//!
//! Faithful Rust port of the reference `fd_alpenglow_base.h`, which itself
//! mirrors the Solana Alpenglow Rust reference (`alpenglow/src/types.rs`,
//! `alpenglow/src/consensus.rs` constants, `alpenglow/src/types/fraction.rs`,
//! `alpenglow/src/types/slot.rs`). Values are byte/semantics-exact.

/// 32-byte block hash (double-Merkle root of a block).
pub type BlockHash = [u8; 32];

/// Genesis block hash is all-zero (`alpenglow/src/crypto/merkle.rs`).
pub const GENESIS_BLOCK_HASH: BlockHash = [0u8; 32];

/// Number of consecutive slots a single leader owns.
pub const SLOTS_PER_WINDOW: u64 = 4;
/// Number of slots in an epoch.
pub const SLOTS_PER_EPOCH: u64 = 18_000;

/// `DELTA` = 250 ms (base network delay unit), in nanoseconds.
pub const DELTA_NS: i64 = 250_000_000;
/// `DELTA_BLOCK` = 400 ms, in nanoseconds.
pub const DELTA_BLOCK_NS: i64 = 400_000_000;
/// `DELTA_FIRST_SLICE` = 10 ms, in nanoseconds.
pub const DELTA_FIRST_SLICE_NS: i64 = 10_000_000;
/// `DELTA_TIMEOUT` = 3 × DELTA = 750 ms, in nanoseconds.
pub const DELTA_TIMEOUT_NS: i64 = 3 * DELTA_NS;
/// `DELTA_STANDSTILL` = 10 s, in nanoseconds.
pub const DELTA_STANDSTILL_NS: i64 = 10_000_000_000;

/// Quorum threshold numerators (shared denominator [`QUORUM_DENOM`] = 5).
pub const WEAKEST_QUORUM_NUMER: u64 = 1; // 20%
/// Weak-quorum numerator (40%).
pub const WEAK_QUORUM_NUMER: u64 = 2; // 40%
/// Standard-quorum numerator (60%).
pub const QUORUM_NUMER: u64 = 3; // 60%
/// Strong-quorum numerator (80%).
pub const STRONG_QUORUM_NUMER: u64 = 4; // 80%
/// Shared quorum denominator.
pub const QUORUM_DENOM: u64 = 5;

/// A block reference: `(slot, hash)`. Mirrors the reference `BlockId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId {
    /// Slot the block was produced in.
    pub slot: u64,
    /// Double-Merkle root hash of the block.
    pub hash: BlockHash,
}

impl BlockId {
    /// Construct a block id.
    pub const fn new(slot: u64, hash: BlockHash) -> Self {
        Self { slot, hash }
    }

    /// The genesis block id for `slot`.
    pub const fn genesis(slot: u64) -> Self {
        Self {
            slot,
            hash: GENESIS_BLOCK_HASH,
        }
    }
}

/// Returns `true` iff `stake/total >= numer/denom`, computed with 128-bit
/// cross-multiplication to avoid overflow and rounding. Mirrors
/// `Fraction::is_met`. A `total` of 0 is met only by a `numer` of 0.
#[inline]
pub fn fraction_is_met(stake: u64, total: u64, numer: u64, denom: u64) -> bool {
    (stake as u128) * (denom as u128) >= (total as u128) * (numer as u128)
}

/// `true` iff `stake` is at least a weakest quorum (≥20%) of `total`.
#[inline]
pub fn is_weakest_quorum(stake: u64, total: u64) -> bool {
    fraction_is_met(stake, total, WEAKEST_QUORUM_NUMER, QUORUM_DENOM)
}

/// `true` iff `stake` is at least a weak quorum (≥40%) of `total`.
#[inline]
pub fn is_weak_quorum(stake: u64, total: u64) -> bool {
    fraction_is_met(stake, total, WEAK_QUORUM_NUMER, QUORUM_DENOM)
}

/// `true` iff `stake` is at least a standard quorum (≥60%) of `total`.
#[inline]
pub fn is_quorum(stake: u64, total: u64) -> bool {
    fraction_is_met(stake, total, QUORUM_NUMER, QUORUM_DENOM)
}

/// `true` iff `stake` is at least a strong quorum (≥80%) of `total`.
#[inline]
pub fn is_strong_quorum(stake: u64, total: u64) -> bool {
    fraction_is_met(stake, total, STRONG_QUORUM_NUMER, QUORUM_DENOM)
}

/// First slot of the leader window containing `slot`.
#[inline]
pub fn first_slot_in_window(slot: u64) -> u64 {
    (slot / SLOTS_PER_WINDOW) * SLOTS_PER_WINDOW
}

/// Last slot of the leader window containing `slot`.
#[inline]
pub fn last_slot_in_window(slot: u64) -> u64 {
    first_slot_in_window(slot) + SLOTS_PER_WINDOW - 1
}

/// `true` iff `slot` is the first slot of a leader window.
#[inline]
pub fn is_start_of_window(slot: u64) -> bool {
    slot.is_multiple_of(SLOTS_PER_WINDOW)
}

/// `true` iff `slot` is in the genesis (first) window.
#[inline]
pub fn is_genesis_window(slot: u64) -> bool {
    slot < SLOTS_PER_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_three_delta() {
        assert_eq!(DELTA_TIMEOUT_NS, 750_000_000);
        assert_eq!(DELTA_TIMEOUT_NS, 3 * DELTA_NS);
    }

    #[test]
    fn quorum_thresholds_are_inclusive_at_exact_fraction() {
        // total = 100; exact thresholds 20/40/60/80 must be met (>=).
        assert!(is_weakest_quorum(20, 100));
        assert!(is_weak_quorum(40, 100));
        assert!(is_quorum(60, 100));
        assert!(is_strong_quorum(80, 100));
        // One below each threshold must NOT be met.
        assert!(!is_weakest_quorum(19, 100));
        assert!(!is_weak_quorum(39, 100));
        assert!(!is_quorum(59, 100));
        assert!(!is_strong_quorum(79, 100));
    }

    #[test]
    fn fraction_handles_zero_total() {
        // Faithful to the reference cross-multiply: with total == 0 the right
        // side (total*numer) is 0, so stake*denom >= 0 always holds — every
        // threshold is vacuously met. (Total stake is never 0 in practice.)
        assert!(fraction_is_met(0, 0, 0, 5));
        assert!(fraction_is_met(0, 0, 1, 5));
        assert!(fraction_is_met(5, 0, 3, 5));
    }

    #[test]
    fn fraction_no_overflow_at_large_stake() {
        // Near-u64::MAX values must not overflow (128-bit math).
        let big = u64::MAX;
        assert!(is_quorum(big, big));
        assert!(!is_strong_quorum(big / 2, big));
    }

    #[test]
    fn window_helpers() {
        // SLOTS_PER_WINDOW = 4 → windows [0..3], [4..7], ...
        assert_eq!(first_slot_in_window(0), 0);
        assert_eq!(first_slot_in_window(5), 4);
        assert_eq!(last_slot_in_window(5), 7);
        assert!(is_start_of_window(0));
        assert!(is_start_of_window(8));
        assert!(!is_start_of_window(5));
        assert!(is_genesis_window(0));
        assert!(is_genesis_window(3));
        assert!(!is_genesis_window(4));
    }

    #[test]
    fn block_id_equality_and_genesis() {
        let a = BlockId::new(7, [1u8; 32]);
        let b = BlockId::new(7, [1u8; 32]);
        let c = BlockId::new(7, [2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(BlockId::genesis(0).hash, GENESIS_BLOCK_HASH);
    }
}
