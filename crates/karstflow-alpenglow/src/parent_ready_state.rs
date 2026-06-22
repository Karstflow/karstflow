//! Per-slot state for the parent-ready tracker.
//!
//! Port of the reference `consensus/pool/parent_ready_tracker/
//! fd_parent_ready_state.{h,c}` (mirrors `parent_ready_state.rs`). The Rust
//! reference's tokio oneshot waiter is dropped: `wait_for_parent_ready` returns
//! synchronously (`Some(min-slot ready parent)` if ready, else `None`). The
//! fixed-cap arrays of the C port become growable `Vec`s.

use crate::base::{BlockHash, BlockId, GENESIS_BLOCK_HASH};

/// Per-slot parent-ready state: skip-certification, notarized-fallback blocks,
/// and the currently-ready parent block ids.
#[derive(Clone, Debug, Default)]
pub struct ParentReadyState {
    /// The slot this state tracks.
    pub slot: u64,
    skip: bool,
    notar_fallbacks: Vec<BlockHash>,
    ready_ids: Vec<BlockId>,
}

impl ParentReadyState {
    /// Empty (default) state for `slot`.
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            skip: false,
            notar_fallbacks: Vec::new(),
            ready_ids: Vec::new(),
        }
    }

    /// Genesis state: like [`Self::new`] but with the genesis block hash as the
    /// single notarized-fallback.
    pub fn genesis(slot: u64) -> Self {
        let mut s = Self::new(slot);
        s.notar_fallbacks.push(GENESIS_BLOCK_HASH);
        s
    }

    /// Mark this slot skip-certified; returns `true` iff it was not already.
    pub fn mark_skip(&mut self) -> bool {
        if self.skip {
            false
        } else {
            self.skip = true;
            true
        }
    }

    /// `true` iff this slot is skip-certified.
    pub fn is_skip_certified(&self) -> bool {
        self.skip
    }

    /// Mark `hash` notarized-fallback; returns `true` iff newly marked.
    pub fn mark_notar_fallback(&mut self, hash: &BlockHash) -> bool {
        if self.notar_fallbacks.contains(hash) {
            false
        } else {
            self.notar_fallbacks.push(*hash);
            true
        }
    }

    /// Notarized-fallback block hashes for this slot.
    pub fn notar_fallback_blocks(&self) -> &[BlockHash] {
        &self.notar_fallbacks
    }

    /// Add `id` to the ready-parents list. Panics if already present (matches
    /// the reference assert).
    pub fn add_to_ready(&mut self, id: &BlockId) {
        assert!(
            !self.ready_ids.contains(id),
            "add_to_ready: parent already ready for slot {}",
            self.slot
        );
        self.ready_ids.push(*id);
    }

    /// Currently valid parents for this slot.
    pub fn ready_block_ids(&self) -> &[BlockId] {
        &self.ready_ids
    }

    /// `true` iff at least one parent is ready.
    pub fn is_ready(&self) -> bool {
        !self.ready_ids.is_empty()
    }

    /// The minimal-`(slot, hash)` ready parent, or `None` if not ready.
    pub fn wait_for_parent_ready(&self) -> Option<BlockId> {
        self.ready_ids
            .iter()
            .min_by_key(|b| (b.slot, b.hash))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_and_notar_fallback_dedup() {
        let mut s = ParentReadyState::new(4);
        assert!(s.mark_skip());
        assert!(!s.mark_skip());
        let h = [1u8; 32];
        assert!(s.mark_notar_fallback(&h));
        assert!(!s.mark_notar_fallback(&h));
        assert_eq!(s.notar_fallback_blocks(), &[h]);
    }

    #[test]
    fn genesis_has_zero_hash_fallback() {
        let s = ParentReadyState::genesis(0);
        assert_eq!(s.notar_fallback_blocks(), &[GENESIS_BLOCK_HASH]);
    }

    #[test]
    fn wait_returns_minimal_parent() {
        let mut s = ParentReadyState::new(8);
        assert!(s.wait_for_parent_ready().is_none());
        s.add_to_ready(&BlockId::new(5, [2u8; 32]));
        s.add_to_ready(&BlockId::new(3, [9u8; 32]));
        assert_eq!(s.wait_for_parent_ready(), Some(BlockId::new(3, [9u8; 32])));
        assert!(s.is_ready());
    }

    #[test]
    #[should_panic(expected = "already ready")]
    fn add_to_ready_rejects_duplicate() {
        let mut s = ParentReadyState::new(8);
        let id = BlockId::new(1, [1u8; 32]);
        s.add_to_ready(&id);
        s.add_to_ready(&id);
    }
}
