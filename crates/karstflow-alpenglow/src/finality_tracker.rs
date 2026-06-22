//! Finality tracker: tracks direct finalization of blocks plus the resulting
//! implicit finalization of ancestors and implicit skipping of earlier slots.
//!
//! Port of the reference `consensus/pool/fd_finality_tracker.{h,c}` (mirrors
//! `finality_tracker.rs`). The reference's wksp pool/map/treap pair becomes a
//! `BTreeMap<slot, (status, hash)>` (ordered → prefix prune) and a
//! `HashMap<BlockId, BlockId>` (child → parent). "Consensus safety violation"
//! fatal logs become panics (they indicate impossible input).

use std::collections::{BTreeMap, HashMap};

use crate::base::{BlockHash, BlockId, GENESIS_BLOCK_HASH};

/// The finality state of a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinStatus {
    /// Block with the given hash is notarized; slot not yet known finalized.
    Notarized,
    /// Slot is known finalized but the notarization cert is missing.
    FinalPendingNotar,
    /// Slot is finalized and the notarized block hash is known.
    Finalized,
    /// Block was implicitly finalized through a later finalization.
    ImplicitlyFinalized,
    /// Slot was implicitly skipped through a later finalization.
    ImplicitlySkipped,
}

/// The result of a finalization step.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinalizationEvent {
    /// The directly finalized block, if any.
    pub finalized: Option<BlockId>,
    /// Blocks implicitly finalized as ancestors.
    pub implicitly_finalized: Vec<BlockId>,
    /// Slots implicitly skipped.
    pub implicitly_skipped: Vec<u64>,
}

/// Tracks block / slot finality.
#[derive(Debug)]
pub struct FinalityTracker {
    status: BTreeMap<u64, (FinStatus, BlockHash)>,
    parents: HashMap<BlockId, BlockId>,
    highest_finalized_slot: u64,
    first_unpruned_slot: u64,
}

impl Default for FinalityTracker {
    /// Genesis state: slot 0 is `Notarized(GENESIS_BLOCK_HASH)`, parents empty,
    /// watermarks at slot 0.
    fn default() -> Self {
        let mut status = BTreeMap::new();
        status.insert(0, (FinStatus::Notarized, GENESIS_BLOCK_HASH));
        Self {
            status,
            parents: HashMap::new(),
            highest_finalized_slot: 0,
            first_unpruned_slot: 0,
        }
    }
}

impl FinalityTracker {
    /// Insert/overwrite the status for `slot`, returning the previous value
    /// (mirrors `BTreeMap::insert`).
    fn status_insert(
        &mut self,
        slot: u64,
        status: FinStatus,
        hash: BlockHash,
    ) -> Option<(FinStatus, BlockHash)> {
        self.status.insert(slot, (status, hash))
    }

    /// Highest directly-finalized slot.
    pub fn highest_finalized_slot(&self) -> u64 {
        self.highest_finalized_slot
    }
    /// Lowest slot still tracked.
    pub fn first_unpruned_slot(&self) -> u64 {
        self.first_unpruned_slot
    }
    /// The status (and hash) of `slot`, or `None` if untracked.
    pub fn status(&self, slot: u64) -> Option<(FinStatus, BlockHash)> {
        self.status.get(&slot).copied()
    }
    /// `true` iff a parent edge is recorded for `block`.
    pub fn has_parent(&self, block: &BlockId) -> bool {
        self.parents.contains_key(block)
    }

    fn handle_implicitly_finalized(
        &mut self,
        mut source_slot: u64,
        mut cur: BlockId,
        ev: &mut FinalizationEvent,
    ) {
        loop {
            assert!(source_slot > cur.slot);
            if cur.slot < self.first_unpruned_slot {
                return;
            }

            // Implicitly skip slots between cur.slot and source_slot.
            let mut slot = cur.slot + 1;
            while slot != source_slot {
                let old =
                    self.status_insert(slot, FinStatus::ImplicitlySkipped, GENESIS_BLOCK_HASH);
                match old {
                    Some((FinStatus::ImplicitlySkipped, _)) => return, // already skipped
                    Some((FinStatus::Notarized, _)) | None => {}
                    Some(_) => panic!("consensus safety violation"),
                }
                ev.implicitly_skipped.push(slot);
                slot += 1;
            }

            // Mark cur implicitly finalized.
            let old = self.status_insert(cur.slot, FinStatus::ImplicitlyFinalized, cur.hash);
            if let Some((old_status, old_hash)) = old {
                match old_status {
                    FinStatus::Finalized | FinStatus::ImplicitlyFinalized => {
                        assert!(old_hash == cur.hash, "consensus safety violation");
                        // Restore the previous status and return.
                        self.status_insert(cur.slot, old_status, old_hash);
                        return;
                    }
                    FinStatus::Notarized => {
                        assert!(old_hash == cur.hash, "consensus safety violation");
                    }
                    FinStatus::FinalPendingNotar => {}
                    FinStatus::ImplicitlySkipped => panic!("consensus safety violation"),
                }
            }
            ev.implicitly_finalized.push(cur);

            // Recurse through ancestors (flattened tail call).
            match self.parents.get(&cur).copied() {
                None => return,
                Some(parent) => {
                    source_slot = cur.slot;
                    cur = parent;
                }
            }
        }
    }

    fn handle_finalized_block(&mut self, finalized: BlockId, ev: &mut FinalizationEvent) {
        ev.finalized = Some(finalized);
        self.highest_finalized_slot = self.highest_finalized_slot.max(finalized.slot);
        if let Some(parent) = self.parents.get(&finalized).copied() {
            self.handle_implicitly_finalized(finalized.slot, parent, ev);
        }
        self.prune();
    }

    fn prune(&mut self) {
        let mut next = self.first_unpruned_slot + 1;
        while let Some((s, _)) = self.status.get(&next) {
            let decided = matches!(
                s,
                FinStatus::Finalized
                    | FinStatus::ImplicitlyFinalized
                    | FinStatus::ImplicitlySkipped
            );
            if !decided {
                break;
            }
            self.first_unpruned_slot = next;
            next += 1;
        }
        let root = self.first_unpruned_slot;
        self.status.retain(|&slot, _| slot >= root);
        self.parents.retain(|k, _| k.slot >= root);
    }

    /// Record that `block`'s parent is `parent`. May trigger implicit
    /// finalization if `block` is already (implicitly) finalized.
    pub fn add_parent(&mut self, block: &BlockId, parent: &BlockId) -> FinalizationEvent {
        let mut ev = FinalizationEvent::default();
        assert!(block.slot > parent.slot);
        if block.slot < self.first_unpruned_slot {
            return ev;
        }
        if let Some(existing) = self.parents.get(block) {
            assert!(existing == parent, "conflicting parent");
            return ev;
        }
        self.parents.insert(*block, *parent);

        if let Some((status, hash)) = self.status.get(&block.slot).copied() {
            if matches!(status, FinStatus::Finalized | FinStatus::ImplicitlyFinalized)
                && hash == block.hash
            {
                self.handle_implicitly_finalized(block.slot, *parent, &mut ev);
                self.prune();
            }
        }
        ev
    }

    /// Mark `block` fast-finalized.
    pub fn mark_fast_finalized(&mut self, block: &BlockId) -> FinalizationEvent {
        let mut ev = FinalizationEvent::default();
        if block.slot < self.first_unpruned_slot {
            return ev;
        }
        let old = self.status_insert(block.slot, FinStatus::Finalized, block.hash);
        if let Some((old_status, old_hash)) = old {
            match old_status {
                FinStatus::Finalized | FinStatus::ImplicitlyFinalized => {
                    assert!(old_hash == block.hash, "consensus safety violation");
                    return ev;
                }
                FinStatus::Notarized => {
                    assert!(old_hash == block.hash, "consensus safety violation");
                }
                FinStatus::FinalPendingNotar => {}
                FinStatus::ImplicitlySkipped => panic!("consensus safety violation"),
            }
        }
        self.handle_finalized_block(*block, &mut ev);
        ev
    }

    /// Mark `block` notarized.
    pub fn mark_notarized(&mut self, block: &BlockId) -> FinalizationEvent {
        let mut ev = FinalizationEvent::default();
        if block.slot < self.first_unpruned_slot {
            return ev;
        }
        let old = self.status_insert(block.slot, FinStatus::Notarized, block.hash);
        let Some((old_status, old_hash)) = old else {
            return ev; // was vacant: just recorded Notarized
        };
        match old_status {
            FinStatus::Notarized | FinStatus::Finalized | FinStatus::ImplicitlyFinalized => {
                assert!(old_hash == block.hash, "consensus safety violation");
            }
            FinStatus::ImplicitlySkipped => {}
            FinStatus::FinalPendingNotar => {
                self.status_insert(block.slot, FinStatus::Finalized, block.hash);
                self.handle_finalized_block(*block, &mut ev);
            }
        }
        ev
    }

    /// Mark `slot` finalized (notarization cert may still be missing).
    pub fn mark_finalized(&mut self, slot: u64) -> FinalizationEvent {
        let mut ev = FinalizationEvent::default();
        if slot < self.first_unpruned_slot {
            return ev;
        }
        let old = self.status_insert(slot, FinStatus::FinalPendingNotar, GENESIS_BLOCK_HASH);
        let Some((old_status, old_hash)) = old else {
            return ev;
        };
        match old_status {
            FinStatus::FinalPendingNotar
            | FinStatus::Finalized
            | FinStatus::ImplicitlyFinalized => {}
            FinStatus::Notarized => {
                let block = BlockId::new(slot, old_hash);
                self.status_insert(slot, FinStatus::Finalized, old_hash);
                self.handle_finalized_block(block, &mut ev);
            }
            FinStatus::ImplicitlySkipped => panic!("consensus safety violation"),
        }
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_default() {
        let t = FinalityTracker::default();
        assert_eq!(t.highest_finalized_slot(), 0);
        assert_eq!(t.first_unpruned_slot(), 0);
        assert_eq!(
            t.status(0),
            Some((FinStatus::Notarized, GENESIS_BLOCK_HASH))
        );
    }

    #[test]
    fn notarize_then_finalize() {
        let mut t = FinalityTracker::default();
        let b = BlockId::new(1, [1u8; 32]);
        let ev = t.mark_notarized(&b);
        assert_eq!(ev, FinalizationEvent::default());
        assert_eq!(t.status(1).unwrap().0, FinStatus::Notarized);

        let ev = t.mark_finalized(1);
        assert_eq!(ev.finalized, Some(b));
        assert!(ev.implicitly_finalized.is_empty());
        assert_eq!(t.highest_finalized_slot(), 1);
        assert_eq!(t.first_unpruned_slot(), 1);
    }

    #[test]
    fn finalization_implicitly_finalizes_ancestor_and_skips_gap() {
        let mut t = FinalityTracker::default();
        let a = BlockId::new(1, [0xAu8; 32]);
        let c = BlockId::new(3, [0xCu8; 32]);
        // c's parent is a; slot 2 has no block.
        t.add_parent(&c, &a);
        t.mark_notarized(&a);
        t.mark_notarized(&c);

        let ev = t.mark_finalized(3);
        assert_eq!(ev.finalized, Some(c));
        assert_eq!(ev.implicitly_finalized, vec![a]);
        assert_eq!(ev.implicitly_skipped, vec![2]);
        assert_eq!(t.highest_finalized_slot(), 3);
        assert_eq!(t.first_unpruned_slot(), 3);
        // Pruned below root 3.
        assert!(t.status(1).is_none());
        assert!(t.status(2).is_none());
    }

    #[test]
    fn fast_finalize_records_and_prunes() {
        let mut t = FinalityTracker::default();
        let b = BlockId::new(1, [2u8; 32]);
        let ev = t.mark_fast_finalized(&b);
        assert_eq!(ev.finalized, Some(b));
        assert_eq!(t.status(1).unwrap().0, FinStatus::Finalized);
        assert_eq!(t.first_unpruned_slot(), 1);
    }

    #[test]
    fn stale_slot_below_watermark_is_ignored() {
        let mut t = FinalityTracker::default();
        // Contiguously finalize slots 1 then 2 so the watermark advances to 2.
        t.mark_fast_finalized(&BlockId::new(1, [1u8; 32]));
        t.mark_fast_finalized(&BlockId::new(2, [2u8; 32]));
        assert_eq!(t.first_unpruned_slot(), 2);
        // A notarization for slot 1 (below watermark) is a no-op and slot 1 is pruned.
        let ev = t.mark_notarized(&BlockId::new(1, [9u8; 32]));
        assert_eq!(ev, FinalizationEvent::default());
        assert!(t.status(1).is_none());
    }
}
