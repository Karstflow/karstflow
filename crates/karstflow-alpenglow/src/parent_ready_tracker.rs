//! Parent-ready tracker: tracks, across slots, which blocks are valid parents
//! for block production at window-start slots.
//!
//! Part of the Alpenglow consensus engine port. The parent-ready condition for a
//! window-start slot `s` and block `b` (with `s > slot(b)`): `b` is notarized
//! or notarized-fallback, and every slot in `(slot(b), s)` is skip-certified.
//! The reference's workspace pool/map become a `BTreeMap<slot, ParentReadyState>`.

use std::collections::BTreeMap;

use crate::base::{first_slot_in_window, is_start_of_window, BlockId};
use crate::parent_ready_state::ParentReadyState;

/// A newly-ready parent paired with the window-start slot it became valid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentReady {
    /// Window-start slot the parent became ready for.
    pub slot: u64,
    /// The parent block id.
    pub parent: BlockId,
}

/// Tracks the parent-ready condition across slots.
#[derive(Debug)]
pub struct ParentReadyTracker {
    root: u64,
    states: BTreeMap<u64, ParentReadyState>,
}

impl Default for ParentReadyTracker {
    /// Mirrors the Rust `Default`: only the genesis block is initially
    /// notarized-fallback, and root = genesis slot 0.
    fn default() -> Self {
        let mut states = BTreeMap::new();
        states.insert(0, ParentReadyState::genesis(0));
        Self { root: 0, states }
    }
}

impl ParentReadyTracker {
    /// An empty tracker (no genesis seeding), root 0.
    pub fn new_empty() -> Self {
        Self {
            root: 0,
            states: BTreeMap::new(),
        }
    }

    /// Lowest slot still tracked.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Per-slot state, lazily created with the default value if absent.
    pub fn slot_state(&mut self, slot: u64) -> &mut ParentReadyState {
        self.states
            .entry(slot)
            .or_insert_with(|| ParentReadyState::new(slot))
    }

    /// Mark `id`'s block notarized-fallback; returns the parents that became
    /// ready (one per skip-connected future window start).
    pub fn mark_notar_fallback(&mut self, id: &BlockId) -> Vec<ParentReady> {
        let mut out = Vec::new();
        let slot = id.slot;
        if slot < self.root {
            return out;
        }
        if !self.slot_state(slot).mark_notar_fallback(&id.hash) {
            return out;
        }

        let mut s = slot + 1;
        loop {
            let fstate = self.slot_state(s);
            if is_start_of_window(s) {
                fstate.add_to_ready(id);
                out.push(ParentReady {
                    slot: s,
                    parent: *id,
                });
            }
            if !self.slot_state(s).is_skip_certified() {
                break;
            }
            s += 1;
        }
        out
    }

    /// Mark `marked_slot` skipped; returns parents that became ready for
    /// skip-connected future windows.
    pub fn mark_skipped(&mut self, marked_slot: u64) -> Vec<ParentReady> {
        let mut out = Vec::new();
        if marked_slot < self.root {
            return out;
        }
        if !self.slot_state(marked_slot).mark_skip() {
            return out;
        }

        // Gather potential parents going backward through the window.
        let mut potential: Vec<BlockId> = Vec::new();
        let root = self.root;
        let first = first_slot_in_window(marked_slot);
        let mut s = marked_slot;
        loop {
            if s >= first && s <= marked_slot && s >= root {
                let sstate = self.slot_state(s);
                if s != marked_slot {
                    for h in sstate.notar_fallback_blocks() {
                        potential.push(BlockId::new(s, *h));
                    }
                }
                let skip = self.slot_state(s).is_skip_certified();
                if !skip {
                    break;
                }
                let readies: Vec<BlockId> = self.slot_state(s).ready_block_ids().to_vec();
                potential.extend(readies);
            }
            if s == 0 || s < first || s < root {
                break;
            }
            s -= 1;
        }

        // Add them to skip-connected future windows.
        let mut s = marked_slot + 1;
        loop {
            if is_start_of_window(s) {
                for p in &potential {
                    self.slot_state(s).add_to_ready(p);
                    out.push(ParentReady {
                        slot: s,
                        parent: *p,
                    });
                }
            }
            if !self.slot_state(s).is_skip_certified() {
                break;
            }
            s += 1;
        }
        out
    }

    /// Handle a finalization: marks the finalized / implicitly-finalized blocks
    /// notar-fallback and the implicitly-skipped slots skipped, returning at
    /// most the single highest-slot parent that became ready.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_finalization(
        &mut self,
        finalized: Option<&BlockId>,
        implicitly_finalized: &[BlockId],
        implicitly_skipped: &[u64],
    ) -> Option<ParentReady> {
        let mut best: Option<ParentReady> = None;
        let consider = |v: Vec<ParentReady>, best: &mut Option<ParentReady>| {
            for pr in v {
                if best.map(|b| pr.slot > b.slot).unwrap_or(true) {
                    *best = Some(pr);
                }
            }
        };
        if let Some(f) = finalized {
            consider(self.mark_notar_fallback(f), &mut best);
        }
        for f in implicitly_finalized {
            consider(self.mark_notar_fallback(f), &mut best);
        }
        for &s in implicitly_skipped {
            consider(self.mark_skipped(s), &mut best);
        }
        best
    }

    /// The currently valid parents for `slot` (no lazy creation).
    pub fn parents_ready(&self, slot: u64) -> &[BlockId] {
        self.states
            .get(&slot)
            .map(|s| s.ready_block_ids())
            .unwrap_or(&[])
    }

    /// Request a valid parent for `slot` (lazy-creates the slot state).
    pub fn wait_for_parent_ready(&mut self, slot: u64) -> Option<BlockId> {
        self.slot_state(slot).wait_for_parent_ready()
    }

    /// Drop all slots below `new_root`.
    pub fn prune(&mut self, new_root: u64) {
        self.root = new_root;
        self.states.retain(|&s, _| s >= new_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notar_fallback_connects_next_window() {
        // SLOTS_PER_WINDOW = 4 → window starts at 0,4,8,... A block at slot 3
        // (the slot immediately before window-start 4, no intervening slots)
        // becomes a ready parent for slot 4.
        let mut t = ParentReadyTracker::default();
        let id = BlockId::new(3, [7u8; 32]);
        let ready = t.mark_notar_fallback(&id);
        assert!(ready.iter().any(|p| p.slot == 4 && p.parent == id));
        assert!(t.parents_ready(4).contains(&id));
    }

    #[test]
    fn skip_connects_earlier_parent_across_window() {
        // Skip slot 3, then a notar-fallback block at slot 2 connects to
        // window-start 4 (slot 3 between them is skip-certified).
        let mut t = ParentReadyTracker::default();
        t.mark_skipped(3);
        let id = BlockId::new(2, [9u8; 32]);
        let ready = t.mark_notar_fallback(&id);
        assert!(ready.iter().any(|p| p.slot == 4 && p.parent == id));
    }

    #[test]
    fn duplicate_notar_fallback_noop() {
        let mut t = ParentReadyTracker::default();
        let id = BlockId::new(3, [7u8; 32]);
        assert!(!t.mark_notar_fallback(&id).is_empty());
        assert!(t.mark_notar_fallback(&id).is_empty());
    }

    #[test]
    fn prune_drops_old_slots() {
        let mut t = ParentReadyTracker::default();
        t.mark_notar_fallback(&BlockId::new(3, [1u8; 32]));
        t.prune(4);
        assert_eq!(t.root(), 4);
        assert!(t.parents_ready(3).is_empty());
    }

    #[test]
    fn wait_for_parent_ready_reports_min() {
        let mut t = ParentReadyTracker::default();
        let id = BlockId::new(3, [5u8; 32]);
        t.mark_notar_fallback(&id);
        assert_eq!(t.wait_for_parent_ready(4), Some(id));
        // A slot with no ready parents returns None.
        assert_eq!(t.wait_for_parent_ready(6), None);
    }
}
