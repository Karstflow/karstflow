//! Votor: the per-slot voting decision process (when to cast notar / skip /
//! notar-fallback / skip-fallback / final votes).
//!
//! Part of the Alpenglow consensus engine port. The reference's async task
//! (tokio channels + spawned timers + broadcast) is collapsed: handlers are
//! called directly and
//! append outgoing votes/certs and timeouts-to-schedule to a [`VotorOut`]
//! buffer; the embedding tile owns the wall-clock and feeds fired timeouts back
//! into [`Votor::handle_timeout_event`]. The slot map is a `BTreeMap`.

use std::collections::BTreeMap;

use crate::aggsig::SecretKey;
use crate::base::{
    first_slot_in_window, is_start_of_window, last_slot_in_window, BlockHash, BlockId,
    GENESIS_BLOCK_HASH,
};
use crate::cert::Cert;
use crate::vote::Vote;

/// A consensus message Votor broadcasts: a single vote or a single cert.
///
/// The `Cert` variant is intrinsically much larger than `Vote` (it carries
/// aggregate signatures + signer bitmasks); this matches the reference wire
/// shape, so the size difference is accepted rather than boxed.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusMessage {
    /// A vote.
    Vote(Vote),
    /// A certificate.
    Cert(Cert),
}

/// An internal timeout Votor schedules for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VotorTimeout {
    /// Regular per-slot timeout.
    Timeout(u64),
    /// Early crashed-leader timeout.
    CrashedLeader(u64),
}

impl VotorTimeout {
    /// The slot this timeout is for.
    pub fn slot(&self) -> u64 {
        match self {
            VotorTimeout::Timeout(s) | VotorTimeout::CrashedLeader(s) => *s,
        }
    }
}

/// Pool events Votor consumes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum VotorPoolEvent {
    /// A new valid parent for `slot` is ready.
    ParentReady {
        /// The slot.
        slot: u64,
        /// The ready parent.
        parent: BlockId,
    },
    /// Safe to notar-fallback for the given block.
    SafeToNotar(BlockId),
    /// Safe to skip-fallback for the slot.
    SafeToSkip(u64),
    /// A new certificate was created.
    CertCreated(Cert),
    /// Recovery bundle (certs then votes) to re-broadcast.
    Standstill {
        /// The slot.
        slot: u64,
        /// Messages to re-broadcast in order.
        bundle: Vec<ConsensusMessage>,
    },
}

/// Blockstore events Votor consumes.
#[derive(Clone, Copy, Debug)]
pub enum VotorBlockstoreEvent {
    /// First shred for the slot received.
    FirstShred(u64),
    /// Leader produced an invalid block for the slot.
    InvalidBlock(u64),
    /// A complete valid block is available.
    Block {
        /// The block's slot.
        slot: u64,
        /// The block id.
        block_id: BlockId,
        /// The parent block id.
        parent_block_id: BlockId,
    },
}

/// Output buffer the handlers append to.
#[derive(Default, Debug)]
pub struct VotorOut {
    /// Votes/certs to broadcast, in emission order.
    pub msgs: Vec<ConsensusMessage>,
    /// Timeouts to schedule.
    pub timeouts: Vec<VotorTimeout>,
}

#[derive(Default, Clone)]
struct VotorSlotState {
    voted: bool,
    voted_notar: Option<BlockHash>,
    bad_window: bool,
    block_notarized: Option<BlockHash>,
    parents_ready: Vec<BlockId>,
    received_shred: bool,
    pending_block: Option<(BlockId, BlockId)>, // (block_id, parent_block_id)
    retired: bool,
}

/// The voting decision engine.
pub struct Votor {
    slots: BTreeMap<u64, VotorSlotState>,
    validator_index: u16,
    voting_key: SecretKey,
    highest_final_cert_slot: u64,
}

impl Votor {
    /// Construct a Votor, pre-populating the genesis slot state and emitting the
    /// genesis window's timeouts (mirrors `Votor::new`, which calls
    /// `set_timeouts(0)`).
    pub fn new(validator_index: u16, voting_key: SecretKey) -> (Self, VotorOut) {
        let mut v = Self {
            slots: BTreeMap::new(),
            validator_index,
            voting_key,
            highest_final_cert_slot: 0,
        };
        let g = v.slot_state_mut(0);
        g.voted = true;
        g.voted_notar = Some(GENESIS_BLOCK_HASH);
        g.block_notarized = Some(GENESIS_BLOCK_HASH);
        g.parents_ready.push(BlockId::genesis(0));
        g.retired = true;

        let mut out = VotorOut::default();
        v.set_timeouts(0, &mut out);
        (v, out)
    }

    /// Our own validator index.
    pub fn validator_index(&self) -> u16 {
        self.validator_index
    }
    /// Highest slot for which a (fast-)final cert has been seen.
    pub fn highest_final_cert_slot(&self) -> u64 {
        self.highest_final_cert_slot
    }

    fn slot_state_mut(&mut self, slot: u64) -> &mut VotorSlotState {
        self.slots.entry(slot).or_default()
    }

    fn is_retired(&self, slot: u64) -> bool {
        self.slots.get(&slot).map(|s| s.retired).unwrap_or(false)
    }
    fn has_voted(&self, slot: u64) -> bool {
        self.slots.get(&slot).map(|s| s.voted).unwrap_or(false)
    }
    fn received_shred(&self, slot: u64) -> bool {
        self.slots
            .get(&slot)
            .map(|s| s.received_shred)
            .unwrap_or(false)
    }

    fn first_unpruned_slot(&self) -> u64 {
        first_slot_in_window(self.highest_final_cert_slot)
    }

    fn set_timeouts(&mut self, slot: u64, out: &mut VotorOut) {
        assert!(is_start_of_window(slot));
        out.timeouts.push(VotorTimeout::CrashedLeader(slot));
        let last = last_slot_in_window(slot);
        for s in slot..=last {
            out.timeouts.push(VotorTimeout::Timeout(s));
        }
    }

    fn try_final(&mut self, slot: u64, hash: &BlockHash, out: &mut VotorOut) {
        assert!(slot >= self.first_unpruned_slot());
        let (notarized, voted_notar, not_bad) = match self.slots.get(&slot) {
            Some(s) => (
                s.block_notarized.as_ref() == Some(hash),
                s.voted_notar.as_ref() == Some(hash),
                !s.bad_window,
            ),
            None => (false, false, true),
        };
        if notarized && voted_notar && not_bad {
            let vote = Vote::new_final(slot, &self.voting_key, self.validator_index);
            out.msgs.push(ConsensusMessage::Vote(vote));
            self.slot_state_mut(slot).retired = true;
        }
    }

    fn try_notar(
        &mut self,
        slot: u64,
        block_id: &BlockId,
        parent_block_id: &BlockId,
        out: &mut VotorOut,
    ) -> bool {
        assert!(slot >= self.first_unpruned_slot());
        let first_slot = first_slot_in_window(slot);

        if slot == first_slot {
            let valid_parent = self
                .slots
                .get(&slot)
                .map(|s| s.parents_ready.contains(parent_block_id))
                .unwrap_or(false);
            if !valid_parent {
                return false;
            }
        } else {
            if parent_block_id.slot != slot - 1 {
                return false;
            }
            let matches = self
                .slots
                .get(&parent_block_id.slot)
                .map(|ps| ps.voted_notar.as_ref() == Some(&parent_block_id.hash))
                .unwrap_or(false);
            if !matches {
                return false;
            }
        }

        let vote = Vote::new_notar(slot, &block_id.hash, &self.voting_key, self.validator_index);
        out.msgs.push(ConsensusMessage::Vote(vote));

        let state = self.slot_state_mut(slot);
        state.voted = true;
        state.voted_notar = Some(block_id.hash);
        state.pending_block = None;

        self.try_final(slot, &block_id.hash, out);
        true
    }

    fn try_skip_window(&mut self, slot: u64, out: &mut VotorOut) {
        assert!(slot >= self.first_unpruned_slot());
        let first = first_slot_in_window(slot);
        let last = last_slot_in_window(slot);
        for s in first..=last {
            if self.has_voted(s) {
                continue;
            }
            let state = self.slot_state_mut(s);
            state.voted = true;
            state.bad_window = true;
            let vote = Vote::new_skip(s, &self.voting_key, self.validator_index);
            out.msgs.push(ConsensusMessage::Vote(vote));
        }
    }

    fn check_pending_blocks(&mut self, out: &mut VotorOut) {
        let pending: Vec<(u64, BlockId, BlockId)> = self
            .slots
            .iter()
            .filter_map(|(&slot, s)| s.pending_block.map(|(b, p)| (slot, b, p)))
            .collect();
        for (slot, block_id, parent_block_id) in pending {
            self.try_notar(slot, &block_id, &parent_block_id, out);
        }
    }

    fn prune(&mut self) {
        let cutoff = self.first_unpruned_slot();
        self.slots.retain(|&slot, _| slot >= cutoff);
    }

    fn handle_cert_created(&mut self, cert: &Cert, out: &mut VotorOut) {
        match cert {
            Cert::Notar(_) => {
                let slot = cert.slot();
                let hash = *cert.block_hash().expect("notar cert has a block hash");
                let s = self.slot_state_mut(slot);
                s.block_notarized = Some(hash);
                self.try_final(slot, &hash, out);
            }
            Cert::Final(_) | Cert::FastFinal(_) => {
                let slot = cert.slot();
                self.set_timeouts(first_slot_in_window(slot), out);
                self.highest_final_cert_slot = self.highest_final_cert_slot.max(slot);
                self.prune();
            }
            _ => {}
        }
        out.msgs.push(ConsensusMessage::Cert(*cert));
    }

    fn should_ignore_pool_event(&self, event: &VotorPoolEvent) -> bool {
        match event {
            VotorPoolEvent::Standstill { .. } => false,
            VotorPoolEvent::CertCreated(c) => c.slot() < self.first_unpruned_slot(),
            VotorPoolEvent::ParentReady { slot, .. } => {
                *slot < self.first_unpruned_slot() || self.is_retired(*slot)
            }
            VotorPoolEvent::SafeToNotar(b) => {
                b.slot < self.first_unpruned_slot() || self.is_retired(b.slot)
            }
            VotorPoolEvent::SafeToSkip(slot) => {
                *slot < self.first_unpruned_slot() || self.is_retired(*slot)
            }
        }
    }

    /// Handle a pool event (mirrors `Votor::handle_pool_event`).
    pub fn handle_pool_event(&mut self, event: &VotorPoolEvent, out: &mut VotorOut) {
        if self.should_ignore_pool_event(event) {
            return;
        }
        match event {
            VotorPoolEvent::ParentReady { slot, parent } => {
                let s = self.slot_state_mut(*slot);
                if !s.parents_ready.contains(parent) {
                    s.parents_ready.push(*parent);
                }
                self.check_pending_blocks(out);
                self.set_timeouts(*slot, out);
            }
            VotorPoolEvent::SafeToNotar(blk) => {
                let vote = Vote::new_notar_fallback(
                    blk.slot,
                    &blk.hash,
                    &self.voting_key,
                    self.validator_index,
                );
                out.msgs.push(ConsensusMessage::Vote(vote));
                self.try_skip_window(blk.slot, out);
                self.slot_state_mut(blk.slot).bad_window = true;
            }
            VotorPoolEvent::SafeToSkip(slot) => {
                let vote = Vote::new_skip_fallback(*slot, &self.voting_key, self.validator_index);
                out.msgs.push(ConsensusMessage::Vote(vote));
                self.try_skip_window(*slot, out);
                self.slot_state_mut(*slot).bad_window = true;
            }
            VotorPoolEvent::CertCreated(cert) => self.handle_cert_created(cert, out),
            VotorPoolEvent::Standstill { bundle, .. } => {
                for m in bundle {
                    out.msgs.push(*m);
                }
            }
        }
    }

    /// Handle a blockstore event (mirrors `Votor::handle_blockstore_event`).
    pub fn handle_blockstore_event(&mut self, event: &VotorBlockstoreEvent, out: &mut VotorOut) {
        let slot = match event {
            VotorBlockstoreEvent::FirstShred(s) | VotorBlockstoreEvent::InvalidBlock(s) => *s,
            VotorBlockstoreEvent::Block { slot, .. } => *slot,
        };
        if slot <= self.highest_final_cert_slot || self.is_retired(slot) {
            return;
        }
        match event {
            VotorBlockstoreEvent::FirstShred(_) => {
                self.slot_state_mut(slot).received_shred = true;
            }
            VotorBlockstoreEvent::InvalidBlock(_) => {
                self.try_skip_window(slot, out);
            }
            VotorBlockstoreEvent::Block {
                block_id,
                parent_block_id,
                ..
            } => {
                if self.has_voted(slot) {
                    return;
                }
                if self.try_notar(slot, block_id, parent_block_id, out) {
                    self.check_pending_blocks(out);
                } else {
                    let s = self.slot_state_mut(slot);
                    s.pending_block = Some((*block_id, *parent_block_id));
                }
            }
        }
    }

    /// Handle a timeout event (mirrors `Votor::handle_timeout_event`).
    pub fn handle_timeout_event(&mut self, event: &VotorTimeout, out: &mut VotorOut) {
        let slot = event.slot();
        if slot <= self.highest_final_cert_slot || self.is_retired(slot) {
            return;
        }
        match event {
            VotorTimeout::Timeout(_) => {
                if !self.has_voted(slot) {
                    self.try_skip_window(slot, out);
                }
            }
            VotorTimeout::CrashedLeader(_) => {
                if !self.received_shred(slot) && !self.has_voted(slot) {
                    self.try_skip_window(slot, out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey([3u8; 32])
    }

    #[test]
    fn new_emits_genesis_window_timeouts() {
        let (_v, out) = Votor::new(0, key());
        // CrashedLeader(0) + Timeout(0..=3) = 5 timeouts.
        assert_eq!(out.timeouts.len(), 5);
        assert_eq!(out.timeouts[0], VotorTimeout::CrashedLeader(0));
        assert_eq!(out.timeouts[1], VotorTimeout::Timeout(0));
        assert_eq!(out.timeouts[4], VotorTimeout::Timeout(3));
    }

    #[test]
    fn parent_ready_then_block_casts_notar() {
        let (mut v, _) = Votor::new(0, key());
        let parent = BlockId::new(3, [3u8; 32]);
        let mut out = VotorOut::default();
        v.handle_pool_event(&VotorPoolEvent::ParentReady { slot: 4, parent }, &mut out);

        let mut out = VotorOut::default();
        let block = BlockId::new(4, [4u8; 32]);
        v.handle_blockstore_event(
            &VotorBlockstoreEvent::Block {
                slot: 4,
                block_id: block,
                parent_block_id: parent,
            },
            &mut out,
        );
        let notar = out.msgs.iter().any(|m| {
            matches!(
                m,
                ConsensusMessage::Vote(Vote::Notar(n)) if n.slot == 4
            )
        });
        assert!(notar, "expected a notar vote for slot 4");
    }

    #[test]
    fn block_without_parent_ready_is_pending_not_voted() {
        let (mut v, _) = Votor::new(0, key());
        let mut out = VotorOut::default();
        // Slot 4 is a window start; no ParentReady issued → block becomes pending.
        v.handle_blockstore_event(
            &VotorBlockstoreEvent::Block {
                slot: 4,
                block_id: BlockId::new(4, [4u8; 32]),
                parent_block_id: BlockId::new(3, [3u8; 32]),
            },
            &mut out,
        );
        assert!(out.msgs.is_empty());
        assert!(!v.has_voted(4));
    }

    #[test]
    fn timeout_skips_unvoted_window() {
        let (mut v, _) = Votor::new(0, key());
        let mut out = VotorOut::default();
        // Timeout for slot 1: window [0..3]; slot 0 is the genesis (voted), so
        // slots 1,2,3 get skip votes.
        v.handle_timeout_event(&VotorTimeout::Timeout(1), &mut out);
        let skips = out
            .msgs
            .iter()
            .filter(|m| matches!(m, ConsensusMessage::Vote(Vote::Skip(_))))
            .count();
        assert_eq!(skips, 3);
    }

    #[test]
    fn invalid_block_skips_window() {
        let (mut v, _) = Votor::new(0, key());
        let mut out = VotorOut::default();
        v.handle_blockstore_event(&VotorBlockstoreEvent::InvalidBlock(5), &mut out);
        let skips = out
            .msgs
            .iter()
            .filter(|m| matches!(m, ConsensusMessage::Vote(Vote::Skip(_))))
            .count();
        // Window [4..7], none voted → 4 skip votes.
        assert_eq!(skips, 4);
    }
}
