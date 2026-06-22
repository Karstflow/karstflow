//! Pool: the central consensus data structure (the Rust `PoolImpl`).
//!
//! Port of the reference `consensus/fd_pool.{h,c}` (mirrors `pool.rs`).
//! Received votes/certs are placed into the pool, which tracks per-slot status,
//! drives the finality and parent-ready trackers, and emits events to Votor and
//! repair requests. The reference's wksp pools/maps become `HashMap`s; the
//! Rust mpsc channels become a [`PoolOut`] buffer. Events are typed as
//! [`VotorPoolEvent`] so they can be fed straight into [`crate::votor::Votor`].

use std::collections::HashMap;

use crate::base::{is_start_of_window, BlockId, SLOTS_PER_EPOCH};
use crate::cert::Cert;
use crate::epoch_info::EpochInfo;
use crate::finality_tracker::{FinalityTracker, FinalizationEvent};
use crate::parent_ready_tracker::{ParentReady, ParentReadyTracker};
use crate::slot_state::{
    NotifyParent, PoolEvent as SsEvent, Slashable, SlotState, SlotStateOutputs,
};
use crate::vote::Vote;
use crate::votor::VotorPoolEvent;

/// Errors from [`Pool::add_vote`] / [`Pool::add_cert`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    /// Slot is below the watermark or far in the future.
    SlotOutOfBounds,
    /// Vote signer is outside the current epoch's validator set.
    UnknownSigner,
    /// Signature verification failed.
    InvalidSignature,
    /// A benign duplicate.
    Duplicate,
    /// A slashable offence (carries the detail).
    Slashable(Slashable),
    /// Certificate stake threshold not met.
    ThresholdNotMet,
}

/// Output sink: votor-bound events + repair requests.
#[derive(Default, Debug)]
pub struct PoolOut {
    /// Events to deliver to Votor.
    pub events: Vec<VotorPoolEvent>,
    /// Blocks to repair.
    pub repairs: Vec<BlockId>,
}

/// A standstill-recovery bundle to re-broadcast.
#[derive(Default, Debug)]
pub struct RecoveryBundle {
    /// The standstill slot (`finalized_slot + 1`).
    pub slot: u64,
    /// Certificates to re-broadcast.
    pub certs: Vec<Cert>,
    /// Own votes to re-broadcast.
    pub votes: Vec<Vote>,
}

#[derive(Default)]
struct Recorded {
    notar: Option<Cert>,
    skip: Option<Cert>,
    fast_finalize: Option<Cert>,
    finalize: Option<Cert>,
    nf: Vec<Cert>,
    own: Vec<Vote>,
}

/// The central consensus pool.
pub struct Pool {
    epoch_info: EpochInfo,
    own_id: u64,
    slot_states: HashMap<u64, SlotState>,
    recorded: HashMap<u64, Recorded>,
    s2n_waiting: HashMap<BlockId, BlockId>, // parent -> child
    finality: FinalityTracker,
    parent_ready: ParentReadyTracker,
}

impl Pool {
    /// Construct an empty pool over `epoch_info`'s validator set, owned by
    /// `own_id`. Genesis-default finality + parent-ready trackers.
    pub fn new(own_id: u64, epoch_info: EpochInfo) -> Self {
        Self {
            epoch_info,
            own_id,
            slot_states: HashMap::new(),
            recorded: HashMap::new(),
            s2n_waiting: HashMap::new(),
            finality: FinalityTracker::default(),
            parent_ready: ParentReadyTracker::default(),
        }
    }

    /// Highest finalized slot.
    pub fn finalized_slot(&self) -> u64 {
        self.finality.highest_finalized_slot()
    }
    /// Lowest slot still tracked.
    pub fn first_unpruned_slot(&self) -> u64 {
        self.finality.first_unpruned_slot()
    }
    /// Valid parents currently ready for `slot`.
    pub fn parents_ready(&self, slot: u64) -> &[BlockId] {
        self.parent_ready.parents_ready(slot)
    }

    fn slot_state(&mut self, slot: u64) -> &mut SlotState {
        let own = self.own_id;
        self.slot_states
            .entry(slot)
            .or_insert_with(|| SlotState::new(slot, own))
    }

    fn send_parent_ready(out: &mut PoolOut, pr: Option<ParentReady>) {
        if let Some(pr) = pr {
            debug_assert!(is_start_of_window(pr.slot));
            out.events.push(VotorPoolEvent::ParentReady {
                slot: pr.slot,
                parent: pr.parent,
            });
        }
    }

    fn handle_finalization(&mut self, fe: &FinalizationEvent, out: &mut PoolOut) {
        let pr = self.parent_ready.handle_finalization(
            fe.finalized.as_ref(),
            &fe.implicitly_finalized,
            &fe.implicitly_skipped,
        );
        Self::send_parent_ready(out, pr);
        self.prune();
    }

    fn prune(&mut self) {
        let first_unpruned = self.finality.first_unpruned_slot();
        self.slot_states.retain(|&s, _| s >= first_unpruned);
        self.recorded.retain(|&s, _| s >= first_unpruned);
        self.parent_ready.prune(first_unpruned);
    }

    fn record_cert(&mut self, slot: u64, cert: &Cert) {
        let r = self.recorded.entry(slot).or_default();
        match cert {
            Cert::Notar(_) => r.notar = Some(*cert),
            Cert::Skip(_) => r.skip = Some(*cert),
            Cert::FastFinal(_) => r.fast_finalize = Some(*cert),
            Cert::Final(_) => r.finalize = Some(*cert),
            Cert::NotarFallback(c) => {
                if !r
                    .nf
                    .iter()
                    .any(|e| matches!(e, Cert::NotarFallback(x) if x.block_hash == c.block_hash))
                {
                    r.nf.push(*cert);
                }
            }
        }
    }

    fn add_valid_cert(&mut self, cert: &Cert, out: &mut PoolOut) {
        let slot = cert.slot();
        self.slot_state(slot).add_cert(cert);
        self.record_cert(slot, cert);

        match cert {
            Cert::Notar(_) | Cert::NotarFallback(_) => {
                let block_id = BlockId::new(slot, *cert.block_hash().unwrap());
                if matches!(cert, Cert::Notar(_)) {
                    let fe = self.finality.mark_notarized(&block_id);
                    self.handle_finalization(&fe, out);
                }
                // Notify a child waiting for this block's safe-to-notar.
                if let Some(child) = self.s2n_waiting.remove(&block_id) {
                    let ei = self.epoch_info.clone();
                    let r = self
                        .slot_state(child.slot)
                        .notify_parent_certified(&child.hash, &ei);
                    Self::push_notify(out, r);
                }
                let pr = self.parent_ready.mark_notar_fallback(&block_id);
                for p in pr {
                    out.events.push(VotorPoolEvent::ParentReady {
                        slot: p.slot,
                        parent: p.parent,
                    });
                }
                out.repairs.push(block_id);
            }
            Cert::Skip(_) => {
                let pr = self.parent_ready.mark_skipped(slot);
                for p in pr {
                    out.events.push(VotorPoolEvent::ParentReady {
                        slot: p.slot,
                        parent: p.parent,
                    });
                }
            }
            Cert::FastFinal(_) => {
                let block_id = BlockId::new(slot, *cert.block_hash().unwrap());
                let fe = self.finality.mark_fast_finalized(&block_id);
                self.handle_finalization(&fe, out);
            }
            Cert::Final(_) => {
                let fe = self.finality.mark_finalized(slot);
                self.handle_finalization(&fe, out);
            }
        }
        out.events.push(VotorPoolEvent::CertCreated(*cert));
    }

    fn push_notify(out: &mut PoolOut, r: NotifyParent) {
        match r {
            NotifyParent::Event(SsEvent::SafeToNotar(b)) => {
                out.events.push(VotorPoolEvent::SafeToNotar(b))
            }
            NotifyParent::Event(SsEvent::SafeToSkip(s)) => {
                out.events.push(VotorPoolEvent::SafeToSkip(s))
            }
            NotifyParent::Repair(b) => out.repairs.push(b),
            NotifyParent::None => {}
        }
    }

    fn slot_in_bounds(&self, slot: u64) -> bool {
        let far = self.finalized_slot() + 2 * SLOTS_PER_EPOCH;
        slot >= self.first_unpruned_slot() && slot < far
    }

    /// Add a certificate. Mirrors `PoolImpl::add_cert`.
    pub fn add_cert(&mut self, cert: &Cert, out: &mut PoolOut) -> Result<(), AddError> {
        let slot = cert.slot();
        if !self.slot_in_bounds(slot) {
            return Err(AddError::SlotOutOfBounds);
        }
        if !cert.check_threshold(&self.epoch_info) {
            return Err(AddError::ThresholdNotMet);
        }
        let ei = self.epoch_info.clone();
        if !cert.check_sig(ei.validators()) {
            return Err(AddError::InvalidSignature);
        }
        let ss = self.slot_state(slot);
        let duplicate = match cert {
            Cert::Notar(_) => ss.has_notar_cert(),
            Cert::NotarFallback(c) => ss.is_notar_fallback(&c.block_hash),
            Cert::Skip(_) => ss.has_skip_cert(),
            Cert::FastFinal(_) => ss.has_fast_finalize_cert(),
            Cert::Final(_) => ss.has_finalize_cert(),
        };
        if duplicate {
            return Err(AddError::Duplicate);
        }
        self.add_valid_cert(cert, out);
        Ok(())
    }

    /// Add a vote. Mirrors `PoolImpl::add_vote`.
    pub fn add_vote(&mut self, vote: &Vote, out: &mut PoolOut) -> Result<(), AddError> {
        let slot = vote.slot();
        if !self.slot_in_bounds(slot) {
            return Err(AddError::SlotOutOfBounds);
        }
        let signer = vote.signer() as u64;
        if signer >= self.epoch_info.validator_cnt() {
            return Err(AddError::UnknownSigner);
        }
        let v = *self.epoch_info.validator(signer);
        if !vote.check_sig(&v.voting_pubkey) {
            return Err(AddError::InvalidSignature);
        }
        let voter_stake = v.stake;
        let ei = self.epoch_info.clone();

        let ss = self.slot_state(slot);
        if let Some(off) = ss.check_slashable_offence(vote) {
            return Err(AddError::Slashable(off));
        }
        if ss.should_ignore_vote(vote) {
            return Err(AddError::Duplicate);
        }

        let mut so = SlotStateOutputs::default();
        self.slot_state(slot)
            .add_vote(vote, voter_stake, &ei, &mut so);

        if signer == self.own_id {
            self.recorded.entry(slot).or_default().own.push(*vote);
        }

        for ev in so.events {
            match ev {
                SsEvent::SafeToNotar(b) => out.events.push(VotorPoolEvent::SafeToNotar(b)),
                SsEvent::SafeToSkip(s) => out.events.push(VotorPoolEvent::SafeToSkip(s)),
            }
        }
        out.repairs.extend(so.repairs);
        for cert in so.certs {
            self.add_valid_cert(&cert, out);
        }
        Ok(())
    }

    /// Register a block with its parent. Mirrors `PoolImpl::add_block`.
    pub fn add_block(&mut self, block_id: &BlockId, parent_id: &BlockId, out: &mut PoolOut) {
        assert!(block_id.slot > parent_id.slot);
        let fe = self.finality.add_parent(block_id, parent_id);
        self.handle_finalization(&fe, out);

        let ei = self.epoch_info.clone();
        self.slot_state(block_id.slot)
            .notify_parent_known(&block_id.hash);

        let parent_is_nf = self
            .slot_states
            .get(&parent_id.slot)
            .map(|ps| ps.is_notar_fallback(&parent_id.hash))
            .unwrap_or(false);
        if parent_is_nf {
            let r = self
                .slot_state(block_id.slot)
                .notify_parent_certified(&block_id.hash, &ei);
            Self::push_notify(out, r);
            return;
        }
        // Park the child waiting for the parent's cert.
        self.s2n_waiting.insert(*parent_id, *block_id);
    }

    /// Build the standstill-recovery bundle. Mirrors
    /// `PoolImpl::recover_from_standstill`. Panics if no final cert exists for
    /// the finalized slot.
    pub fn recover_from_standstill(&mut self, out: &mut PoolOut) -> RecoveryBundle {
        let slot = self.finalized_slot();
        let mut bundle = RecoveryBundle {
            slot: slot + 1,
            ..Default::default()
        };

        if let Some(r) = self.recorded.get(&slot) {
            if let Some(c) = r.fast_finalize {
                bundle.certs.push(c);
            } else if let (Some(f), Some(n)) = (r.finalize, r.notar) {
                bundle.certs.push(f);
                bundle.certs.push(n);
            }
        }
        assert!(!bundle.certs.is_empty(), "no final cert");

        for (&s, r) in self.recorded.iter() {
            if s <= slot {
                continue;
            }
            if let Some(c) = r.finalize {
                bundle.certs.push(c);
            }
            if let Some(c) = r.fast_finalize {
                bundle.certs.push(c);
            }
            if let Some(c) = r.notar {
                bundle.certs.push(c);
            }
            bundle.certs.extend(r.nf.iter().copied());
            if let Some(c) = r.skip {
                bundle.certs.push(c);
            }
            bundle.votes.extend(r.own.iter().copied());
        }

        out.events.push(VotorPoolEvent::Standstill {
            slot: slot + 1,
            bundle: Vec::new(),
        });
        bundle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggsig::SecretKey;
    use crate::epoch_info::test_epoch;
    use crate::vote::Vote;

    fn sk(seed: u8) -> SecretKey {
        SecretKey([seed; 32])
    }

    #[test]
    fn add_vote_to_quorum_emits_cert_created() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]); // 100, quorum 60
        let mut pool = Pool::new(0, ei);
        let h = [9u8; 32];
        let mut cert_created = false;
        for i in 0..3u16 {
            let v = Vote::new_notar(4, &h, &sk(i as u8), i);
            let mut out = PoolOut::default();
            pool.add_vote(&v, &mut out).unwrap();
            if out
                .events
                .iter()
                .any(|e| matches!(e, VotorPoolEvent::CertCreated(_)))
            {
                cert_created = true;
            }
        }
        assert!(cert_created, "reaching quorum must emit CertCreated");
    }

    #[test]
    fn slashable_vote_rejected() {
        let ei = test_epoch(&[20, 20, 20]);
        let mut pool = Pool::new(0, ei);
        let mut out = PoolOut::default();
        pool.add_vote(&Vote::new_skip(4, &sk(1), 1), &mut out)
            .unwrap();
        // Same validator now notarizes the slot → SkipAndNotarize.
        let err = pool
            .add_vote(&Vote::new_notar(4, &[1u8; 32], &sk(1), 1), &mut out)
            .unwrap_err();
        assert!(matches!(err, AddError::Slashable(_)));
    }

    #[test]
    fn duplicate_vote_rejected() {
        let ei = test_epoch(&[20, 20, 20]);
        let mut pool = Pool::new(0, ei);
        let v = Vote::new_notar(4, &[1u8; 32], &sk(1), 1);
        let mut out = PoolOut::default();
        pool.add_vote(&v, &mut out).unwrap();
        assert_eq!(
            pool.add_vote(&v, &mut out).unwrap_err(),
            AddError::Duplicate
        );
    }

    #[test]
    fn out_of_bounds_and_unknown_signer() {
        let ei = test_epoch(&[20, 20]);
        let mut pool = Pool::new(0, ei);
        let mut out = PoolOut::default();
        // Far-future slot.
        let far = 2 * SLOTS_PER_EPOCH + 10;
        assert_eq!(
            pool.add_vote(&Vote::new_skip(far, &sk(1), 1), &mut out)
                .unwrap_err(),
            AddError::SlotOutOfBounds
        );
        // Signer index >= validator_cnt (2).
        assert_eq!(
            pool.add_vote(&Vote::new_skip(4, &sk(9), 9), &mut out)
                .unwrap_err(),
            AddError::UnknownSigner
        );
    }

    #[test]
    fn add_block_parent_flow_does_not_panic() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]);
        let mut pool = Pool::new(0, ei);
        let mut out = PoolOut::default();
        // Register a block whose parent is not yet notar-fallback → parked.
        pool.add_block(
            &BlockId::new(4, [4u8; 32]),
            &BlockId::new(3, [3u8; 32]),
            &mut out,
        );
        assert!(pool.first_unpruned_slot() <= 4);
    }
}
