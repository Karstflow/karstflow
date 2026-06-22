//! Per-slot consensus state: votes, running stake totals, certificates, and
//! safe-to-notar / safe-to-skip bookkeeping for a single slot.
//!
//! Part of the Alpenglow consensus engine port. The reference is a
//! workspace-backed object built on low-level pool/map generics; here the same
//! logic is expressed with idiomatic `HashMap`/`HashSet`/`Vec`. The control
//! flow is faithful, including the per-vote-kind ordering of stake-counting vs.
//! vote-storage (NOTAR / NOTAR_FALLBACK count before storing; SKIP /
//! SKIP_FALLBACK / FINAL store before counting).

use std::collections::{HashMap, HashSet};

use crate::base::{BlockHash, BlockId};
use crate::cert::{Cert, FastFinalCert, FinalCert, NotarCert, NotarFallbackCert, SkipCert};
use crate::epoch_info::EpochInfo;
use crate::vote::{FinalVote, NotarFallbackVote, NotarVote, SkipFallbackVote, SkipVote, Vote};

/// Whether a block's parent is known (in blockstore) or certified (notarized-fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentStatus {
    /// Parent present in the blockstore.
    Known,
    /// Parent has a notarization-fallback certificate.
    Certified,
}

/// Result of the safe-to-notar check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum S2n {
    SafeToNotar,
    MissingBlock,
    Awaiting,
}

/// The slashable offences the pool may detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashableOffence {
    /// Two notar votes for different block hashes.
    NotarDifferentHash,
    /// A skip and a notarize for the same slot.
    SkipAndNotarize,
    /// A skip and a finalize for the same slot.
    SkipAndFinalize,
    /// A notar-fallback and a finalize for the same slot.
    NotarFallbackAndFinalize,
}

/// A detected slashable offence (offence kind + offending validator + slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slashable {
    /// The offence kind.
    pub offence: SlashableOffence,
    /// Offending validator index.
    pub validator: u64,
    /// Slot the offence was detected for.
    pub slot: u64,
}

/// Pool events emitted by the slot state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolEvent {
    /// A block became safe to notarize.
    SafeToNotar(BlockId),
    /// The slot became safe to skip.
    SafeToSkip(u64),
}

/// Result of [`SlotState::notify_parent_certified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyParent {
    /// No action.
    None,
    /// Emit a pool event.
    Event(PoolEvent),
    /// Request repair of a block.
    Repair(BlockId),
}

/// Output sink for [`SlotState::add_vote`]: newly created certs, votor events,
/// and blocks to repair.
#[derive(Default, Debug)]
pub struct SlotStateOutputs {
    /// Newly created certificates.
    pub certs: Vec<Cert>,
    /// Emitted pool events.
    pub events: Vec<PoolEvent>,
    /// Blocks to repair.
    pub repairs: Vec<BlockId>,
}

#[derive(Default, Clone)]
struct ValidatorVotes {
    notar: Option<NotarVote>,
    skip: Option<SkipVote>,
    skip_fallback: Option<SkipFallbackVote>,
    finalize: Option<FinalVote>,
}

#[derive(Default)]
struct SlotCertificates {
    notar: Option<NotarCert>,
    skip: Option<SkipCert>,
    fast_finalize: Option<FastFinalCert>,
    finalize: Option<FinalCert>,
    nf: Vec<NotarFallbackCert>,
}

/// Per-slot consensus state.
pub struct SlotState {
    slot: u64,
    own_id: u64,
    votes: HashMap<u16, ValidatorVotes>,
    nf_votes: HashMap<(u16, BlockHash), NotarFallbackVote>,
    notar_stake: HashMap<BlockHash, u64>,
    nf_stake: HashMap<BlockHash, u64>,
    skip_stake: u64,
    skip_fallback_stake: u64,
    finalize_stake: u64,
    notar_or_skip_stake: u64,
    top_notar_stake: u64,
    parents: HashMap<BlockHash, ParentStatus>,
    pending_s2n: HashSet<BlockHash>,
    sent_s2n: HashSet<BlockHash>,
    sent_safe_to_skip: bool,
    certs: SlotCertificates,
}

impl SlotState {
    /// Empty slot state for `slot`, owned by `own_id`.
    pub fn new(slot: u64, own_id: u64) -> Self {
        Self {
            slot,
            own_id,
            votes: HashMap::new(),
            nf_votes: HashMap::new(),
            notar_stake: HashMap::new(),
            nf_stake: HashMap::new(),
            skip_stake: 0,
            skip_fallback_stake: 0,
            finalize_stake: 0,
            notar_or_skip_stake: 0,
            top_notar_stake: 0,
            parents: HashMap::new(),
            pending_s2n: HashSet::new(),
            sent_s2n: HashSet::new(),
            sent_safe_to_skip: false,
            certs: SlotCertificates::default(),
        }
    }

    fn vv(&self, v: u16) -> Option<&ValidatorVotes> {
        self.votes.get(&v)
    }

    fn collect_notar(&self, hash: &BlockHash) -> Vec<NotarVote> {
        let mut out: Vec<NotarVote> = self
            .votes
            .values()
            .filter_map(|vv| vv.notar)
            .filter(|n| &n.block_hash == hash)
            .collect();
        out.sort_by_key(|n| n.signer);
        out
    }

    fn collect_nf(&self, hash: &BlockHash) -> Vec<NotarFallbackVote> {
        let mut out: Vec<NotarFallbackVote> = self
            .nf_votes
            .iter()
            .filter(|((_, h), _)| h == hash)
            .map(|(_, v)| *v)
            .collect();
        out.sort_by_key(|v| v.signer);
        out
    }

    fn collect_skip(&self) -> Vec<SkipVote> {
        let mut out: Vec<SkipVote> = self.votes.values().filter_map(|vv| vv.skip).collect();
        out.sort_by_key(|v| v.signer);
        out
    }

    fn collect_skip_fallback(&self) -> Vec<SkipFallbackVote> {
        let mut out: Vec<SkipFallbackVote> = self
            .votes
            .values()
            .filter_map(|vv| vv.skip_fallback)
            .collect();
        out.sort_by_key(|v| v.signer);
        out
    }

    fn collect_final(&self) -> Vec<FinalVote> {
        let mut out: Vec<FinalVote> = self.votes.values().filter_map(|vv| vv.finalize).collect();
        out.sort_by_key(|v| v.signer);
        out
    }

    /// `true` iff a notar-fallback cert exists for `block_hash`.
    pub fn is_notar_fallback(&self, block_hash: &BlockHash) -> bool {
        self.certs.nf.iter().any(|c| &c.block_hash == block_hash)
    }

    fn notar_stake_of(&self, h: &BlockHash) -> u64 {
        *self.notar_stake.get(h).unwrap_or(&0)
    }
    fn nf_stake_of(&self, h: &BlockHash) -> u64 {
        *self.nf_stake.get(h).unwrap_or(&0)
    }

    /// Mirrors `check_safe_to_notar`: mutates the pending / sent sets exactly as
    /// the reference does and returns the status.
    fn check_safe_to_notar(&mut self, block_hash: &BlockHash, ei: &EpochInfo) -> S2n {
        let notar_stake = self.notar_stake_of(block_hash);
        let skip_stake = self.skip_stake;

        if !ei.is_weakest_quorum(notar_stake) {
            return S2n::Awaiting;
        }
        if !ei.is_weak_quorum(notar_stake) && !ei.is_quorum(notar_stake + skip_stake) {
            self.pending_s2n.insert(*block_hash);
            return S2n::Awaiting;
        }

        match self.parents.get(block_hash) {
            None => return S2n::MissingBlock,
            Some(ParentStatus::Known) => return S2n::Awaiting,
            Some(ParentStatus::Certified) => {}
        }

        let own = self.own_id as u16;
        let (has_skip, notar_hash) = match self.vv(own) {
            Some(vv) => (vv.skip.is_some(), vv.notar.map(|n| n.block_hash)),
            None => (false, None),
        };
        if has_skip {
            self.pending_s2n.remove(block_hash);
            self.sent_s2n.insert(*block_hash);
            return S2n::SafeToNotar;
        }
        if let Some(nh) = notar_hash {
            if &nh != block_hash {
                self.pending_s2n.remove(block_hash);
                self.sent_s2n.insert(*block_hash);
                return S2n::SafeToNotar;
            }
            return S2n::Awaiting;
        }
        // Neither skip nor notar from us yet.
        self.pending_s2n.insert(*block_hash);
        S2n::Awaiting
    }

    fn process_pending_safe_to_notar(&mut self, ei: &EpochInfo, out: &mut SlotStateOutputs) {
        let snapshot: Vec<BlockHash> = self
            .pending_s2n
            .iter()
            .filter(|h| !self.sent_s2n.contains(*h))
            .copied()
            .collect();
        for h in snapshot {
            if self.sent_s2n.contains(&h) {
                continue;
            }
            match self.check_safe_to_notar(&h, ei) {
                S2n::SafeToNotar => out
                    .events
                    .push(PoolEvent::SafeToNotar(BlockId::new(self.slot, h))),
                S2n::MissingBlock => out.repairs.push(BlockId::new(self.slot, h)),
                S2n::Awaiting => {}
            }
        }
    }

    fn count_notar_stake(
        &mut self,
        block_hash: &BlockHash,
        stake: u64,
        ei: &EpochInfo,
        out: &mut SlotStateOutputs,
    ) {
        let notar_stake = {
            let e = self.notar_stake.entry(*block_hash).or_insert(0);
            *e += stake;
            *e
        };
        self.notar_or_skip_stake += stake;
        self.top_notar_stake = self.top_notar_stake.max(notar_stake);

        if !self.sent_s2n.contains(block_hash) {
            match self.check_safe_to_notar(block_hash, ei) {
                S2n::SafeToNotar => out
                    .events
                    .push(PoolEvent::SafeToNotar(BlockId::new(self.slot, *block_hash))),
                S2n::MissingBlock => out.repairs.push(BlockId::new(self.slot, *block_hash)),
                S2n::Awaiting => {}
            }
        }

        if !self.sent_safe_to_skip
            && ei.is_weak_quorum(self.notar_or_skip_stake - self.top_notar_stake)
            && self
                .vv(self.own_id as u16)
                .map(|v| v.notar.is_some())
                .unwrap_or(false)
        {
            out.events.push(PoolEvent::SafeToSkip(self.slot));
            self.sent_safe_to_skip = true;
        }

        let nf_stake = self.nf_stake_of(block_hash);
        if ei.is_quorum(nf_stake + notar_stake) && !self.is_notar_fallback(block_hash) {
            let nv = self.collect_notar(block_hash);
            let nf = self.collect_nf(block_hash);
            let c =
                NotarFallbackCert::try_new(&nv, &nf, ei.validators()).expect("notar-fallback cert");
            out.certs.push(Cert::NotarFallback(c));
        }
        if ei.is_quorum(notar_stake) && self.certs.notar.is_none() {
            let nv = self.collect_notar(block_hash);
            let c = NotarCert::try_new(&nv, ei.validators()).expect("notar cert");
            out.certs.push(Cert::Notar(c));
        }
        if ei.is_strong_quorum(notar_stake) && self.certs.fast_finalize.is_none() {
            let nv = self.collect_notar(block_hash);
            let c = FastFinalCert::try_new(&nv, ei.validators()).expect("fast-final cert");
            out.certs.push(Cert::FastFinal(c));
        }
    }

    fn count_notar_fallback_stake(
        &mut self,
        block_hash: &BlockHash,
        stake: u64,
        ei: &EpochInfo,
        out: &mut SlotStateOutputs,
    ) {
        let nf_stake = {
            let e = self.nf_stake.entry(*block_hash).or_insert(0);
            *e += stake;
            *e
        };
        let notar_stake = self.notar_stake_of(block_hash);
        if ei.is_quorum(nf_stake + notar_stake) && !self.is_notar_fallback(block_hash) {
            let nv = self.collect_notar(block_hash);
            let nf = self.collect_nf(block_hash);
            let c =
                NotarFallbackCert::try_new(&nv, &nf, ei.validators()).expect("notar-fallback cert");
            out.certs.push(Cert::NotarFallback(c));
        }
    }

    fn count_skip_stake(
        &mut self,
        stake: u64,
        fallback: bool,
        ei: &EpochInfo,
        out: &mut SlotStateOutputs,
    ) {
        if fallback {
            self.skip_fallback_stake += stake;
        } else {
            self.skip_stake += stake;
        }

        self.process_pending_safe_to_notar(ei, out);

        let total_skip = self.skip_stake + self.skip_fallback_stake;
        if ei.is_quorum(total_skip) && self.certs.skip.is_none() {
            let skip = self.collect_skip();
            let sf = self.collect_skip_fallback();
            let c = SkipCert::try_new(&skip, &sf, ei.validators()).expect("skip cert");
            out.certs.push(Cert::Skip(c));
        }
        if !self.sent_safe_to_skip
            && ei.is_weak_quorum(self.notar_or_skip_stake - self.top_notar_stake)
            && self
                .vv(self.own_id as u16)
                .map(|v| v.notar.is_some())
                .unwrap_or(false)
        {
            out.events.push(PoolEvent::SafeToSkip(self.slot));
            self.sent_safe_to_skip = true;
        }
    }

    fn count_finalize_stake(&mut self, stake: u64, ei: &EpochInfo, out: &mut SlotStateOutputs) {
        self.finalize_stake += stake;
        if ei.is_quorum(self.finalize_stake) && self.certs.finalize.is_none() {
            let f = self.collect_final();
            let c = FinalCert::try_new(&f, ei.validators()).expect("final cert");
            out.certs.push(Cert::Final(c));
        }
    }

    /// Add a certificate to this slot (mirrors `add_cert`). A notar-fallback
    /// cert is stored only if none for the same block hash exists.
    pub fn add_cert(&mut self, cert: &Cert) {
        match cert {
            Cert::Notar(c) => self.certs.notar = Some(*c),
            Cert::NotarFallback(c) => {
                if !self.is_notar_fallback(&c.block_hash) {
                    self.certs.nf.push(*c);
                }
            }
            Cert::Skip(c) => self.certs.skip = Some(*c),
            Cert::FastFinal(c) => self.certs.fast_finalize = Some(*c),
            Cert::Final(c) => self.certs.finalize = Some(*c),
        }
    }

    /// Add a vote to this slot (mirrors `add_vote`). Updates running stake
    /// totals, creates any new certs, checks safe-to-notar / safe-to-skip, and
    /// appends results to `out`. `voter_stake` is the signer's stake. The caller
    /// must first call [`Self::should_ignore_vote`] and
    /// [`Self::check_slashable_offence`].
    pub fn add_vote(
        &mut self,
        vote: &Vote,
        voter_stake: u64,
        ei: &EpochInfo,
        out: &mut SlotStateOutputs,
    ) {
        let voter = vote.signer();
        match vote {
            Vote::Notar(n) => {
                let h = n.block_hash;
                self.count_notar_stake(&h, voter_stake, ei, out);
                self.votes.entry(voter).or_default().notar = Some(*n);
            }
            Vote::NotarFallback(n) => {
                let h = n.block_hash;
                self.count_notar_fallback_stake(&h, voter_stake, ei, out);
                let prev = self.nf_votes.insert((voter, h), *n);
                debug_assert!(prev.is_none(), "duplicate notar-fallback vote");
            }
            Vote::Skip(s) => {
                self.votes.entry(voter).or_default().skip = Some(*s);
                self.notar_or_skip_stake += voter_stake;
                self.count_skip_stake(voter_stake, false, ei, out);
            }
            Vote::SkipFallback(s) => {
                self.votes.entry(voter).or_default().skip_fallback = Some(*s);
                self.count_skip_stake(voter_stake, true, ei, out);
            }
            Vote::Final(f) => {
                self.votes.entry(voter).or_default().finalize = Some(*f);
                self.count_finalize_stake(voter_stake, ei, out);
            }
        }

        if voter as u64 == self.own_id {
            self.process_pending_safe_to_notar(ei, out);
        }
    }

    /// Mark the parent of the block keyed by `hash` as known (idempotent).
    pub fn notify_parent_known(&mut self, hash: &BlockHash) {
        self.parents.entry(*hash).or_insert(ParentStatus::Known);
    }

    /// Mark the parent of the block keyed by `hash` as certified and possibly
    /// emit a safe-to-notar event. Panics if `notify_parent_known` was not
    /// called for `hash` first.
    pub fn notify_parent_certified(&mut self, hash: &BlockHash, ei: &EpochInfo) -> NotifyParent {
        let cur = self.parents.get(hash).copied();
        assert!(cur.is_some(), "parent not known");
        self.parents.insert(*hash, ParentStatus::Certified);

        if self.sent_s2n.contains(hash) {
            return NotifyParent::None;
        }
        match self.check_safe_to_notar(hash, ei) {
            S2n::SafeToNotar => {
                NotifyParent::Event(PoolEvent::SafeToNotar(BlockId::new(self.slot, *hash)))
            }
            S2n::MissingBlock => NotifyParent::Repair(BlockId::new(self.slot, *hash)),
            S2n::Awaiting => NotifyParent::None,
        }
    }

    /// The slashable offence `vote` would constitute given the current votes, or
    /// `None`. Must be called before dismissing duplicates.
    pub fn check_slashable_offence(&self, vote: &Vote) -> Option<Slashable> {
        let slot = vote.slot();
        let voter = vote.signer();
        let vv = self.vv(voter);
        let mk = |o: SlashableOffence| {
            Some(Slashable {
                offence: o,
                validator: voter as u64,
                slot,
            })
        };
        let has = |f: fn(&ValidatorVotes) -> bool| vv.map(f).unwrap_or(false);

        match vote {
            Vote::Notar(n) => {
                if has(|v| v.skip.is_some()) {
                    return mk(SlashableOffence::SkipAndNotarize);
                }
                if let Some(existing) = vv.and_then(|v| v.notar) {
                    if existing.block_hash != n.block_hash {
                        return mk(SlashableOffence::NotarDifferentHash);
                    }
                }
                None
            }
            Vote::NotarFallback(_) => {
                if has(|v| v.finalize.is_some()) {
                    return mk(SlashableOffence::NotarFallbackAndFinalize);
                }
                None
            }
            Vote::Skip(_) => {
                if has(|v| v.finalize.is_some()) {
                    mk(SlashableOffence::SkipAndFinalize)
                } else if has(|v| v.notar.is_some()) {
                    mk(SlashableOffence::SkipAndNotarize)
                } else {
                    None
                }
            }
            Vote::SkipFallback(_) => {
                if has(|v| v.finalize.is_some()) {
                    mk(SlashableOffence::SkipAndFinalize)
                } else {
                    None
                }
            }
            Vote::Final(_) => {
                if has(|v| v.skip.is_some() || v.skip_fallback.is_some()) {
                    return mk(SlashableOffence::SkipAndFinalize);
                }
                if self.nf_votes.keys().any(|(val, _)| *val == voter) {
                    return mk(SlashableOffence::NotarFallbackAndFinalize);
                }
                None
            }
        }
    }

    /// `true` iff `vote` should be ignored as a benign duplicate.
    pub fn should_ignore_vote(&self, vote: &Vote) -> bool {
        let voter = vote.signer();
        let vv = self.vv(voter);
        let has = |f: fn(&ValidatorVotes) -> bool| vv.map(f).unwrap_or(false);
        match vote {
            Vote::Notar(_) => has(|v| v.notar.is_some()),
            Vote::NotarFallback(n) => self.nf_votes.contains_key(&(voter, n.block_hash)),
            Vote::Skip(_) | Vote::SkipFallback(_) => {
                has(|v| v.skip.is_some() || v.skip_fallback.is_some())
            }
            Vote::Final(_) => has(|v| v.finalize.is_some()),
        }
    }

    // --- accessors (mirror the pub(super) fields the Rust tests read) ---

    /// The slot.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// Running notar stake for `block_hash`.
    pub fn notar_stake(&self, block_hash: &BlockHash) -> u64 {
        self.notar_stake_of(block_hash)
    }
    /// Running notar-fallback stake for `block_hash`.
    pub fn notar_fallback_stake(&self, block_hash: &BlockHash) -> u64 {
        self.nf_stake_of(block_hash)
    }
    /// Running skip stake.
    pub fn skip_stake(&self) -> u64 {
        self.skip_stake
    }
    /// Running skip-fallback stake.
    pub fn skip_fallback_stake(&self) -> u64 {
        self.skip_fallback_stake
    }
    /// Running finalize stake.
    pub fn finalize_stake(&self) -> u64 {
        self.finalize_stake
    }
    /// Running notar-or-skip stake.
    pub fn notar_or_skip_stake(&self) -> u64 {
        self.notar_or_skip_stake
    }
    /// Top single-block notar stake.
    pub fn top_notar_stake(&self) -> u64 {
        self.top_notar_stake
    }
    /// `true` iff validator `v` cast a notar vote.
    pub fn has_notar_vote(&self, v: u16) -> bool {
        self.vv(v).map(|x| x.notar.is_some()).unwrap_or(false)
    }
    /// `true` iff a notar cert is stored.
    pub fn has_notar_cert(&self) -> bool {
        self.certs.notar.is_some()
    }
    /// `true` iff a skip cert is stored.
    pub fn has_skip_cert(&self) -> bool {
        self.certs.skip.is_some()
    }
    /// `true` iff a fast-finalize cert is stored.
    pub fn has_fast_finalize_cert(&self) -> bool {
        self.certs.fast_finalize.is_some()
    }
    /// `true` iff a finalize cert is stored.
    pub fn has_finalize_cert(&self) -> bool {
        self.certs.finalize.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggsig::SecretKey;
    use crate::epoch_info::test_epoch;

    fn sk(seed: u8) -> SecretKey {
        SecretKey([seed; 32])
    }

    #[test]
    fn notar_stake_increments_per_vote() {
        let ei = test_epoch(&[1, 1, 1, 1, 1]); // total 5, stake 1 each
        let mut ss = SlotState::new(10, 0);
        let h = [7u8; 32];
        for i in 0..5u16 {
            assert!(!ss.has_notar_vote(i));
            let v = Vote::new_notar(10, &h, &sk(i as u8), i);
            let mut out = SlotStateOutputs::default();
            ss.add_vote(&v, 1, &ei, &mut out);
            assert!(ss.has_notar_vote(i));
            assert_eq!(ss.notar_stake(&h), (i + 1) as u64);
        }
    }

    #[test]
    fn skip_and_notarize_is_slashable() {
        // validator 1 skips slot, then notarizes → SkipAndNotarize.
        let ei = test_epoch(&[10, 10, 10]);
        let mut ss = SlotState::new(5, 0);
        let s1 = Vote::new_skip(5, &sk(1), 1);
        let mut out = SlotStateOutputs::default();
        ss.add_vote(&s1, 10, &ei, &mut out);
        let n1 = Vote::new_notar(5, &[1u8; 32], &sk(1), 1);
        let off = ss.check_slashable_offence(&n1).unwrap();
        assert_eq!(off.offence, SlashableOffence::SkipAndNotarize);
        assert_eq!(off.validator, 1);
        assert_eq!(off.slot, 5);
    }

    #[test]
    fn notar_different_hash_is_slashable() {
        let ei = test_epoch(&[10, 10]);
        let mut ss = SlotState::new(5, 0);
        let a = Vote::new_notar(5, &[1u8; 32], &sk(1), 1);
        let mut out = SlotStateOutputs::default();
        ss.add_vote(&a, 10, &ei, &mut out);
        let b = Vote::new_notar(5, &[2u8; 32], &sk(1), 1);
        assert_eq!(
            ss.check_slashable_offence(&b).unwrap().offence,
            SlashableOffence::NotarDifferentHash
        );
        // Same hash again → no offence.
        let c = Vote::new_notar(5, &[1u8; 32], &sk(1), 1);
        assert!(ss.check_slashable_offence(&c).is_none());
    }

    #[test]
    fn finalize_then_notar_fallback_is_slashable() {
        let ei = test_epoch(&[10, 10, 10]);
        let mut ss = SlotState::new(5, 0);
        let f1 = Vote::new_final(5, &sk(1), 1);
        let mut out = SlotStateOutputs::default();
        ss.add_vote(&f1, 10, &ei, &mut out);
        let nf = Vote::new_notar_fallback(5, &[3u8; 32], &sk(1), 1);
        assert_eq!(
            ss.check_slashable_offence(&nf).unwrap().offence,
            SlashableOffence::NotarFallbackAndFinalize
        );
    }

    #[test]
    fn should_ignore_duplicate_votes() {
        let ei = test_epoch(&[10, 10, 10, 10]);
        let mut ss = SlotState::new(5, 0);
        let v1 = Vote::new_notar(5, &[1u8; 32], &sk(1), 1);
        assert!(!ss.should_ignore_vote(&v1));
        let mut out = SlotStateOutputs::default();
        ss.add_vote(&v1, 10, &ei, &mut out);
        assert!(ss.should_ignore_vote(&v1));
        // A notar for a different hash by the same validator is still a dup.
        let v1b = Vote::new_notar(5, &[2u8; 32], &sk(1), 1);
        assert!(ss.should_ignore_vote(&v1b));
    }

    #[test]
    fn notar_quorum_emits_certs() {
        // 5 × 20 = 100; quorum 60. Drive notar votes to 60% and observe a
        // notar cert is emitted (faithful reference also emits a NF cert at the
        // same point).
        let ei = test_epoch(&[20, 20, 20, 20, 20]);
        let mut ss = SlotState::new(5, 0);
        let h = [9u8; 32];
        let mut emitted_notar = false;
        for i in 0..3u16 {
            let v = Vote::new_notar(5, &h, &sk(i as u8), i);
            let mut out = SlotStateOutputs::default();
            ss.add_vote(&v, 20, &ei, &mut out);
            if out.certs.iter().any(|c| matches!(c, Cert::Notar(_))) {
                emitted_notar = true;
            }
        }
        assert!(emitted_notar, "a notar cert must be emitted at quorum");
        assert_eq!(ss.notar_stake(&h), 60);
    }

    #[test]
    fn finalize_quorum_emits_final_cert() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]); // 100, quorum 60
        let mut ss = SlotState::new(5, 0);
        let mut got = false;
        for i in 0..3u16 {
            let v = Vote::new_final(5, &sk(i as u8), i);
            let mut out = SlotStateOutputs::default();
            ss.add_vote(&v, 20, &ei, &mut out);
            if out.certs.iter().any(|c| matches!(c, Cert::Final(_))) {
                got = true;
            }
        }
        assert!(got);
        assert_eq!(ss.finalize_stake(), 60);
    }
}
