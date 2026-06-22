//! The five Alpenglow certificate kinds and the `Cert` sum type.
//!
//! Part of the Alpenglow consensus engine port. A certificate aggregates a
//! quorum of votes into a BLS aggregate signature plus a signer bitmask.
//!
//! - `NotarCert`         ≥60% notar votes for one block   (block notarized)
//! - `NotarFallbackCert` ≥60% notar + notar-fallback      (weak notarization)
//! - `SkipCert`          ≥60% skip + skip-fallback         (slot skipped)
//! - `FastFinalCert`     ≥80% notar votes for one block    (fast finalized)
//! - `FinalCert`         ≥60% final votes                  (slow finalized)
//!
//! Cert discriminant order (wire-critical): Notar=0, NotarFallback=1, Skip=2,
//! FastFinal=3, Final=4 — note index 3 differs from the `Vote` enum's index 3
//! (SkipFallback). Mixed certs (NotarFallback, Skip) carry two optional
//! aggregate signatures because the two vote kinds sign different payloads.

use crate::aggsig::AggregateSignature;
use crate::base::BlockHash;
use crate::epoch_info::{EpochInfo, ValidatorInfo};
use crate::vote::{
    payload_bytes_to_sign, FinalVote, NotarFallbackVote, NotarVote, SkipFallbackVote, SkipVote,
    VOTE_PAYLOAD_MAX, VOTE_TYPE_FINAL, VOTE_TYPE_NOTAR, VOTE_TYPE_NOTAR_FALLBACK, VOTE_TYPE_SKIP,
    VOTE_TYPE_SKIP_FALLBACK,
};

/// Cert discriminant: notarization.
pub const CERT_TYPE_NOTAR: u32 = 0;
/// Cert discriminant: notarization fallback.
pub const CERT_TYPE_NOTAR_FALLBACK: u32 = 1;
/// Cert discriminant: skip.
pub const CERT_TYPE_SKIP: u32 = 2;
/// Cert discriminant: fast-final.
pub const CERT_TYPE_FAST_FINAL: u32 = 3;
/// Cert discriminant: final.
pub const CERT_TYPE_FINAL: u32 = 4;

/// Certificate construction errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// A vote referenced a different slot than the first.
    SlotMismatch,
    /// A vote referenced a different block hash than the first.
    BlockHashMismatch,
}

/// Notarization certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarCert {
    /// Notarized slot.
    pub slot: u64,
    /// Notarized block hash.
    pub block_hash: BlockHash,
    /// Aggregate signature over the notar votes.
    pub agg_sig: AggregateSignature,
    /// Summed stake of the contributing votes (as provided at construction).
    pub stake: u64,
}

/// Notarization-fallback certificate (mixed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarFallbackCert {
    /// Slot.
    pub slot: u64,
    /// Block hash.
    pub block_hash: BlockHash,
    /// Aggregate over notar votes, if any.
    pub agg_sig_notar: Option<AggregateSignature>,
    /// Aggregate over notar-fallback votes, if any.
    pub agg_sig_notar_fallback: Option<AggregateSignature>,
    /// Summed stake.
    pub stake: u64,
}

/// Skip certificate (mixed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkipCert {
    /// Skipped slot.
    pub slot: u64,
    /// Aggregate over skip votes, if any.
    pub agg_sig_skip: Option<AggregateSignature>,
    /// Aggregate over skip-fallback votes, if any.
    pub agg_sig_skip_fallback: Option<AggregateSignature>,
    /// Summed stake.
    pub stake: u64,
}

/// Fast-final certificate (≥80% notar).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastFinalCert {
    /// Slot.
    pub slot: u64,
    /// Block hash.
    pub block_hash: BlockHash,
    /// Aggregate over notar votes.
    pub agg_sig: AggregateSignature,
    /// Summed stake.
    pub stake: u64,
}

/// Final certificate (≥60% final).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalCert {
    /// Slot.
    pub slot: u64,
    /// Aggregate over final votes.
    pub agg_sig: AggregateSignature,
    /// Summed stake.
    pub stake: u64,
}

fn agg_build(items: &[(u16, crate::aggsig::Signature)], nbits: u64) -> AggregateSignature {
    let mut a = AggregateSignature::init(nbits);
    for (signer, sig) in items {
        a.add(*signer as u64, sig);
    }
    a
}

impl NotarCert {
    /// Aggregate notar votes into a notar cert. Errors on slot/hash mismatch.
    pub fn try_new(votes: &[NotarVote], validators: &[ValidatorInfo]) -> Result<Self, CertError> {
        assert!(!votes.is_empty());
        let slot = votes[0].slot;
        let bh = votes[0].block_hash;
        let mut stake = 0u64;
        let mut items = Vec::with_capacity(votes.len());
        for v in votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            if v.block_hash != bh {
                return Err(CertError::BlockHashMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            items.push((v.signer, v.sig));
        }
        Ok(Self {
            slot,
            block_hash: bh,
            agg_sig: agg_build(&items, validators.len() as u64),
            stake,
        })
    }
}

impl FastFinalCert {
    /// Aggregate notar votes into a fast-final cert (same shape as notar; the
    /// 80% threshold is enforced separately by [`Cert::check_threshold`]).
    pub fn try_new(votes: &[NotarVote], validators: &[ValidatorInfo]) -> Result<Self, CertError> {
        let n = NotarCert::try_new(votes, validators)?;
        Ok(Self {
            slot: n.slot,
            block_hash: n.block_hash,
            agg_sig: n.agg_sig,
            stake: n.stake,
        })
    }
}

impl FinalCert {
    /// Aggregate final votes into a final cert. Errors on slot mismatch.
    pub fn try_new(votes: &[FinalVote], validators: &[ValidatorInfo]) -> Result<Self, CertError> {
        assert!(!votes.is_empty());
        let slot = votes[0].slot;
        let mut stake = 0u64;
        let mut items = Vec::with_capacity(votes.len());
        for v in votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            items.push((v.signer, v.sig));
        }
        Ok(Self {
            slot,
            agg_sig: agg_build(&items, validators.len() as u64),
            stake,
        })
    }
}

impl NotarFallbackCert {
    /// Aggregate notar + notar-fallback votes (either slice may be empty, but
    /// not both) into a mixed cert. Errors on slot/hash mismatch.
    pub fn try_new(
        notar_votes: &[NotarVote],
        nf_votes: &[NotarFallbackVote],
        validators: &[ValidatorInfo],
    ) -> Result<Self, CertError> {
        assert!(!notar_votes.is_empty() || !nf_votes.is_empty());
        let (slot, bh) = if !notar_votes.is_empty() {
            (notar_votes[0].slot, notar_votes[0].block_hash)
        } else {
            (nf_votes[0].slot, nf_votes[0].block_hash)
        };
        let nbits = validators.len() as u64;
        let mut stake = 0u64;

        let mut notar_items = Vec::with_capacity(notar_votes.len());
        for v in notar_votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            if v.block_hash != bh {
                return Err(CertError::BlockHashMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            notar_items.push((v.signer, v.sig));
        }
        let mut nf_items = Vec::with_capacity(nf_votes.len());
        for v in nf_votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            if v.block_hash != bh {
                return Err(CertError::BlockHashMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            nf_items.push((v.signer, v.sig));
        }

        Ok(Self {
            slot,
            block_hash: bh,
            agg_sig_notar: (!notar_items.is_empty()).then(|| agg_build(&notar_items, nbits)),
            agg_sig_notar_fallback: (!nf_items.is_empty()).then(|| agg_build(&nf_items, nbits)),
            stake,
        })
    }
}

impl SkipCert {
    /// Aggregate skip + skip-fallback votes (either slice may be empty, but not
    /// both) into a mixed cert. Errors on slot mismatch.
    pub fn try_new(
        skip_votes: &[SkipVote],
        sf_votes: &[SkipFallbackVote],
        validators: &[ValidatorInfo],
    ) -> Result<Self, CertError> {
        assert!(!skip_votes.is_empty() || !sf_votes.is_empty());
        let slot = if !skip_votes.is_empty() {
            skip_votes[0].slot
        } else {
            sf_votes[0].slot
        };
        let nbits = validators.len() as u64;
        let mut stake = 0u64;

        let mut skip_items = Vec::with_capacity(skip_votes.len());
        for v in skip_votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            skip_items.push((v.signer, v.sig));
        }
        let mut sf_items = Vec::with_capacity(sf_votes.len());
        for v in sf_votes {
            if v.slot != slot {
                return Err(CertError::SlotMismatch);
            }
            stake = stake.saturating_add(validators[v.signer as usize].stake);
            sf_items.push((v.signer, v.sig));
        }

        Ok(Self {
            slot,
            agg_sig_skip: (!skip_items.is_empty()).then(|| agg_build(&skip_items, nbits)),
            agg_sig_skip_fallback: (!sf_items.is_empty()).then(|| agg_build(&sf_items, nbits)),
            stake,
        })
    }
}

/// The network `Cert` sum type over the five concrete kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cert {
    /// Notarization certificate.
    Notar(NotarCert),
    /// Notarization-fallback certificate.
    NotarFallback(NotarFallbackCert),
    /// Skip certificate.
    Skip(SkipCert),
    /// Fast-final certificate.
    FastFinal(FastFinalCert),
    /// Final certificate.
    Final(FinalCert),
}

impl Cert {
    /// Discriminant.
    pub fn kind(&self) -> u32 {
        match self {
            Cert::Notar(_) => CERT_TYPE_NOTAR,
            Cert::NotarFallback(_) => CERT_TYPE_NOTAR_FALLBACK,
            Cert::Skip(_) => CERT_TYPE_SKIP,
            Cert::FastFinal(_) => CERT_TYPE_FAST_FINAL,
            Cert::Final(_) => CERT_TYPE_FINAL,
        }
    }

    /// Certificate slot.
    pub fn slot(&self) -> u64 {
        match self {
            Cert::Notar(c) => c.slot,
            Cert::NotarFallback(c) => c.slot,
            Cert::Skip(c) => c.slot,
            Cert::FastFinal(c) => c.slot,
            Cert::Final(c) => c.slot,
        }
    }

    /// Summed stake recorded at construction.
    pub fn stake(&self) -> u64 {
        match self {
            Cert::Notar(c) => c.stake,
            Cert::NotarFallback(c) => c.stake,
            Cert::Skip(c) => c.stake,
            Cert::FastFinal(c) => c.stake,
            Cert::Final(c) => c.stake,
        }
    }

    /// Block hash, or `None` for skip / final.
    pub fn block_hash(&self) -> Option<&BlockHash> {
        match self {
            Cert::Notar(c) => Some(&c.block_hash),
            Cert::NotarFallback(c) => Some(&c.block_hash),
            Cert::FastFinal(c) => Some(&c.block_hash),
            _ => None,
        }
    }

    /// `true` iff validator `v` signed (union of both aggs for mixed certs).
    pub fn is_signer(&self, v: u64) -> bool {
        let any = |o: &Option<AggregateSignature>| o.map(|a| a.is_signer(v)).unwrap_or(false);
        match self {
            Cert::Notar(c) => c.agg_sig.is_signer(v),
            Cert::FastFinal(c) => c.agg_sig.is_signer(v),
            Cert::Final(c) => c.agg_sig.is_signer(v),
            Cert::NotarFallback(c) => any(&c.agg_sig_notar) || any(&c.agg_sig_notar_fallback),
            Cert::Skip(c) => any(&c.agg_sig_skip) || any(&c.agg_sig_skip_fallback),
        }
    }

    /// Stake of all epoch validators that signed this cert (each counted once).
    fn signed_stake(&self, ei: &EpochInfo) -> u64 {
        ei.validators()
            .iter()
            .filter(|v| self.is_signer(v.id))
            .map(|v| v.stake)
            .sum()
    }

    /// `true` iff the cert meets its stake threshold (80% for fast-final, else
    /// 60%), counting each validator once. Mirrors `Cert::check_threshold`.
    pub fn check_threshold(&self, ei: &EpochInfo) -> bool {
        let stake = self.signed_stake(ei);
        match self {
            Cert::FastFinal(_) => ei.is_strong_quorum(stake),
            _ => ei.is_quorum(stake),
        }
    }

    /// `true` iff the aggregate signatures verify against the per-index voting
    /// public keys (stub: structural check then accept). Mirrors `Cert::check_sig`.
    pub fn check_sig(&self, validators: &[ValidatorInfo]) -> bool {
        let pks: Vec<_> = validators.iter().map(|v| v.voting_pubkey).collect();
        let buf = [0u8; VOTE_PAYLOAD_MAX];
        let verify = |agg: &AggregateSignature, kind: u32, slot: u64, bh: Option<&BlockHash>| {
            let mut b = buf;
            let sz = payload_bytes_to_sign(&mut b, kind, slot, bh);
            agg.verify_bytes(&b[..sz], &pks)
        };
        match self {
            Cert::Notar(c) => verify(&c.agg_sig, VOTE_TYPE_NOTAR, c.slot, Some(&c.block_hash)),
            Cert::FastFinal(c) => verify(&c.agg_sig, VOTE_TYPE_NOTAR, c.slot, Some(&c.block_hash)),
            Cert::Final(c) => verify(&c.agg_sig, VOTE_TYPE_FINAL, c.slot, None),
            Cert::NotarFallback(c) => {
                let mut ok = true;
                if let Some(a) = &c.agg_sig_notar {
                    ok &= verify(a, VOTE_TYPE_NOTAR, c.slot, Some(&c.block_hash));
                }
                if let Some(a) = &c.agg_sig_notar_fallback {
                    ok &= verify(a, VOTE_TYPE_NOTAR_FALLBACK, c.slot, Some(&c.block_hash));
                }
                ok
            }
            Cert::Skip(c) => {
                let mut ok = true;
                if let Some(a) = &c.agg_sig_skip {
                    ok &= verify(a, VOTE_TYPE_SKIP, c.slot, None);
                }
                if let Some(a) = &c.agg_sig_skip_fallback {
                    ok &= verify(a, VOTE_TYPE_SKIP_FALLBACK, c.slot, None);
                }
                ok
            }
        }
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
    fn notar_cert_threshold_and_signers() {
        // 5 validators × 20 stake = 100. 3 notar votes = 60% → quorum met.
        let ei = test_epoch(&[20, 20, 20, 20, 20]);
        let h = [9u8; 32];
        let votes: Vec<NotarVote> = (0..3)
            .map(|i| NotarVote::new(7, &h, &sk(i), i as u16))
            .collect();
        let c = Cert::Notar(NotarCert::try_new(&votes, ei.validators()).unwrap());
        assert_eq!(c.slot(), 7);
        assert_eq!(c.block_hash(), Some(&h));
        assert!(c.is_signer(0) && c.is_signer(2));
        assert!(!c.is_signer(3));
        assert!(c.check_threshold(&ei)); // 60% met
        assert!(c.check_sig(ei.validators()));

        // 2 of 5 = 40% → not a quorum.
        let votes2: Vec<NotarVote> = (0..2)
            .map(|i| NotarVote::new(7, &h, &sk(i), i as u16))
            .collect();
        let c2 = Cert::Notar(NotarCert::try_new(&votes2, ei.validators()).unwrap());
        assert!(!c2.check_threshold(&ei));
    }

    #[test]
    fn fast_final_needs_strong_quorum() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]); // 100
        let h = [1u8; 32];
        // 4 of 5 = 80% → strong quorum met.
        let votes: Vec<NotarVote> = (0..4)
            .map(|i| NotarVote::new(3, &h, &sk(i), i as u16))
            .collect();
        let c = Cert::FastFinal(FastFinalCert::try_new(&votes, ei.validators()).unwrap());
        assert_eq!(c.kind(), CERT_TYPE_FAST_FINAL);
        assert!(c.check_threshold(&ei));
        // 3 of 5 = 60% → not strong.
        let votes3: Vec<NotarVote> = (0..3)
            .map(|i| NotarVote::new(3, &h, &sk(i), i as u16))
            .collect();
        let c3 = Cert::FastFinal(FastFinalCert::try_new(&votes3, ei.validators()).unwrap());
        assert!(!c3.check_threshold(&ei));
    }

    #[test]
    fn block_hash_mismatch_rejected() {
        let ei = test_epoch(&[10, 10]);
        let mut votes = vec![NotarVote::new(1, &[1u8; 32], &sk(0), 0)];
        votes.push(NotarVote::new(1, &[2u8; 32], &sk(1), 1));
        assert_eq!(
            NotarCert::try_new(&votes, ei.validators()),
            Err(CertError::BlockHashMismatch)
        );
    }

    #[test]
    fn mixed_skip_cert_counts_both_groups() {
        let ei = test_epoch(&[20, 20, 20, 20, 20]); // 100
        let skip: Vec<SkipVote> = (0..2).map(|i| SkipVote::new(4, &sk(i), i as u16)).collect();
        let sf: Vec<SkipFallbackVote> = (2..3)
            .map(|i| SkipFallbackVote::new(4, &sk(i), i as u16))
            .collect();
        let c = Cert::Skip(SkipCert::try_new(&skip, &sf, ei.validators()).unwrap());
        // signers 0,1 (skip) + 2 (skip-fallback) = 60% → quorum.
        assert!(c.is_signer(0) && c.is_signer(1) && c.is_signer(2));
        assert!(c.check_threshold(&ei));
        assert!(c.check_sig(ei.validators()));
    }
}
