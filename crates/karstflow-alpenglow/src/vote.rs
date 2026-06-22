//! The five Alpenglow vote kinds and the `Vote` sum type.
//!
//! Part of the Alpenglow consensus engine port. Each vote signs a `VotePayload` — a
//! tagged `(kind, slot[, block_hash])` tuple. The payload discriminant width is
//! taken to be 4 bytes (wincode), matching upstream; this is only load-bearing
//! for cross-client signature interop, not for internal (self-consistent)
//! consensus, and upstream itself flags it as not-yet-byte-verified.
//!
//! Concrete-vote payload kind values (the wire `kind` written into the signed
//! payload) follow the reference protocol's vote-type discriminants: Notar=0, Final=1,
//! Skip=2, NotarFallback=3, SkipFallback=4.

use crate::aggsig::{PublicKey, SecretKey, Signature};
use crate::base::BlockHash;

/// Payload kind: notarization vote.
pub const VOTE_TYPE_NOTAR: u32 = 0;
/// Payload kind: final vote.
pub const VOTE_TYPE_FINAL: u32 = 1;
/// Payload kind: skip vote.
pub const VOTE_TYPE_SKIP: u32 = 2;
/// Payload kind: notarization-fallback vote.
pub const VOTE_TYPE_NOTAR_FALLBACK: u32 = 3;
/// Payload kind: skip-fallback vote.
pub const VOTE_TYPE_SKIP_FALLBACK: u32 = 4;

/// Maximum bytes of a signed `VotePayload`: 4 (kind) + 8 (slot) + 32 (hash).
pub const VOTE_PAYLOAD_MAX: usize = 44;

/// Encode the bytes a vote of `kind` signs into `out` (len ≥ [`VOTE_PAYLOAD_MAX`])
/// and return the byte count: `u32 LE kind`, `u64 LE slot`, and for
/// Notar / NotarFallback the 32-byte block hash. `h` must be `Some` iff `kind`
/// is Notar or NotarFallback.
pub fn payload_bytes_to_sign(out: &mut [u8], kind: u32, slot: u64, h: Option<&BlockHash>) -> usize {
    let mut o = 0;
    out[o..o + 4].copy_from_slice(&kind.to_le_bytes());
    o += 4;
    out[o..o + 8].copy_from_slice(&slot.to_le_bytes());
    o += 8;
    if kind == VOTE_TYPE_NOTAR || kind == VOTE_TYPE_NOTAR_FALLBACK {
        let h = h.expect("notar payload requires a block hash");
        out[o..o + 32].copy_from_slice(h);
        o += 32;
    }
    o
}

fn sign_payload(kind: u32, slot: u64, h: Option<&BlockHash>, sk: &SecretKey) -> Signature {
    let mut buf = [0u8; VOTE_PAYLOAD_MAX];
    let sz = payload_bytes_to_sign(&mut buf, kind, slot, h);
    sk.sign_bytes(&buf[..sz])
}

/// A notarization vote (cast immediately after obtaining a valid block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarVote {
    /// Voted slot.
    pub slot: u64,
    /// Notarized block hash.
    pub block_hash: BlockHash,
    /// Signature over the payload.
    pub sig: Signature,
    /// Signer validator index.
    pub signer: u16,
}

/// A notarization-fallback vote (supports an alternate block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarFallbackVote {
    /// Voted slot.
    pub slot: u64,
    /// Alternate block hash.
    pub block_hash: BlockHash,
    /// Signature over the payload.
    pub sig: Signature,
    /// Signer validator index.
    pub signer: u16,
}

/// A skip vote (cast on invalid block / timeout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkipVote {
    /// Skipped slot.
    pub slot: u64,
    /// Signature over the payload.
    pub sig: Signature,
    /// Signer validator index.
    pub signer: u16,
}

/// A skip-fallback vote (contributes to skip after notarizing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkipFallbackVote {
    /// Skipped slot.
    pub slot: u64,
    /// Signature over the payload.
    pub sig: Signature,
    /// Signer validator index.
    pub signer: u16,
}

/// A final vote (cast after seeing a notarization cert for our block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalVote {
    /// Finalized slot.
    pub slot: u64,
    /// Signature over the payload.
    pub sig: Signature,
    /// Signer validator index.
    pub signer: u16,
}

impl NotarVote {
    /// Construct and sign.
    pub fn new(slot: u64, h: &BlockHash, sk: &SecretKey, signer: u16) -> Self {
        Self {
            slot,
            block_hash: *h,
            sig: sign_payload(VOTE_TYPE_NOTAR, slot, Some(h), sk),
            signer,
        }
    }
}
impl NotarFallbackVote {
    /// Construct and sign.
    pub fn new(slot: u64, h: &BlockHash, sk: &SecretKey, signer: u16) -> Self {
        Self {
            slot,
            block_hash: *h,
            sig: sign_payload(VOTE_TYPE_NOTAR_FALLBACK, slot, Some(h), sk),
            signer,
        }
    }
}
impl SkipVote {
    /// Construct and sign.
    pub fn new(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Self {
            slot,
            sig: sign_payload(VOTE_TYPE_SKIP, slot, None, sk),
            signer,
        }
    }
}
impl SkipFallbackVote {
    /// Construct and sign.
    pub fn new(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Self {
            slot,
            sig: sign_payload(VOTE_TYPE_SKIP_FALLBACK, slot, None, sk),
            signer,
        }
    }
}
impl FinalVote {
    /// Construct and sign.
    pub fn new(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Self {
            slot,
            sig: sign_payload(VOTE_TYPE_FINAL, slot, None, sk),
            signer,
        }
    }
}

/// The network `Vote` sum type over the five concrete kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vote {
    /// Notarization vote.
    Notar(NotarVote),
    /// Notarization-fallback vote.
    NotarFallback(NotarFallbackVote),
    /// Skip vote.
    Skip(SkipVote),
    /// Skip-fallback vote.
    SkipFallback(SkipFallbackVote),
    /// Final vote.
    Final(FinalVote),
}

impl Vote {
    /// Build a notarization vote.
    pub fn new_notar(slot: u64, h: &BlockHash, sk: &SecretKey, signer: u16) -> Self {
        Vote::Notar(NotarVote::new(slot, h, sk, signer))
    }
    /// Build a notarization-fallback vote.
    pub fn new_notar_fallback(slot: u64, h: &BlockHash, sk: &SecretKey, signer: u16) -> Self {
        Vote::NotarFallback(NotarFallbackVote::new(slot, h, sk, signer))
    }
    /// Build a skip vote.
    pub fn new_skip(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Vote::Skip(SkipVote::new(slot, sk, signer))
    }
    /// Build a skip-fallback vote.
    pub fn new_skip_fallback(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Vote::SkipFallback(SkipFallbackVote::new(slot, sk, signer))
    }
    /// Build a final vote.
    pub fn new_final(slot: u64, sk: &SecretKey, signer: u16) -> Self {
        Vote::Final(FinalVote::new(slot, sk, signer))
    }

    /// Payload kind discriminant.
    pub fn kind(&self) -> u32 {
        match self {
            Vote::Notar(_) => VOTE_TYPE_NOTAR,
            Vote::NotarFallback(_) => VOTE_TYPE_NOTAR_FALLBACK,
            Vote::Skip(_) => VOTE_TYPE_SKIP,
            Vote::SkipFallback(_) => VOTE_TYPE_SKIP_FALLBACK,
            Vote::Final(_) => VOTE_TYPE_FINAL,
        }
    }

    /// Voted slot.
    pub fn slot(&self) -> u64 {
        match self {
            Vote::Notar(v) => v.slot,
            Vote::NotarFallback(v) => v.slot,
            Vote::Skip(v) => v.slot,
            Vote::SkipFallback(v) => v.slot,
            Vote::Final(v) => v.slot,
        }
    }

    /// Signer validator index.
    pub fn signer(&self) -> u16 {
        match self {
            Vote::Notar(v) => v.signer,
            Vote::NotarFallback(v) => v.signer,
            Vote::Skip(v) => v.signer,
            Vote::SkipFallback(v) => v.signer,
            Vote::Final(v) => v.signer,
        }
    }

    /// Block hash, or `None` for skip / skip-fallback / final votes.
    pub fn block_hash(&self) -> Option<&BlockHash> {
        match self {
            Vote::Notar(v) => Some(&v.block_hash),
            Vote::NotarFallback(v) => Some(&v.block_hash),
            _ => None,
        }
    }

    fn sig(&self) -> &Signature {
        match self {
            Vote::Notar(v) => &v.sig,
            Vote::NotarFallback(v) => &v.sig,
            Vote::Skip(v) => &v.sig,
            Vote::SkipFallback(v) => &v.sig,
            Vote::Final(v) => &v.sig,
        }
    }

    /// `true` iff the signature is valid under `pk` (stub: always accepts after
    /// reconstructing the signed payload). Mirrors `Vote::check_sig`.
    pub fn check_sig(&self, pk: &PublicKey) -> bool {
        let mut buf = [0u8; VOTE_PAYLOAD_MAX];
        let sz = payload_bytes_to_sign(&mut buf, self.kind(), self.slot(), self.block_hash());
        self.sig().verify_bytes(pk, &buf[..sz])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> SecretKey {
        SecretKey([seed; 32])
    }

    #[test]
    fn payload_layout_and_lengths() {
        let mut buf = [0u8; VOTE_PAYLOAD_MAX];
        // Skip: kind(4) + slot(8) = 12 bytes, no hash.
        let n = payload_bytes_to_sign(&mut buf, VOTE_TYPE_SKIP, 9, None);
        assert_eq!(n, 12);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            VOTE_TYPE_SKIP
        );
        assert_eq!(u64::from_le_bytes(buf[4..12].try_into().unwrap()), 9);
        // Notar: + 32-byte hash = 44 bytes.
        let h = [0xAB; 32];
        let n = payload_bytes_to_sign(&mut buf, VOTE_TYPE_NOTAR, 9, Some(&h));
        assert_eq!(n, VOTE_PAYLOAD_MAX);
        assert_eq!(&buf[12..44], &h);
    }

    #[test]
    fn accessors_and_check_sig() {
        let h = [1u8; 32];
        let v = Vote::new_notar(42, &h, &sk(3), 7);
        assert_eq!(v.kind(), VOTE_TYPE_NOTAR);
        assert_eq!(v.slot(), 42);
        assert_eq!(v.signer(), 7);
        assert_eq!(v.block_hash(), Some(&h));
        assert!(v.check_sig(&sk(3).to_pubkey()));

        let s = Vote::new_skip(5, &sk(1), 2);
        assert_eq!(s.kind(), VOTE_TYPE_SKIP);
        assert_eq!(s.block_hash(), None);
    }

    #[test]
    fn distinct_kinds_sign_distinct_payloads() {
        // Skip vs skip-fallback at the same slot must produce different sigs
        // (different payload kind), proving the discriminant participates.
        let a = SkipVote::new(5, &sk(4), 0).sig;
        let b = SkipFallbackVote::new(5, &sk(4), 0).sig;
        assert_ne!(a, b);
    }
}
