//! Aggregate signature scheme for Alpenglow (BLS12-381, `min_sig` shape).
//!
//! Faithful port of the reference Alpenglow aggregate-signature scheme. The
//! signer-bitmask logic and the wincode wire format are real and exact; the
//! cryptographic sign/verify operations are a **deterministic stub**, exactly
//! as the reference — the real BLS primitives (keygen / hash-to-curve sign /
//! aggregate verify) are not yet wired in the reference. The stub is sufficient
//! to exercise all consensus logic (vote/cert accumulation, thresholds,
//! finalization), which is independent of the signature scheme. Swapping in
//! real BLS (via the `blst` crate) is the final hardening step and does not
//! change any wire format or consensus logic.
//!
//! Deviation from the reference: its secret-key→public-key stub writes
//! `SIG_SZ` (192) bytes into a `PUBKEY_SZ` (96) buffer — a harmless latent
//! over-write because verification ignores key/sig content in the stub. Here we
//! fill exactly the destination length, preserving determinism without the
//! over-write.

/// BLS secret key size (bytes).
pub const SECKEY_SZ: usize = 32;
/// Public key size (bytes).
pub const PUBKEY_SZ: usize = 96;
/// Individual signature size (bytes).
pub const SIG_SZ: usize = 192;
/// Maximum number of signers (validator indices) in an aggregate.
pub const MAX_SIGNERS: usize = 2048;
/// Number of `u64` words in the signer bitmask (`MAX_SIGNERS / 64`).
pub const BITMASK_WORDS: usize = MAX_SIGNERS / 64;

/// Words needed to hold `nbits` bits.
#[inline]
pub const fn words_for_bits(nbits: u64) -> u64 {
    nbits.div_ceil(64)
}

/// Serialized size of an aggregate with `nbits` bits (sig + num_bits + num_words + words).
#[inline]
pub const fn serialized_sz(nbits: u64) -> usize {
    SIG_SZ + 8 + 8 + 8 * words_for_bits(nbits) as usize
}

/// Maximum serialized aggregate size (`nbits == MAX_SIGNERS`).
pub const SERIALIZED_MAX: usize = serialized_sz(MAX_SIGNERS as u64);

/// A BLS secret key (stub key material).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecretKey(pub [u8; SECKEY_SZ]);

/// A BLS public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub [u8; PUBKEY_SZ]);

/// A single individual signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; SIG_SZ]);

/// Deterministic non-cryptographic fill (stub). Mirrors `stub_fill`: an
/// FNV-style absorb of key+msg+len followed by an LCG byte stream. Stable so
/// serialize/round-trip tests are reproducible.
fn stub_fill(out: &mut [u8], key: &[u8; SECKEY_SZ], msg: &[u8]) {
    let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
    for &k in key.iter() {
        acc = acc.wrapping_mul(1099511628211) ^ (k as u64);
    }
    for &m in msg.iter() {
        acc = acc.wrapping_mul(1099511628211) ^ (m as u64);
    }
    acc ^= msg.len() as u64;
    for b in out.iter_mut() {
        acc = acc
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (acc >> 56) as u8;
    }
}

impl SecretKey {
    /// Derive the public key (stub: deterministic, not a real sk→pk map).
    pub fn to_pubkey(&self) -> PublicKey {
        let mut pk = [0u8; PUBKEY_SZ];
        stub_fill(&mut pk, &self.0, b"pk");
        PublicKey(pk)
    }

    /// Sign `msg` (stub: deterministic, not a real BLS signature).
    pub fn sign_bytes(&self, msg: &[u8]) -> Signature {
        let mut sig = [0u8; SIG_SZ];
        stub_fill(&mut sig, &self.0, msg);
        Signature(sig)
    }
}

impl Signature {
    /// Verify `msg` under `pk` (stub: always accepts). Mirrors
    /// `IndividualSignature::verify_bytes`.
    pub fn verify_bytes(&self, _pk: &PublicKey, _msg: &[u8]) -> bool {
        true
    }
}

/// An aggregate signature: an aggregate point plus a signer bitmask of `nbits`
/// logical bits. Mirrors the Rust `AggregateSignature`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AggregateSignature {
    /// Aggregate point (stub: XOR-folded individual signatures).
    pub sig: [u8; SIG_SZ],
    /// Logical bitmask length (the epoch's validator count) for the wire form.
    pub nbits: u64,
    /// 2048-bit signer set (one bit per validator index).
    pub bitmask: [u64; BITMASK_WORDS],
}

impl AggregateSignature {
    /// Empty aggregate of `nbits` bits (no signers, zeroed point).
    pub fn init(nbits: u64) -> Self {
        assert!(nbits <= MAX_SIGNERS as u64);
        Self {
            sig: [0u8; SIG_SZ],
            nbits,
            bitmask: [0u64; BITMASK_WORDS],
        }
    }

    /// Aggregate `sigs[i]` for signer `indices[i]` into a new aggregate of
    /// `nbits` bits. Requires `cnt>0`, every index `< nbits`, no duplicates.
    pub fn new(sigs: &[Signature], indices: &[u64], nbits: u64) -> Self {
        assert!(
            !sigs.is_empty(),
            "aggregate requires at least one signature"
        );
        assert_eq!(sigs.len(), indices.len());
        assert!(nbits <= MAX_SIGNERS as u64);
        let mut agg = Self::init(nbits);
        for (sig, &idx) in sigs.iter().zip(indices.iter()) {
            agg.add(idx, sig);
        }
        agg
    }

    /// Add one signer's signature. Requires `signer_idx < nbits` and the bit
    /// not already set (mirrors the Rust duplicate-signer assert).
    pub fn add(&mut self, signer_idx: u64, sig: &Signature) {
        assert!(signer_idx < self.nbits);
        assert!(!self.is_signer(signer_idx), "duplicate signer");
        let i = signer_idx as usize;
        self.bitmask[i / 64] |= 1u64 << (i % 64);
        for (a, b) in self.sig.iter_mut().zip(sig.0.iter()) {
            *a ^= *b;
        }
    }

    /// Verify against `msg` under per-index public keys (stub: structural check
    /// then accept). The bitmask length must equal the number of public keys.
    pub fn verify_bytes(&self, _msg: &[u8], pks: &[PublicKey]) -> bool {
        if self.nbits != pks.len() as u64 {
            return false;
        }
        true
    }

    /// `true` iff `validator_idx` is a signer.
    pub fn is_signer(&self, validator_idx: u64) -> bool {
        if validator_idx >= self.nbits {
            return false;
        }
        let i = validator_idx as usize;
        (self.bitmask[i / 64] >> (i % 64)) & 1 == 1
    }

    /// Number of signers.
    pub fn signer_cnt(&self) -> u64 {
        self.bitmask.iter().map(|w| w.count_ones() as u64).sum()
    }

    /// Serialize to the wincode encoding; returns bytes written or `None` if
    /// `out` is too small.
    pub fn serialize(&self, out: &mut [u8]) -> Option<usize> {
        let num_words = words_for_bits(self.nbits) as usize;
        let sz = serialized_sz(self.nbits);
        if out.len() < sz {
            return None;
        }
        let mut o = 0;
        out[o..o + SIG_SZ].copy_from_slice(&self.sig);
        o += SIG_SZ;
        out[o..o + 8].copy_from_slice(&self.nbits.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&(num_words as u64).to_le_bytes());
        o += 8;
        for w in 0..num_words {
            out[o..o + 8].copy_from_slice(&self.bitmask[w].to_le_bytes());
            o += 8;
        }
        debug_assert_eq!(o, sz);
        Some(sz)
    }

    /// Deserialize a wincode-encoded aggregate; returns `(agg, bytes_consumed)`
    /// or `None` on truncation / over-long bitmask / inconsistent `nbits`.
    pub fn deserialize(input: &[u8]) -> Option<(Self, usize)> {
        if input.len() < SIG_SZ + 16 {
            return None;
        }
        let mut o = 0;
        let mut sig = [0u8; SIG_SZ];
        sig.copy_from_slice(&input[o..o + SIG_SZ]);
        o += SIG_SZ;
        let num_bits = u64::from_le_bytes(input[o..o + 8].try_into().unwrap());
        o += 8;
        let num_words = u64::from_le_bytes(input[o..o + 8].try_into().unwrap());
        o += 8;

        if num_words > words_for_bits(MAX_SIGNERS as u64) {
            return None;
        }
        if num_bits > num_words * 64 {
            return None;
        }
        if input.len() < o + (num_words as usize) * 8 {
            return None;
        }

        let mut bitmask = [0u64; BITMASK_WORDS];
        for word in bitmask.iter_mut().take(num_words as usize) {
            *word = u64::from_le_bytes(input[o..o + 8].try_into().unwrap());
            o += 8;
        }
        Some((
            Self {
                sig,
                nbits: num_bits,
                bitmask,
            },
            o,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> SecretKey {
        SecretKey([seed; SECKEY_SZ])
    }

    #[test]
    fn sign_is_deterministic_and_msg_sensitive() {
        let k = sk(7);
        let a = k.sign_bytes(b"hello");
        let b = k.sign_bytes(b"hello");
        let c = k.sign_bytes(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Stub verify always accepts.
        assert!(a.verify_bytes(&k.to_pubkey(), b"hello"));
    }

    #[test]
    fn aggregate_tracks_signers() {
        let sigs: Vec<Signature> = (0..3).map(|i| sk(i as u8).sign_bytes(b"m")).collect();
        let idx = [0u64, 5, 9];
        let agg = AggregateSignature::new(&sigs, &idx, 16);
        assert_eq!(agg.signer_cnt(), 3);
        for &i in &idx {
            assert!(agg.is_signer(i));
        }
        assert!(!agg.is_signer(1));
        assert!(!agg.is_signer(20)); // out of range
    }

    #[test]
    #[should_panic(expected = "duplicate signer")]
    fn duplicate_signer_panics() {
        let s = sk(1).sign_bytes(b"m");
        let mut agg = AggregateSignature::init(8);
        agg.add(3, &s);
        agg.add(3, &s);
    }

    #[test]
    fn serialize_round_trips() {
        let sigs: Vec<Signature> = (0..4).map(|i| sk(i as u8 + 1).sign_bytes(b"x")).collect();
        let idx = [1u64, 2, 70, 200];
        let agg = AggregateSignature::new(&sigs, &idx, 256);
        let mut buf = [0u8; SERIALIZED_MAX];
        let n = agg.serialize(&mut buf).unwrap();
        assert_eq!(n, serialized_sz(256));
        let (back, consumed) = AggregateSignature::deserialize(&buf[..n]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(back, agg);
        assert_eq!(back.signer_cnt(), 4);
    }

    #[test]
    fn deserialize_rejects_truncated_and_overlong() {
        // Too short.
        assert!(AggregateSignature::deserialize(&[0u8; 10]).is_none());
        // Overlong bitmask (num_words huge).
        let mut buf = vec![0u8; SIG_SZ + 16];
        buf[SIG_SZ + 8..SIG_SZ + 16].copy_from_slice(&(9999u64).to_le_bytes());
        assert!(AggregateSignature::deserialize(&buf).is_none());
    }

    #[test]
    fn verify_requires_matching_pk_count() {
        let s = sk(2).sign_bytes(b"m");
        let agg = AggregateSignature::new(&[s], &[0], 4);
        let pks = [sk(2).to_pubkey(); 4];
        assert!(agg.verify_bytes(b"m", &pks));
        let pks3 = [sk(2).to_pubkey(); 3];
        assert!(!agg.verify_bytes(b"m", &pks3));
    }
}
