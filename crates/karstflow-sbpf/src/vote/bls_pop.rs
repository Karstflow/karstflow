//! BLS12-381 proof-of-possession verification for the Alpenglow vote program.
//!
//! When a validator registers a BLS public key in its vote account (the V4
//! `vote_state_v4` / Alpenglow format), it must prove possession of the
//! corresponding secret key. The proof is verified against a fixed message and
//! domain separation tag matching the reference implementation exactly, so a
//! proof accepted here is accepted on mainnet and vice versa.
//!
//! Ciphersuite (must match the reference implementation byte-for-byte):
//! - public key in G1 (48-byte compressed), proof in G2 (96-byte compressed) —
//!   the `blst` `min_pk` variant;
//! - hash-to-curve SHA-256 / SSWU / RO (random oracle);
//! - PoP domain separation tag `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`;
//! - empty augmentation.

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;

/// Domain separation tag for proof-of-possession hashing (43 bytes).
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Alpenglow PoP message domain prefix (9 bytes).
pub const ALPENGLOW_DOMAIN: &[u8] = b"ALPENGLOW";

/// Length of the vote-account proof-of-possession message: domain (9) +
/// vote account pubkey (32) + BLS public key (48).
pub const VOTE_BLS_MSG_SZ: usize = ALPENGLOW_DOMAIN.len() + 32 + 48;

/// Verify a BLS12-381 proof-of-possession over an arbitrary message.
///
/// `pubkey` is a 48-byte compressed G1 point, `proof` a 96-byte compressed G2
/// point. Returns `true` only if both points are valid group members and the
/// pairing check succeeds under [`POP_DST`].
pub fn verify_proof_of_possession(msg: &[u8], proof: &[u8; 96], pubkey: &[u8; 48]) -> bool {
    let pk = match PublicKey::from_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes(proof) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    // sig_groupcheck + pk_validate reject non-group-members and the point at
    // infinity, matching the reference's explicit checks.
    sig.verify(true, msg, POP_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

/// Verify a vote account's BLS proof-of-possession.
///
/// Builds the canonical 89-byte message
/// `"ALPENGLOW" || vote_account_pubkey || bls_pubkey` and verifies `proof`
/// against it.
pub fn verify_vote_bls_pop(
    vote_account_pubkey: &[u8; 32],
    bls_pubkey: &[u8; 48],
    proof: &[u8; 96],
) -> bool {
    let mut msg = [0u8; VOTE_BLS_MSG_SZ];
    msg[..9].copy_from_slice(ALPENGLOW_DOMAIN);
    msg[9..41].copy_from_slice(vote_account_pubkey);
    msg[41..89].copy_from_slice(bls_pubkey);
    verify_proof_of_possession(&msg, proof, bls_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr48(s: &str) -> [u8; 48] {
        hx(s).try_into().unwrap()
    }
    fn arr96(s: &str) -> [u8; 96] {
        hx(s).try_into().unwrap()
    }
    fn arr32(s: &str) -> [u8; 32] {
        hx(s).try_into().unwrap()
    }

    /// Reference KAT (test_bls12_381.c test 1): a valid Alpenglow vote PoP.
    #[test]
    fn vote_pop_known_answer_passes() {
        let vote = arr32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let bls = arr48(
            "b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc",
        );
        let proof = arr96(
            "b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d",
        );
        assert!(verify_vote_bls_pop(&vote, &bls, &proof));
    }

    /// A single-byte mutation of the vote account pubkey must fail.
    #[test]
    fn vote_pop_rejects_tampered_message() {
        let mut vote = arr32("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        vote[0] ^= 0x01;
        let bls = arr48(
            "b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc",
        );
        let proof = arr96(
            "b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d",
        );
        assert!(!verify_vote_bls_pop(&vote, &bls, &proof));
    }

    /// Reference KAT (test_bls12_381.c test 0): generic PoP, msg == pubkey.
    #[test]
    fn generic_pop_known_answer_passes() {
        let pk = arr48(
            "a8cf3d21aea94391b844264ca99cadd22388406ab492e1625328d7b045ce31d36d0ba7753b8821c34f8af888c16d88ab",
        );
        let proof = arr96(
            "913e00764fcc3e44d2f0f6bcefb7c946ad4deb3ec93adf143bd7fb111b9f57cc01b0c09b9f3934249be8ca5be6a3251c099f11709387a1877d4c270c39ee25c30951e5a6b2da9db5688244e474d6d60684195b2df361200608115ac14e74b04c",
        );
        assert!(verify_proof_of_possession(&pk, &proof, &pk));
    }

    /// A tampered proof must fail.
    #[test]
    fn rejects_tampered_proof() {
        let pk = arr48(
            "a8cf3d21aea94391b844264ca99cadd22388406ab492e1625328d7b045ce31d36d0ba7753b8821c34f8af888c16d88ab",
        );
        let mut proof = arr96(
            "913e00764fcc3e44d2f0f6bcefb7c946ad4deb3ec93adf143bd7fb111b9f57cc01b0c09b9f3934249be8ca5be6a3251c099f11709387a1877d4c270c39ee25c30951e5a6b2da9db5688244e474d6d60684195b2df361200608115ac14e74b04c",
        );
        proof[0] ^= 0x01;
        assert!(!verify_proof_of_possession(&pk, &proof, &pk));
    }

    #[test]
    fn vote_message_layout_is_89_bytes() {
        assert_eq!(VOTE_BLS_MSG_SZ, 89);
        assert_eq!(POP_DST.len(), 43);
    }
}
