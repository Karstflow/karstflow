//! ZK ElGamal proof verification module.
//!
//! Implements verification for all 12 proof types used by the ZK ElGamal proof
//! program (SPL Token-2022 confidential transfers). Uses curve25519-dalek for
//! Ristretto255 group operations and Merlin for Fiat-Shamir transcripts.

mod errors;
mod generators;
mod sigma;
mod transcript;

pub use errors::ZkProofError;

mod range_proof;
use range_proof::verify as range_proof_verify;

/// Unit length for Ristretto points and scalars (32 bytes).
const UNIT_LEN: usize = 32;

/// Verify a ZK proof given the instruction discriminant and proof data bytes.
///
/// The `proof_data` slice contains the full instruction payload after the
/// 1-byte discriminant (i.e. context + proof bytes concatenated).
///
/// Returns `Ok(context_bytes)` on success, where `context_bytes` is the
/// proof context that should be stored in the context state account.
pub fn verify_proof(discriminant: u8, proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    match discriminant {
        1 => sigma::verify_zero_ciphertext(proof_data),
        2 => sigma::verify_ciphertext_ciphertext_equality(proof_data),
        3 => sigma::verify_ciphertext_commitment_equality(proof_data),
        4 => sigma::verify_pubkey_validity(proof_data),
        5 => sigma::verify_percentage_with_cap(proof_data),
        6 => sigma::verify_batched_range_proof(proof_data, 64),
        7 => sigma::verify_batched_range_proof(proof_data, 128),
        8 => sigma::verify_batched_range_proof(proof_data, 256),
        9 => sigma::verify_grouped_ciphertext_validity(proof_data, 2, false),
        10 => sigma::verify_grouped_ciphertext_validity(proof_data, 2, true),
        11 => sigma::verify_grouped_ciphertext_validity(proof_data, 3, false),
        12 => sigma::verify_grouped_ciphertext_validity(proof_data, 3, true),
        _ => Err(ZkProofError::UnknownProofType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_discriminant_returns_error() {
        assert_eq!(verify_proof(0, &[]), Err(ZkProofError::UnknownProofType));
        assert_eq!(verify_proof(13, &[]), Err(ZkProofError::UnknownProofType));
        assert_eq!(verify_proof(255, &[]), Err(ZkProofError::UnknownProofType));
    }

    #[test]
    fn valid_discriminant_with_empty_data_returns_insufficient() {
        // All valid discriminants should fail with empty proof data
        for d in 1..=12 {
            let result = verify_proof(d, &[]);
            assert!(
                result.is_err(),
                "discriminant {d} should fail with empty data"
            );
        }
    }

    #[test]
    fn unit_len_is_32() {
        assert_eq!(UNIT_LEN, 32);
    }
}
