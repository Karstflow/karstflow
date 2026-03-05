//! Merlin transcript protocol for ZK ElGamal proofs.
//!
//! Implements the TranscriptProtocol trait matching the solana-zk-sdk
//! specification for domain separators, point/scalar appending, and
//! challenge derivation.

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;

use super::errors::ZkProofError;

/// Extension trait for Merlin transcript with ZK proof operations.
pub trait TranscriptProtocol {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ZkProofError>;
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;

    // Domain separators
    fn pubkey_proof_domain_separator(&mut self);
    fn zero_ciphertext_proof_domain_separator(&mut self);
    fn ciphertext_ciphertext_equality_proof_domain_separator(&mut self);
    fn ciphertext_commitment_equality_proof_domain_separator(&mut self);
    fn percentage_with_cap_proof_domain_separator(&mut self);
    fn grouped_ciphertext_validity_proof_domain_separator(&mut self, handles: u64);
    fn batched_grouped_ciphertext_validity_proof_domain_separator(&mut self, handles: u64);
    fn range_proof_domain_separator(&mut self, n: u64);
    fn inner_product_proof_domain_separator(&mut self, n: u64);
}

impl TranscriptProtocol for Transcript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ZkProofError> {
        if point.is_identity() {
            return Err(ZkProofError::IdentityPoint);
        }
        self.append_message(label, point.as_bytes());
        Ok(())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn pubkey_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"pubkey-proof");
    }

    fn zero_ciphertext_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"zero-ciphertext-proof");
    }

    fn ciphertext_ciphertext_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-ciphertext-equality-proof");
    }

    fn ciphertext_commitment_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-commitment-equality-proof");
    }

    fn percentage_with_cap_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"percentage-with-cap-proof");
    }

    fn grouped_ciphertext_validity_proof_domain_separator(&mut self, handles: u64) {
        self.append_message(b"dom-sep", b"validity-proof");
        self.append_u64(b"handles", handles);
    }

    fn batched_grouped_ciphertext_validity_proof_domain_separator(&mut self, handles: u64) {
        self.append_message(b"dom-sep", b"batched-validity-proof");
        self.append_u64(b"handles", handles);
    }

    fn range_proof_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"range-proof");
        self.append_u64(b"n", n);
    }

    fn inner_product_proof_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"inner-product");
        self.append_u64(b"n", n);
    }
}
