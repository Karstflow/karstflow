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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_and_append_identity_point_fails() {
        use curve25519_dalek::traits::Identity;
        let mut t = Transcript::new(b"test");
        let identity = CompressedRistretto::identity();
        let result = t.validate_and_append_point(b"pt", &identity);
        assert_eq!(result, Err(ZkProofError::IdentityPoint));
    }

    #[test]
    fn validate_and_append_non_identity_succeeds() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
        let mut t = Transcript::new(b"test");
        let result = t.validate_and_append_point(b"pt", &RISTRETTO_BASEPOINT_COMPRESSED);
        assert!(result.is_ok());
    }

    #[test]
    fn challenge_scalar_is_deterministic() {
        let mut t1 = Transcript::new(b"test");
        t1.append_message(b"msg", b"hello");
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        t2.append_message(b"msg", b"hello");
        let c2 = t2.challenge_scalar(b"challenge");

        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_scalar_differs_with_different_messages() {
        let mut t1 = Transcript::new(b"test");
        t1.append_message(b"msg", b"hello");
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        t2.append_message(b"msg", b"world");
        let c2 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn append_scalar_affects_transcript() {
        let scalar = Scalar::ONE;

        let mut t1 = Transcript::new(b"test");
        t1.append_scalar(b"s", &scalar);
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        let c2 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn domain_separators_affect_transcript() {
        let mut t1 = Transcript::new(b"test");
        t1.pubkey_proof_domain_separator();
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        t2.zero_ciphertext_proof_domain_separator();
        let c2 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn range_proof_domain_separator_varies_by_n() {
        let mut t1 = Transcript::new(b"test");
        t1.range_proof_domain_separator(64);
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        t2.range_proof_domain_separator(128);
        let c2 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn grouped_validity_domain_separator_varies_by_handles() {
        let mut t1 = Transcript::new(b"test");
        t1.grouped_ciphertext_validity_proof_domain_separator(2);
        let c1 = t1.challenge_scalar(b"challenge");

        let mut t2 = Transcript::new(b"test");
        t2.grouped_ciphertext_validity_proof_domain_separator(3);
        let c2 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2);
    }
}
