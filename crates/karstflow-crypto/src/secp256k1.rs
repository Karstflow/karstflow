//! Secp256k1 ECDSA signature verification and public key recovery.
//!
//! Supports operations needed for Ethereum-compatible signature
//! verification on Solana: key recovery from a message hash and
//! recoverable signature, direct verification, and compressed
//! public key decompression.

use crate::{CryptoError, CryptoResult};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::ops::Reduce;

/// Reduce a 32-byte message hash modulo the secp256k1 curve order.
///
/// Matches the behavior of libsecp256k1 (Bitcoin reference) and
/// Firedancer's fd_secp256k1. The message bytes are interpreted as
/// a big-endian unsigned integer and unconditionally reduced modulo
/// the curve order n. For most hashes this is a no-op (hash < n),
/// but for values >= n this ensures correct ECDSA math.
#[inline]
fn reduce_message_hash(hash: &[u8; 32]) -> [u8; 32] {
    let scalar = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(hash.into());
    scalar.to_bytes().into()
}

/// Recover the uncompressed public key from a message hash and signature.
///
/// Returns the 64-byte uncompressed public key (x || y) without the
/// 0x04 prefix byte. The `recovery_id` must be in the range 0..=3.
///
/// The message hash is reduced modulo the curve order before recovery,
/// matching libsecp256k1 behavior.
pub fn recover_public_key(
    message_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
    recovery_id: u8,
) -> CryptoResult<[u8; 64]> {
    let recid = RecoveryId::from_byte(recovery_id).ok_or_else(|| {
        CryptoError::InvalidSignature(format!("invalid recovery id: {}", recovery_id))
    })?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

    let reduced_hash = reduce_message_hash(message_hash);
    let recovered = VerifyingKey::recover_from_prehash(&reduced_hash, &signature, recid)
        .map_err(|_| CryptoError::VerificationFailed)?;

    let point = recovered.to_encoded_point(false);
    let uncompressed = point.as_bytes();

    // The uncompressed encoding is 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes.
    // We strip the 0x04 prefix and return 64 bytes.
    if uncompressed.len() != 65 {
        return Err(CryptoError::InternalError(
            "unexpected uncompressed key length".to_string(),
        ));
    }

    let mut result = [0u8; 64];
    result.copy_from_slice(&uncompressed[1..]);
    Ok(result)
}

/// Verify a secp256k1 ECDSA signature against a public key and message hash.
///
/// The `public_key_bytes` should be the 33-byte compressed key or the
/// 65-byte uncompressed key (with 0x04 prefix).
///
/// The message hash is reduced modulo the curve order before verification,
/// matching libsecp256k1 behavior.
pub fn verify(
    public_key_bytes: &[u8],
    message_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> CryptoResult<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

    let reduced_hash = reduce_message_hash(message_hash);
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    match verifying_key.verify_prehash(&reduced_hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Decompress a 33-byte compressed secp256k1 public key into the
/// 65-byte uncompressed form (0x04 || x || y).
pub fn decompress_public_key(compressed: &[u8; 33]) -> CryptoResult<[u8; 65]> {
    let verifying_key = VerifyingKey::from_sec1_bytes(compressed)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();

    if bytes.len() != 65 {
        return Err(CryptoError::InternalError(
            "unexpected decompressed key length".to_string(),
        ));
    }

    let mut result = [0u8; 65];
    result.copy_from_slice(bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;

    /// secp256k1 curve order n (big-endian).
    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    #[test]
    fn recover_roundtrip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0x42u8; 32];

        let (signature, recid): (Signature, RecoveryId) =
            signing_key.sign_prehash_recoverable(&message_hash).unwrap();

        let recovered =
            recover_public_key(&message_hash, &signature.to_bytes().into(), recid.to_byte())
                .unwrap();

        // Compare with expected uncompressed key
        let expected = verifying_key.to_encoded_point(false);
        assert_eq!(&recovered[..], &expected.as_bytes()[1..]);
    }

    #[test]
    fn verify_valid_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0xAB; 32];

        let (signature, _): (Signature, RecoveryId) =
            signing_key.sign_prehash_recoverable(&message_hash).unwrap();

        let compressed = verifying_key.to_encoded_point(true);
        let valid = verify(
            compressed.as_bytes(),
            &message_hash,
            &signature.to_bytes().into(),
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0xAB; 32];

        let (signature, _): (Signature, RecoveryId) =
            signing_key.sign_prehash_recoverable(&message_hash).unwrap();

        let wrong_hash = [0xCD; 32];
        let compressed = verifying_key.to_encoded_point(true);
        let valid = verify(
            compressed.as_bytes(),
            &wrong_hash,
            &signature.to_bytes().into(),
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn decompress_roundtrip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let compressed_point = verifying_key.to_encoded_point(true);
        let compressed_bytes: [u8; 33] = compressed_point.as_bytes().try_into().unwrap();

        let uncompressed = decompress_public_key(&compressed_bytes).unwrap();

        let expected = verifying_key.to_encoded_point(false);
        assert_eq!(&uncompressed[..], expected.as_bytes());
    }

    #[test]
    fn invalid_recovery_id_errors() {
        let result = recover_public_key(&[0u8; 32], &[0u8; 64], 4);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_compressed_key_errors() {
        let bad_key = [0u8; 33];
        assert!(decompress_public_key(&bad_key).is_err());
    }

    // --- Scalar reduction tests ---

    #[test]
    fn reduce_hash_below_order_is_noop() {
        // A normal hash (all zeros) is below curve order — reduction is identity.
        let hash = [0u8; 32];
        assert_eq!(reduce_message_hash(&hash), hash);

        // Typical hash value well below n.
        let hash = [0x42u8; 32];
        assert_eq!(reduce_message_hash(&hash), hash);
    }

    #[test]
    fn reduce_hash_equal_to_order_gives_zero() {
        // hash == n should reduce to 0.
        let reduced = reduce_message_hash(&SECP256K1_ORDER);
        assert_eq!(reduced, [0u8; 32]);
    }

    #[test]
    fn reduce_hash_above_order() {
        // n + 1: should reduce to 1.
        let mut n_plus_1 = SECP256K1_ORDER;
        // Add 1 to least significant byte (big-endian, so last byte).
        n_plus_1[31] = n_plus_1[31].wrapping_add(1);
        // If wrapping overflowed, this is n+1 = ...4142 which is fine.
        let reduced = reduce_message_hash(&n_plus_1);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(reduced, expected);
    }

    #[test]
    fn reduce_all_ff_hash() {
        // 0xFF..FF (2^256 - 1) must be reduced modulo n.
        let hash = [0xFF; 32];
        let reduced = reduce_message_hash(&hash);
        // Must not equal input (since 2^256-1 > n).
        assert_ne!(reduced, hash);
        // Must not be zero (since 2^256-1 mod n != 0).
        assert_ne!(reduced, [0u8; 32]);
    }

    #[test]
    fn reduce_n_minus_1_is_identity() {
        // n - 1 is the largest valid scalar — should not change.
        let mut n_minus_1 = SECP256K1_ORDER;
        n_minus_1[31] = n_minus_1[31].wrapping_sub(1);
        assert_eq!(reduce_message_hash(&n_minus_1), n_minus_1);
    }

    #[test]
    fn recover_with_large_hash() {
        // Sign with a normal hash, then verify recovery works with
        // a hash that requires reduction (all-0xFF).
        let signing_key = SigningKey::random(&mut OsRng);

        // Use all-0xFF as message hash — this exceeds the curve order.
        let big_hash = [0xFF; 32];
        let (signature, recid): (Signature, RecoveryId) =
            signing_key.sign_prehash_recoverable(&big_hash).unwrap();

        // Recovery must succeed (scalar reduction handles the large hash).
        let recovered =
            recover_public_key(&big_hash, &signature.to_bytes().into(), recid.to_byte()).unwrap();

        let expected = signing_key.verifying_key().to_encoded_point(false);
        assert_eq!(&recovered[..], &expected.as_bytes()[1..]);
    }

    #[test]
    fn verify_with_large_hash() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let big_hash = [0xFF; 32];
        let (signature, _): (Signature, RecoveryId) =
            signing_key.sign_prehash_recoverable(&big_hash).unwrap();

        let compressed = verifying_key.to_encoded_point(true);
        let valid = verify(
            compressed.as_bytes(),
            &big_hash,
            &signature.to_bytes().into(),
        )
        .unwrap();
        assert!(valid);
    }
}
