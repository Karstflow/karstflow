//! Secp256k1 ECDSA signature verification and public key recovery.
//!
//! Supports operations needed for Ethereum-compatible signature
//! verification on Solana: key recovery from a message hash and
//! recoverable signature, direct verification, and compressed
//! public key decompression.

use crate::{CryptoError, CryptoResult};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// Recover the uncompressed public key from a message hash and signature.
///
/// Returns the 64-byte uncompressed public key (x || y) without the
/// 0x04 prefix byte. The `recovery_id` must be in the range 0..=3.
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

    let recovered = VerifyingKey::recover_from_prehash(message_hash, &signature, recid)
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
pub fn verify(
    public_key_bytes: &[u8],
    message_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> CryptoResult<bool> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    match verifying_key.verify_prehash(message_hash, &signature) {
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
}
