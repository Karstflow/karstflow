//! Secp256r1 (NIST P-256) ECDSA signature verification.
//!
//! Provides signature verification and public key decompression for
//! the P-256 elliptic curve, used by the Solana secp256r1 precompile
//! program for WebAuthn and passkey-based authentication.

use crate::{CryptoError, CryptoResult};
use p256::ecdsa::{Signature, VerifyingKey};

/// Verify a P-256 ECDSA signature against a compressed or SEC1-encoded
/// public key and a pre-hashed message digest.
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

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    match verifying_key.verify_prehash(message_hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a P-256 ECDSA signature against a 64-byte uncompressed public
/// key (without the 0x04 prefix) and a pre-hashed message digest.
///
/// This is a convenience wrapper that prepends the 0x04 tag before
/// delegating to the standard verification path.
pub fn verify_uncompressed(
    public_key_xy: &[u8; 64],
    message_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> CryptoResult<bool> {
    let mut full = [0u8; 65];
    full[0] = 0x04;
    full[1..].copy_from_slice(public_key_xy);
    verify(&full, message_hash, signature_bytes)
}

/// Decompress a 33-byte compressed P-256 public key into the
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
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn verify_valid_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0x42u8; 32];

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: Signature = signing_key.sign_prehash(&message_hash).unwrap();

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
    fn verify_rejects_wrong_hash() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0xAA; 32];

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: Signature = signing_key.sign_prehash(&message_hash).unwrap();

        let wrong_hash = [0xBB; 32];
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
    fn verify_uncompressed_key() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message_hash = [0x55; 32];

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: Signature = signing_key.sign_prehash(&message_hash).unwrap();

        let uncompressed = verifying_key.to_encoded_point(false);
        let xy: [u8; 64] = uncompressed.as_bytes()[1..].try_into().unwrap();

        let valid = verify_uncompressed(&xy, &message_hash, &signature.to_bytes().into()).unwrap();
        assert!(valid);
    }

    #[test]
    fn decompress_roundtrip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let compressed_point = verifying_key.to_encoded_point(true);
        let compressed_bytes: [u8; 33] = compressed_point.as_bytes().try_into().unwrap();

        let decompressed = decompress_public_key(&compressed_bytes).unwrap();

        let expected = verifying_key.to_encoded_point(false);
        assert_eq!(&decompressed[..], expected.as_bytes());
    }

    #[test]
    fn invalid_compressed_key_errors() {
        let bad_key = [0u8; 33];
        assert!(decompress_public_key(&bad_key).is_err());
    }
}
