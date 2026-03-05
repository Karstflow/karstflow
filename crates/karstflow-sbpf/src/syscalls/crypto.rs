//! Cryptographic hash and signature verification syscalls.
//!
//! Provides SHA-256, Keccak-256, and secp256k1 signature recovery
//! operations, each metered by compute cost.

use super::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Compute SHA-256 hash of input data.
///
/// Cost scales linearly with input length.
pub fn sha256(ctx: &mut SyscallContext, data: &[u8]) -> Result<[u8; 32], SyscallError> {
    let cost = SHA256_BASE_COST + SHA256_PER_BYTE_COST * data.len() as u64;
    ctx.consume_compute(cost)?;

    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// Compute Keccak-256 hash of input data.
///
/// Uses the real Keccak-256 algorithm (not SHA-3) for Ethereum compatibility.
pub fn keccak256(ctx: &mut SyscallContext, data: &[u8]) -> Result<[u8; 32], SyscallError> {
    let cost = KECCAK256_BASE_COST + KECCAK256_PER_BYTE_COST * data.len() as u64;
    ctx.consume_compute(cost)?;

    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Ok(output)
}

/// Recover a secp256k1 public key from a message hash and signature.
///
/// Returns the 64-byte uncompressed public key (x || y) without the
/// 0x04 prefix. The `recovery_id` must be in the range 0..=3.
pub fn secp256k1_recover(
    ctx: &mut SyscallContext,
    hash: &[u8; 32],
    recovery_id: u8,
    signature: &[u8; 64],
) -> Result<[u8; 64], SyscallError> {
    ctx.consume_compute(SECP256K1_RECOVER_COST)?;

    if recovery_id > 3 {
        return Err(SyscallError::InvalidArgument(
            "recovery_id must be 0-3".to_string(),
        ));
    }

    let recid = k256::ecdsa::RecoveryId::from_byte(recovery_id).ok_or_else(|| {
        SyscallError::InvalidArgument(format!("invalid recovery id: {}", recovery_id))
    })?;

    let sig = k256::ecdsa::Signature::from_slice(signature).map_err(|e| {
        SyscallError::InvalidArgument(format!("invalid secp256k1 signature: {}", e))
    })?;

    let recovered_key = k256::ecdsa::VerifyingKey::recover_from_prehash(hash, &sig, recid)
        .map_err(|e| SyscallError::InvalidArgument(format!("secp256k1 recovery failed: {}", e)))?;

    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point = recovered_key.to_encoded_point(false);
    let bytes = point.as_bytes();

    // Uncompressed encoding: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes.
    if bytes.len() != 65 {
        return Err(SyscallError::InvalidArgument(
            "unexpected recovered key length".to_string(),
        ));
    }

    let mut result = [0u8; 64];
    result.copy_from_slice(&bytes[1..]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    #[test]
    fn sha256_deterministic() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = sha256(&mut c1, b"test data").unwrap();
        let h2 = sha256(&mut c2, b"test data").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = sha256(&mut c1, b"aaa").unwrap();
        let h2 = sha256(&mut c2, b"bbb").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_consumes_compute() {
        let mut c = ctx(5);
        assert!(sha256(&mut c, b"hello").is_err());
    }

    #[test]
    fn keccak256_deterministic() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = keccak256(&mut c1, b"test data").unwrap();
        let h2 = keccak256(&mut c2, b"test data").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn keccak256_different_inputs_differ() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = keccak256(&mut c1, b"aaa").unwrap();
        let h2 = keccak256(&mut c2, b"bbb").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_and_keccak256_differ() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = sha256(&mut c1, b"hello").unwrap();
        let h2 = keccak256(&mut c2, b"hello").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn secp256k1_recover_rejects_bad_recovery_id() {
        let mut c = ctx(100_000);
        let hash = [0u8; 32];
        let sig = [0u8; 64];
        assert!(secp256k1_recover(&mut c, &hash, 4, &sig).is_err());
    }
}
