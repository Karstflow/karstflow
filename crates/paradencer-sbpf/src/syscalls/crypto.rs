//! Cryptographic hash and signature verification syscalls.
//!
//! Provides SHA-256, Keccak-256, and secp256k1 signature recovery
//! operations, each metered by compute cost.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;
use sha2::{Digest, Sha256};

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
/// Uses a simplified implementation (SHA-256 based stub) since the full
/// sha3 crate is not in the workspace. The compute metering is accurate.
pub fn keccak256(ctx: &mut SyscallContext, data: &[u8]) -> Result<[u8; 32], SyscallError> {
    let cost = KECCAK256_BASE_COST + KECCAK256_PER_BYTE_COST * data.len() as u64;
    ctx.consume_compute(cost)?;

    // Stub: use SHA-256 with a domain separator to produce distinct output.
    // The actual implementation requires the sha3 crate for real Keccak-256.
    let mut hasher = Sha256::new();
    hasher.update(b"keccak256_domain_sep");
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// Recover a secp256k1 public key from a message hash and signature.
///
/// This is a stub implementation that deducts the correct compute cost
/// but returns a deterministic placeholder result. A full implementation
/// requires the k256 or libsecp256k1 crate.
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

    // Stub: produce a deterministic output from inputs.
    // Real implementation would use k256::ecdsa for actual recovery.
    let mut result = [0u8; 64];
    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.update(&[recovery_id]);
    hasher.update(signature);
    let digest: [u8; 32] = hasher.finalize().into();
    result[..32].copy_from_slice(&digest);

    let mut hasher2 = Sha256::new();
    hasher2.update(&digest);
    hasher2.update(b"secp256k1_recover_part2");
    let digest2: [u8; 32] = hasher2.finalize().into();
    result[32..].copy_from_slice(&digest2);

    Ok(result)
}
