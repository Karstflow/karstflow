//! Elliptic curve operations for alt_bn128.
//!
//! These syscalls are used for zero-knowledge proof verification on-chain.
//! The alt_bn128 curve (also known as BN254) supports point addition,
//! scalar multiplication, and pairing checks.
//!
//! Current implementation is a compute-metered stub. Actual curve math
//! requires a dedicated alt_bn128 library.

pub mod alt_bn128 {
    use crate::syscalls::{SyscallContext, SyscallError};
    use paradencer_constants::syscalls::*;

    /// Expected input size for a point addition (two uncompressed points).
    const ADD_INPUT_SIZE: usize = 128;

    /// Expected input size for a scalar multiplication (point + scalar).
    const MUL_INPUT_SIZE: usize = 96;

    /// Size of a single pairing input pair (G1 point + G2 point).
    const PAIRING_PAIR_SIZE: usize = 192;

    /// Point addition on the alt_bn128 curve.
    ///
    /// Takes two uncompressed curve points (64 bytes each) and returns
    /// their sum as an uncompressed point.
    pub fn add(ctx: &mut SyscallContext, input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        ctx.consume_compute(ALT_BN128_ADD_COST)?;

        if input.len() != ADD_INPUT_SIZE {
            return Err(SyscallError::InvalidArgument(format!(
                "alt_bn128 add expects {} bytes, got {}",
                ADD_INPUT_SIZE,
                input.len()
            )));
        }

        // Stub: return a zero point as placeholder.
        // Real implementation would perform EC point addition.
        Ok(vec![0u8; 64])
    }

    /// Scalar multiplication on the alt_bn128 curve.
    ///
    /// Takes an uncompressed curve point (64 bytes) and a scalar (32 bytes)
    /// and returns the product point.
    pub fn mul(ctx: &mut SyscallContext, input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        ctx.consume_compute(ALT_BN128_MUL_COST)?;

        if input.len() != MUL_INPUT_SIZE {
            return Err(SyscallError::InvalidArgument(format!(
                "alt_bn128 mul expects {} bytes, got {}",
                MUL_INPUT_SIZE,
                input.len()
            )));
        }

        // Stub: return a zero point as placeholder.
        Ok(vec![0u8; 64])
    }

    /// Pairing check on the alt_bn128 curve.
    ///
    /// Takes a sequence of (G1, G2) point pairs and verifies the pairing
    /// equation. Returns true if the pairing check passes.
    pub fn pairing(ctx: &mut SyscallContext, input: &[u8]) -> Result<bool, SyscallError> {
        if input.len() % PAIRING_PAIR_SIZE != 0 {
            return Err(SyscallError::InvalidArgument(format!(
                "alt_bn128 pairing input must be a multiple of {} bytes, got {}",
                PAIRING_PAIR_SIZE,
                input.len()
            )));
        }

        let num_pairs = input.len() / PAIRING_PAIR_SIZE;
        let cost = ALT_BN128_PAIRING_BASE_COST + ALT_BN128_PAIRING_PER_PAIR_COST * num_pairs as u64;
        ctx.consume_compute(cost)?;

        // Stub: return true as placeholder.
        // Real implementation would perform the bilinear pairing check.
        Ok(true)
    }
}
