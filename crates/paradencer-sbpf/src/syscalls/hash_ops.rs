//! Blake3 hash syscall.
//!
//! Provides compute-metered access to the Blake3 cryptographic hash
//! function, which offers high throughput on modern hardware.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;

/// Compute Blake3 hash of input data.
///
/// Cost scales linearly with input length.
pub fn blake3_hash(ctx: &mut SyscallContext, data: &[u8]) -> Result<[u8; 32], SyscallError> {
    let cost = BLAKE3_BASE_COST + BLAKE3_PER_BYTE_COST * data.len() as u64;
    ctx.consume_compute(cost)?;

    let hash = blake3::hash(data);
    Ok(*hash.as_bytes())
}
