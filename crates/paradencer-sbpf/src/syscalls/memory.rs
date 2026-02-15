//! Memory manipulation syscalls.
//!
//! Provides compute-metered memory operations analogous to libc's
//! memcpy, memcmp, memmove, and memset. These are used by programs
//! for efficient bulk memory operations within their heap.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;

/// Copy bytes from source to destination (non-overlapping).
///
/// The caller must ensure `src` and `dst` do not overlap. For
/// overlapping regions, use `sol_memmove` instead.
pub fn sol_memcpy(
    ctx: &mut SyscallContext,
    dst: &mut [u8],
    src: &[u8],
    len: usize,
) -> Result<(), SyscallError> {
    let cost = MEMCPY_BASE_COST + MEMCPY_PER_BYTE_COST * len as u64;
    ctx.consume_compute(cost)?;

    if len > dst.len() {
        return Err(SyscallError::AccessViolation(
            "destination buffer too small for memcpy".to_string(),
        ));
    }
    if len > src.len() {
        return Err(SyscallError::AccessViolation(
            "source buffer too small for memcpy".to_string(),
        ));
    }

    dst[..len].copy_from_slice(&src[..len]);
    Ok(())
}

/// Compare two byte slices lexicographically.
///
/// Returns a negative value if `a < b`, zero if `a == b`, or a positive
/// value if `a > b` (comparing only the first `len` bytes).
pub fn sol_memcmp(
    ctx: &mut SyscallContext,
    a: &[u8],
    b: &[u8],
    len: usize,
) -> Result<i32, SyscallError> {
    let cost = MEMCMP_BASE_COST + MEMCMP_PER_BYTE_COST * len as u64;
    ctx.consume_compute(cost)?;

    if len > a.len() {
        return Err(SyscallError::AccessViolation(
            "first buffer too small for memcmp".to_string(),
        ));
    }
    if len > b.len() {
        return Err(SyscallError::AccessViolation(
            "second buffer too small for memcmp".to_string(),
        ));
    }

    for i in 0..len {
        let diff = a[i] as i32 - b[i] as i32;
        if diff != 0 {
            return Ok(diff);
        }
    }
    Ok(0)
}

/// Copy bytes from source to destination, handling overlapping regions.
///
/// Safe to use when source and destination memory regions overlap.
pub fn sol_memmove(
    ctx: &mut SyscallContext,
    dst: &mut [u8],
    src: &[u8],
    len: usize,
) -> Result<(), SyscallError> {
    // Memmove has the same cost model as memcpy.
    let cost = MEMCPY_BASE_COST + MEMCPY_PER_BYTE_COST * len as u64;
    ctx.consume_compute(cost)?;

    if len > dst.len() {
        return Err(SyscallError::AccessViolation(
            "destination buffer too small for memmove".to_string(),
        ));
    }
    if len > src.len() {
        return Err(SyscallError::AccessViolation(
            "source buffer too small for memmove".to_string(),
        ));
    }

    // Use a temporary buffer to handle potential overlap safely.
    let tmp: Vec<u8> = src[..len].to_vec();
    dst[..len].copy_from_slice(&tmp);
    Ok(())
}

/// Fill a byte slice with a repeated value.
pub fn sol_memset(
    ctx: &mut SyscallContext,
    dst: &mut [u8],
    val: u8,
    len: usize,
) -> Result<(), SyscallError> {
    let cost = MEMSET_BASE_COST + MEMSET_PER_BYTE_COST * len as u64;
    ctx.consume_compute(cost)?;

    if len > dst.len() {
        return Err(SyscallError::AccessViolation(
            "destination buffer too small for memset".to_string(),
        ));
    }

    dst[..len].fill(val);
    Ok(())
}
