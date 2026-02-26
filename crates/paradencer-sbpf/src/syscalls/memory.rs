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

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::Pubkey;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    #[test]
    fn memcpy_copies_bytes() {
        let mut c = ctx(100_000);
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        sol_memcpy(&mut c, &mut dst, &src, 5).unwrap();
        assert_eq!(dst, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn memcpy_partial() {
        let mut c = ctx(100_000);
        let src = [10, 20, 30];
        let mut dst = [0u8; 5];
        sol_memcpy(&mut c, &mut dst, &src, 2).unwrap();
        assert_eq!(dst[..2], [10, 20]);
        assert_eq!(dst[2], 0);
    }

    #[test]
    fn memcpy_rejects_dst_too_small() {
        let mut c = ctx(100_000);
        let src = [1, 2, 3];
        let mut dst = [0u8; 2];
        assert!(sol_memcpy(&mut c, &mut dst, &src, 3).is_err());
    }

    #[test]
    fn memcpy_rejects_src_too_small() {
        let mut c = ctx(100_000);
        let src = [1, 2];
        let mut dst = [0u8; 5];
        assert!(sol_memcpy(&mut c, &mut dst, &src, 3).is_err());
    }

    #[test]
    fn memcpy_consumes_compute() {
        let mut c = ctx(10);
        let src = [0u8; 100];
        let mut dst = [0u8; 100];
        // Should exceed budget
        assert!(sol_memcpy(&mut c, &mut dst, &src, 100).is_err());
    }

    #[test]
    fn memcmp_equal() {
        let mut c = ctx(100_000);
        assert_eq!(sol_memcmp(&mut c, b"abc", b"abc", 3).unwrap(), 0);
    }

    #[test]
    fn memcmp_less() {
        let mut c = ctx(100_000);
        let result = sol_memcmp(&mut c, b"abc", b"abd", 3).unwrap();
        assert!(result < 0);
    }

    #[test]
    fn memcmp_greater() {
        let mut c = ctx(100_000);
        let result = sol_memcmp(&mut c, b"abd", b"abc", 3).unwrap();
        assert!(result > 0);
    }

    #[test]
    fn memcmp_partial() {
        let mut c = ctx(100_000);
        assert_eq!(sol_memcmp(&mut c, b"abx", b"aby", 2).unwrap(), 0);
    }

    #[test]
    fn memmove_copies_bytes() {
        let mut c = ctx(100_000);
        let src = [5, 6, 7];
        let mut dst = [0u8; 3];
        sol_memmove(&mut c, &mut dst, &src, 3).unwrap();
        assert_eq!(dst, [5, 6, 7]);
    }

    #[test]
    fn memmove_rejects_dst_too_small() {
        let mut c = ctx(100_000);
        let src = [1, 2, 3];
        let mut dst = [0u8; 2];
        assert!(sol_memmove(&mut c, &mut dst, &src, 3).is_err());
    }

    #[test]
    fn memset_fills_value() {
        let mut c = ctx(100_000);
        let mut dst = [0u8; 5];
        sol_memset(&mut c, &mut dst, 0xAB, 5).unwrap();
        assert_eq!(dst, [0xAB; 5]);
    }

    #[test]
    fn memset_partial() {
        let mut c = ctx(100_000);
        let mut dst = [0u8; 5];
        sol_memset(&mut c, &mut dst, 0xFF, 3).unwrap();
        assert_eq!(dst, [0xFF, 0xFF, 0xFF, 0, 0]);
    }

    #[test]
    fn memset_rejects_dst_too_small() {
        let mut c = ctx(100_000);
        let mut dst = [0u8; 2];
        assert!(sol_memset(&mut c, &mut dst, 0, 5).is_err());
    }
}
