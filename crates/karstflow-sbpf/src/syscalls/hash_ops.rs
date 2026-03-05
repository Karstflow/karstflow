//! Blake3 hash syscall.
//!
//! Provides compute-metered access to the Blake3 cryptographic hash
//! function, which offers high throughput on modern hardware.

use super::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;

/// Compute Blake3 hash of input data.
///
/// Cost scales linearly with input length.
pub fn blake3_hash(ctx: &mut SyscallContext, data: &[u8]) -> Result<[u8; 32], SyscallError> {
    let cost = BLAKE3_BASE_COST + BLAKE3_PER_BYTE_COST * data.len() as u64;
    ctx.consume_compute(cost)?;

    let hash = blake3::hash(data);
    Ok(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    #[test]
    fn blake3_deterministic() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = blake3_hash(&mut c1, b"test data").unwrap();
        let h2 = blake3_hash(&mut c2, b"test data").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_different_inputs_differ() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let h1 = blake3_hash(&mut c1, b"aaa").unwrap();
        let h2 = blake3_hash(&mut c2, b"bbb").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake3_empty_input() {
        let mut c = ctx(100_000);
        let hash = blake3_hash(&mut c, b"").unwrap();
        // Blake3 of empty input is well-defined
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn blake3_consumes_compute() {
        let mut c = ctx(5);
        assert!(blake3_hash(&mut c, b"hello").is_err());
    }

    #[test]
    fn blake3_cost_scales_with_length() {
        let short_data = b"hi";
        let long_data = vec![0u8; 1000];
        let short_cost = BLAKE3_BASE_COST + BLAKE3_PER_BYTE_COST * short_data.len() as u64;
        let long_cost = BLAKE3_BASE_COST + BLAKE3_PER_BYTE_COST * long_data.len() as u64;
        assert!(long_cost > short_cost);

        let mut c = ctx(short_cost);
        assert!(blake3_hash(&mut c, short_data).is_ok());
        assert_eq!(c.compute_meter, 0);
    }

    #[test]
    fn blake3_differs_from_sha256() {
        let mut c1 = ctx(100_000);
        let mut c2 = ctx(100_000);
        let blake = blake3_hash(&mut c1, b"hello").unwrap();
        let sha = super::super::sha256(&mut c2, b"hello").unwrap();
        assert_ne!(blake, sha);
    }
}
