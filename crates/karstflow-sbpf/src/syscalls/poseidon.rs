//! Poseidon hash syscall for BN254 field elements.
//!
//! Implements the `sol_poseidon` syscall which computes a Poseidon hash
//! over a sequence of BN254 field elements. Uses the Light protocol
//! parameter set (BN254 x5) compatible with on-chain ZK applications.

use crate::syscalls::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonError};

/// Compute a Poseidon hash over a sequence of 32-byte field elements.
///
/// The `params` parameter selects the parameter set (only 0 = Light protocol is valid).
/// The `endianness` parameter selects input encoding (0 = big-endian, 1 = little-endian).
/// Each input element must be exactly 32 bytes representing a BN254 scalar field element.
///
/// Returns `Ok(0)` on success with the 32-byte hash written to `result`,
/// or `Ok(1)` on a soft error (e.g., invalid input element).
pub fn poseidon_hash(
    ctx: &mut SyscallContext,
    params: u64,
    endianness: u64,
    inputs: &[&[u8]],
    result: &mut [u8; 32],
) -> Result<u64, SyscallError> {
    // Validate parameter set
    if params != POSEIDON_PARAMS_LIGHT {
        return Err(SyscallError::InvalidArgument(
            "invalid poseidon parameter set".into(),
        ));
    }

    // Validate endianness
    if endianness != POSEIDON_ENDIAN_BIG && endianness != POSEIDON_ENDIAN_LITTLE {
        return Err(SyscallError::InvalidArgument(
            "invalid poseidon endianness".into(),
        ));
    }

    let vals_len = inputs.len();

    // Validate input count
    if vals_len > POSEIDON_MAX_INPUTS {
        return Err(SyscallError::InvalidArgument(format!(
            "Poseidon hashing {} sequences is not supported",
            vals_len
        )));
    }

    // Compute cost: A * n^2 + C
    let cost = POSEIDON_COST_COEFFICIENT_A
        .saturating_mul((vals_len as u64).saturating_mul(vals_len as u64))
        .saturating_add(POSEIDON_COST_COEFFICIENT_C);
    ctx.consume_compute(cost)?;

    // Empty input returns soft error
    if vals_len == 0 {
        return Ok(1);
    }

    // Compute Poseidon hash using light-poseidon
    let is_big_endian = endianness == POSEIDON_ENDIAN_BIG;
    match compute_poseidon(inputs, is_big_endian) {
        Ok(hash) => {
            result.copy_from_slice(&hash);
            Ok(0)
        }
        Err(_) => Ok(1),
    }
}

/// Internal Poseidon computation using the light-poseidon crate.
fn compute_poseidon(inputs: &[&[u8]], big_endian: bool) -> Result<[u8; 32], PoseidonError> {
    let nr_inputs = inputs.len();
    let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(nr_inputs)?;

    if big_endian {
        hasher.hash_bytes_be(inputs)
    } else {
        hasher.hash_bytes_le(inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn test_ctx() -> SyscallContext {
        SyscallContext::new(Pubkey::zeroed(), 1_000_000)
    }

    #[test]
    fn poseidon_single_input() {
        let mut ctx = test_ctx();
        let input = [1u8; 32];
        let mut result = [0u8; 32];
        let ret = poseidon_hash(&mut ctx, 0, 0, &[&input], &mut result).unwrap();
        assert_eq!(ret, 0);
        assert_ne!(result, [0u8; 32]); // Hash should be non-zero
    }

    #[test]
    fn poseidon_two_inputs() {
        let mut ctx = test_ctx();
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        let mut result = [0u8; 32];
        let ret = poseidon_hash(&mut ctx, 0, 0, &[&input1, &input2], &mut result).unwrap();
        assert_eq!(ret, 0);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn poseidon_empty_returns_soft_error() {
        let mut ctx = test_ctx();
        let mut result = [0u8; 32];
        let ret = poseidon_hash(&mut ctx, 0, 0, &[], &mut result).unwrap();
        assert_eq!(ret, 1);
    }

    #[test]
    fn poseidon_too_many_inputs_errors() {
        let mut ctx = test_ctx();
        let input = [0u8; 32];
        let inputs: Vec<&[u8]> = (0..13).map(|_| input.as_ref()).collect();
        let mut result = [0u8; 32];
        let err = poseidon_hash(&mut ctx, 0, 0, &inputs, &mut result);
        assert!(err.is_err());
    }

    #[test]
    fn poseidon_invalid_params_errors() {
        let mut ctx = test_ctx();
        let input = [1u8; 32];
        let mut result = [0u8; 32];
        let err = poseidon_hash(&mut ctx, 1, 0, &[&input], &mut result);
        assert!(err.is_err());
    }

    #[test]
    fn poseidon_invalid_endianness_errors() {
        let mut ctx = test_ctx();
        let input = [1u8; 32];
        let mut result = [0u8; 32];
        let err = poseidon_hash(&mut ctx, 0, 2, &[&input], &mut result);
        assert!(err.is_err());
    }

    #[test]
    fn poseidon_big_endian_vs_little_endian_differ() {
        let mut ctx = test_ctx();
        // Use an asymmetric input so BE vs LE gives different results
        let mut input = [0u8; 32];
        input[0] = 1; // BE: high byte set; LE: would be low byte

        let mut result_be = [0u8; 32];
        let mut result_le = [0u8; 32];
        poseidon_hash(&mut ctx, 0, 0, &[&input], &mut result_be).unwrap();

        let mut ctx2 = test_ctx();
        poseidon_hash(&mut ctx2, 0, 1, &[&input], &mut result_le).unwrap();

        // For the same bytes, BE and LE interpretations should differ
        assert_ne!(result_be, result_le);
    }

    #[test]
    fn poseidon_deterministic() {
        let mut ctx1 = test_ctx();
        let mut ctx2 = test_ctx();
        let input = [42u8; 32];
        let mut r1 = [0u8; 32];
        let mut r2 = [0u8; 32];
        poseidon_hash(&mut ctx1, 0, 0, &[&input], &mut r1).unwrap();
        poseidon_hash(&mut ctx2, 0, 0, &[&input], &mut r2).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn poseidon_max_inputs() {
        let mut ctx = test_ctx();
        let input = [1u8; 32];
        let inputs: Vec<&[u8]> = (0..12).map(|_| input.as_ref()).collect();
        let mut result = [0u8; 32];
        let ret = poseidon_hash(&mut ctx, 0, 0, &inputs, &mut result).unwrap();
        assert_eq!(ret, 0);
    }

    #[test]
    fn poseidon_cost_model() {
        let mut ctx = test_ctx();
        let initial = ctx.compute_meter;
        let input = [1u8; 32];
        let mut result = [0u8; 32];
        poseidon_hash(&mut ctx, 0, 0, &[&input, &input, &input], &mut result).unwrap();

        // Cost should be A * 3^2 + C = 61 * 9 + 542 = 549 + 542 = 1091
        let expected_cost = 61 * 9 + 542;
        assert_eq!(initial - ctx.compute_meter, expected_cost);
    }
}
