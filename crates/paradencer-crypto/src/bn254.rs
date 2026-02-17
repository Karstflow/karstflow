//! BN254 (alt_bn128) elliptic curve operations.
//!
//! Provides point addition, scalar multiplication, and pairing checks
//! on the BN254 curve used for zero-knowledge proof verification.
//! Field elements are encoded as 32-byte big-endian unsigned integers.

use crate::{CryptoError, CryptoResult};
use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

/// Size of a single G1 point in the serialized input (x: 32 bytes, y: 32 bytes).
const G1_INPUT_SIZE: usize = 64;

/// Add two G1 points on the BN254 curve.
///
/// Takes 128 bytes of input (two 64-byte big-endian G1 points) and
/// returns the 64-byte encoding of the sum point.
pub fn g1_add(input: &[u8]) -> CryptoResult<[u8; 64]> {
    if input.len() != 128 {
        return Err(CryptoError::InvalidMessageLength(input.len()));
    }

    let p1 = decode_g1_point(&input[..64])?;
    let p2 = decode_g1_point(&input[64..])?;

    let sum = p1 + p2;
    encode_g1_point(&sum)
}

/// Multiply a G1 point by a scalar.
///
/// Takes 96 bytes of input: a 64-byte G1 point followed by a 32-byte
/// big-endian scalar, and returns the 64-byte encoding of the product.
pub fn g1_mul(input: &[u8]) -> CryptoResult<[u8; 64]> {
    if input.len() != 96 {
        return Err(CryptoError::InvalidMessageLength(input.len()));
    }

    let point = decode_g1_point(&input[..64])?;
    let scalar = Fr::from_slice(&input[64..96])
        .map_err(|_| CryptoError::InternalError("invalid scalar field element".to_string()))?;

    let product = point * scalar;
    encode_g1_point(&product)
}

/// Check a BN254 pairing equation.
///
/// Input is a sequence of (G1, G2) pairs, each 192 bytes. Verifies that
/// the product of pairings e(P_i, Q_i) equals the identity in Gt.
/// Returns `true` if the pairing check passes.
pub fn pairing_check(input: &[u8]) -> CryptoResult<bool> {
    if !input.len().is_multiple_of(192) {
        return Err(CryptoError::InvalidMessageLength(input.len()));
    }

    let num_pairs = input.len() / 192;

    // Empty input is a valid pairing check that passes trivially.
    if num_pairs == 0 {
        return Ok(true);
    }

    let mut pairs = Vec::with_capacity(num_pairs);

    for i in 0..num_pairs {
        let offset = i * 192;
        let g1 = decode_g1_point(&input[offset..offset + G1_INPUT_SIZE])?;
        let g2 = decode_g2_point(&input[offset + G1_INPUT_SIZE..offset + 192])?;
        pairs.push((g1, g2));
    }

    let result = pairing_batch(&pairs);
    Ok(result == Gt::one())
}

// --- Internal helpers ---

/// Decode a 64-byte big-endian G1 point.
///
/// The point at infinity is represented as (0, 0).
fn decode_g1_point(data: &[u8]) -> CryptoResult<G1> {
    let x = Fq::from_slice(&data[..32])
        .map_err(|_| CryptoError::InternalError("invalid G1 x-coordinate".to_string()))?;
    let y = Fq::from_slice(&data[32..64])
        .map_err(|_| CryptoError::InternalError("invalid G1 y-coordinate".to_string()))?;

    if x.is_zero() && y.is_zero() {
        return Ok(G1::zero());
    }

    let point = AffineG1::new(x, y)
        .map_err(|_| CryptoError::InvalidPublicKey("G1 point not on curve".to_string()))?;

    Ok(point.into())
}

/// Decode a 128-byte big-endian G2 point.
///
/// G2 coordinates are elements of Fq2, each encoded as two 32-byte
/// field elements in (imaginary, real) order.
fn decode_g2_point(data: &[u8]) -> CryptoResult<G2> {
    let x_imag = Fq::from_slice(&data[..32])
        .map_err(|_| CryptoError::InternalError("invalid G2 x imaginary".to_string()))?;
    let x_real = Fq::from_slice(&data[32..64])
        .map_err(|_| CryptoError::InternalError("invalid G2 x real".to_string()))?;
    let y_imag = Fq::from_slice(&data[64..96])
        .map_err(|_| CryptoError::InternalError("invalid G2 y imaginary".to_string()))?;
    let y_real = Fq::from_slice(&data[96..128])
        .map_err(|_| CryptoError::InternalError("invalid G2 y real".to_string()))?;

    let x = Fq2::new(x_real, x_imag);
    let y = Fq2::new(y_real, y_imag);

    if x.is_zero() && y.is_zero() {
        return Ok(G2::zero());
    }

    let point = AffineG2::new(x, y)
        .map_err(|_| CryptoError::InvalidPublicKey("G2 point not on curve".to_string()))?;

    Ok(point.into())
}

/// Encode a G1 point as 64 bytes in big-endian form.
fn encode_g1_point(point: &G1) -> CryptoResult<[u8; 64]> {
    let mut output = [0u8; 64];

    if point.is_zero() {
        return Ok(output);
    }

    let affine = AffineG1::from_jacobian(*point)
        .ok_or_else(|| CryptoError::InternalError("failed to convert to affine".to_string()))?;

    affine
        .x()
        .to_big_endian(&mut output[..32])
        .map_err(|_| CryptoError::InternalError("failed to encode x-coordinate".to_string()))?;
    affine
        .y()
        .to_big_endian(&mut output[32..])
        .map_err(|_| CryptoError::InternalError("failed to encode y-coordinate".to_string()))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BN254 G1 generator point: (1, 2).
    fn g1_generator_bytes() -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[31] = 1; // x = 1
        buf[63] = 2; // y = 2
        buf
    }

    #[test]
    fn add_identity_returns_same_point() {
        let gen = g1_generator_bytes();
        let zero = [0u8; 64];

        let mut input = [0u8; 128];
        input[..64].copy_from_slice(&gen);
        input[64..].copy_from_slice(&zero);

        let result = g1_add(&input).unwrap();
        assert_eq!(&result[..], &gen[..]);
    }

    #[test]
    fn add_point_to_itself() {
        let gen = g1_generator_bytes();
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(&gen);
        input[64..].copy_from_slice(&gen);

        // G + G = 2G, should not be zero or the same as G
        let result = g1_add(&input).unwrap();
        assert_ne!(&result[..], &gen[..]);
        assert_ne!(&result[..], &[0u8; 64][..]);
    }

    #[test]
    fn mul_by_one_returns_same_point() {
        let gen = g1_generator_bytes();
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(&gen);
        input[95] = 1; // scalar = 1

        let result = g1_mul(&input).unwrap();
        assert_eq!(&result[..], &gen[..]);
    }

    #[test]
    fn mul_by_zero_returns_identity() {
        let gen = g1_generator_bytes();
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(&gen);
        // scalar = 0 (all zeros)

        let result = g1_mul(&input).unwrap();
        assert_eq!(&result[..], &[0u8; 64][..]);
    }

    #[test]
    fn mul_by_two_equals_add_to_self() {
        let gen = g1_generator_bytes();

        // 2 * G via multiplication
        let mut mul_input = [0u8; 96];
        mul_input[..64].copy_from_slice(&gen);
        mul_input[95] = 2; // scalar = 2
        let mul_result = g1_mul(&mul_input).unwrap();

        // G + G via addition
        let mut add_input = [0u8; 128];
        add_input[..64].copy_from_slice(&gen);
        add_input[64..].copy_from_slice(&gen);
        let add_result = g1_add(&add_input).unwrap();

        assert_eq!(&mul_result[..], &add_result[..]);
    }

    #[test]
    fn pairing_empty_input_passes() {
        assert!(pairing_check(b"").unwrap());
    }

    #[test]
    fn pairing_wrong_input_size_errors() {
        assert!(pairing_check(&[0u8; 100]).is_err());
    }

    #[test]
    fn pairing_with_zero_points_passes() {
        // A pair of (zero, zero) should pass: e(0, 0) = 1 in Gt.
        let input = [0u8; 192];
        assert!(pairing_check(&input).unwrap());
    }

    #[test]
    fn invalid_input_size_for_add() {
        assert!(g1_add(&[0u8; 100]).is_err());
    }

    #[test]
    fn invalid_input_size_for_mul() {
        assert!(g1_mul(&[0u8; 100]).is_err());
    }
}
