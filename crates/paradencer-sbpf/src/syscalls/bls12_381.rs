//! BLS12-381 elliptic curve operations for on-chain verification.
//!
//! Provides G1/G2 point decompression and multi-pairing operations
//! used by the `sol_curve_decompress` and `sol_curve_pairing_map`
//! syscalls. Supports both big-endian and little-endian encodings.

use crate::syscalls::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;

/// Decompress a BLS12-381 G1 point from 48 bytes to 96 bytes.
///
/// Input: 48-byte compressed G1 point.
/// Output: 96-byte uncompressed affine G1 point (x, y each 48 bytes).
/// The point is validated to be on the curve and in the G1 subgroup.
/// Returns `Ok(0)` on success, `Ok(1)` on invalid input.
pub fn g1_decompress(
    _ctx: &mut SyscallContext,
    compressed: &[u8],
    output: &mut [u8],
    big_endian: bool,
) -> Result<u64, SyscallError> {
    if compressed.len() != BLS12_381_G1_COMPRESSED_SIZE {
        return Ok(1);
    }
    if output.len() < BLS12_381_G1_POINT_SIZE {
        return Ok(1);
    }

    // Convert to big-endian if input is little-endian.
    let be_input;
    let input_ref = if big_endian {
        compressed
    } else {
        be_input = reverse_48(compressed);
        &be_input
    };

    // Decompress using BLST.
    let mut affine = blst::blst_p1_affine::default();
    let err = unsafe { blst::blst_p1_uncompress(&mut affine, input_ref.as_ptr()) };
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Ok(1);
    }

    // Validate the point is in the G1 subgroup.
    let in_group = unsafe { blst::blst_p1_affine_in_g1(&affine) };
    if !in_group {
        return Ok(1);
    }

    // Serialize affine point to output: x (48 bytes) || y (48 bytes).
    let mut x_bytes = [0u8; 48];
    let mut y_bytes = [0u8; 48];
    unsafe {
        blst::blst_bendian_from_fp(x_bytes.as_mut_ptr(), &affine.x);
        blst::blst_bendian_from_fp(y_bytes.as_mut_ptr(), &affine.y);
    }

    if big_endian {
        output[..48].copy_from_slice(&x_bytes);
        output[48..96].copy_from_slice(&y_bytes);
    } else {
        // Reverse each 48-byte coordinate for little-endian output.
        let mut x_le = x_bytes;
        x_le.reverse();
        let mut y_le = y_bytes;
        y_le.reverse();
        output[..48].copy_from_slice(&x_le);
        output[48..96].copy_from_slice(&y_le);
    }

    Ok(0)
}

/// Decompress a BLS12-381 G2 point from 96 bytes to 192 bytes.
///
/// Input: 96-byte compressed G2 point.
/// Output: 192-byte uncompressed affine G2 point (x, y each as Fp2 = 2×48 bytes).
/// The point is validated to be on the curve and in the G2 subgroup.
/// Returns `Ok(0)` on success, `Ok(1)` on invalid input.
pub fn g2_decompress(
    _ctx: &mut SyscallContext,
    compressed: &[u8],
    output: &mut [u8],
    big_endian: bool,
) -> Result<u64, SyscallError> {
    if compressed.len() != BLS12_381_G2_COMPRESSED_SIZE {
        return Ok(1);
    }
    if output.len() < BLS12_381_G2_POINT_SIZE {
        return Ok(1);
    }

    // Convert to big-endian if input is little-endian.
    let be_input;
    let input_ref = if big_endian {
        compressed
    } else {
        be_input = reverse_48_elements(compressed);
        &be_input
    };

    // Decompress using BLST.
    let mut affine = blst::blst_p2_affine::default();
    let err = unsafe { blst::blst_p2_uncompress(&mut affine, input_ref.as_ptr()) };
    if err != blst::BLST_ERROR::BLST_SUCCESS {
        return Ok(1);
    }

    // Validate the point is in the G2 subgroup.
    let in_group = unsafe { blst::blst_p2_affine_in_g2(&affine) };
    if !in_group {
        return Ok(1);
    }

    // Serialize affine point to output.
    // G2 x = Fp2 (c0, c1), each 48 bytes. Similarly for y.
    // Wire format: x.c0 || x.c1 || y.c0 || y.c1 (big-endian).
    let mut buf = [0u8; 192];
    unsafe {
        blst::blst_bendian_from_fp(buf[0..48].as_mut_ptr(), &affine.x.fp[0]);
        blst::blst_bendian_from_fp(buf[48..96].as_mut_ptr(), &affine.x.fp[1]);
        blst::blst_bendian_from_fp(buf[96..144].as_mut_ptr(), &affine.y.fp[0]);
        blst::blst_bendian_from_fp(buf[144..192].as_mut_ptr(), &affine.y.fp[1]);
    }

    if big_endian {
        output[..192].copy_from_slice(&buf);
    } else {
        let le_buf = reverse_48_elements(&buf);
        output[..192].copy_from_slice(&le_buf);
    }

    Ok(0)
}

/// Compute a BLS12-381 multi-pairing operation.
///
/// Takes `n` pairs of (G1, G2) affine points and computes the product of
/// pairings: e(G1_0, G2_0) * e(G1_1, G2_1) * ... * e(G1_{n-1}, G2_{n-1}).
/// The result is a GT element (576 bytes = 12 × 48-byte field elements).
///
/// Returns `Ok(0)` on success with the GT element written to `output`.
/// Returns `Ok(1)` on invalid input (bad points, too many pairs, etc.).
pub fn pairing_map(
    _ctx: &mut SyscallContext,
    g1_data: &[u8],
    g2_data: &[u8],
    num_pairs: usize,
    output: &mut [u8],
    big_endian: bool,
) -> Result<u64, SyscallError> {
    if num_pairs == 0 {
        return Ok(1);
    }
    if num_pairs > BLS12_381_MAX_PAIRING_PAIRS {
        return Ok(1);
    }
    if g1_data.len() < num_pairs * BLS12_381_G1_POINT_SIZE {
        return Ok(1);
    }
    if g2_data.len() < num_pairs * BLS12_381_G2_POINT_SIZE {
        return Ok(1);
    }
    if output.len() < BLS12_381_GT_ELEMENT_SIZE {
        return Ok(1);
    }

    // Convert to big-endian if needed.
    let g1_be;
    let g1_ref = if big_endian {
        g1_data
    } else {
        g1_be = reverse_48_elements(g1_data);
        &g1_be
    };
    let g2_be;
    let g2_ref = if big_endian {
        g2_data
    } else {
        g2_be = reverse_48_elements(g2_data);
        &g2_be
    };

    // Deserialize and validate all G1 and G2 points.
    let mut g1_affines = Vec::with_capacity(num_pairs);
    let mut g2_affines = Vec::with_capacity(num_pairs);

    for i in 0..num_pairs {
        let g1_offset = i * BLS12_381_G1_POINT_SIZE;
        let g1_bytes = &g1_ref[g1_offset..g1_offset + BLS12_381_G1_POINT_SIZE];

        let mut g1_aff = blst::blst_p1_affine::default();
        unsafe {
            blst::blst_p1_deserialize(&mut g1_aff, g1_bytes.as_ptr());
        }
        let in_g1 = unsafe { blst::blst_p1_affine_in_g1(&g1_aff) };
        if !in_g1 {
            return Ok(1);
        }
        g1_affines.push(g1_aff);

        let g2_offset = i * BLS12_381_G2_POINT_SIZE;
        let g2_bytes = &g2_ref[g2_offset..g2_offset + BLS12_381_G2_POINT_SIZE];

        let mut g2_aff = blst::blst_p2_affine::default();
        unsafe {
            blst::blst_p2_deserialize(&mut g2_aff, g2_bytes.as_ptr());
        }
        let in_g2 = unsafe { blst::blst_p2_affine_in_g2(&g2_aff) };
        if !in_g2 {
            return Ok(1);
        }
        g2_affines.push(g2_aff);
    }

    // Compute the multi-pairing using Miller loop + final exponentiation.
    let mut result = blst::blst_fp12::default();

    // First pair.
    unsafe {
        blst::blst_miller_loop(&mut result, &g2_affines[0], &g1_affines[0]);
    }

    // Remaining pairs: multiply into the accumulator.
    for i in 1..num_pairs {
        let mut tmp = blst::blst_fp12::default();
        unsafe {
            blst::blst_miller_loop(&mut tmp, &g2_affines[i], &g1_affines[i]);
            blst::blst_fp12_mul(&mut result, &result, &tmp);
        }
    }

    // Final exponentiation.
    unsafe {
        blst::blst_final_exp(&mut result, &result);
    }

    // Serialize GT element to output (12 × 48-byte field elements).
    let mut buf = [0u8; BLS12_381_GT_ELEMENT_SIZE];
    for (idx, fp) in result.fp6.iter().enumerate() {
        for (jdx, fp2) in fp.fp2.iter().enumerate() {
            let offset = (idx * 6 + jdx * 2) * 48;
            unsafe {
                blst::blst_bendian_from_fp(buf[offset..offset + 48].as_mut_ptr(), &fp2.fp[0]);
                blst::blst_bendian_from_fp(buf[offset + 48..offset + 96].as_mut_ptr(), &fp2.fp[1]);
            }
        }
    }

    if big_endian {
        output[..BLS12_381_GT_ELEMENT_SIZE].copy_from_slice(&buf);
    } else {
        let le_buf = reverse_48_elements(&buf);
        output[..BLS12_381_GT_ELEMENT_SIZE].copy_from_slice(&le_buf);
    }

    Ok(0)
}

// --- Endianness helpers ---

/// Reverse a single 48-byte element (for little-endian ↔ big-endian conversion).
fn reverse_48(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    result.reverse();
    result
}

/// Reverse each 48-byte element in the data independently.
fn reverse_48_elements(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    for chunk in result.chunks_exact_mut(48) {
        chunk.reverse();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::SyscallContext;
    use paradencer_types::Pubkey;

    fn make_ctx() -> SyscallContext {
        SyscallContext::new(Pubkey::zeroed(), 1_000_000)
    }

    #[test]
    fn g1_decompress_identity_point() {
        let mut ctx = make_ctx();
        // BLS12-381 compressed identity: 0xc0 followed by 47 zero bytes.
        let mut compressed = [0u8; 48];
        compressed[0] = 0xC0; // Infinity flag + compression flag
        let mut output = [0u8; 96];

        let result = g1_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        // Identity point decompresses successfully.
        assert_eq!(result, 0);
    }

    #[test]
    fn g1_decompress_generator() {
        let mut ctx = make_ctx();
        // BLS12-381 G1 generator in compressed form.
        // The compressed generator is the x-coordinate with the compression flag set.
        let compressed = blst_g1_generator_compressed();
        let mut output = [0u8; 96];

        let result = g1_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 0);
        // Output should be non-zero (valid decompressed point).
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn g1_decompress_invalid_point() {
        let mut ctx = make_ctx();
        // All zeros is not a valid compressed point (no flags set).
        let compressed = [0u8; 48];
        let mut output = [0u8; 96];

        let result = g1_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 1); // Invalid input
    }

    #[test]
    fn g1_decompress_wrong_input_size() {
        let mut ctx = make_ctx();
        let compressed = [0u8; 32]; // Too short
        let mut output = [0u8; 96];

        let result = g1_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn g2_decompress_identity_point() {
        let mut ctx = make_ctx();
        // BLS12-381 compressed G2 identity: 0xc0 followed by 95 zero bytes.
        let mut compressed = [0u8; 96];
        compressed[0] = 0xC0;
        let mut output = [0u8; 192];

        let result = g2_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn g2_decompress_generator() {
        let mut ctx = make_ctx();
        let compressed = blst_g2_generator_compressed();
        let mut output = [0u8; 192];

        let result = g2_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 0);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn g2_decompress_wrong_input_size() {
        let mut ctx = make_ctx();
        let compressed = [0u8; 48]; // Too short for G2
        let mut output = [0u8; 192];

        let result = g2_decompress(&mut ctx, &compressed, &mut output, true).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn pairing_trivial_identity() {
        let mut ctx = make_ctx();
        // Pairing with the G1 and G2 generators should produce a non-identity GT element.
        let g1 = blst_g1_generator_uncompressed();
        let g2 = blst_g2_generator_uncompressed();
        let mut output = [0u8; 576];

        let result = pairing_map(&mut ctx, &g1, &g2, 1, &mut output, true).unwrap();
        assert_eq!(result, 0);
        // GT element should be non-zero.
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn pairing_rejects_zero_pairs() {
        let mut ctx = make_ctx();
        let mut output = [0u8; 576];

        let result = pairing_map(&mut ctx, &[], &[], 0, &mut output, true).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn pairing_rejects_too_many_pairs() {
        let mut ctx = make_ctx();
        let mut output = [0u8; 576];

        let result = pairing_map(
            &mut ctx,
            &[0u8; 96 * 9],
            &[0u8; 192 * 9],
            9,
            &mut output,
            true,
        )
        .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn g1_decompress_little_endian_roundtrip() {
        let mut ctx = make_ctx();
        // Get BE compressed generator, convert to LE.
        let be_compressed = blst_g1_generator_compressed();
        let mut le_compressed = be_compressed;
        le_compressed.reverse();

        let mut output_be = [0u8; 96];
        let mut output_le = [0u8; 96];

        let r1 = g1_decompress(&mut ctx, &be_compressed, &mut output_be, true).unwrap();
        let r2 = g1_decompress(&mut ctx, &le_compressed, &mut output_le, false).unwrap();

        assert_eq!(r1, 0);
        assert_eq!(r2, 0);

        // LE output should be byte-reversed per 48-byte element compared to BE.
        let le_to_be = reverse_48_elements(&output_le);
        assert_eq!(output_be[..96], le_to_be[..96]);
    }

    // --- Helper functions to produce test points ---

    fn blst_g1_generator_compressed() -> [u8; 48] {
        let mut p = blst::blst_p1::default();
        unsafe {
            blst::blst_p1_from_affine(&mut p, blst::blst_p1_affine_generator());
        }
        let mut compressed = [0u8; 48];
        unsafe {
            blst::blst_p1_compress(compressed.as_mut_ptr(), &p);
        }
        compressed
    }

    fn blst_g2_generator_compressed() -> [u8; 96] {
        let mut p = blst::blst_p2::default();
        unsafe {
            blst::blst_p2_from_affine(&mut p, blst::blst_p2_affine_generator());
        }
        let mut compressed = [0u8; 96];
        unsafe {
            blst::blst_p2_compress(compressed.as_mut_ptr(), &p);
        }
        compressed
    }

    fn blst_g1_generator_uncompressed() -> [u8; 96] {
        let gen = unsafe { &*blst::blst_p1_affine_generator() };
        let mut buf = [0u8; 96];
        unsafe {
            blst::blst_bendian_from_fp(buf[0..48].as_mut_ptr(), &gen.x);
            blst::blst_bendian_from_fp(buf[48..96].as_mut_ptr(), &gen.y);
        }
        buf
    }

    fn blst_g2_generator_uncompressed() -> [u8; 192] {
        let gen = unsafe { &*blst::blst_p2_affine_generator() };
        let mut buf = [0u8; 192];
        unsafe {
            blst::blst_bendian_from_fp(buf[0..48].as_mut_ptr(), &gen.x.fp[0]);
            blst::blst_bendian_from_fp(buf[48..96].as_mut_ptr(), &gen.x.fp[1]);
            blst::blst_bendian_from_fp(buf[96..144].as_mut_ptr(), &gen.y.fp[0]);
            blst::blst_bendian_from_fp(buf[144..192].as_mut_ptr(), &gen.y.fp[1]);
        }
        buf
    }
}
