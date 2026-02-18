//! Elliptic curve operations for alt_bn128 and curve25519.
//!
//! These syscalls provide BN254 (alt_bn128) point addition, scalar
//! multiplication, and pairing checks, plus ed25519/ristretto255
//! point validation, group operations, and multi-scalar multiplication
//! used for zero-knowledge proof verification on-chain.

pub mod alt_bn128 {
    //! BN254 (alt_bn128) elliptic curve group operations and compression.
    //!
    //! Supports G1 and G2 point addition, subtraction, scalar multiplication,
    //! pairing checks, and point compression/decompression. Both big-endian
    //! and little-endian encodings are supported via the LE flag (SIMD-0284).

    use crate::syscalls::{SyscallContext, SyscallError};
    use paradencer_constants::syscalls::*;
    use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

    /// Dispatch a BN254 group operation based on the operation ID.
    ///
    /// This is the unified entry point for the `sol_alt_bn128_group_op` syscall.
    /// The `group_op` selects the operation (G1/G2 add/sub/mul/pairing)
    /// and encoding (big-endian by default, little-endian if bit 7 is set).
    /// Returns `Ok(0)` on success with result written to `output`,
    /// or `Ok(1)` on a soft error (invalid input point, bad input size).
    pub fn group_op(
        ctx: &mut SyscallContext,
        group_op: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, SyscallError> {
        let is_le = (group_op & ALT_BN128_LITTLE_ENDIAN_FLAG) != 0;
        let base_op = group_op & !ALT_BN128_LITTLE_ENDIAN_FLAG;

        // Determine cost and expected output size
        let (cost, expected_output) = match base_op {
            ALT_BN128_G1_ADD_BE | ALT_BN128_G1_SUB_BE => {
                (ALT_BN128_G1_ADD_COST, ALT_BN128_G1_POINT_SIZE)
            }
            ALT_BN128_G1_MUL_BE => (ALT_BN128_G1_MUL_COST, ALT_BN128_G1_POINT_SIZE),
            ALT_BN128_PAIRING_BE => {
                let pair_count = input.len() / ALT_BN128_PAIRING_PAIR_SIZE;
                let cost = ALT_BN128_PAIRING_FIRST_PAIR_COST
                    .saturating_add(SHA256_BASE_COST)
                    .saturating_add(ALT_BN128_PAIRING_OUTPUT_SIZE as u64)
                    .saturating_add(
                        ALT_BN128_PAIRING_EACH_ADDITIONAL_PAIR_COST
                            .saturating_mul(pair_count.saturating_sub(1) as u64),
                    )
                    .saturating_add(input.len() as u64);
                (cost, ALT_BN128_PAIRING_OUTPUT_SIZE)
            }
            ALT_BN128_G2_ADD_BE | ALT_BN128_G2_SUB_BE => {
                (ALT_BN128_G2_ADD_COST, ALT_BN128_G2_POINT_SIZE)
            }
            ALT_BN128_G2_MUL_BE => (ALT_BN128_G2_MUL_COST, ALT_BN128_G2_POINT_SIZE),
            _ => return Err(SyscallError::InvalidArgument("invalid group op".into())),
        };

        ctx.consume_compute(cost)?;

        if output.len() < expected_output {
            return Ok(1);
        }

        // Prepare input: if little-endian, reverse each 32-byte element
        let input_be;
        let input_ref = if is_le {
            input_be = to_big_endian_elements(input);
            &input_be
        } else {
            input
        };

        let result = match base_op {
            ALT_BN128_G1_ADD_BE => g1_add(input_ref),
            ALT_BN128_G1_SUB_BE => g1_sub(input_ref),
            ALT_BN128_G1_MUL_BE => g1_mul(input_ref),
            ALT_BN128_PAIRING_BE => {
                return match pairing_check(input_ref) {
                    Ok(passed) => {
                        output[..ALT_BN128_PAIRING_OUTPUT_SIZE].fill(0);
                        if passed {
                            output[ALT_BN128_PAIRING_OUTPUT_SIZE - 1] = 1;
                        }
                        Ok(0)
                    }
                    Err(_) => Ok(1),
                };
            }
            ALT_BN128_G2_ADD_BE => g2_add(input_ref),
            ALT_BN128_G2_SUB_BE => g2_sub(input_ref),
            ALT_BN128_G2_MUL_BE => g2_mul(input_ref),
            _ => unreachable!(),
        };

        match result {
            Ok(bytes) => {
                if is_le {
                    let le_bytes = to_little_endian_elements(&bytes);
                    output[..le_bytes.len()].copy_from_slice(&le_bytes);
                } else {
                    output[..bytes.len()].copy_from_slice(&bytes);
                }
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }

    /// Dispatch a BN254 compression/decompression operation.
    ///
    /// Entry point for the `sol_alt_bn128_compression` syscall.
    /// Returns `Ok(0)` on success, `Ok(1)` on soft error.
    pub fn compression(
        ctx: &mut SyscallContext,
        op: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u64, SyscallError> {
        let is_le = (op & ALT_BN128_LITTLE_ENDIAN_FLAG) != 0;
        let base_op = op & !ALT_BN128_LITTLE_ENDIAN_FLAG;

        let (cost, expected_input_sz, expected_output_sz) = match base_op {
            ALT_BN128_G1_COMPRESS_BE => (
                ALT_BN128_G1_COMPRESS_COST,
                ALT_BN128_G1_POINT_SIZE,
                ALT_BN128_G1_COMPRESSED_SIZE,
            ),
            ALT_BN128_G1_DECOMPRESS_BE => (
                ALT_BN128_G1_DECOMPRESS_COST,
                ALT_BN128_G1_COMPRESSED_SIZE,
                ALT_BN128_G1_POINT_SIZE,
            ),
            ALT_BN128_G2_COMPRESS_BE => (
                ALT_BN128_G2_COMPRESS_COST,
                ALT_BN128_G2_POINT_SIZE,
                ALT_BN128_G2_COMPRESSED_SIZE,
            ),
            ALT_BN128_G2_DECOMPRESS_BE => (
                ALT_BN128_G2_DECOMPRESS_COST,
                ALT_BN128_G2_COMPRESSED_SIZE,
                ALT_BN128_G2_POINT_SIZE,
            ),
            _ => {
                return Err(SyscallError::InvalidArgument(
                    "invalid compression op".into(),
                ))
            }
        };

        let total_cost = cost.saturating_add(SYSCALL_BASE_COST);
        ctx.consume_compute(total_cost)?;

        if input.len() != expected_input_sz || output.len() < expected_output_sz {
            return Ok(1);
        }

        // Convert to big-endian if needed
        let input_be;
        let input_ref = if is_le {
            input_be = to_big_endian_elements(input);
            &input_be
        } else {
            input
        };

        let result = match base_op {
            ALT_BN128_G1_COMPRESS_BE => g1_compress(input_ref),
            ALT_BN128_G1_DECOMPRESS_BE => g1_decompress(input_ref),
            ALT_BN128_G2_COMPRESS_BE => g2_compress(input_ref),
            ALT_BN128_G2_DECOMPRESS_BE => g2_decompress(input_ref),
            _ => unreachable!(),
        };

        match result {
            Ok(bytes) => {
                if is_le {
                    let le_bytes = to_little_endian_elements(&bytes);
                    output[..le_bytes.len()].copy_from_slice(&le_bytes);
                } else {
                    output[..bytes.len()].copy_from_slice(&bytes);
                }
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }

    // Legacy entry points used by existing code

    /// Point addition on the BN254 G1 curve (legacy API, big-endian only).
    pub fn add(ctx: &mut SyscallContext, input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        ctx.consume_compute(ALT_BN128_G1_ADD_COST)?;
        g1_add(input).map(|r| r.to_vec())
    }

    /// Scalar multiplication on the BN254 G1 curve (legacy API, big-endian only).
    pub fn mul(ctx: &mut SyscallContext, input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        ctx.consume_compute(ALT_BN128_G1_MUL_COST)?;
        g1_mul(input).map(|r| r.to_vec())
    }

    /// Pairing check on the BN254 curve (legacy API, big-endian only).
    pub fn pairing(ctx: &mut SyscallContext, input: &[u8]) -> Result<bool, SyscallError> {
        let num_pairs = input.len() / ALT_BN128_PAIRING_PAIR_SIZE;
        let cost = ALT_BN128_PAIRING_BASE_COST + ALT_BN128_PAIRING_PER_PAIR_COST * num_pairs as u64;
        ctx.consume_compute(cost)?;
        pairing_check(input)
    }

    // --- G1 operations ---

    fn g1_add(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != 2 * ALT_BN128_G1_POINT_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G1 add input size".into(),
            ));
        }
        let p1 = decode_g1(&input[..64])?;
        let p2 = decode_g1(&input[64..])?;
        Ok(encode_g1(&(p1 + p2))?.to_vec())
    }

    fn g1_sub(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != 2 * ALT_BN128_G1_POINT_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G1 sub input size".into(),
            ));
        }
        let p1 = decode_g1(&input[..64])?;
        let p2 = decode_g1(&input[64..])?;
        Ok(encode_g1(&(p1 - p2))?.to_vec())
    }

    fn g1_mul(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != ALT_BN128_G1_POINT_SIZE + ALT_BN128_SCALAR_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G1 mul input size".into(),
            ));
        }
        let point = decode_g1(&input[..64])?;
        let scalar = Fr::from_slice(&input[64..96])
            .map_err(|_| SyscallError::InvalidArgument("invalid scalar".into()))?;
        Ok(encode_g1(&(point * scalar))?.to_vec())
    }

    // --- G2 operations ---

    fn g2_add(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != 2 * ALT_BN128_G2_POINT_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G2 add input size".into(),
            ));
        }
        let p1 = decode_g2(&input[..128])?;
        let p2 = decode_g2(&input[128..])?;
        Ok(encode_g2(&(p1 + p2))?.to_vec())
    }

    fn g2_sub(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != 2 * ALT_BN128_G2_POINT_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G2 sub input size".into(),
            ));
        }
        let p1 = decode_g2(&input[..128])?;
        let p2 = decode_g2(&input[128..])?;
        Ok(encode_g2(&(p1 - p2))?.to_vec())
    }

    fn g2_mul(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != ALT_BN128_G2_POINT_SIZE + ALT_BN128_SCALAR_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G2 mul input size".into(),
            ));
        }
        let point = decode_g2(&input[..128])?;
        let scalar = Fr::from_slice(&input[128..160])
            .map_err(|_| SyscallError::InvalidArgument("invalid scalar".into()))?;
        Ok(encode_g2(&(point * scalar))?.to_vec())
    }

    // --- Pairing ---

    fn pairing_check(input: &[u8]) -> Result<bool, SyscallError> {
        if !input.len().is_multiple_of(ALT_BN128_PAIRING_PAIR_SIZE) {
            return Err(SyscallError::InvalidArgument(
                "invalid pairing input size".into(),
            ));
        }
        let num_pairs = input.len() / ALT_BN128_PAIRING_PAIR_SIZE;
        if num_pairs == 0 {
            return Ok(true);
        }
        let mut pairs = Vec::with_capacity(num_pairs);
        for i in 0..num_pairs {
            let offset = i * ALT_BN128_PAIRING_PAIR_SIZE;
            let g1 = decode_g1(&input[offset..offset + 64])?;
            let g2 = decode_g2(&input[offset + 64..offset + 192])?;
            pairs.push((g1, g2));
        }
        let result = pairing_batch(&pairs);
        Ok(result == Gt::one())
    }

    // --- Compression / Decompression ---

    /// Compress a G1 point from 64 bytes (x, y) to 32 bytes (x with sign bit).
    fn g1_compress(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        let point = decode_g1(input)?;
        if point.is_zero() {
            return Ok(vec![0u8; ALT_BN128_G1_COMPRESSED_SIZE]);
        }
        let affine = AffineG1::from_jacobian(point).ok_or_else(|| {
            SyscallError::InvalidArgument("failed to convert G1 to affine".into())
        })?;
        let mut compressed = [0u8; 32];
        affine.x().to_big_endian(&mut compressed).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 x-coordinate".into())
        })?;
        // Set sign bit: if y is odd (y > (p-1)/2), set the high bit of the first byte
        let mut y_bytes = [0u8; 32];
        affine.y().to_big_endian(&mut y_bytes).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 y-coordinate".into())
        })?;
        if y_bytes[31] & 1 != 0 {
            compressed[0] |= 0x80;
        }
        Ok(compressed.to_vec())
    }

    /// Decompress a G1 point from 32 bytes (x with sign bit) to 64 bytes (x, y).
    fn g1_decompress(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != ALT_BN128_G1_COMPRESSED_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G1 compressed size".into(),
            ));
        }
        // Check for zero point
        if input.iter().all(|&b| b == 0) {
            return Ok(vec![0u8; ALT_BN128_G1_POINT_SIZE]);
        }
        let sign_bit = (input[0] & 0x80) != 0;
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(input);
        x_bytes[0] &= 0x7F; // Clear sign bit

        let x = Fq::from_slice(&x_bytes)
            .map_err(|_| SyscallError::InvalidArgument("invalid G1 x-coordinate".into()))?;

        // Compute y^2 = x^3 + 3
        let three = Fq::from_u256(3u64.into())
            .map_err(|_| SyscallError::InvalidArgument("field error".into()))?;
        let y_squared = x * x * x + three;
        let y = sqrt_fq(y_squared)
            .ok_or_else(|| SyscallError::InvalidArgument("no square root for G1 y".into()))?;

        // Select correct y based on sign bit
        let mut y_bytes = [0u8; 32];
        y.to_big_endian(&mut y_bytes)
            .map_err(|_| SyscallError::InvalidArgument("failed to encode y".into()))?;
        let y_is_odd = y_bytes[31] & 1 != 0;
        let final_y = if y_is_odd != sign_bit { -y } else { y };

        let mut output = [0u8; 64];
        x.to_big_endian(&mut output[..32])
            .map_err(|_| SyscallError::InvalidArgument("failed to encode x".into()))?;
        final_y
            .to_big_endian(&mut output[32..])
            .map_err(|_| SyscallError::InvalidArgument("failed to encode y".into()))?;
        Ok(output.to_vec())
    }

    /// Compress a G2 point from 128 bytes to 64 bytes.
    fn g2_compress(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        let point = decode_g2(input)?;
        if point.is_zero() {
            return Ok(vec![0u8; ALT_BN128_G2_COMPRESSED_SIZE]);
        }
        let affine = AffineG2::from_jacobian(point).ok_or_else(|| {
            SyscallError::InvalidArgument("failed to convert G2 to affine".into())
        })?;
        // G2 x-coordinate is in Fq2 = (x_imag, x_real), output as (imag || real) = 64 bytes
        let mut compressed = [0u8; 64];
        affine
            .x()
            .imaginary()
            .to_big_endian(&mut compressed[..32])
            .map_err(|_| SyscallError::InvalidArgument("failed to encode G2 x imaginary".into()))?;
        affine
            .x()
            .real()
            .to_big_endian(&mut compressed[32..])
            .map_err(|_| SyscallError::InvalidArgument("failed to encode G2 x real".into()))?;
        // Set sign bit based on y imaginary component
        let mut y_imag_bytes = [0u8; 32];
        affine
            .y()
            .imaginary()
            .to_big_endian(&mut y_imag_bytes)
            .map_err(|_| SyscallError::InvalidArgument("failed to encode G2 y imaginary".into()))?;
        if y_imag_bytes[31] & 1 != 0 {
            compressed[0] |= 0x80;
        }
        Ok(compressed.to_vec())
    }

    /// Decompress a G2 point from 64 bytes to 128 bytes.
    fn g2_decompress(input: &[u8]) -> Result<Vec<u8>, SyscallError> {
        if input.len() != ALT_BN128_G2_COMPRESSED_SIZE {
            return Err(SyscallError::InvalidArgument(
                "invalid G2 compressed size".into(),
            ));
        }
        if input.iter().all(|&b| b == 0) {
            return Ok(vec![0u8; ALT_BN128_G2_POINT_SIZE]);
        }
        let sign_bit = (input[0] & 0x80) != 0;
        let mut x_imag_bytes = [0u8; 32];
        x_imag_bytes.copy_from_slice(&input[..32]);
        x_imag_bytes[0] &= 0x7F;
        let x_real_bytes = &input[32..64];

        let x_imag = Fq::from_slice(&x_imag_bytes)
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x imaginary".into()))?;
        let x_real = Fq::from_slice(x_real_bytes)
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x real".into()))?;
        let x = Fq2::new(x_real, x_imag);

        // Compute y^2 = x^3 + b' where b' = 3 / (i + 9) for BN254
        // b' in Fq2 is the twist parameter
        let y_squared = x * x * x + get_bn254_twist_b();
        let y = sqrt_fq2(y_squared)
            .ok_or_else(|| SyscallError::InvalidArgument("no square root for G2 y".into()))?;

        let mut y_imag_bytes = [0u8; 32];
        y.imaginary()
            .to_big_endian(&mut y_imag_bytes)
            .map_err(|_| SyscallError::InvalidArgument("failed to encode y imaginary".into()))?;
        let y_is_odd = y_imag_bytes[31] & 1 != 0;
        let final_y = if y_is_odd != sign_bit { -y } else { y };

        let mut output = [0u8; 128];
        x.imaginary()
            .to_big_endian(&mut output[..32])
            .map_err(|_| SyscallError::InvalidArgument("encode x imag".into()))?;
        x.real()
            .to_big_endian(&mut output[32..64])
            .map_err(|_| SyscallError::InvalidArgument("encode x real".into()))?;
        final_y
            .imaginary()
            .to_big_endian(&mut output[64..96])
            .map_err(|_| SyscallError::InvalidArgument("encode y imag".into()))?;
        final_y
            .real()
            .to_big_endian(&mut output[96..128])
            .map_err(|_| SyscallError::InvalidArgument("encode y real".into()))?;
        Ok(output.to_vec())
    }

    // --- Endianness helpers ---

    /// Convert a byte slice from little-endian to big-endian by reversing each 32-byte element.
    fn to_big_endian_elements(data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        for chunk in result.chunks_exact_mut(32) {
            chunk.reverse();
        }
        result
    }

    /// Convert a byte slice from big-endian to little-endian by reversing each 32-byte element.
    fn to_little_endian_elements(data: &[u8]) -> Vec<u8> {
        to_big_endian_elements(data) // Same operation: reverse is its own inverse
    }

    // --- Point encoding/decoding helpers ---

    fn decode_g1(data: &[u8]) -> Result<G1, SyscallError> {
        if data.len() < 64 {
            return Err(SyscallError::InvalidArgument("G1 input too short".into()));
        }
        let x = Fq::from_slice(&data[..32])
            .map_err(|_| SyscallError::InvalidArgument("invalid G1 x-coordinate".into()))?;
        let y = Fq::from_slice(&data[32..64])
            .map_err(|_| SyscallError::InvalidArgument("invalid G1 y-coordinate".into()))?;

        if x.is_zero() && y.is_zero() {
            return Ok(G1::zero());
        }

        let point = AffineG1::new(x, y)
            .map_err(|_| SyscallError::InvalidArgument("G1 point not on curve".into()))?;
        Ok(point.into())
    }

    fn decode_g2(data: &[u8]) -> Result<G2, SyscallError> {
        if data.len() < 128 {
            return Err(SyscallError::InvalidArgument("G2 input too short".into()));
        }
        let x_imag = Fq::from_slice(&data[..32])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x imaginary".into()))?;
        let x_real = Fq::from_slice(&data[32..64])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x real".into()))?;
        let y_imag = Fq::from_slice(&data[64..96])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 y imaginary".into()))?;
        let y_real = Fq::from_slice(&data[96..128])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 y real".into()))?;

        let x = Fq2::new(x_real, x_imag);
        let y = Fq2::new(y_real, y_imag);

        if x.is_zero() && y.is_zero() {
            return Ok(G2::zero());
        }

        let point = AffineG2::new(x, y)
            .map_err(|_| SyscallError::InvalidArgument("G2 point not on curve".into()))?;
        Ok(point.into())
    }

    fn encode_g1(point: &G1) -> Result<[u8; 64], SyscallError> {
        let mut output = [0u8; 64];
        if point.is_zero() {
            return Ok(output);
        }
        let affine = AffineG1::from_jacobian(*point).ok_or_else(|| {
            SyscallError::InvalidArgument("failed to convert G1 to affine".into())
        })?;
        affine.x().to_big_endian(&mut output[..32]).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 x-coordinate".into())
        })?;
        affine.y().to_big_endian(&mut output[32..]).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 y-coordinate".into())
        })?;
        Ok(output)
    }

    fn encode_g2(point: &G2) -> Result<[u8; 128], SyscallError> {
        let mut output = [0u8; 128];
        if point.is_zero() {
            return Ok(output);
        }
        let affine = AffineG2::from_jacobian(*point).ok_or_else(|| {
            SyscallError::InvalidArgument("failed to convert G2 to affine".into())
        })?;
        affine
            .x()
            .imaginary()
            .to_big_endian(&mut output[..32])
            .map_err(|_| SyscallError::InvalidArgument("encode G2 x imag".into()))?;
        affine
            .x()
            .real()
            .to_big_endian(&mut output[32..64])
            .map_err(|_| SyscallError::InvalidArgument("encode G2 x real".into()))?;
        affine
            .y()
            .imaginary()
            .to_big_endian(&mut output[64..96])
            .map_err(|_| SyscallError::InvalidArgument("encode G2 y imag".into()))?;
        affine
            .y()
            .real()
            .to_big_endian(&mut output[96..128])
            .map_err(|_| SyscallError::InvalidArgument("encode G2 y real".into()))?;
        Ok(output)
    }

    // --- Field arithmetic helpers ---

    /// Compute the Tonelli-Shanks square root of an Fq element.
    /// Returns `None` if the element is not a quadratic residue.
    fn sqrt_fq(a: Fq) -> Option<Fq> {
        // BN254 p ≡ 3 mod 4, so sqrt(a) = a^((p+1)/4) if a is a QR
        // For substrate-bn, we use the exponentiation approach
        // p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
        // (p+1)/4 = 5472060717959818805561601436314318772174077789324455915672259473661306552146

        if a.is_zero() {
            return Some(Fq::zero());
        }

        // Use Euler's criterion and the (p+1)/4 exponent
        // Since substrate-bn doesn't expose a direct sqrt, we compute it via the formula:
        // For BN254, p ≡ 3 (mod 4), so sqrt = a^((p+1)/4)
        //
        // We need to compute a^exp where exp = (p+1)/4
        // Using the fact that substrate-bn supports pow via repeated squaring:
        let exp_bytes = [
            0x0c, 0x19, 0x13, 0x9c, 0xb8, 0x4c, 0x68, 0x0a, 0x6e, 0x14, 0x11, 0x6d, 0xa0, 0x60,
            0x56, 0x17, 0x65, 0xe0, 0x5a, 0xa4, 0x5a, 0x1c, 0x72, 0xa3, 0x4f, 0x08, 0x23, 0x05,
            0xb6, 0x1f, 0x3f, 0x52,
        ];
        let candidate = fq_pow(a, &exp_bytes);

        // Verify: candidate^2 == a
        if candidate * candidate == a {
            Some(candidate)
        } else {
            None
        }
    }

    /// Square root in Fq2, returns None if not a quadratic residue.
    fn sqrt_fq2(a: Fq2) -> Option<Fq2> {
        // For Fq2, use the algorithm: sqrt(a + bi) via the formula
        // if a^2 + b^2 is a QR in Fq, compute norm = sqrt(a^2 + b^2),
        // then x0 = sqrt((a + norm)/2), x1 = b / (2 * x0)
        let a_comp = a.real();
        let b_comp = a.imaginary();

        if b_comp.is_zero() {
            // Pure real: just sqrt the real part
            return sqrt_fq(a_comp).map(|r| Fq2::new(r, Fq::zero()));
        }

        let norm_sq = a_comp * a_comp + b_comp * b_comp;
        let norm = sqrt_fq(norm_sq)?;

        // t = (a + norm) / 2
        let two_inv = Fq::from_u256(2u64.into()).unwrap().inverse().unwrap();
        let t = (a_comp + norm) * two_inv;
        let x0 = sqrt_fq(t)?;

        if x0.is_zero() {
            return None;
        }

        let x1 = b_comp * (x0 + x0).inverse()?;
        let candidate = Fq2::new(x0, x1);

        if candidate * candidate == a {
            Some(candidate)
        } else {
            None
        }
    }

    /// Exponentiate an Fq element by a big-endian byte array exponent.
    fn fq_pow(base: Fq, exp: &[u8]) -> Fq {
        let mut result = Fq::one();
        for byte in exp {
            for bit in (0..8).rev() {
                result = result * result;
                if (byte >> bit) & 1 == 1 {
                    result = result * base;
                }
            }
        }
        result
    }

    /// The BN254 twist parameter b' = 3 / (9 + i) in Fq2.
    fn get_bn254_twist_b() -> Fq2 {
        // b' = 3 * (9 + i)^{-1} in Fq2
        // Precomputed: b' = (19485874751759354771024239261021720505790618469301721065564631296452457478373,
        //                    266929791119991161246907387137283842545076965332900288569378510910307636690)
        // These are the real and imaginary parts respectively.
        let real_bytes = [
            0x2b, 0x14, 0x9d, 0x40, 0xce, 0xb8, 0xaa, 0xae, 0x81, 0xbe, 0x18, 0x99, 0x1b, 0xe0,
            0x6a, 0xc3, 0xb5, 0xb4, 0xc5, 0xe5, 0x59, 0xdb, 0xef, 0xa3, 0x32, 0x67, 0xe6, 0xdc,
            0x24, 0xa1, 0x38, 0xe5,
        ];
        let imag_bytes = [
            0x00, 0x97, 0x13, 0xb0, 0x3a, 0xf0, 0xfe, 0xd4, 0xcd, 0x2c, 0xaf, 0xad, 0xee, 0xd8,
            0xfd, 0xf4, 0xa7, 0x4f, 0xa0, 0x84, 0xe5, 0x2d, 0x18, 0x52, 0xe4, 0xa2, 0xbd, 0x06,
            0x85, 0xc3, 0x15, 0xd2,
        ];
        let real = Fq::from_slice(&real_bytes).unwrap();
        let imag = Fq::from_slice(&imag_bytes).unwrap();
        Fq2::new(real, imag)
    }
}

pub mod curve25519 {
    use crate::syscalls::{SyscallContext, SyscallError};
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_COMPRESSED},
        edwards::{CompressedEdwardsY, EdwardsPoint},
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{Identity, VartimeMultiscalarMul},
    };
    use paradencer_constants::syscalls::*;

    /// Validate a compressed point on ed25519 or ristretto255.
    ///
    /// Returns true if the point is valid (can be decompressed).
    pub fn validate_point(
        ctx: &mut SyscallContext,
        curve_id: u64,
        point_bytes: &[u8; 32],
    ) -> Result<bool, SyscallError> {
        match curve_id {
            CURVE_ID_ED25519 => {
                ctx.consume_compute(CURVE25519_EDWARDS_VALIDATE_POINT_COST)?;
                Ok(CompressedEdwardsY(*point_bytes).decompress().is_some())
            }
            CURVE_ID_RISTRETTO255 => {
                ctx.consume_compute(CURVE25519_RISTRETTO_VALIDATE_POINT_COST)?;
                Ok(CompressedRistretto(*point_bytes).decompress().is_some())
            }
            _ => Err(SyscallError::InvalidArgument(format!(
                "unknown curve id: {}",
                curve_id
            ))),
        }
    }

    /// Perform a group operation (add, sub, mul) on ed25519 or ristretto255.
    ///
    /// For ADD/SUB, both `left` and `right` are compressed points (32 bytes each).
    /// For MUL, `left` is a scalar (32 bytes LE) and `right` is a compressed point.
    /// Returns the compressed result, or None if any input is invalid.
    pub fn group_op(
        ctx: &mut SyscallContext,
        curve_id: u64,
        op: u64,
        left: &[u8; 32],
        right: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, SyscallError> {
        match curve_id {
            CURVE_ID_ED25519 => edwards_group_op(ctx, op, left, right),
            CURVE_ID_RISTRETTO255 => ristretto_group_op(ctx, op, left, right),
            _ => Err(SyscallError::InvalidArgument(format!(
                "unknown curve id: {}",
                curve_id
            ))),
        }
    }

    /// Multi-scalar multiplication on ed25519 or ristretto255.
    ///
    /// Computes sum(scalars[i] * points[i]) and returns the compressed result.
    /// Returns None if any point is invalid.
    pub fn multiscalar_mul(
        ctx: &mut SyscallContext,
        curve_id: u64,
        scalars: &[[u8; 32]],
        points: &[[u8; 32]],
    ) -> Result<Option<[u8; 32]>, SyscallError> {
        if scalars.len() != points.len() || scalars.is_empty() {
            return Err(SyscallError::InvalidArgument(
                "scalars and points must have equal non-zero length".to_string(),
            ));
        }

        match curve_id {
            CURVE_ID_ED25519 => {
                let cost = CURVE25519_EDWARDS_MSM_BASE_COST
                    + CURVE25519_EDWARDS_MSM_INCREMENTAL_COST
                        * (scalars.len().saturating_sub(1)) as u64;
                ctx.consume_compute(cost)?;

                let parsed_scalars: Vec<Scalar> = scalars
                    .iter()
                    .map(|s| Scalar::from_bytes_mod_order(*s))
                    .collect();

                let parsed_points: Option<Vec<EdwardsPoint>> = points
                    .iter()
                    .map(|p| CompressedEdwardsY(*p).decompress())
                    .collect();

                match parsed_points {
                    Some(pts) => {
                        let result = EdwardsPoint::vartime_multiscalar_mul(&parsed_scalars, &pts);
                        Ok(Some(result.compress().to_bytes()))
                    }
                    None => Ok(None),
                }
            }
            CURVE_ID_RISTRETTO255 => {
                let cost = CURVE25519_RISTRETTO_MSM_BASE_COST
                    + CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST
                        * (scalars.len().saturating_sub(1)) as u64;
                ctx.consume_compute(cost)?;

                let parsed_scalars: Vec<Scalar> = scalars
                    .iter()
                    .map(|s| Scalar::from_bytes_mod_order(*s))
                    .collect();

                let parsed_points: Option<Vec<RistrettoPoint>> = points
                    .iter()
                    .map(|p| CompressedRistretto(*p).decompress())
                    .collect();

                match parsed_points {
                    Some(pts) => {
                        let result = RistrettoPoint::vartime_multiscalar_mul(&parsed_scalars, &pts);
                        Ok(Some(result.compress().to_bytes()))
                    }
                    None => Ok(None),
                }
            }
            _ => Err(SyscallError::InvalidArgument(format!(
                "unknown curve id: {}",
                curve_id
            ))),
        }
    }

    // --- Internal helpers ---

    fn edwards_group_op(
        ctx: &mut SyscallContext,
        op: u64,
        left: &[u8; 32],
        right: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, SyscallError> {
        match op {
            CURVE_OP_ADD => {
                ctx.consume_compute(CURVE25519_EDWARDS_ADD_COST)?;
                let a = match CompressedEdwardsY(*left).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                let b = match CompressedEdwardsY(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((a + b).compress().to_bytes()))
            }
            CURVE_OP_SUB => {
                ctx.consume_compute(CURVE25519_EDWARDS_SUB_COST)?;
                let a = match CompressedEdwardsY(*left).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                let b = match CompressedEdwardsY(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((a - b).compress().to_bytes()))
            }
            CURVE_OP_MUL => {
                ctx.consume_compute(CURVE25519_EDWARDS_MUL_COST)?;
                let scalar = Scalar::from_bytes_mod_order(*left);
                let point = match CompressedEdwardsY(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((scalar * point).compress().to_bytes()))
            }
            _ => Err(SyscallError::InvalidArgument(format!(
                "unknown group op: {}",
                op
            ))),
        }
    }

    fn ristretto_group_op(
        ctx: &mut SyscallContext,
        op: u64,
        left: &[u8; 32],
        right: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, SyscallError> {
        match op {
            CURVE_OP_ADD => {
                ctx.consume_compute(CURVE25519_RISTRETTO_ADD_COST)?;
                let a = match CompressedRistretto(*left).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                let b = match CompressedRistretto(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((a + b).compress().to_bytes()))
            }
            CURVE_OP_SUB => {
                ctx.consume_compute(CURVE25519_RISTRETTO_SUB_COST)?;
                let a = match CompressedRistretto(*left).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                let b = match CompressedRistretto(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((a - b).compress().to_bytes()))
            }
            CURVE_OP_MUL => {
                ctx.consume_compute(CURVE25519_RISTRETTO_MUL_COST)?;
                let scalar = Scalar::from_bytes_mod_order(*left);
                let point = match CompressedRistretto(*right).decompress() {
                    Some(p) => p,
                    None => return Ok(None),
                };
                Ok(Some((scalar * point).compress().to_bytes()))
            }
            _ => Err(SyscallError::InvalidArgument(format!(
                "unknown group op: {}",
                op
            ))),
        }
    }
}
