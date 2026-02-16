//! Elliptic curve operations for alt_bn128.
//!
//! These syscalls provide BN254 (alt_bn128) point addition, scalar
//! multiplication, and pairing checks used for zero-knowledge proof
//! verification on-chain.

pub mod alt_bn128 {
    use crate::syscalls::{SyscallContext, SyscallError};
    use paradencer_constants::syscalls::*;
    use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

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

        let p1 = decode_g1(&input[..64])?;
        let p2 = decode_g1(&input[64..])?;

        let sum = p1 + p2;
        Ok(encode_g1(&sum)?.to_vec())
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

        let point = decode_g1(&input[..64])?;
        let scalar = Fr::from_slice(&input[64..96]).map_err(|_| {
            SyscallError::InvalidArgument("invalid scalar field element".to_string())
        })?;

        let product = point * scalar;
        Ok(encode_g1(&product)?.to_vec())
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

        if num_pairs == 0 {
            return Ok(true);
        }

        let mut pairs = Vec::with_capacity(num_pairs);
        for i in 0..num_pairs {
            let offset = i * PAIRING_PAIR_SIZE;
            let g1 = decode_g1(&input[offset..offset + 64])?;
            let g2 = decode_g2(&input[offset + 64..offset + 192])?;
            pairs.push((g1, g2));
        }

        let result = pairing_batch(&pairs);
        Ok(result == Gt::one())
    }

    // --- Internal helpers ---

    fn decode_g1(data: &[u8]) -> Result<G1, SyscallError> {
        let x = Fq::from_slice(&data[..32])
            .map_err(|_| SyscallError::InvalidArgument("invalid G1 x-coordinate".to_string()))?;
        let y = Fq::from_slice(&data[32..64])
            .map_err(|_| SyscallError::InvalidArgument("invalid G1 y-coordinate".to_string()))?;

        if x.is_zero() && y.is_zero() {
            return Ok(G1::zero());
        }

        let point = AffineG1::new(x, y)
            .map_err(|_| SyscallError::InvalidArgument("G1 point not on curve".to_string()))?;

        Ok(point.into())
    }

    fn decode_g2(data: &[u8]) -> Result<G2, SyscallError> {
        let x_imag = Fq::from_slice(&data[..32])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x imaginary".to_string()))?;
        let x_real = Fq::from_slice(&data[32..64])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 x real".to_string()))?;
        let y_imag = Fq::from_slice(&data[64..96])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 y imaginary".to_string()))?;
        let y_real = Fq::from_slice(&data[96..128])
            .map_err(|_| SyscallError::InvalidArgument("invalid G2 y real".to_string()))?;

        let x = Fq2::new(x_real, x_imag);
        let y = Fq2::new(y_real, y_imag);

        if x.is_zero() && y.is_zero() {
            return Ok(G2::zero());
        }

        let point = AffineG2::new(x, y)
            .map_err(|_| SyscallError::InvalidArgument("G2 point not on curve".to_string()))?;

        Ok(point.into())
    }

    fn encode_g1(point: &G1) -> Result<[u8; 64], SyscallError> {
        let mut output = [0u8; 64];

        if point.is_zero() {
            return Ok(output);
        }

        let affine = AffineG1::from_jacobian(*point).ok_or_else(|| {
            SyscallError::InvalidArgument("failed to convert G1 to affine".to_string())
        })?;

        affine.x().to_big_endian(&mut output[..32]).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 x-coordinate".to_string())
        })?;
        affine.y().to_big_endian(&mut output[32..]).map_err(|_| {
            SyscallError::InvalidArgument("failed to encode G1 y-coordinate".to_string())
        })?;

        Ok(output)
    }
}
