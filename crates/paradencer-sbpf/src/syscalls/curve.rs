//! Elliptic curve operations for alt_bn128 and curve25519.
//!
//! These syscalls provide BN254 (alt_bn128) point addition, scalar
//! multiplication, and pairing checks, plus ed25519/ristretto255
//! point validation, group operations, and multi-scalar multiplication
//! used for zero-knowledge proof verification on-chain.

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
                    + CURVE25519_EDWARDS_MSM_INCREMENTAL_COST * (scalars.len().saturating_sub(1)) as u64;
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
                    + CURVE25519_RISTRETTO_MSM_INCREMENTAL_COST * (scalars.len().saturating_sub(1)) as u64;
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
                        let result =
                            RistrettoPoint::vartime_multiscalar_mul(&parsed_scalars, &pts);
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
