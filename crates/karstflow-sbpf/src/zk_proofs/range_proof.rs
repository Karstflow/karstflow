//! Bulletproofs range proof verification.
//!
//! Implements the verification-only path for Bulletproofs range proofs as used by
//! the ZK ElGamal proof program (SPL Token-2022 confidential transfers).
//! Includes SHAKE256-based generator computation, inner product proof verification,
//! and the "mega check" multi-scalar multiplication.

#![allow(non_snake_case)]

use core::iter;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use merlin::Transcript;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use super::errors::ZkProofError;
use super::generators::{h, G};
use super::transcript::TranscriptProtocol;

const UNIT_LEN: usize = 32;

// ---------------------------------------------------------------------------
// SHAKE256-based generator chain (matches solana-zk-sdk GeneratorsChain)
// ---------------------------------------------------------------------------

struct GeneratorsChain {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl GeneratorsChain {
    fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);
        GeneratorsChain {
            reader: shake.finalize_xof(),
        }
    }
}

impl Iterator for GeneratorsChain {
    type Item = RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);
        Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

// ---------------------------------------------------------------------------
// Range proof generator points (G and H vectors)
// ---------------------------------------------------------------------------

struct RangeProofGens {
    G_vec: Vec<RistrettoPoint>,
    H_vec: Vec<RistrettoPoint>,
}

impl RangeProofGens {
    fn new(capacity: usize) -> Self {
        let G_vec: Vec<RistrettoPoint> = GeneratorsChain::new(b"G").take(capacity).collect();
        let H_vec: Vec<RistrettoPoint> = GeneratorsChain::new(b"H").take(capacity).collect();
        RangeProofGens { G_vec, H_vec }
    }

    fn G(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        self.G_vec[..n].iter()
    }

    fn H(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        self.H_vec[..n].iter()
    }
}

// ---------------------------------------------------------------------------
// Inner product proof (deserialization + verification scalars)
// ---------------------------------------------------------------------------

struct InnerProductProof {
    L_vec: Vec<CompressedRistretto>,
    R_vec: Vec<CompressedRistretto>,
    a: Scalar,
    b: Scalar,
}

impl InnerProductProof {
    /// Deserialize from interleaved L[32]R[32] pairs followed by a[32]b[32].
    fn from_bytes(slice: &[u8]) -> Result<Self, ZkProofError> {
        if !slice.len().is_multiple_of(UNIT_LEN) {
            return Err(ZkProofError::InsufficientData);
        }
        let num_elements = slice.len() / UNIT_LEN;
        if num_elements < 2 {
            return Err(ZkProofError::InsufficientData);
        }
        if !((num_elements - 2).is_multiple_of(2)) {
            return Err(ZkProofError::InsufficientData);
        }
        let lg_n = (num_elements - 2) / 2;
        if lg_n >= 32 {
            return Err(ZkProofError::InvalidBitLength);
        }

        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let pos = 2 * i * UNIT_LEN;
            L_vec.push(
                CompressedRistretto::from_slice(&slice[pos..pos + UNIT_LEN])
                    .expect("slice is 32 bytes"),
            );
            R_vec.push(
                CompressedRistretto::from_slice(&slice[pos + UNIT_LEN..pos + 2 * UNIT_LEN])
                    .expect("slice is 32 bytes"),
            );
        }

        let pos = 2 * lg_n * UNIT_LEN;
        let a_bytes: [u8; 32] = slice[pos..pos + UNIT_LEN].try_into().unwrap();
        let b_bytes: [u8; 32] = slice[pos + UNIT_LEN..pos + 2 * UNIT_LEN]
            .try_into()
            .unwrap();

        let a = Option::from(Scalar::from_canonical_bytes(a_bytes))
            .ok_or(ZkProofError::InvalidScalar)?;
        let b = Option::from(Scalar::from_canonical_bytes(b_bytes))
            .ok_or(ZkProofError::InvalidScalar)?;

        Ok(InnerProductProof { L_vec, R_vec, a, b })
    }

    /// Compute verification scalars (u_i^2, u_i^{-2}, s_i) from the transcript.
    #[allow(clippy::type_complexity)]
    fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<Scalar>, Vec<Scalar>, Vec<Scalar>), ZkProofError> {
        let lg_n = self.L_vec.len();
        if lg_n == 0 || lg_n >= 32 {
            return Err(ZkProofError::InvalidBitLength);
        }
        if n != (1usize << lg_n) {
            return Err(ZkProofError::InvalidBitLength);
        }

        transcript.inner_product_proof_domain_separator(n as u64);

        // Recompute challenges u_i from the transcript
        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            transcript.validate_and_append_point(b"L", L)?;
            transcript.validate_and_append_point(b"R", R)?;
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        // Compute u_i^{-1} via batch inversion; allinv = product of all inverses
        let mut challenges_inv = challenges.clone();
        let allinv = Scalar::batch_invert(&mut challenges_inv);

        // Square to get u_i^2 and u_i^{-2}
        for i in 0..lg_n {
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        // Compute s_i values inductively (Section 6.2 of Bulletproofs paper)
        let mut s = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = 31u32.checked_sub((i as u32).leading_zeros()).unwrap() as usize;
            let k = 1usize << lg_i;
            // Challenges are in creation order [u_{lg_n}, ..., u_1]
            let u_lg_i_sq = challenges_sq[lg_n - 1 - lg_i];
            s.push(s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }
}

// ---------------------------------------------------------------------------
// Scalar utility functions
// ---------------------------------------------------------------------------

struct ScalarExp {
    x: Scalar,
    next_exp_x: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

/// Iterator over powers of x: 1, x, x^2, x^3, ...
fn exp_iter(x: Scalar) -> ScalarExp {
    ScalarExp {
        x,
        next_exp_x: Scalar::ONE,
    }
}

/// Compute 1 + x + x^2 + ... + x^{n-1}.
fn sum_of_powers(x: &Scalar, n: usize) -> Scalar {
    if n == 0 || n == 1 {
        return Scalar::from(n as u64);
    }
    if !n.is_power_of_two() {
        return exp_iter(*x).take(n).sum();
    }
    let mut m = n;
    let mut result = Scalar::ONE + x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m /= 2;
    }
    result
}

/// Compute delta(y,z) for the range proof verification equation.
///
/// delta = (z - z^2) * <1, y^nm> - sum_{j=0}^{m-1} z^{j+3} * <1, 2^{n_j}>
fn delta(bit_lengths: &[usize], y: &Scalar, z: &Scalar) -> Scalar {
    let nm: usize = bit_lengths.iter().sum();
    let sum_y = sum_of_powers(y, nm);

    let mut agg_delta = (z - z * z) * sum_y;
    let mut exp_z = z * z * z;
    for n_i in bit_lengths.iter() {
        let sum_2 = sum_of_powers(&Scalar::from(2u64), *n_i);
        agg_delta -= exp_z * sum_2;
        exp_z *= z;
    }
    agg_delta
}

// ---------------------------------------------------------------------------
// Main verification entry point
// ---------------------------------------------------------------------------

/// Verify a Bulletproofs batched range proof.
///
/// The transcript should already have the context data (commitments, bit lengths)
/// appended before calling this function. The commitment_points are the decompressed
/// Pedersen commitments, bit_lengths are the per-commitment bit sizes, and
/// proof_bytes is the serialized proof (A, S, T_1, T_2, t_x, t_x_blinding,
/// e_blinding, inner_product_proof).
pub fn verify(
    transcript: &mut Transcript,
    commitment_points: &[RistrettoPoint],
    bit_lengths: &[u8],
    proof_bytes: &[u8],
    _max_bits: usize,
) -> Result<(), ZkProofError> {
    let m = commitment_points.len();
    if m != bit_lengths.len() || m == 0 {
        return Err(ZkProofError::InvalidBitLength);
    }

    // Convert bit lengths to usize for arithmetic
    let bl_usize: Vec<usize> = bit_lengths.iter().map(|&b| b as usize).collect();
    let nm: usize = bl_usize.iter().sum();

    if !nm.is_power_of_two() {
        return Err(ZkProofError::InvalidBitLength);
    }

    // Deserialize proof: 7 * 32 bytes header + inner product proof
    if proof_bytes.len() < 7 * UNIT_LEN {
        return Err(ZkProofError::InsufficientData);
    }
    if !proof_bytes.len().is_multiple_of(UNIT_LEN) {
        return Err(ZkProofError::InsufficientData);
    }

    let A = CompressedRistretto::from_slice(&proof_bytes[0..32]).expect("32 bytes");
    let S = CompressedRistretto::from_slice(&proof_bytes[32..64]).expect("32 bytes");
    let T_1 = CompressedRistretto::from_slice(&proof_bytes[64..96]).expect("32 bytes");
    let T_2 = CompressedRistretto::from_slice(&proof_bytes[96..128]).expect("32 bytes");

    let t_x_bytes: [u8; 32] = proof_bytes[128..160].try_into().unwrap();
    let t_x =
        Option::from(Scalar::from_canonical_bytes(t_x_bytes)).ok_or(ZkProofError::InvalidScalar)?;

    let t_x_blinding_bytes: [u8; 32] = proof_bytes[160..192].try_into().unwrap();
    let t_x_blinding = Option::from(Scalar::from_canonical_bytes(t_x_blinding_bytes))
        .ok_or(ZkProofError::InvalidScalar)?;

    let e_blinding_bytes: [u8; 32] = proof_bytes[192..224].try_into().unwrap();
    let e_blinding = Option::from(Scalar::from_canonical_bytes(e_blinding_bytes))
        .ok_or(ZkProofError::InvalidScalar)?;

    let ipp_proof = InnerProductProof::from_bytes(&proof_bytes[224..])?;

    // Generate range proof G/H vectors
    let bp_gens = RangeProofGens::new(nm);

    // --- Transcript protocol (must match prover exactly) ---

    transcript.range_proof_domain_separator(nm as u64);

    transcript.validate_and_append_point(b"A", &A)?;
    transcript.validate_and_append_point(b"S", &S)?;

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    let zz = z * z;
    let minus_z = -z;

    transcript.validate_and_append_point(b"T_1", &T_1)?;
    transcript.validate_and_append_point(b"T_2", &T_2)?;

    let x = transcript.challenge_scalar(b"x");

    transcript.append_scalar(b"t_x", &t_x);
    transcript.append_scalar(b"t_x_blinding", &t_x_blinding);
    transcript.append_scalar(b"e_blinding", &e_blinding);

    let w = transcript.challenge_scalar(b"w");

    // Backwards-compatibility challenge (consumed but unused)
    let _c = transcript.challenge_scalar(b"c");

    // Inner product verification scalars
    let (x_sq, x_inv_sq, s) = ipp_proof.verification_scalars(nm, transcript)?;

    let a = ipp_proof.a;
    let b_scalar = ipp_proof.b;

    transcript.append_scalar(b"ipp_a", &a);
    transcript.append_scalar(b"ipp_b", &b_scalar);

    // Batching challenge for algebraic relation checks
    let d = transcript.challenge_scalar(b"d");

    // --- Construct scalars for the mega check MSM ---

    // z^j * 2^i concatenated across all commitments
    let concat_z_and_2: Vec<Scalar> = exp_iter(z)
        .zip(bl_usize.iter())
        .flat_map(|(exp_z, n_i)| {
            exp_iter(Scalar::from(2u64))
                .take(*n_i)
                .map(move |exp_2| exp_2 * exp_z)
        })
        .collect();

    // G generator scalars: -z - a * s_i
    let gs = s.iter().map(|s_i| minus_z - a * s_i);

    // H generator scalars: z + y_inv^i * (z^2 * concat_z_and_2[i] - b * s_inv[i])
    let s_inv = s.iter().rev();
    let hs = s_inv
        .zip(exp_iter(y.invert()))
        .zip(concat_z_and_2.iter())
        .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b_scalar * s_i_inv));

    // Pedersen basepoint scalar
    let basepoint_scalar = w * (t_x - a * b_scalar) + d * (delta(&bl_usize, &y, &z) - t_x);

    // Value commitment scalars: d * z^2 * z^j for j = 0..m-1
    let value_commitment_scalars = exp_iter(z).take(m).map(|z_exp| d * zz * z_exp);

    // --- Final "mega check" MSM ---
    //
    // Verifies: 1*A + x*S + d*x*T_1 + d*x^2*T_2 + (-e - d*t_x_bl)*H_ped
    //           + basepoint*G_ped + <x_sq, L> + <x_inv_sq, R>
    //           + <gs, G_gens> + <hs, H_gens> + <vcs, V_comms> = identity
    let mega_check = RistrettoPoint::optional_multiscalar_mul(
        iter::once(Scalar::ONE)
            .chain(iter::once(x))
            .chain(iter::once(d * x))
            .chain(iter::once(d * x * x))
            .chain(iter::once(-e_blinding - d * t_x_blinding))
            .chain(iter::once(basepoint_scalar))
            .chain(x_sq.iter().cloned())
            .chain(x_inv_sq.iter().cloned())
            .chain(gs)
            .chain(hs)
            .chain(value_commitment_scalars),
        iter::once(A.decompress())
            .chain(iter::once(S.decompress()))
            .chain(iter::once(T_1.decompress()))
            .chain(iter::once(T_2.decompress()))
            .chain(iter::once(Some(*h())))
            .chain(iter::once(Some(G)))
            .chain(ipp_proof.L_vec.iter().map(|L| L.decompress()))
            .chain(ipp_proof.R_vec.iter().map(|R| R.decompress()))
            .chain(bp_gens.G(nm).map(|p| Some(*p)))
            .chain(bp_gens.H(nm).map(|p| Some(*p)))
            .chain(commitment_points.iter().map(|v| Some(*v))),
    )
    .ok_or(ZkProofError::InvalidPoint)?;

    if mega_check.is_identity() {
        Ok(())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_chain_deterministic() {
        let g1: Vec<RistrettoPoint> = GeneratorsChain::new(b"G").take(4).collect();
        let g2: Vec<RistrettoPoint> = GeneratorsChain::new(b"G").take(4).collect();
        assert_eq!(g1, g2);

        // Different labels produce different points
        let h1: Vec<RistrettoPoint> = GeneratorsChain::new(b"H").take(4).collect();
        assert_ne!(g1[0], h1[0]);
    }

    #[test]
    fn sum_of_powers_correctness() {
        let x = Scalar::from(3u64);
        // 1 + 3 + 9 + 27 = 40
        assert_eq!(sum_of_powers(&x, 4), Scalar::from(40u64));
        // 1 + 3 = 4
        assert_eq!(sum_of_powers(&x, 2), Scalar::from(4u64));
        // 1
        assert_eq!(sum_of_powers(&x, 1), Scalar::from(1u64));
        // 0
        assert_eq!(sum_of_powers(&x, 0), Scalar::from(0u64));
    }

    #[test]
    fn exp_iter_produces_powers() {
        let x = Scalar::from(5u64);
        let powers: Vec<Scalar> = exp_iter(x).take(4).collect();
        assert_eq!(powers[0], Scalar::ONE);
        assert_eq!(powers[1], Scalar::from(5u64));
        assert_eq!(powers[2], Scalar::from(25u64));
        assert_eq!(powers[3], Scalar::from(125u64));
    }

    #[test]
    fn inner_product_proof_from_bytes_rejects_bad_length() {
        // Not a multiple of 32
        assert!(InnerProductProof::from_bytes(&[0u8; 31]).is_err());
        // Too short (need at least a[32] + b[32])
        assert!(InnerProductProof::from_bytes(&[0u8; 32]).is_err());
        // Odd number of points
        assert!(InnerProductProof::from_bytes(&[0u8; 32 * 3]).is_err());
    }

    #[test]
    fn insufficient_proof_data_rejected() {
        let mut transcript = Transcript::new(b"test");
        let result = verify(&mut transcript, &[], &[], &[], 64);
        assert!(result.is_err());
    }
}
