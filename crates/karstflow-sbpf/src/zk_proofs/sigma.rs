//! Sigma proof verifiers for all ZK ElGamal proof types.
//!
//! Each verifier takes raw proof data bytes (context + proof concatenated),
//! parses the components, creates the Merlin transcript, and verifies the
//! algebraic relation via multi-scalar multiplication.

#![allow(non_snake_case)]

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use merlin::Transcript;

use super::errors::ZkProofError;
use super::generators::{h, G};
use super::transcript::TranscriptProtocol;
use super::UNIT_LEN;

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_point(data: &[u8]) -> Result<CompressedRistretto, ZkProofError> {
    if data.len() < UNIT_LEN {
        return Err(ZkProofError::InsufficientData);
    }
    Ok(CompressedRistretto::from_slice(&data[..UNIT_LEN]).expect("slice is 32 bytes"))
}

fn parse_scalar(data: &[u8]) -> Result<Scalar, ZkProofError> {
    if data.len() < UNIT_LEN {
        return Err(ZkProofError::InsufficientData);
    }
    let bytes: [u8; 32] = data[..UNIT_LEN].try_into().unwrap();
    // Validate canonical form (< group order)
    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(ZkProofError::InvalidScalar)
}

fn decompress(point: &CompressedRistretto) -> Result<RistrettoPoint, ZkProofError> {
    point.decompress().ok_or(ZkProofError::InvalidPoint)
}

/// Split data at offset, returning (left, right). Errors if insufficient.
fn split_at(data: &[u8], offset: usize) -> Result<(&[u8], &[u8]), ZkProofError> {
    if data.len() < offset {
        return Err(ZkProofError::InsufficientData);
    }
    Ok(data.split_at(offset))
}

// ---------------------------------------------------------------------------
// Pubkey Validity (discriminant 4)
// ---------------------------------------------------------------------------
// Context: pubkey[32] = 32 bytes
// Proof: Y[32] + z[32] = 64 bytes
// Total: 96 bytes

pub fn verify_pubkey_validity(proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    let (context, proof) = split_at(proof_data, 32)?;

    // Parse context
    let pubkey_bytes = &context[..32];
    let P_compressed = parse_point(pubkey_bytes)?;
    let P = decompress(&P_compressed)?;

    if P_compressed.is_identity() {
        return Err(ZkProofError::IdentityPoint);
    }

    // Parse proof
    let Y_compressed = parse_point(proof)?;
    let z = parse_scalar(&proof[32..])?;

    // Build transcript
    let mut transcript = Transcript::new(b"pubkey-validity-instruction");
    transcript.append_message(b"pubkey", pubkey_bytes);
    transcript.pubkey_proof_domain_separator();

    // Append Y and derive challenge
    transcript.validate_and_append_point(b"Y", &Y_compressed)?;
    let c = transcript.challenge_scalar(b"c");

    // Decompress Y
    let Y = decompress(&Y_compressed)?;

    // Verify: z*H - c*P - Y = identity
    let check = RistrettoPoint::vartime_multiscalar_mul(&[z, -c, -Scalar::ONE], &[*h(), P, Y]);

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Zero Ciphertext (discriminant 1)
// ---------------------------------------------------------------------------
// Context: pubkey[32] + ciphertext[64] = 96 bytes
// Proof: Y_P[32] + Y_D[32] + z[32] = 96 bytes
// Total: 192 bytes

pub fn verify_zero_ciphertext(proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    let (context, proof) = split_at(proof_data, 96)?;

    // Parse context
    let pubkey_bytes = &context[..32];
    let ciphertext_bytes = &context[32..96];
    // Ciphertext = commitment[32] + handle[32]
    let C_compressed = parse_point(&ciphertext_bytes[..32])?;
    let D_compressed = parse_point(&ciphertext_bytes[32..64])?;
    let P_compressed = parse_point(pubkey_bytes)?;

    let P = decompress(&P_compressed)?;
    let C = decompress(&C_compressed)?;
    let D = decompress(&D_compressed)?;

    // Parse proof
    let Y_P_compressed = parse_point(proof)?;
    let Y_D_compressed = parse_point(&proof[32..])?;
    let z = parse_scalar(&proof[64..])?;

    // Build transcript
    let mut transcript = Transcript::new(b"zero-ciphertext-instruction");
    transcript.append_message(b"pubkey", pubkey_bytes);
    transcript.append_message(b"ciphertext", ciphertext_bytes);
    transcript.zero_ciphertext_proof_domain_separator();

    // Append proof points and derive challenges
    transcript.validate_and_append_point(b"Y_P", &Y_P_compressed)?;
    transcript.append_point(b"Y_D", &Y_D_compressed);
    let c = transcript.challenge_scalar(b"c");

    transcript.append_scalar(b"z", &z);
    let w = transcript.challenge_scalar(b"w");

    let w_neg = -w;

    // Decompress proof points
    let Y_P = decompress(&Y_P_compressed)?;
    let Y_D = decompress(&Y_D_compressed)?;

    // Verify: z*P - c*H - Y_P + w*(z*D - c*C - Y_D) = identity
    let check = RistrettoPoint::vartime_multiscalar_mul(
        &[
            z,            // P
            -c,           // H
            -Scalar::ONE, // Y_P
            w * z,        // D
            w_neg * c,    // C
            w_neg,        // Y_D
        ],
        &[P, *h(), Y_P, D, C, Y_D],
    );

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Ciphertext-Ciphertext Equality (discriminant 2)
// ---------------------------------------------------------------------------
// Context: first_pubkey[32] + second_pubkey[32] + first_ciphertext[64] +
//          second_ciphertext[64] = 192 bytes
// Proof: Y_0[32]+Y_1[32]+Y_2[32]+Y_3[32]+z_s[32]+z_x[32]+z_r[32] = 224 bytes
// Total: 416 bytes

pub fn verify_ciphertext_ciphertext_equality(proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    let (context, proof) = split_at(proof_data, 192)?;

    // Parse context
    let first_pubkey_bytes = &context[0..32];
    let second_pubkey_bytes = &context[32..64];
    let first_ciphertext_bytes = &context[64..128];
    let second_ciphertext_bytes = &context[128..192];

    let P_first = decompress(&parse_point(first_pubkey_bytes)?)?;
    let P_second = decompress(&parse_point(second_pubkey_bytes)?)?;
    // first ciphertext: commitment[32] + handle[32]
    let C_first = decompress(&parse_point(&first_ciphertext_bytes[..32])?)?;
    let D_first = decompress(&parse_point(&first_ciphertext_bytes[32..64])?)?;
    // second ciphertext
    let C_second = decompress(&parse_point(&second_ciphertext_bytes[..32])?)?;
    let D_second = decompress(&parse_point(&second_ciphertext_bytes[32..64])?)?;

    // Parse proof (7 * 32 = 224 bytes)
    if proof.len() < 224 {
        return Err(ZkProofError::InsufficientData);
    }
    let Y_0_c = parse_point(&proof[0..])?;
    let Y_1_c = parse_point(&proof[32..])?;
    let Y_2_c = parse_point(&proof[64..])?;
    let Y_3_c = parse_point(&proof[96..])?;
    let z_s = parse_scalar(&proof[128..])?;
    let z_x = parse_scalar(&proof[160..])?;
    let z_r = parse_scalar(&proof[192..])?;

    // Build transcript
    let mut transcript = Transcript::new(b"ciphertext-ciphertext-equality-instruction");
    transcript.append_message(b"first-pubkey", first_pubkey_bytes);
    transcript.append_message(b"second-pubkey", second_pubkey_bytes);
    transcript.append_message(b"first-ciphertext", first_ciphertext_bytes);
    transcript.append_message(b"second-ciphertext", second_ciphertext_bytes);
    transcript.ciphertext_ciphertext_equality_proof_domain_separator();

    transcript.validate_and_append_point(b"Y_0", &Y_0_c)?;
    transcript.validate_and_append_point(b"Y_1", &Y_1_c)?;
    transcript.validate_and_append_point(b"Y_2", &Y_2_c)?;
    transcript.validate_and_append_point(b"Y_3", &Y_3_c)?;

    let c = transcript.challenge_scalar(b"c");

    transcript.append_scalar(b"z_s", &z_s);
    transcript.append_scalar(b"z_x", &z_x);
    transcript.append_scalar(b"z_r", &z_r);
    let w = transcript.challenge_scalar(b"w");
    let ww = w * w;
    let www = w * ww;

    let w_neg = -w;
    let ww_neg = -ww;
    let www_neg = -www;

    // Decompress proof points
    let Y_0 = decompress(&Y_0_c)?;
    let Y_1 = decompress(&Y_1_c)?;
    let Y_2 = decompress(&Y_2_c)?;
    let Y_3 = decompress(&Y_3_c)?;

    // MSM check: 4 equations batched with powers of w
    let check = RistrettoPoint::vartime_multiscalar_mul(
        &[
            z_s,          // P_first
            -c,           // H
            -Scalar::ONE, // Y_0
            w * z_x,      // G
            w * z_s,      // D_first
            w_neg * c,    // C_first
            w_neg,        // Y_1
            ww * z_x,     // G (again)
            ww * z_r,     // H (again)
            ww_neg * c,   // C_second
            ww_neg,       // Y_2
            www * z_r,    // P_second
            www_neg * c,  // D_second
            www_neg,      // Y_3
        ],
        &[
            P_first,
            *h(),
            Y_0,
            G,
            D_first,
            C_first,
            Y_1,
            G,
            *h(),
            C_second,
            Y_2,
            P_second,
            D_second,
            Y_3,
        ],
    );

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Ciphertext-Commitment Equality (discriminant 3)
// ---------------------------------------------------------------------------
// Context: pubkey[32] + ciphertext[64] + commitment[32] = 128 bytes
// Proof: Y_0[32]+Y_1[32]+Y_2[32]+z_s[32]+z_x[32]+z_r[32] = 192 bytes
// Total: 320 bytes

pub fn verify_ciphertext_commitment_equality(proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    let (context, proof) = split_at(proof_data, 128)?;

    // Parse context
    let pubkey_bytes = &context[0..32];
    let ciphertext_bytes = &context[32..96];
    let commitment_bytes = &context[96..128];

    let P = decompress(&parse_point(pubkey_bytes)?)?;
    let C_ciphertext = decompress(&parse_point(&ciphertext_bytes[..32])?)?;
    let D = decompress(&parse_point(&ciphertext_bytes[32..64])?)?;
    let C_commitment = decompress(&parse_point(commitment_bytes)?)?;

    // Parse proof (6 * 32 = 192 bytes)
    if proof.len() < 192 {
        return Err(ZkProofError::InsufficientData);
    }
    let Y_0_c = parse_point(&proof[0..])?;
    let Y_1_c = parse_point(&proof[32..])?;
    let Y_2_c = parse_point(&proof[64..])?;
    let z_s = parse_scalar(&proof[96..])?;
    let z_x = parse_scalar(&proof[128..])?;
    let z_r = parse_scalar(&proof[160..])?;

    // Build transcript
    let mut transcript = Transcript::new(b"ciphertext-commitment-equality-instruction");
    transcript.append_message(b"pubkey", pubkey_bytes);
    transcript.append_message(b"ciphertext", ciphertext_bytes);
    transcript.append_message(b"commitment", commitment_bytes);
    transcript.ciphertext_commitment_equality_proof_domain_separator();

    transcript.validate_and_append_point(b"Y_0", &Y_0_c)?;
    transcript.validate_and_append_point(b"Y_1", &Y_1_c)?;
    transcript.validate_and_append_point(b"Y_2", &Y_2_c)?;

    let c = transcript.challenge_scalar(b"c");

    transcript.append_scalar(b"z_s", &z_s);
    transcript.append_scalar(b"z_x", &z_x);
    transcript.append_scalar(b"z_r", &z_r);
    let w = transcript.challenge_scalar(b"w");
    let ww = w * w;

    let w_neg = -w;
    let ww_neg = -ww;

    let Y_0 = decompress(&Y_0_c)?;
    let Y_1 = decompress(&Y_1_c)?;
    let Y_2 = decompress(&Y_2_c)?;

    // 3 equations batched with powers of w
    let check = RistrettoPoint::vartime_multiscalar_mul(
        &[
            z_s,          // P
            -c,           // H
            -Scalar::ONE, // Y_0
            w * z_x,      // G
            w * z_s,      // D
            w_neg * c,    // C_ciphertext
            w_neg,        // Y_1
            ww * z_x,     // G
            ww * z_r,     // H
            ww_neg * c,   // C_commitment
            ww_neg,       // Y_2
        ],
        &[
            P,
            *h(),
            Y_0,
            G,
            D,
            C_ciphertext,
            Y_1,
            G,
            *h(),
            C_commitment,
            Y_2,
        ],
    );

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Percentage with Cap (discriminant 5)
// ---------------------------------------------------------------------------
// Context: percentage_commitment[32] + delta_commitment[32] +
//          claimed_commitment[32] + max_value[8] = 104 bytes
// Proof: Y_max[32]+z_max[32]+c_max[32]+Y_delta[32]+Y_claimed[32]+
//        z_x[32]+z_delta[32]+z_claimed[32] = 256 bytes
// Total: 360 bytes

pub fn verify_percentage_with_cap(proof_data: &[u8]) -> Result<Vec<u8>, ZkProofError> {
    let (context, proof) = split_at(proof_data, 104)?;

    // Parse context
    let pct_commitment_bytes = &context[0..32];
    let delta_commitment_bytes = &context[32..64];
    let claimed_commitment_bytes = &context[64..96];
    let max_value_bytes = &context[96..104];
    let max_value = u64::from_le_bytes(max_value_bytes.try_into().unwrap());
    let m = Scalar::from(max_value);

    let C_max = decompress(&parse_point(pct_commitment_bytes)?)?;
    let C_delta = decompress(&parse_point(delta_commitment_bytes)?)?;
    let C_claimed = decompress(&parse_point(claimed_commitment_bytes)?)?;

    // Parse proof (8 * 32 = 256 bytes)
    if proof.len() < 256 {
        return Err(ZkProofError::InsufficientData);
    }
    let Y_max_c = parse_point(&proof[0..])?;
    let z_max = parse_scalar(&proof[32..])?;
    let c_max_proof = parse_scalar(&proof[64..])?;
    let Y_delta_c = parse_point(&proof[96..])?;
    let Y_claimed_c = parse_point(&proof[128..])?;
    let z_x = parse_scalar(&proof[160..])?;
    let z_delta = parse_scalar(&proof[192..])?;
    let z_claimed = parse_scalar(&proof[224..])?;

    // Build transcript
    let mut transcript = Transcript::new(b"percentage-with-cap-instruction");
    transcript.append_message(b"percentage-commitment", pct_commitment_bytes);
    transcript.append_message(b"delta-commitment", delta_commitment_bytes);
    transcript.append_message(b"claimed-commitment", claimed_commitment_bytes);
    transcript.append_u64(b"max-value", max_value);
    transcript.percentage_with_cap_proof_domain_separator();

    transcript.validate_and_append_point(b"Y_max_proof", &Y_max_c)?;
    transcript.validate_and_append_point(b"Y_delta", &Y_delta_c)?;
    transcript.validate_and_append_point(b"Y_claimed", &Y_claimed_c)?;

    let Y_max = decompress(&Y_max_c)?;
    let Y_delta = decompress(&Y_delta_c)?;
    let Y_claimed = decompress(&Y_claimed_c)?;

    let c = transcript.challenge_scalar(b"c");
    let c_equality = c - c_max_proof;

    transcript.append_scalar(b"z_max", &z_max);
    transcript.append_scalar(b"c_max_proof", &c_max_proof);
    transcript.append_scalar(b"z_x", &z_x);
    transcript.append_scalar(b"z_delta_real", &z_delta);
    transcript.append_scalar(b"z_claimed", &z_claimed);
    let w = transcript.challenge_scalar(b"w");
    let ww = w * w;

    // 3 equations batched: max proof + equality-delta (w) + equality-claimed (w^2)
    let check = RistrettoPoint::vartime_multiscalar_mul(
        &[
            c_max_proof,
            -c_max_proof * m,
            -z_max,
            Scalar::ONE,
            w * z_x,
            w * z_delta,
            -w * c_equality,
            -w,
            ww * z_x,
            ww * z_claimed,
            -ww * c_equality,
            -ww,
        ],
        &[
            C_max,
            G,
            *h(),
            Y_max,
            G,
            *h(),
            C_delta,
            Y_delta,
            G,
            *h(),
            C_claimed,
            Y_claimed,
        ],
    );

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Grouped Ciphertext Validity (discriminants 9-12)
// ---------------------------------------------------------------------------
// 2-handle non-batched (disc 9):
//   Context: first_pubkey[32] + second_pubkey[32] + grouped_ciphertext[96] = 160 bytes
//   Proof: Y_0[32]+Y_1[32]+Y_2[32]+z_r[32]+z_x[32] = 160 bytes
//
// 3-handle non-batched (disc 11):
//   Context: pubkey1[32]+pubkey2[32]+pubkey3[32]+grouped_ciphertext[128] = 224 bytes
//   Proof: Y_0[32]+Y_1[32]+Y_2[32]+Y_3[32]+z_r[32]+z_x[32] = 192 bytes
//
// 2-handle batched (disc 10):
//   Context: pubkey1[32]+pubkey2[32]+grouped_ct_lo[96]+grouped_ct_hi[96] = 256 bytes
//   Proof: 2 * (Y_0[32]+Y_1[32]+Y_2[32]+z_r[32]+z_x[32]) = 320 bytes
//
// 3-handle batched (disc 12):
//   Context: pubkey1[32]+pubkey2[32]+pubkey3[32]+grouped_ct_lo[128]+grouped_ct_hi[128] = 352 bytes
//   Proof: 2 * (Y_0..Y_3+z_r+z_x) = 384 bytes

pub fn verify_grouped_ciphertext_validity(
    proof_data: &[u8],
    handles: usize,
    batched: bool,
) -> Result<Vec<u8>, ZkProofError> {
    if batched {
        verify_batched_grouped_ciphertext(proof_data, handles)
    } else {
        verify_single_grouped_ciphertext(proof_data, handles)
    }
}

fn verify_single_grouped_ciphertext(
    proof_data: &[u8],
    handles: usize,
) -> Result<Vec<u8>, ZkProofError> {
    // grouped_ciphertext = commitment[32] + handle[32]*handles
    let grouped_ct_len = 32 + 32 * handles;
    let context_len = 32 * handles + grouped_ct_len;
    let proof_points = handles + 1; // Y_0..Y_{handles}
    let proof_len = proof_points * 32 + 2 * 32; // points + z_r + z_x

    let (context, proof) = split_at(proof_data, context_len)?;
    if proof.len() < proof_len {
        return Err(ZkProofError::InsufficientData);
    }

    // Parse pubkeys
    let mut pubkeys = Vec::with_capacity(handles);
    for i in 0..handles {
        pubkeys.push(decompress(&parse_point(&context[i * 32..])?)?);
    }

    // Parse grouped ciphertext
    let ct_offset = handles * 32;
    let C = decompress(&parse_point(&context[ct_offset..])?)?;
    let mut D_handles = Vec::with_capacity(handles);
    for i in 0..handles {
        D_handles.push(decompress(&parse_point(
            &context[ct_offset + 32 + i * 32..],
        )?)?);
    }

    // Parse proof points
    let mut Y_points = Vec::with_capacity(proof_points);
    let mut Y_compressed = Vec::with_capacity(proof_points);
    for i in 0..proof_points {
        let yc = parse_point(&proof[i * 32..])?;
        Y_compressed.push(yc);
        Y_points.push(decompress(&yc)?);
    }
    let scalar_offset = proof_points * 32;
    let z_r = parse_scalar(&proof[scalar_offset..])?;
    let z_x = parse_scalar(&proof[scalar_offset + 32..])?;

    // Build transcript
    let transcript_label = match handles {
        2 => &b"grouped-ciphertext-validity-2-handles-instruction"[..],
        3 => &b"grouped-ciphertext-validity-3-handles-instruction"[..],
        _ => return Err(ZkProofError::UnknownProofType),
    };
    let mut transcript = Transcript::new(transcript_label);

    // Append pubkey context
    for i in 0..handles {
        let label: &[u8] = match i {
            0 => b"first-pubkey",
            1 => b"second-pubkey",
            2 => b"third-pubkey",
            _ => unreachable!(),
        };
        transcript.append_message(label, &context[i * 32..(i + 1) * 32]);
    }
    transcript.append_message(
        b"grouped-ciphertext",
        &context[ct_offset..ct_offset + grouped_ct_len],
    );

    transcript.grouped_ciphertext_validity_proof_domain_separator(handles as u64);

    // Append proof points
    transcript.validate_and_append_point(b"Y_0", &Y_compressed[0])?;
    transcript.validate_and_append_point(b"Y_1", &Y_compressed[1])?;
    if handles >= 2 {
        // Y_2 can be identity if second pubkey is zero
        transcript.append_point(b"Y_2", &Y_compressed[2]);
    }
    if handles >= 3 {
        transcript.append_point(b"Y_3", &Y_compressed[3]);
    }

    let c = transcript.challenge_scalar(b"c");

    transcript.append_scalar(b"z_r", &z_r);
    transcript.append_scalar(b"z_x", &z_x);
    let w = transcript.challenge_scalar(b"w");

    // Build MSM: equation 0 (commitment) + equations 1..handles (handles)
    let mut scalars = Vec::new();
    let mut points = Vec::new();

    // Eq 0: z_r*H + z_x*G - c*C - Y_0 = 0
    scalars.extend_from_slice(&[z_r, z_x, -c, -Scalar::ONE]);
    points.extend_from_slice(&[*h(), G, C, Y_points[0]]);

    // Eq i (for each handle): w^i * (z_r*P_i - c*D_i - Y_{i+1}) = 0
    let mut w_power = w;
    for i in 0..handles {
        scalars.push(w_power * z_r);
        points.push(pubkeys[i]);
        scalars.push(-w_power * c);
        points.push(D_handles[i]);
        scalars.push(-w_power);
        points.push(Y_points[i + 1]);
        w_power *= w;
    }

    let check = RistrettoPoint::vartime_multiscalar_mul(&scalars, &points);

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

fn verify_batched_grouped_ciphertext(
    proof_data: &[u8],
    handles: usize,
) -> Result<Vec<u8>, ZkProofError> {
    // Batched = two grouped ciphertexts (lo + hi) with a single batched proof
    // that proves both are valid under the same pubkeys.
    let grouped_ct_len = 32 + 32 * handles;
    let context_len = 32 * handles + 2 * grouped_ct_len;

    let (context, proof) = split_at(proof_data, context_len)?;

    // Parse pubkeys
    let mut pubkeys = Vec::with_capacity(handles);
    let mut pubkey_bytes_list = Vec::with_capacity(handles);
    for i in 0..handles {
        pubkey_bytes_list.push(&context[i * 32..(i + 1) * 32]);
        pubkeys.push(decompress(&parse_point(&context[i * 32..])?)?);
    }

    // Parse two grouped ciphertexts
    let ct_offset = handles * 32;
    let lo_ct = &context[ct_offset..ct_offset + grouped_ct_len];
    let hi_ct = &context[ct_offset + grouped_ct_len..ct_offset + 2 * grouped_ct_len];

    // For batched proofs, the proof contains TWO sigma proofs concatenated,
    // but with a single batched verification using a transcript challenge t.
    // Each sub-proof has: (handles+1) points + 2 scalars
    let proof_points = handles + 1;
    let single_proof_len = proof_points * 32 + 2 * 32;

    if proof.len() < 2 * single_proof_len {
        return Err(ZkProofError::InsufficientData);
    }

    // Build transcript
    let transcript_label = match handles {
        2 => &b"batched-grouped-ciphertext-validity-2-handles-instruction"[..],
        3 => &b"batched-grouped-ciphertext-validity-3-handles-instruction"[..],
        _ => return Err(ZkProofError::UnknownProofType),
    };
    let mut transcript = Transcript::new(transcript_label);

    for i in 0..handles {
        let label: &[u8] = match i {
            0 => b"first-pubkey",
            1 => b"second-pubkey",
            2 => b"third-pubkey",
            _ => unreachable!(),
        };
        transcript.append_message(label, pubkey_bytes_list[i]);
    }
    transcript.append_message(b"grouped-ciphertext-lo", lo_ct);
    transcript.append_message(b"grouped-ciphertext-hi", hi_ct);

    transcript.batched_grouped_ciphertext_validity_proof_domain_separator(handles as u64);

    // Derive batching challenge t
    let t = transcript.challenge_scalar(b"t");

    // Now verify each sub-proof independently but combine with batching scalar t.
    // We verify: proof_lo + t * proof_hi using a single grouped ciphertext
    // verification on combined values.

    // Parse lo ciphertext
    let C_lo = decompress(&parse_point(&lo_ct[0..])?)?;
    let mut D_lo = Vec::with_capacity(handles);
    for i in 0..handles {
        D_lo.push(decompress(&parse_point(&lo_ct[32 + i * 32..])?)?);
    }

    // Parse hi ciphertext
    let C_hi = decompress(&parse_point(&hi_ct[0..])?)?;
    let mut D_hi = Vec::with_capacity(handles);
    for i in 0..handles {
        D_hi.push(decompress(&parse_point(&hi_ct[32 + i * 32..])?)?);
    }

    // Combine: C_combined = C_lo + t*C_hi, D_combined[i] = D_lo[i] + t*D_hi[i]
    let C_combined = C_lo + t * C_hi;
    let mut D_combined = Vec::with_capacity(handles);
    for i in 0..handles {
        D_combined.push(D_lo[i] + t * D_hi[i]);
    }

    // Parse proof (single combined proof after batching)
    // The batched proof proof section contains the combined sigma proof
    let mut Y_compressed = Vec::with_capacity(proof_points);
    let mut Y_points = Vec::with_capacity(proof_points);
    for i in 0..proof_points {
        let yc = parse_point(&proof[i * 32..])?;
        Y_compressed.push(yc);
        Y_points.push(decompress(&yc)?);
    }
    let scalar_offset = proof_points * 32;
    let z_r = parse_scalar(&proof[scalar_offset..])?;
    let z_x = parse_scalar(&proof[scalar_offset + 32..])?;

    // Continue transcript with combined proof
    transcript.validate_and_append_point(b"Y_0", &Y_compressed[0])?;
    transcript.validate_and_append_point(b"Y_1", &Y_compressed[1])?;
    if proof_points > 2 {
        transcript.append_point(b"Y_2", &Y_compressed[2]);
    }
    if proof_points > 3 {
        transcript.append_point(b"Y_3", &Y_compressed[3]);
    }

    let c = transcript.challenge_scalar(b"c");

    transcript.append_scalar(b"z_r", &z_r);
    transcript.append_scalar(b"z_x", &z_x);
    let w = transcript.challenge_scalar(b"w");

    // Build MSM (same structure as non-batched but with combined ciphertext)
    let mut scalars = Vec::new();
    let mut points_vec = Vec::new();

    // Eq 0: z_r*H + z_x*G - c*C_combined - Y_0
    scalars.extend_from_slice(&[z_r, z_x, -c, -Scalar::ONE]);
    points_vec.extend_from_slice(&[*h(), G, C_combined, Y_points[0]]);

    let mut w_power = w;
    for i in 0..handles {
        scalars.push(w_power * z_r);
        points_vec.push(pubkeys[i]);
        scalars.push(-w_power * c);
        points_vec.push(D_combined[i]);
        scalars.push(-w_power);
        points_vec.push(Y_points[i + 1]);
        w_power *= w;
    }

    let check = RistrettoPoint::vartime_multiscalar_mul(&scalars, &points_vec);

    if check.is_identity() {
        Ok(context.to_vec())
    } else {
        Err(ZkProofError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Batched Range Proof (discriminants 6, 7, 8)
// ---------------------------------------------------------------------------
// Context: commitments[8*32] + bit_lengths[8] = 264 bytes
// Proof: A[32]+S[32]+T_1[32]+T_2[32]+t_x[32]+t_x_blinding[32]+e_blinding[32]
//        + inner_product_proof[variable]
//
// Range proof verification is complex (Bulletproofs). For now, delegate to
// a dedicated range proof module. This is a placeholder that will be
// completed in Wave 2 (task #189).

pub fn verify_batched_range_proof(
    proof_data: &[u8],
    max_bits: usize,
) -> Result<Vec<u8>, ZkProofError> {
    let context_len = 8 * 32 + 8; // 264 bytes
    let (context, proof) = split_at(proof_data, context_len)?;

    // Parse context: validate commitments and bit lengths
    let commitments_bytes = &context[0..256];
    let bit_lengths_bytes = &context[256..264];

    // Count active commitments (non-zero bit lengths)
    let mut total_bits: usize = 0;
    let mut num_commitments: usize = 0;
    for i in 0..8 {
        let bl = bit_lengths_bytes[i] as usize;
        if bl > 0 {
            if bl > 64 {
                return Err(ZkProofError::InvalidBitLength);
            }
            total_bits += bl;
            num_commitments = i + 1;
        } else if num_commitments > 0 {
            // Non-zero bit lengths must be contiguous from the start
            // (remaining must be zero)
            let commitment = &commitments_bytes[i * 32..(i + 1) * 32];
            if commitment.iter().any(|&b| b != 0) {
                return Err(ZkProofError::InvalidBitLength);
            }
        }
    }

    if num_commitments == 0 {
        return Err(ZkProofError::InvalidBitLength);
    }

    // total_bits must equal max_bits
    if total_bits != max_bits {
        return Err(ZkProofError::InvalidBitLength);
    }

    // Build transcript
    let mut transcript = Transcript::new(b"batched-range-proof-instruction");
    transcript.append_message(b"commitments", commitments_bytes);
    transcript.append_message(b"bit-lengths", bit_lengths_bytes);

    // Decompress commitment points
    let mut commitment_points = Vec::with_capacity(num_commitments);
    for i in 0..num_commitments {
        commitment_points.push(decompress(&parse_point(&commitments_bytes[i * 32..])?)?);
    }

    // Delegate to range proof verifier
    super::range_proof_verify(
        &mut transcript,
        &commitment_points,
        &bit_lengths_bytes[..num_commitments],
        proof,
        max_bits,
    )?;

    Ok(context.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_data_rejected() {
        assert!(verify_pubkey_validity(&[0u8; 10]).is_err());
        assert!(verify_zero_ciphertext(&[0u8; 10]).is_err());
        assert!(verify_ciphertext_ciphertext_equality(&[0u8; 10]).is_err());
        assert!(verify_ciphertext_commitment_equality(&[0u8; 10]).is_err());
        assert!(verify_percentage_with_cap(&[0u8; 10]).is_err());
    }

    #[test]
    fn all_zeros_rejected() {
        // All-zero proof data should fail (identity point rejection or verification failure)
        let result = verify_pubkey_validity(&[0u8; 96]);
        assert!(result.is_err());

        let result = verify_zero_ciphertext(&[0u8; 192]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_point_rejected() {
        // Point that doesn't decompress to a valid Ristretto point
        let mut data = [0u8; 96];
        data[0] = 0xFF; // invalid compressed point
        let result = verify_pubkey_validity(&data);
        assert!(result.is_err());
    }
}
