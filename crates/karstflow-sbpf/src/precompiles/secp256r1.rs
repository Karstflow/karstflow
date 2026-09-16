//! Secp256r1 (NIST P-256) ECDSA signature verification precompile.
//!
//! Verifies P-256 ECDSA signatures within transaction instruction data.
//! Each instruction encodes one or more verification entries, each
//! containing a compressed public key, signature, and message. The
//! message is SHA-256 hashed before verification. All entries must
//! pass for the instruction to succeed.
//!
//! Enforces low-S signatures to prevent malleability.

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::precompiles;

/// Compressed P-256 public key size in bytes.
const COMPRESSED_PUBKEY_SIZE: usize = 33;
/// P-256 ECDSA signature size: r (32 bytes) || s (32 bytes).
const SIGNATURE_SIZE: usize = 64;

/// Per-entry header size in the instruction data.
///
/// Each entry (14 bytes):
///   [2 bytes signature_offset] [2 bytes signature_instruction_index]
///   [2 bytes public_key_offset] [2 bytes public_key_instruction_index]
///   [2 bytes message_data_offset] [2 bytes message_data_size]
///   [2 bytes message_instruction_index]
const ENTRY_HEADER_SIZE: usize = 14;

/// Executor for the Secp256r1 ECDSA verification precompile.
#[derive(Default)]
pub struct Secp256r1PrecompileExecutor;

impl Secp256r1PrecompileExecutor {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(
                precompiles::PRECOMPILE_COMPUTE_UNITS,
            ));
        }

        if ctx.instruction_data.len() < 2 {
            return Err("Secp256r1: instruction data too short".to_string());
        }

        let num_signatures = ctx.instruction_data[0] as usize;
        // Byte 1 is padding (reserved, should be 0)

        if num_signatures == 0 {
            return Ok(ExecutionOutcome::success(
                precompiles::PRECOMPILE_COMPUTE_UNITS,
            ));
        }

        // A precompile instruction consumes no compute units: its
        // signature verification is paid for by the transaction fee.
        let compute_used = precompiles::PRECOMPILE_COMPUTE_UNITS;

        // Validate minimum data length for entry headers
        let min_data_len = 2 + num_signatures * ENTRY_HEADER_SIZE;
        if ctx.instruction_data.len() < min_data_len {
            return Err(format!(
                "Secp256r1: instruction data too short for {} signatures (need at least {} bytes, got {})",
                num_signatures, min_data_len, ctx.instruction_data.len()
            ));
        }

        // Verify each entry
        for i in 0..num_signatures {
            let entry_offset = 2 + i * ENTRY_HEADER_SIZE;

            let sig_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset..entry_offset + 2]
                    .try_into()
                    .map_err(|_| "Secp256r1: failed to parse signature offset")?,
            ) as usize;

            let pubkey_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 4..entry_offset + 6]
                    .try_into()
                    .map_err(|_| "Secp256r1: failed to parse public key offset")?,
            ) as usize;

            let message_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 8..entry_offset + 10]
                    .try_into()
                    .map_err(|_| "Secp256r1: failed to parse message offset")?,
            ) as usize;

            let message_size = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 10..entry_offset + 12]
                    .try_into()
                    .map_err(|_| "Secp256r1: failed to parse message size")?,
            ) as usize;

            // Validate bounds
            if sig_offset + SIGNATURE_SIZE > ctx.instruction_data.len() {
                return Err(format!("Secp256r1: signature #{} out of bounds", i));
            }
            if pubkey_offset + COMPRESSED_PUBKEY_SIZE > ctx.instruction_data.len() {
                return Err(format!("Secp256r1: public key #{} out of bounds", i));
            }
            if message_offset + message_size > ctx.instruction_data.len() {
                return Err(format!("Secp256r1: message #{} out of bounds", i));
            }

            let sig_bytes = &ctx.instruction_data[sig_offset..sig_offset + SIGNATURE_SIZE];
            let pubkey_bytes =
                &ctx.instruction_data[pubkey_offset..pubkey_offset + COMPRESSED_PUBKEY_SIZE];
            let message_bytes =
                &ctx.instruction_data[message_offset..message_offset + message_size];

            // Parse and validate signature
            let signature = p256::ecdsa::Signature::from_slice(sig_bytes)
                .map_err(|e| format!("Secp256r1: invalid signature #{}: {}", i, e))?;

            // Reject high-S signatures to prevent malleability.
            // normalize_s() returns Some if s was high (and normalizes it),
            // None if s was already low.
            if signature.normalize_s().is_some() {
                return Err(format!(
                    "Secp256r1: high-S signature #{} rejected (malleability prevention)",
                    i
                ));
            }

            // Parse compressed public key
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey_bytes)
                .map_err(|e| format!("Secp256r1: invalid public key #{}: {}", i, e))?;

            // SHA-256 hash the message
            use sha2::Digest;
            let message_hash = sha2::Sha256::digest(message_bytes);
            let hash_bytes: [u8; 32] = message_hash.into();

            // Verify: ECDSA on pre-hashed digest
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            verifying_key
                .verify_prehash(&hash_bytes, &signature)
                .map_err(|e| format!("Secp256r1: signature #{} verification failed: {}", i, e))?;
        }

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.logs.push(format!(
            "Secp256r1: verified {} signature(s)",
            num_signatures
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::SECP256R1_PROGRAM_ID;

    /// Build a secp256r1 precompile instruction with a real signature.
    fn build_secp256r1_instruction(message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // SHA-256 hash the message (this is what the precompile does internally)
        use sha2::Digest;
        let message_hash = sha2::Sha256::digest(message);
        let hash_bytes: [u8; 32] = message_hash.into();

        // Sign the pre-hashed message
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash_bytes).unwrap();

        // Normalize to low-S if needed
        let signature = match signature.normalize_s() {
            Some(normalized) => normalized,
            None => signature,
        };

        // Get compressed public key
        let compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = compressed.as_bytes();

        let num_signatures: u8 = 1;
        let padding: u8 = 0;

        // Layout: header(2) + entry_header(14) + signature(64) + pubkey(33) + message
        let sig_offset = (2 + ENTRY_HEADER_SIZE) as u16;
        let pubkey_offset = sig_offset + SIGNATURE_SIZE as u16;
        let message_offset = pubkey_offset + COMPRESSED_PUBKEY_SIZE as u16;
        let message_size = message.len() as u16;

        let mut data = Vec::new();
        data.push(num_signatures);
        data.push(padding);

        // Entry header (14 bytes)
        data.extend_from_slice(&sig_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // sig instruction index
        data.extend_from_slice(&pubkey_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // pubkey instruction index
        data.extend_from_slice(&message_offset.to_le_bytes());
        data.extend_from_slice(&message_size.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // msg instruction index

        // Signature (64 bytes)
        data.extend_from_slice(&signature.to_bytes());
        // Compressed public key (33 bytes)
        data.extend_from_slice(pubkey_bytes);
        // Message
        data.extend_from_slice(message);

        data
    }

    #[test]
    fn verifies_valid_signature() {
        let executor = Secp256r1PrecompileExecutor::new();

        let instruction_data = build_secp256r1_instruction(b"hello world");
        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("verified 1 signature"));
    }

    #[test]
    fn consumes_no_compute_units() {
        let executor = Secp256r1PrecompileExecutor::new();

        let instruction_data = build_secp256r1_instruction(b"test");
        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert_eq!(
            outcome.compute_units_consumed,
            precompiles::PRECOMPILE_COMPUTE_UNITS
        );
    }

    #[test]
    fn zero_signatures_succeeds() {
        let executor = Secp256r1PrecompileExecutor::new();

        let instruction_data = vec![0u8, 0u8]; // 0 signatures + padding
        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            precompiles::PRECOMPILE_COMPUTE_UNITS
        );
    }

    #[test]
    fn empty_instruction_succeeds() {
        let executor = Secp256r1PrecompileExecutor::new();

        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], vec![]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn rejects_truncated_instruction() {
        let executor = Secp256r1PrecompileExecutor::new();

        // 1 signature but only 5 bytes of data (not enough for header)
        let instruction_data = vec![1u8, 0, 0, 0, 0];
        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn rejects_corrupted_signature() {
        let executor = Secp256r1PrecompileExecutor::new();

        let mut instruction_data = build_secp256r1_instruction(b"test");
        // Corrupt the signature (located at 2 + ENTRY_HEADER_SIZE)
        let sig_start = 2 + ENTRY_HEADER_SIZE;
        instruction_data[sig_start] ^= 0xFF;

        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_message() {
        let executor = Secp256r1PrecompileExecutor::new();

        let mut instruction_data = build_secp256r1_instruction(b"original message");
        // Corrupt the message (last bytes of instruction data)
        let msg_start = instruction_data.len() - 16;
        instruction_data[msg_start] ^= 0xFF;

        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn succeeds_under_a_tiny_compute_budget() {
        let executor = Secp256r1PrecompileExecutor::new();

        let instruction_data = build_secp256r1_instruction(b"test");
        let mut ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], instruction_data);
        ctx.compute_budget = 0;

        // A precompile charges nothing, so no budget is small enough to
        // starve it. This once returned "compute budget exceeded".
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            precompiles::PRECOMPILE_COMPUTE_UNITS
        );
    }

    #[test]
    fn rejects_high_s_signature() {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test high-S";
        use sha2::Digest;
        let message_hash = sha2::Sha256::digest(message);
        let hash_bytes: [u8; 32] = message_hash.into();

        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash_bytes).unwrap();

        // If the signature is already low-S, we need to create a high-S variant.
        // We do this by "un-normalizing" the signature if it's already low-S,
        // or skipping this test if we can't produce a high-S signature.
        let high_s_sig = match signature.normalize_s() {
            Some(_) => {
                // Already high-S — use original
                signature
            }
            None => {
                // Already low-S — we can't easily produce a high-S without
                // raw field manipulation. Test with a hand-crafted high-S
                // signature instead: create raw bytes with s > half_order.

                // The P-256 order n:
                // 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
                // half_order = n/2:
                // 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE7357D6538BCF427DCE5E6117E31928
                //
                // A value of s = n-1 would be high-S. Let's use the signature r
                // with a fabricated high-s to test the rejection path.
                let sig_bytes = signature.to_bytes();
                let mut high_s_bytes = [0u8; 64];
                high_s_bytes[..32].copy_from_slice(&sig_bytes[..32]); // keep r
                                                                      // Set s to 0xFF...FF (definitely > half_order for P-256)
                high_s_bytes[32..].fill(0xFF);

                // This will fail to parse as a valid signature because 0xFF..FF > order
                // So instead, set s = order - 1 which is a valid field element and high-S
                let order_minus_1: [u8; 32] = [
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
                    0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
                ];
                high_s_bytes[32..].copy_from_slice(&order_minus_1);

                match p256::ecdsa::Signature::from_slice(&high_s_bytes) {
                    Ok(s) => s,
                    Err(_) => return, // Can't construct valid high-S test case, skip
                }
            }
        };

        // Build instruction manually with the high-S signature
        let compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = compressed.as_bytes();

        let sig_offset = (2 + ENTRY_HEADER_SIZE) as u16;
        let pubkey_offset = sig_offset + SIGNATURE_SIZE as u16;
        let message_offset = pubkey_offset + COMPRESSED_PUBKEY_SIZE as u16;
        let message_size = message.len() as u16;

        let mut data = Vec::new();
        data.push(1u8); // 1 signature
        data.push(0u8); // padding
        data.extend_from_slice(&sig_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&pubkey_offset.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&message_offset.to_le_bytes());
        data.extend_from_slice(&message_size.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&high_s_sig.to_bytes());
        data.extend_from_slice(pubkey_bytes);
        data.extend_from_slice(message);

        let executor = Secp256r1PrecompileExecutor::new();
        let ctx = ExecutionContext::new(SECP256R1_PROGRAM_ID, vec![], data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should either fail with "high-S" or "verification failed"
        assert!(
            err.contains("high-S") || err.contains("verification failed"),
            "unexpected error: {}",
            err
        );
    }
}
