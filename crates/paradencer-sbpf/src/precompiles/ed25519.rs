//! Ed25519 signature verification precompile.
//!
//! Verifies Ed25519 signatures within transaction instruction data.
//! The instruction encodes one or more signature verification requests,
//! each containing a public key, message, and signature. All signatures
//! must be valid for the instruction to succeed.

use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::precompiles;

/// Ed25519 signature size in bytes.
const SIGNATURE_SIZE: usize = 64;
/// Ed25519 public key size in bytes.
const PUBLIC_KEY_SIZE: usize = 32;

/// Offsets for a single signature verification entry.
///
/// Instruction data layout for each signature:
///   [2 bytes signature_offset] [2 bytes signature_instruction_index]
///   [2 bytes public_key_offset] [2 bytes public_key_instruction_index]
///   [2 bytes message_data_offset] [2 bytes message_data_size]
///   [2 bytes message_instruction_index]
const ENTRY_HEADER_SIZE: usize = 14;

/// Executor for the Ed25519 signature verification precompile.
pub struct Ed25519PrecompileExecutor {
    base_cost: u64,
}

impl Ed25519PrecompileExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        if ctx.instruction_data.len() < 2 {
            return Err("Ed25519: instruction data too short".to_string());
        }

        let num_signatures = ctx.instruction_data[0] as usize;
        let _padding = ctx.instruction_data[1]; // Must be 0, but we skip strict check

        if num_signatures == 0 {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        // Calculate total compute cost
        let compute_used = self
            .base_cost
            .saturating_add(precompiles::ED25519_VERIFY_COST)
            .saturating_add(precompiles::ED25519_VERIFY_PER_SIGNATURE * num_signatures as u64);

        // Check that compute budget is sufficient
        if compute_used > ctx.compute_budget {
            return Err("Ed25519: compute budget exceeded".to_string());
        }

        // Validate that we have enough data for the entry headers
        let min_data_len = 2 + num_signatures * ENTRY_HEADER_SIZE;
        if ctx.instruction_data.len() < min_data_len {
            return Err(format!(
                "Ed25519: instruction data too short for {} signatures (need at least {} bytes, got {})",
                num_signatures, min_data_len, ctx.instruction_data.len()
            ));
        }

        // Attempt to verify each signature
        for i in 0..num_signatures {
            let entry_offset = 2 + i * ENTRY_HEADER_SIZE;

            let sig_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset..entry_offset + 2]
                    .try_into()
                    .map_err(|_| "Ed25519: failed to parse signature offset")?,
            ) as usize;

            let pubkey_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 4..entry_offset + 6]
                    .try_into()
                    .map_err(|_| "Ed25519: failed to parse public key offset")?,
            ) as usize;

            let message_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 8..entry_offset + 10]
                    .try_into()
                    .map_err(|_| "Ed25519: failed to parse message offset")?,
            ) as usize;

            let message_size = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 10..entry_offset + 12]
                    .try_into()
                    .map_err(|_| "Ed25519: failed to parse message size")?,
            ) as usize;

            // Validate bounds
            if sig_offset + SIGNATURE_SIZE > ctx.instruction_data.len() {
                return Err(format!("Ed25519: signature #{} out of bounds", i));
            }
            if pubkey_offset + PUBLIC_KEY_SIZE > ctx.instruction_data.len() {
                return Err(format!("Ed25519: public key #{} out of bounds", i));
            }
            if message_offset + message_size > ctx.instruction_data.len() {
                return Err(format!("Ed25519: message #{} out of bounds", i));
            }

            // Extract signature, public key, and message
            let signature_bytes = &ctx.instruction_data[sig_offset..sig_offset + SIGNATURE_SIZE];
            let pubkey_bytes =
                &ctx.instruction_data[pubkey_offset..pubkey_offset + PUBLIC_KEY_SIZE];
            let message_bytes =
                &ctx.instruction_data[message_offset..message_offset + message_size];

            // Perform actual Ed25519 verification using ed25519-dalek
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                pubkey_bytes
                    .try_into()
                    .map_err(|_| format!("Ed25519: invalid public key #{}", i))?,
            )
            .map_err(|e| format!("Ed25519: invalid public key #{}: {}", i, e))?;

            let signature = ed25519_dalek::Signature::from_bytes(
                signature_bytes
                    .try_into()
                    .map_err(|_| format!("Ed25519: invalid signature #{}", i))?,
            );

            use ed25519_dalek::Verifier;
            verifying_key
                .verify(message_bytes, &signature)
                .map_err(|e| format!("Ed25519: signature #{} verification failed: {}", i, e))?;
        }

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome
            .logs
            .push(format!("Ed25519: verified {} signature(s)", num_signatures));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use paradencer_ids::ED25519_PROGRAM_ID;
    use paradencer_types::Pubkey;

    fn build_ed25519_instruction(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let signature = signing_key.sign(message);
        let public_key = signing_key.verifying_key();

        let num_signatures: u8 = 1;
        let padding: u8 = 0;

        // Header is at offset 0..2
        // Entry starts at offset 2
        // Signature at offset 2 + ENTRY_HEADER_SIZE
        // Public key after signature
        // Message after public key

        let sig_offset = (2 + ENTRY_HEADER_SIZE) as u16;
        let pubkey_offset = sig_offset + SIGNATURE_SIZE as u16;
        let message_offset = pubkey_offset + PUBLIC_KEY_SIZE as u16;
        let message_size = message.len() as u16;

        let mut data = Vec::new();
        data.push(num_signatures);
        data.push(padding);

        // Entry header
        data.extend_from_slice(&sig_offset.to_le_bytes()); // signature_offset
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // signature_instruction_index (same instruction)
        data.extend_from_slice(&pubkey_offset.to_le_bytes()); // public_key_offset
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // public_key_instruction_index
        data.extend_from_slice(&message_offset.to_le_bytes()); // message_data_offset
        data.extend_from_slice(&message_size.to_le_bytes()); // message_data_size
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // message_instruction_index

        // Signature
        data.extend_from_slice(&signature.to_bytes());
        // Public key
        data.extend_from_slice(public_key.as_bytes());
        // Message
        data.extend_from_slice(message);

        data
    }

    #[test]
    fn verifies_valid_signature() {
        let executor = Ed25519PrecompileExecutor::new(150);

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let message = b"hello world";

        let instruction_data = build_ed25519_instruction(&signing_key, message);

        let ctx = ExecutionContext::new(ED25519_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("verified 1 signature"));
    }

    #[test]
    fn rejects_invalid_signature() {
        let executor = Ed25519PrecompileExecutor::new(150);

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let message = b"hello world";

        let mut instruction_data = build_ed25519_instruction(&signing_key, message);
        // Corrupt the signature (first byte after the header)
        let sig_start = 2 + ENTRY_HEADER_SIZE;
        instruction_data[sig_start] ^= 0xFF;

        let ctx = ExecutionContext::new(ED25519_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn deducts_per_signature_cost() {
        let executor = Ed25519PrecompileExecutor::new(150);

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let message = b"test";

        let instruction_data = build_ed25519_instruction(&signing_key, message);
        let ctx = ExecutionContext::new(ED25519_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        let expected_cost =
            150 + precompiles::ED25519_VERIFY_COST + precompiles::ED25519_VERIFY_PER_SIGNATURE;
        assert_eq!(outcome.compute_units_consumed, expected_cost);
    }

    #[test]
    fn zero_signatures_succeeds() {
        let executor = Ed25519PrecompileExecutor::new(150);

        let instruction_data = vec![0u8, 0u8]; // 0 signatures
        let ctx = ExecutionContext::new(ED25519_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.compute_units_consumed, 150);
    }

    #[test]
    fn empty_instruction_succeeds() {
        let executor = Ed25519PrecompileExecutor::new(150);

        let ctx = ExecutionContext::new(ED25519_PROGRAM_ID, vec![], vec![]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
    }
}
