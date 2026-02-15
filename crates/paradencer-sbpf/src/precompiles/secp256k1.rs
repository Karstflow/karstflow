//! Secp256k1 signature recovery precompile.
//!
//! Recovers a public key from a secp256k1 ECDSA signature and message
//! hash, verifying that the recovered key matches the expected one.
//! This is used for Ethereum-compatible signature verification.
//!
//! Note: actual secp256k1 recovery is deferred to a later implementation
//! phase. This executor validates the instruction format and deducts
//! the correct compute costs.

use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::precompiles;

/// Size of a secp256k1 signature (r + s + recovery_id).
const SIGNATURE_SIZE: usize = 65;
/// Size of an Ethereum address (keccak256 of public key, last 20 bytes).
const ETH_ADDRESS_SIZE: usize = 20;
/// Size of a message hash (keccak256).
const MESSAGE_HASH_SIZE: usize = 32;

/// Per-entry header size in the instruction data.
///
/// Each entry:
///   [2 bytes eth_address_offset] [1 byte eth_address_instruction_index]
///   [2 bytes signature_offset] [1 byte signature_instruction_index]
///   [2 bytes message_hash_offset] [2 bytes message_data_size]
///   [1 byte message_instruction_index]
const ENTRY_HEADER_SIZE: usize = 11;

/// Executor for the Secp256k1 ECDSA recovery precompile.
pub struct Secp256k1PrecompileExecutor {
    base_cost: u64,
}

impl Secp256k1PrecompileExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        let num_signatures = ctx.instruction_data[0] as usize;

        if num_signatures == 0 {
            return Ok(ExecutionOutcome::success(self.base_cost));
        }

        if ctx.instruction_data.len() < 2 {
            return Err("Secp256k1: instruction data too short".to_string());
        }

        // Calculate total compute cost
        let compute_used = self
            .base_cost
            .saturating_add(precompiles::SECP256K1_VERIFY_COST)
            .saturating_add(precompiles::SECP256K1_VERIFY_PER_SIGNATURE * num_signatures as u64);

        if compute_used > ctx.compute_budget {
            return Err("Secp256k1: compute budget exceeded".to_string());
        }

        // Validate minimum data length
        let min_data_len = 1 + num_signatures * ENTRY_HEADER_SIZE;
        if ctx.instruction_data.len() < min_data_len {
            return Err(format!(
                "Secp256k1: instruction data too short for {} signatures (need at least {} bytes, got {})",
                num_signatures, min_data_len, ctx.instruction_data.len()
            ));
        }

        // Validate each entry has valid offsets
        for i in 0..num_signatures {
            let entry_offset = 1 + i * ENTRY_HEADER_SIZE;

            let eth_address_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset..entry_offset + 2]
                    .try_into()
                    .map_err(|_| "Secp256k1: failed to parse eth address offset")?,
            ) as usize;

            let sig_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 3..entry_offset + 5]
                    .try_into()
                    .map_err(|_| "Secp256k1: failed to parse signature offset")?,
            ) as usize;

            let msg_hash_offset = u16::from_le_bytes(
                ctx.instruction_data[entry_offset + 6..entry_offset + 8]
                    .try_into()
                    .map_err(|_| "Secp256k1: failed to parse message hash offset")?,
            ) as usize;

            // Validate bounds
            if eth_address_offset + ETH_ADDRESS_SIZE > ctx.instruction_data.len() {
                return Err(format!("Secp256k1: eth address #{} out of bounds", i));
            }
            if sig_offset + SIGNATURE_SIZE > ctx.instruction_data.len() {
                return Err(format!("Secp256k1: signature #{} out of bounds", i));
            }
            if msg_hash_offset + MESSAGE_HASH_SIZE > ctx.instruction_data.len() {
                return Err(format!("Secp256k1: message hash #{} out of bounds", i));
            }
        }

        // Actual secp256k1 recovery will be implemented in a later phase.
        // For now, we validate the format and deduct correct compute costs.

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.logs.push(format!(
            "Secp256k1: processed {} signature(s)",
            num_signatures
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::SECP256K1_PROGRAM_ID;
    use paradencer_types::Pubkey;

    fn build_secp256k1_instruction(num_signatures: u8) -> Vec<u8> {
        // Build a minimal valid instruction with proper offsets
        let mut data = Vec::new();
        data.push(num_signatures);

        let header_total = 1 + num_signatures as usize * ENTRY_HEADER_SIZE;

        for i in 0..num_signatures as usize {
            // Calculate where to place the data for this entry
            let base = header_total + i * (ETH_ADDRESS_SIZE + SIGNATURE_SIZE + MESSAGE_HASH_SIZE);

            let eth_offset = base as u16;
            let eth_instr_index: u8 = 0xFF;
            let sig_offset = (base + ETH_ADDRESS_SIZE) as u16;
            let sig_instr_index: u8 = 0xFF;
            let msg_offset = (base + ETH_ADDRESS_SIZE + SIGNATURE_SIZE) as u16;
            let msg_size: u16 = MESSAGE_HASH_SIZE as u16;
            let msg_instr_index: u8 = 0xFF;

            data.extend_from_slice(&eth_offset.to_le_bytes());
            data.push(eth_instr_index);
            data.extend_from_slice(&sig_offset.to_le_bytes());
            data.push(sig_instr_index);
            data.extend_from_slice(&msg_offset.to_le_bytes());
            data.extend_from_slice(&msg_size.to_le_bytes());
            data.push(msg_instr_index);
        }

        // Append dummy data for each entry
        for _ in 0..num_signatures {
            data.extend_from_slice(&[0u8; ETH_ADDRESS_SIZE]); // eth address
            data.extend_from_slice(&[0u8; SIGNATURE_SIZE]); // signature
            data.extend_from_slice(&[0u8; MESSAGE_HASH_SIZE]); // message hash
        }

        data
    }

    #[test]
    fn deducts_per_signature_cost() {
        let executor = Secp256k1PrecompileExecutor::new(150);

        let instruction_data = build_secp256k1_instruction(2);

        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        let expected_cost = 150
            + precompiles::SECP256K1_VERIFY_COST
            + precompiles::SECP256K1_VERIFY_PER_SIGNATURE * 2;
        assert_eq!(outcome.compute_units_consumed, expected_cost);
    }

    #[test]
    fn zero_signatures_succeeds() {
        let executor = Secp256k1PrecompileExecutor::new(150);

        let instruction_data = vec![0u8]; // 0 signatures
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.compute_units_consumed, 150);
    }

    #[test]
    fn empty_instruction_succeeds() {
        let executor = Secp256k1PrecompileExecutor::new(150);

        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], vec![]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn single_signature_computes_correctly() {
        let executor = Secp256k1PrecompileExecutor::new(150);

        let instruction_data = build_secp256k1_instruction(1);
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let expected =
            150 + precompiles::SECP256K1_VERIFY_COST + precompiles::SECP256K1_VERIFY_PER_SIGNATURE;
        assert_eq!(outcome.compute_units_consumed, expected);
    }

    #[test]
    fn rejects_truncated_instruction() {
        let executor = Secp256k1PrecompileExecutor::new(150);

        // 1 signature but only 5 bytes of data (not enough for header)
        let instruction_data = vec![1u8, 0, 0, 0, 0];
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }
}
