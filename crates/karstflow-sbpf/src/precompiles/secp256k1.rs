//! Secp256k1 signature recovery precompile.
//!
//! Recovers a public key from a secp256k1 ECDSA signature and message
//! hash, then verifies that the derived Ethereum address matches the
//! expected one. This enables Ethereum-compatible signature verification.

use crate::{ExecutionContext, ExecutionOutcome};
use karstflow_constants::precompiles;

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
#[derive(Default)]
pub struct Secp256k1PrecompileExecutor;

impl Secp256k1PrecompileExecutor {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(&self, ctx: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if ctx.instruction_data.is_empty() {
            return Ok(ExecutionOutcome::success(
                precompiles::PRECOMPILE_COMPUTE_UNITS,
            ));
        }

        let num_signatures = ctx.instruction_data[0] as usize;

        if num_signatures == 0 {
            return Ok(ExecutionOutcome::success(
                precompiles::PRECOMPILE_COMPUTE_UNITS,
            ));
        }

        if ctx.instruction_data.len() < 2 {
            return Err("Secp256k1: instruction data too short".to_string());
        }

        // A precompile instruction consumes no compute units: its
        // signature verification is paid for by the transaction fee.
        let compute_used = precompiles::PRECOMPILE_COMPUTE_UNITS;

        // Validate minimum data length
        let min_data_len = 1 + num_signatures * ENTRY_HEADER_SIZE;
        if ctx.instruction_data.len() < min_data_len {
            return Err(format!(
                "Secp256k1: instruction data too short for {} signatures (need at least {} bytes, got {})",
                num_signatures, min_data_len, ctx.instruction_data.len()
            ));
        }

        // Verify each entry: recover the public key and compare the Ethereum address
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

            // Extract data
            let expected_eth_address =
                &ctx.instruction_data[eth_address_offset..eth_address_offset + ETH_ADDRESS_SIZE];
            let sig_bytes = &ctx.instruction_data[sig_offset..sig_offset + SIGNATURE_SIZE];
            let msg_hash =
                &ctx.instruction_data[msg_hash_offset..msg_hash_offset + MESSAGE_HASH_SIZE];

            // The signature is r (32 bytes) || s (32 bytes) || recovery_id (1 byte)
            let recovery_id = sig_bytes[64];
            let signature = &sig_bytes[..64];

            // Perform secp256k1 ECDSA recovery
            let recid = k256::ecdsa::RecoveryId::from_byte(recovery_id).ok_or_else(|| {
                format!(
                    "Secp256k1: invalid recovery id {} for signature #{}",
                    recovery_id, i
                )
            })?;

            let ecdsa_sig = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| format!("Secp256k1: invalid signature #{}: {}", i, e))?;

            let msg_hash_arr: [u8; 32] = msg_hash
                .try_into()
                .map_err(|_| format!("Secp256k1: invalid message hash size for #{}", i))?;

            let recovered_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
                &msg_hash_arr,
                &ecdsa_sig,
                recid,
            )
            .map_err(|e| format!("Secp256k1: recovery failed for signature #{}: {}", i, e))?;

            // Derive Ethereum address: keccak256 of uncompressed pubkey (sans 0x04 prefix), last 20 bytes
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let pubkey_point = recovered_key.to_encoded_point(false);
            let pubkey_bytes = &pubkey_point.as_bytes()[1..]; // skip 0x04 prefix

            use tiny_keccak::{Hasher, Keccak};
            let mut keccak = Keccak::v256();
            keccak.update(pubkey_bytes);
            let mut hash_output = [0u8; 32];
            keccak.finalize(&mut hash_output);

            let derived_address = &hash_output[12..]; // last 20 bytes

            if derived_address != expected_eth_address {
                return Err(format!(
                    "Secp256k1: recovered address does not match expected for signature #{}",
                    i
                ));
            }
        }

        let mut outcome = ExecutionOutcome::success(compute_used);
        outcome.logs.push(format!(
            "Secp256k1: verified {} signature(s)",
            num_signatures
        ));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::SECP256K1_PROGRAM_ID;

    /// Build an instruction with a real secp256k1 signature for end-to-end testing.
    fn build_real_secp256k1_instruction() -> Vec<u8> {
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::rand_core::OsRng;
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Message hash
        let message_hash = [0x42u8; 32];

        // Sign
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key.sign_prehash_recoverable(&message_hash).unwrap();

        // Derive Ethereum address
        let pubkey_point = verifying_key.to_encoded_point(false);
        let pubkey_bytes = &pubkey_point.as_bytes()[1..];

        use tiny_keccak::{Hasher, Keccak};
        let mut keccak = Keccak::v256();
        keccak.update(pubkey_bytes);
        let mut hash_output = [0u8; 32];
        keccak.finalize(&mut hash_output);
        let eth_address = &hash_output[12..];

        // Build instruction
        let num_signatures: u8 = 1;
        let header_total = 1 + ENTRY_HEADER_SIZE;

        let eth_offset = header_total as u16;
        let sig_offset = (header_total + ETH_ADDRESS_SIZE) as u16;
        let msg_offset = (header_total + ETH_ADDRESS_SIZE + SIGNATURE_SIZE) as u16;

        let mut data = Vec::new();
        data.push(num_signatures);

        // Entry header
        data.extend_from_slice(&eth_offset.to_le_bytes());
        data.push(0xFF); // eth_address_instruction_index
        data.extend_from_slice(&sig_offset.to_le_bytes());
        data.push(0xFF); // signature_instruction_index
        data.extend_from_slice(&msg_offset.to_le_bytes());
        data.extend_from_slice(&(MESSAGE_HASH_SIZE as u16).to_le_bytes());
        data.push(0xFF); // message_instruction_index

        // Eth address
        data.extend_from_slice(eth_address);
        // Signature: r || s || recovery_id
        data.extend_from_slice(&signature.to_bytes());
        data.push(recid.to_byte());
        // Message hash
        data.extend_from_slice(&message_hash);

        data
    }

    #[test]
    fn consumes_no_compute_units() {
        let executor = Secp256k1PrecompileExecutor::new();

        let instruction_data = build_real_secp256k1_instruction();

        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert_eq!(
            outcome.compute_units_consumed,
            precompiles::PRECOMPILE_COMPUTE_UNITS
        );
    }

    #[test]
    fn zero_signatures_succeeds() {
        let executor = Secp256k1PrecompileExecutor::new();

        let instruction_data = vec![0u8]; // 0 signatures
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            precompiles::PRECOMPILE_COMPUTE_UNITS
        );
    }

    #[test]
    fn empty_instruction_succeeds() {
        let executor = Secp256k1PrecompileExecutor::new();

        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], vec![]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
    }

    #[test]
    fn real_signature_verifies() {
        let executor = Secp256k1PrecompileExecutor::new();

        let instruction_data = build_real_secp256k1_instruction();
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("verified 1 signature"));
    }

    #[test]
    fn rejects_truncated_instruction() {
        let executor = Secp256k1PrecompileExecutor::new();

        // 1 signature but only 5 bytes of data (not enough for header)
        let instruction_data = vec![1u8, 0, 0, 0, 0];
        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn rejects_wrong_eth_address() {
        let executor = Secp256k1PrecompileExecutor::new();

        let mut instruction_data = build_real_secp256k1_instruction();
        // Corrupt the eth address (located at offset = 1 + ENTRY_HEADER_SIZE)
        let eth_start = 1 + ENTRY_HEADER_SIZE;
        instruction_data[eth_start] ^= 0xFF;

        let ctx = ExecutionContext::new(SECP256K1_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match"));
    }
}
