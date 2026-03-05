/// Solana transaction wire format deserialization.
///
/// Parses raw binary transaction data (as received over the network or via
/// RPC) into `SanitizedTransaction` values ready for execution.
///
/// Supports both legacy and versioned (V0) message formats including
/// address lookup table references.
use crate::bank_executor::{CompiledInstruction, SanitizedTransaction};
use karstflow_constants::transaction as tx_const;
use karstflow_storage::Pubkey;

/// Intermediate result of transaction deserialization.
///
/// Contains the partially-built transaction and any address lookup table
/// references that need to be resolved before execution.
pub struct DeserializedTransaction {
    pub tx: SanitizedTransaction,
    /// `(table_key, writable_indices, readonly_indices)` tuples from V0 messages.
    pub address_table_lookups: Vec<(Pubkey, Vec<u8>, Vec<u8>)>,
}

/// Decode a Solana compact-u16 value from the given byte slice.
///
/// Returns `(decoded_value, bytes_consumed)` or an error message.
pub fn decode_compact_u16(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("unexpected end of data for compact-u16".to_string());
    }

    let first = data[0] as usize;
    if first <= 0x7F {
        Ok((first, 1))
    } else {
        if data.len() < 2 {
            return Err("truncated compact-u16".to_string());
        }
        let value = ((first & 0x7F) << 8) | (data[1] as usize);
        Ok((value, 2))
    }
}

/// Deserialize raw binary transaction data into a `SanitizedTransaction`.
///
/// Wire format (legacy):
///   `[compact-u16: signature_count]`
///   `[signature_count * 64 bytes: signatures]`
///   `[message bytes]`:
///     `[1 byte: num_required_signatures]`
///     `[1 byte: num_readonly_signed]`
///     `[1 byte: num_readonly_unsigned]`
///     `[compact-u16: num_account_keys]`
///     `[num_account_keys * 32 bytes: account keys]`
///     `[32 bytes: recent_blockhash]`
///     `[compact-u16: num_instructions]`
///     per instruction:
///       `[1 byte: program_id_index]`
///       `[compact-u16: num_account_indices]`
///       `[num_account_indices bytes: account indices]`
///       `[compact-u16: data_length]`
///       `[data_length bytes: instruction data]`
///
/// Versioned (V0) messages have an additional prefix byte (`0x80`) and
/// address lookup table entries appended after the instructions.
pub fn deserialize_transaction(data: &[u8]) -> Result<DeserializedTransaction, String> {
    if data.len() < tx_const::MIN_TRANSACTION_SIZE {
        return Err(format!(
            "transaction too small: {} bytes (minimum {})",
            data.len(),
            tx_const::MIN_TRANSACTION_SIZE
        ));
    }
    if data.len() > tx_const::MAX_TRANSACTION_SIZE {
        return Err(format!(
            "transaction too large: {} bytes (maximum {})",
            data.len(),
            tx_const::MAX_TRANSACTION_SIZE
        ));
    }

    let mut offset = 0;

    // --- Signatures ---
    let (sig_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if sig_count == 0 || sig_count > tx_const::MAX_SIGNATURES {
        return Err(format!("invalid signature count: {}", sig_count));
    }

    let sigs_len = sig_count * tx_const::SIGNATURE_SIZE;
    if data.len() < offset + sigs_len {
        return Err("truncated signature data".to_string());
    }

    let mut signatures = Vec::with_capacity(sig_count);
    for i in 0..sig_count {
        let start = offset + i * tx_const::SIGNATURE_SIZE;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[start..start + tx_const::SIGNATURE_SIZE]);
        signatures.push(sig);
    }
    offset += sigs_len;

    // --- Message ---
    let message_start = offset;
    let message_bytes = data[message_start..].to_vec();

    if offset >= data.len() {
        return Err("truncated message".to_string());
    }

    // Detect versioned message: high bit set on first byte means versioned.
    let is_versioned = data[offset] & 0x80 != 0;
    if is_versioned {
        let version = data[offset] & 0x7F;
        if version != 0 {
            return Err(format!("unsupported message version: {version}"));
        }
        offset += 1; // consume version byte
    }

    if data.len() < offset + 3 {
        return Err("truncated message header".to_string());
    }

    let num_required_signatures = data[offset] as u64;
    let num_readonly_signed = data[offset + 1];
    let num_readonly_unsigned = data[offset + 2];
    offset += 3;

    // Account keys
    let (account_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if account_count > tx_const::MAX_ACCOUNTS {
        return Err(format!("too many accounts: {}", account_count));
    }

    let keys_len = account_count * tx_const::PUBKEY_SIZE;
    if data.len() < offset + keys_len {
        return Err("truncated account keys".to_string());
    }

    let mut account_keys = Vec::with_capacity(account_count);
    for i in 0..account_count {
        let start = offset + i * tx_const::PUBKEY_SIZE;
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[start..start + tx_const::PUBKEY_SIZE]);
        account_keys.push(Pubkey::from(key));
    }
    offset += keys_len;

    // Recent blockhash
    if data.len() < offset + tx_const::BLOCKHASH_SIZE {
        return Err("truncated blockhash".to_string());
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(&data[offset..offset + tx_const::BLOCKHASH_SIZE]);
    offset += tx_const::BLOCKHASH_SIZE;

    // Instructions
    let (instruction_count, compact_len) = decode_compact_u16(&data[offset..])?;
    offset += compact_len;

    if instruction_count > tx_const::MAX_INSTRUCTIONS {
        return Err(format!("too many instructions: {}", instruction_count));
    }

    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        if offset >= data.len() {
            return Err("truncated instruction".to_string());
        }

        let program_id_index = data[offset];
        offset += 1;

        let (num_accounts, compact_len) = decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        if data.len() < offset + num_accounts {
            return Err("truncated instruction account indices".to_string());
        }
        let account_indices = data[offset..offset + num_accounts].to_vec();
        offset += num_accounts;

        let (data_len, compact_len) = decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        if data.len() < offset + data_len {
            return Err("truncated instruction data".to_string());
        }
        let instr_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        instructions.push(CompiledInstruction {
            program_id_index,
            account_indices,
            data: instr_data,
        });
    }

    // Parse address table lookups for V0 messages.
    let mut address_table_lookups = Vec::new();
    if is_versioned {
        let (lookup_count, compact_len) = decode_compact_u16(&data[offset..])?;
        offset += compact_len;

        for _ in 0..lookup_count {
            // Table key (32 bytes)
            if data.len() < offset + 32 {
                return Err("truncated lookup table key".to_string());
            }
            let mut table_key = [0u8; 32];
            table_key.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            // Writable indices
            let (num_writable, compact_len) = decode_compact_u16(&data[offset..])?;
            offset += compact_len;
            if data.len() < offset + num_writable {
                return Err("truncated writable indices".to_string());
            }
            let writable_indices = data[offset..offset + num_writable].to_vec();
            offset += num_writable;

            // Readonly indices
            let (num_readonly, compact_len) = decode_compact_u16(&data[offset..])?;
            offset += compact_len;
            if data.len() < offset + num_readonly {
                return Err("truncated readonly indices".to_string());
            }
            let readonly_indices = data[offset..offset + num_readonly].to_vec();
            offset += num_readonly;

            address_table_lookups.push((
                Pubkey::from(table_key),
                writable_indices,
                readonly_indices,
            ));
        }
    }

    let _ = offset; // suppress unused warning
    let num_static = account_keys.len();
    Ok(DeserializedTransaction {
        tx: SanitizedTransaction {
            account_keys,
            recent_blockhash,
            instructions,
            num_signatures: num_required_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
            signatures,
            message_bytes,
            num_static_keys: num_static,
            num_writable_lookup_keys: 0,
        },
        address_table_lookups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a compact-u16 value into a byte buffer (for test transaction construction).
    fn encode_compact_u16(buf: &mut Vec<u8>, value: usize) {
        if value <= 0x7F {
            buf.push(value as u8);
        } else {
            buf.push(((value >> 8) as u8) | 0x80);
            buf.push(value as u8);
        }
    }

    fn build_minimal_legacy_transaction() -> Vec<u8> {
        let mut data = Vec::new();

        // 1 signature
        encode_compact_u16(&mut data, 1);
        data.extend_from_slice(&[0xAA; 64]); // signature

        // Message header: 1 signer, 0 readonly_signed, 0 readonly_unsigned
        data.push(1);
        data.push(0);
        data.push(0);

        // 2 account keys
        encode_compact_u16(&mut data, 2);
        data.extend_from_slice(&[0x11; 32]); // fee payer
        data.extend_from_slice(&[0x22; 32]); // recipient

        // Recent blockhash
        data.extend_from_slice(&[0xBB; 32]);

        // 1 instruction: program_id_index=1, 1 account index [0], 4 bytes data
        encode_compact_u16(&mut data, 1);
        data.push(1); // program_id_index
        encode_compact_u16(&mut data, 1); // 1 account
        data.push(0); // account index
        encode_compact_u16(&mut data, 4); // 4 bytes data
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        data
    }

    #[test]
    fn deserialize_legacy_transaction() {
        let data = build_minimal_legacy_transaction();
        let result = deserialize_transaction(&data).expect("should parse");
        assert_eq!(result.tx.signatures.len(), 1);
        assert_eq!(result.tx.account_keys.len(), 2);
        assert_eq!(result.tx.instructions.len(), 1);
        assert_eq!(result.tx.recent_blockhash, [0xBB; 32]);
        assert!(result.address_table_lookups.is_empty());
    }

    #[test]
    fn reject_empty_transaction() {
        let result = deserialize_transaction(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized_transaction() {
        let data = vec![0u8; tx_const::MAX_TRANSACTION_SIZE + 1];
        let result = deserialize_transaction(&data);
        assert!(result.is_err());
    }

    #[test]
    fn compact_u16_roundtrip() {
        for value in [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x3FFF] {
            let mut buf = Vec::new();
            encode_compact_u16(&mut buf, value);
            let (decoded, _) = decode_compact_u16(&buf).unwrap();
            assert_eq!(decoded, value);
        }
    }
}
