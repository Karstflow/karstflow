/// `FragmentCodec` implementation for `SanitizedTransaction`.
///
/// Encoding format (all multi-byte integers little-endian):
///
/// ```text
/// [num_keys:2][keys:32*N]
/// [blockhash:32]
/// [num_signatures:8]
/// [readonly_signed:1][readonly_unsigned:1]
/// [sig_count:2][sigs:64*N]
/// [num_static_keys:2][num_writable_lookup:2]
/// [ix_count:2][ix_0...ix_N]
/// [msg_len:4][msg_bytes:M]
/// ```
///
/// Instruction encoding:
/// ```text
/// [program_id_index:1][acct_count:2][acct_indices:A][data_len:4][data:D]
/// ```
use paradencer_mesh::FragmentCodec;

use crate::bank_executor::{CompiledInstruction, SanitizedTransaction};

// Fixed header: 2 + 32 + 8 + 1 + 1 + 2 + 2 + 2 + 2 + 4 = 56 bytes
const SAN_TX_FIXED: usize = 2 + 32 + 8 + 1 + 1 + 2 + 2 + 2 + 2 + 4;
// Conservative max: 64 keys, 8 sigs, 16 instructions, 1232-byte message
const SAN_TX_MAX_KEYS: usize = 64;
const SAN_TX_MAX_SIGS: usize = 8;
const SAN_TX_MAX_MSG: usize = 1232;
// Per instruction: 1 + 2 + 256 + 4 + 1232 = 1495 max
const SAN_TX_MAX_IX: usize = 16;
const SAN_TX_IX_MAX: usize = 1 + 2 + 256 + 4 + 1232;
const SAN_TX_MAX_ENCODED: usize = SAN_TX_FIXED
    + SAN_TX_MAX_KEYS * 32
    + SAN_TX_MAX_SIGS * 64
    + SAN_TX_MAX_IX * SAN_TX_IX_MAX
    + SAN_TX_MAX_MSG;

fn encode_instruction(ix: &CompiledInstruction, buf: &mut [u8]) -> usize {
    let mut pos = 0;
    buf[pos] = ix.program_id_index;
    pos += 1;
    let acct_count = ix.account_indices.len();
    buf[pos..pos + 2].copy_from_slice(&(acct_count as u16).to_le_bytes());
    pos += 2;
    buf[pos..pos + acct_count].copy_from_slice(&ix.account_indices);
    pos += acct_count;
    let data_len = ix.data.len();
    buf[pos..pos + 4].copy_from_slice(&(data_len as u32).to_le_bytes());
    pos += 4;
    buf[pos..pos + data_len].copy_from_slice(&ix.data);
    pos += data_len;
    pos
}

fn decode_instruction(bytes: &[u8]) -> (CompiledInstruction, usize) {
    let mut pos = 0;
    let program_id_index = bytes[pos];
    pos += 1;
    let acct_count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let account_indices = bytes[pos..pos + acct_count].to_vec();
    pos += acct_count;
    let data_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let data = bytes[pos..pos + data_len].to_vec();
    pos += data_len;
    (
        CompiledInstruction {
            program_id_index,
            account_indices,
            data,
        },
        pos,
    )
}

impl FragmentCodec for SanitizedTransaction {
    fn encode(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Account keys
        let num_keys = self.account_keys.len();
        buf[pos..pos + 2].copy_from_slice(&(num_keys as u16).to_le_bytes());
        pos += 2;
        for key in &self.account_keys {
            buf[pos..pos + 32].copy_from_slice(key.as_ref());
            pos += 32;
        }

        // Blockhash
        buf[pos..pos + 32].copy_from_slice(&self.recent_blockhash);
        pos += 32;

        // Scalar fields
        buf[pos..pos + 8].copy_from_slice(&self.num_signatures.to_le_bytes());
        pos += 8;
        buf[pos] = self.num_readonly_signed;
        pos += 1;
        buf[pos] = self.num_readonly_unsigned;
        pos += 1;

        // Signatures
        let sig_count = self.signatures.len();
        buf[pos..pos + 2].copy_from_slice(&(sig_count as u16).to_le_bytes());
        pos += 2;
        for sig in &self.signatures {
            buf[pos..pos + 64].copy_from_slice(sig);
            pos += 64;
        }

        // Lookup table metadata
        buf[pos..pos + 2].copy_from_slice(&(self.num_static_keys as u16).to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&(self.num_writable_lookup_keys as u16).to_le_bytes());
        pos += 2;

        // Instructions
        let ix_count = self.instructions.len();
        buf[pos..pos + 2].copy_from_slice(&(ix_count as u16).to_le_bytes());
        pos += 2;
        for ix in &self.instructions {
            let ix_len = encode_instruction(ix, &mut buf[pos..]);
            pos += ix_len;
        }

        // Message bytes
        let msg_len = self.message_bytes.len();
        buf[pos..pos + 4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + msg_len].copy_from_slice(&self.message_bytes);
        pos += msg_len;

        pos
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut pos = 0;

        // Account keys
        let num_keys = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut account_keys = Vec::with_capacity(num_keys);
        for _ in 0..num_keys {
            let key = paradencer_types::Pubkey::from(
                <[u8; 32]>::try_from(&bytes[pos..pos + 32]).unwrap(),
            );
            pos += 32;
            account_keys.push(key);
        }

        // Blockhash
        let mut recent_blockhash = [0u8; 32];
        recent_blockhash.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;

        // Scalar fields
        let num_signatures = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let num_readonly_signed = bytes[pos];
        pos += 1;
        let num_readonly_unsigned = bytes[pos];
        pos += 1;

        // Signatures
        let sig_count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[pos..pos + 64]);
            pos += 64;
            signatures.push(sig);
        }

        // Lookup table metadata
        let num_static_keys = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let num_writable_lookup_keys =
            u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;

        // Instructions
        let ix_count = u16::from_le_bytes(bytes[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let mut instructions = Vec::with_capacity(ix_count);
        for _ in 0..ix_count {
            let (ix, consumed) = decode_instruction(&bytes[pos..]);
            pos += consumed;
            instructions.push(ix);
        }

        // Message bytes
        let msg_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let message_bytes = bytes[pos..pos + msg_len].to_vec();

        Self {
            account_keys,
            recent_blockhash,
            instructions,
            num_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
            signatures,
            message_bytes,
            num_static_keys,
            num_writable_lookup_keys,
        }
    }

    fn max_encoded_size() -> usize {
        SAN_TX_MAX_ENCODED
    }

    fn signature(&self) -> u64 {
        if let Some(sig) = self.signatures.first() {
            u64::from_le_bytes(sig[..8].try_into().unwrap())
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::Pubkey;

    fn make_test_tx() -> SanitizedTransaction {
        SanitizedTransaction::legacy(
            vec![
                Pubkey::from([1u8; 32]),
                Pubkey::from([2u8; 32]),
                Pubkey::from([3u8; 32]),
            ],
            [0xAA; 32],
            vec![CompiledInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data: vec![0x01, 0x02, 0x03],
            }],
            1,
            0,
            1,
            vec![[0xFF; 64]],
            vec![0xBB; 64],
        )
    }

    #[test]
    fn sanitized_transaction_codec_roundtrip() {
        let tx = make_test_tx();
        let mut buf = vec![0u8; SanitizedTransaction::max_encoded_size()];
        let len = tx.encode(&mut buf);
        let decoded = SanitizedTransaction::decode(&buf[..len]);

        assert_eq!(decoded.account_keys.len(), 3);
        assert_eq!(decoded.account_keys[0], Pubkey::from([1u8; 32]));
        assert_eq!(decoded.account_keys[2], Pubkey::from([3u8; 32]));
        assert_eq!(decoded.recent_blockhash, [0xAA; 32]);
        assert_eq!(decoded.num_signatures, 1);
        assert_eq!(decoded.num_readonly_signed, 0);
        assert_eq!(decoded.num_readonly_unsigned, 1);
        assert_eq!(decoded.signatures.len(), 1);
        assert_eq!(decoded.signatures[0], [0xFF; 64]);
        assert_eq!(decoded.num_static_keys, 3);
        assert_eq!(decoded.num_writable_lookup_keys, 0);
        assert_eq!(decoded.instructions.len(), 1);
        assert_eq!(decoded.instructions[0].program_id_index, 2);
        assert_eq!(decoded.instructions[0].account_indices, vec![0, 1]);
        assert_eq!(decoded.instructions[0].data, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.message_bytes, vec![0xBB; 64]);
    }

    #[test]
    fn sanitized_transaction_multiple_instructions() {
        let tx = SanitizedTransaction::legacy(
            vec![Pubkey::from([10u8; 32]), Pubkey::from([20u8; 32])],
            [0; 32],
            vec![
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0],
                    data: vec![1, 2, 3, 4, 5],
                },
                CompiledInstruction {
                    program_id_index: 1,
                    account_indices: vec![0, 1],
                    data: vec![],
                },
            ],
            1,
            0,
            0,
            vec![[0x11; 64]],
            vec![],
        );
        let mut buf = vec![0u8; SanitizedTransaction::max_encoded_size()];
        let len = tx.encode(&mut buf);
        let decoded = SanitizedTransaction::decode(&buf[..len]);
        assert_eq!(decoded.instructions.len(), 2);
        assert_eq!(decoded.instructions[0].data, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.instructions[1].account_indices, vec![0, 1]);
        assert!(decoded.instructions[1].data.is_empty());
    }

    #[test]
    fn sanitized_transaction_signature_uses_first_sig() {
        let tx = make_test_tx();
        assert_eq!(tx.signature(), u64::from_le_bytes([0xFF; 8]));
    }

    #[test]
    fn sanitized_transaction_empty_signature_returns_zero() {
        let tx = SanitizedTransaction::legacy(
            vec![Pubkey::from([1u8; 32])],
            [0; 32],
            vec![],
            0,
            0,
            0,
            vec![],
            vec![],
        );
        assert_eq!(tx.signature(), 0);
    }

    #[test]
    fn sanitized_transaction_with_lookup_keys() {
        let mut tx = make_test_tx();
        // Simulate V0 transaction with lookup table keys appended
        tx.account_keys.push(Pubkey::from([4u8; 32]));
        tx.account_keys.push(Pubkey::from([5u8; 32]));
        tx.num_static_keys = 3;
        tx.num_writable_lookup_keys = 1;

        let mut buf = vec![0u8; SanitizedTransaction::max_encoded_size()];
        let len = tx.encode(&mut buf);
        let decoded = SanitizedTransaction::decode(&buf[..len]);
        assert_eq!(decoded.account_keys.len(), 5);
        assert_eq!(decoded.num_static_keys, 3);
        assert_eq!(decoded.num_writable_lookup_keys, 1);
    }
}
