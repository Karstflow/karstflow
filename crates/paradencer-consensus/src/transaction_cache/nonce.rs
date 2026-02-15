/// Special handling for nonce-based transactions.
///
/// Nonce transactions use a durable nonce instead of a recent blockhash,
/// requiring different deduplication logic. The first instruction of a
/// nonce transaction must be an AdvanceNonceAccount system program
/// instruction (discriminant value 4).

/// System program AdvanceNonceAccount instruction discriminant.
const ADVANCE_NONCE_DISCRIMINANT: u32 = 4;

/// Check if an instruction is a system program AdvanceNonceAccount instruction.
///
/// The instruction data must begin with a little-endian u32 whose value
/// matches the AdvanceNonceAccount discriminant.
pub fn is_nonce_instruction(instruction_data: &[u8]) -> bool {
    if instruction_data.len() < 4 {
        return false;
    }
    let discriminant = u32::from_le_bytes([
        instruction_data[0],
        instruction_data[1],
        instruction_data[2],
        instruction_data[3],
    ]);
    discriminant == ADVANCE_NONCE_DISCRIMINANT
}

/// Extract the nonce account key index from the instruction's account list.
///
/// For an AdvanceNonceAccount instruction the nonce account is always the
/// first account referenced by the instruction. Returns the account-key
/// index if the instruction references at least one account.
pub fn extract_nonce_key_index(instruction_account_indices: &[u8]) -> Option<usize> {
    instruction_account_indices.first().map(|&idx| idx as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_advance_nonce_instruction() {
        let data = ADVANCE_NONCE_DISCRIMINANT.to_le_bytes();
        assert!(is_nonce_instruction(&data));
    }

    #[test]
    fn rejects_non_nonce_instruction() {
        let data = 0u32.to_le_bytes(); // CreateAccount discriminant
        assert!(!is_nonce_instruction(&data));
    }

    #[test]
    fn rejects_short_instruction_data() {
        assert!(!is_nonce_instruction(&[4, 0, 0]));
        assert!(!is_nonce_instruction(&[]));
    }

    #[test]
    fn extracts_nonce_account_index() {
        let accounts = vec![7u8, 3, 1];
        assert_eq!(extract_nonce_key_index(&accounts), Some(7));
    }

    #[test]
    fn returns_none_for_empty_accounts() {
        let accounts: Vec<u8> = vec![];
        assert_eq!(extract_nonce_key_index(&accounts), None);
    }
}
