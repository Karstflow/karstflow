/// Durable nonce transaction validation for the pack scheduler.
///
/// Validates that durable nonce transactions have the correct structure:
/// - First instruction invokes the System Program
/// - Instruction data starts with LE u32 value 4 (AdvanceNonceAccount)
/// - At least 3 accounts: nonce account, recent blockhashes sysvar, nonce authority
/// - The nonce authority (3rd account) must be a signer
///
/// This prevents invalid durable nonce transactions from being packed.

/// System Program ID (all zeros except last byte = 0x00).
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Result of durable nonce validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceValidation {
    /// Transaction is NOT a durable nonce transaction (passes validation).
    NotDurableNonce,
    /// Transaction IS a valid durable nonce transaction.
    ValidDurableNonce,
    /// Transaction claims to be durable nonce but is malformed (reject).
    InvalidDurableNonce,
}

/// Instruction metadata for nonce validation.
#[derive(Debug, Clone)]
pub struct InstructionMeta {
    /// Index of the program account in the transaction's account list.
    pub program_id_index: u8,
    /// Account indices referenced by this instruction.
    pub account_indices: Vec<u8>,
    /// Raw instruction data.
    pub data: Vec<u8>,
}

/// Transaction metadata for nonce validation.
pub struct TxnForNonceCheck<'a> {
    /// All account addresses in the transaction (static + lookup).
    pub account_keys: &'a [[u8; 32]],
    /// Number of required signers (from message header).
    pub num_required_signatures: u8,
    /// Instructions in the transaction.
    pub instructions: &'a [InstructionMeta],
}

/// Validate a durable nonce transaction.
///
/// Returns `NotDurableNonce` if the transaction doesn't look like a nonce tx.
/// Returns `ValidDurableNonce` if it's a properly formed nonce tx.
/// Returns `InvalidDurableNonce` if it looks like a nonce tx but is malformed
/// (nonce authority is not a signer).
pub fn validate_durable_nonce(txn: &TxnForNonceCheck<'_>) -> NonceValidation {
    // Must have at least one instruction
    if txn.instructions.is_empty() {
        return NonceValidation::NotDurableNonce;
    }

    let first_ix = &txn.instructions[0];

    // First instruction data must be at least 4 bytes
    if first_ix.data.len() < 4 {
        return NonceValidation::NotDurableNonce;
    }

    // First instruction must have at least 3 accounts
    if first_ix.account_indices.len() < 3 {
        return NonceValidation::NotDurableNonce;
    }

    // Instruction data must start with LE u32 = 4 (AdvanceNonceAccount)
    let discriminator = u32::from_le_bytes([
        first_ix.data[0],
        first_ix.data[1],
        first_ix.data[2],
        first_ix.data[3],
    ]);
    if discriminator != 4 {
        return NonceValidation::NotDurableNonce;
    }

    // Program must be the System Program
    let program_idx = first_ix.program_id_index as usize;
    if program_idx >= txn.account_keys.len() {
        return NonceValidation::InvalidDurableNonce;
    }
    if txn.account_keys[program_idx] != SYSTEM_PROGRAM_ID {
        return NonceValidation::NotDurableNonce;
    }

    // Third account (nonce authority) must be a signer
    let authority_idx = first_ix.account_indices[2] as usize;
    if authority_idx >= txn.num_required_signatures as usize {
        return NonceValidation::InvalidDurableNonce;
    }

    NonceValidation::ValidDurableNonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system_program() -> [u8; 32] {
        [0u8; 32]
    }

    fn random_key(id: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = id;
        k
    }

    fn advance_nonce_data() -> Vec<u8> {
        4u32.to_le_bytes().to_vec()
    }

    fn make_nonce_txn(authority_is_signer: bool) -> (Vec<[u8; 32]>, Vec<InstructionMeta>) {
        // Accounts: [fee_payer(signer), nonce_authority(signer?), nonce_account, blockhashes_sysvar, system_program]
        let accounts = vec![
            random_key(1),    // 0: fee payer (signer)
            random_key(2),    // 1: nonce authority
            random_key(3),    // 2: nonce account
            random_key(4),    // 3: recent blockhashes sysvar
            system_program(), // 4: system program
        ];

        let ix = InstructionMeta {
            program_id_index: 4, // system program
            account_indices: vec![2, 3, if authority_is_signer { 1 } else { 2 }],
            data: advance_nonce_data(),
        };

        (accounts, vec![ix])
    }

    #[test]
    fn valid_durable_nonce() {
        let (accounts, instructions) = make_nonce_txn(true);
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 2, // fee_payer + authority
            instructions: &instructions,
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::ValidDurableNonce);
    }

    #[test]
    fn invalid_nonce_authority_not_signer() {
        let (accounts, instructions) = make_nonce_txn(false);
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1, // only fee_payer is signer
            instructions: &instructions,
        };
        // authority_idx=2, but only 1 signer, so authority is NOT a signer
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::InvalidDurableNonce);
    }

    #[test]
    fn not_durable_nonce_different_discriminator() {
        let accounts = vec![random_key(1), system_program()];
        let ix = InstructionMeta {
            program_id_index: 1,
            account_indices: vec![0, 0, 0],
            data: 5u32.to_le_bytes().to_vec(), // Not AdvanceNonceAccount
        };
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[ix],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::NotDurableNonce);
    }

    #[test]
    fn not_durable_nonce_wrong_program() {
        let accounts = vec![random_key(1), random_key(2), random_key(3), random_key(99)];
        let ix = InstructionMeta {
            program_id_index: 3, // not system program
            account_indices: vec![1, 2, 0],
            data: advance_nonce_data(),
        };
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[ix],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::NotDurableNonce);
    }

    #[test]
    fn not_durable_nonce_too_few_accounts() {
        let accounts = vec![random_key(1), system_program()];
        let ix = InstructionMeta {
            program_id_index: 1,
            account_indices: vec![0, 0], // Only 2 accounts, need 3
            data: advance_nonce_data(),
        };
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[ix],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::NotDurableNonce);
    }

    #[test]
    fn not_durable_nonce_short_data() {
        let accounts = vec![random_key(1), system_program()];
        let ix = InstructionMeta {
            program_id_index: 1,
            account_indices: vec![0, 0, 0],
            data: vec![4, 0, 0], // Only 3 bytes
        };
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[ix],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::NotDurableNonce);
    }

    #[test]
    fn not_durable_nonce_empty_instructions() {
        let accounts = vec![random_key(1)];
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::NotDurableNonce);
    }

    #[test]
    fn nonce_with_extra_data_still_valid() {
        let accounts = vec![
            random_key(1),    // signer
            random_key(2),    // nonce account
            random_key(3),    // blockhashes
            system_program(), // system program
        ];
        let mut data = advance_nonce_data();
        data.extend_from_slice(&[0xff; 32]); // trailing data
        let ix = InstructionMeta {
            program_id_index: 3,
            account_indices: vec![1, 2, 0, 0, 0], // extra accounts ok
            data,
        };
        let txn = TxnForNonceCheck {
            account_keys: &accounts,
            num_required_signatures: 1,
            instructions: &[ix],
        };
        assert_eq!(validate_durable_nonce(&txn), NonceValidation::ValidDurableNonce);
    }
}
