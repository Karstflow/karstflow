//! Pre-execution transaction verification for the replay pipeline.
//!
//! Validates transactions before they are dispatched for execution:
//! - Signature count matches message header
//! - Fee payer is a valid signer
//! - Program IDs reference valid accounts
//! - Account count does not exceed limits
//! - Instruction account indices are within bounds
//!
//! This catches malformed transactions early, before consuming
//! execution resources.

/// Maximum number of accounts a transaction can reference.
pub const MAX_TRANSACTION_ACCOUNTS: usize = 256;

/// Maximum number of instructions in a transaction.
pub const MAX_INSTRUCTION_COUNT: usize = 64;

/// Maximum transaction size in bytes.
pub const MAX_TRANSACTION_SIZE: usize = 1232;

/// Pre-execution verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxVerifyError {
    /// No signatures present.
    NoSignatures,
    /// Signature count doesn't match header.
    SignatureCountMismatch { expected: u8, actual: usize },
    /// Fee payer (first account) is not a signer.
    FeePayerNotSigner,
    /// Too many accounts referenced.
    TooManyAccounts(usize),
    /// Too many instructions.
    TooManyInstructions(usize),
    /// Instruction references an out-of-bounds account index.
    AccountIndexOutOfBounds {
        instruction_index: usize,
        account_index: u8,
        account_count: usize,
    },
    /// Program ID index out of bounds.
    ProgramIdOutOfBounds {
        instruction_index: usize,
        program_id_index: u8,
        account_count: usize,
    },
    /// Transaction is too large.
    TransactionTooLarge(usize),
    /// Number of required signers exceeds account count.
    TooManySigners { signers: u8, accounts: usize },
}

impl std::fmt::Display for TxVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignatures => write!(f, "transaction has no signatures"),
            Self::SignatureCountMismatch { expected, actual } => {
                write!(f, "expected {expected} signatures, got {actual}")
            }
            Self::FeePayerNotSigner => write!(f, "fee payer is not a signer"),
            Self::TooManyAccounts(n) => write!(f, "too many accounts: {n}"),
            Self::TooManyInstructions(n) => write!(f, "too many instructions: {n}"),
            Self::AccountIndexOutOfBounds {
                instruction_index,
                account_index,
                account_count,
            } => write!(
                f,
                "instruction {instruction_index}: account index {account_index} >= {account_count}"
            ),
            Self::ProgramIdOutOfBounds {
                instruction_index,
                program_id_index,
                account_count,
            } => write!(
                f,
                "instruction {instruction_index}: program_id index {program_id_index} >= {account_count}"
            ),
            Self::TransactionTooLarge(size) => {
                write!(f, "transaction too large: {size} bytes")
            }
            Self::TooManySigners { signers, accounts } => {
                write!(f, "required signers ({signers}) > account count ({accounts})")
            }
        }
    }
}

impl std::error::Error for TxVerifyError {}

/// Instruction metadata for verification.
#[derive(Debug, Clone)]
pub struct VerifyInstruction {
    pub program_id_index: u8,
    pub account_indices: Vec<u8>,
    pub data_len: usize,
}

/// Transaction metadata for pre-execution verification.
pub struct TxForVerification {
    /// Number of signatures present on the transaction.
    pub signature_count: usize,
    /// Number of required signatures from message header.
    pub num_required_signatures: u8,
    /// Number of readonly signed accounts.
    pub num_readonly_signed: u8,
    /// Number of readonly unsigned accounts.
    pub num_readonly_unsigned: u8,
    /// Total number of accounts (static + lookup).
    pub account_count: usize,
    /// Instructions in the transaction.
    pub instructions: Vec<VerifyInstruction>,
    /// Serialized transaction size in bytes.
    pub serialized_size: usize,
}

/// Verify a transaction before execution.
///
/// Returns `Ok(())` if the transaction passes all structural checks.
pub fn verify_transaction(tx: &TxForVerification) -> Result<(), TxVerifyError> {
    // Must have at least one signature
    if tx.signature_count == 0 {
        return Err(TxVerifyError::NoSignatures);
    }

    // Signature count must match header
    if tx.signature_count != tx.num_required_signatures as usize {
        return Err(TxVerifyError::SignatureCountMismatch {
            expected: tx.num_required_signatures,
            actual: tx.signature_count,
        });
    }

    // Required signers can't exceed account count
    if tx.num_required_signatures as usize > tx.account_count {
        return Err(TxVerifyError::TooManySigners {
            signers: tx.num_required_signatures,
            accounts: tx.account_count,
        });
    }

    // Fee payer is always account[0] and must be a signer (index 0 < num_required_signatures)
    if tx.account_count == 0 || tx.num_required_signatures == 0 {
        return Err(TxVerifyError::FeePayerNotSigner);
    }

    // Account count limit
    if tx.account_count > MAX_TRANSACTION_ACCOUNTS {
        return Err(TxVerifyError::TooManyAccounts(tx.account_count));
    }

    // Instruction count limit
    if tx.instructions.len() > MAX_INSTRUCTION_COUNT {
        return Err(TxVerifyError::TooManyInstructions(tx.instructions.len()));
    }

    // Transaction size limit
    if tx.serialized_size > MAX_TRANSACTION_SIZE {
        return Err(TxVerifyError::TransactionTooLarge(tx.serialized_size));
    }

    // Validate each instruction's account references
    for (ix_idx, ix) in tx.instructions.iter().enumerate() {
        // Program ID must reference a valid account
        if ix.program_id_index as usize >= tx.account_count {
            return Err(TxVerifyError::ProgramIdOutOfBounds {
                instruction_index: ix_idx,
                program_id_index: ix.program_id_index,
                account_count: tx.account_count,
            });
        }

        // All account indices must be within bounds
        for &acct_idx in &ix.account_indices {
            if acct_idx as usize >= tx.account_count {
                return Err(TxVerifyError::AccountIndexOutOfBounds {
                    instruction_index: ix_idx,
                    account_index: acct_idx,
                    account_count: tx.account_count,
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_tx() -> TxForVerification {
        TxForVerification {
            signature_count: 1,
            num_required_signatures: 1,
            num_readonly_signed: 0,
            num_readonly_unsigned: 1,
            account_count: 3,
            instructions: vec![VerifyInstruction {
                program_id_index: 2,
                account_indices: vec![0, 1],
                data_len: 10,
            }],
            serialized_size: 200,
        }
    }

    #[test]
    fn valid_transaction_passes() {
        assert!(verify_transaction(&valid_tx()).is_ok());
    }

    #[test]
    fn no_signatures() {
        let mut tx = valid_tx();
        tx.signature_count = 0;
        tx.num_required_signatures = 0;
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::NoSignatures)
        ));
    }

    #[test]
    fn signature_count_mismatch() {
        let mut tx = valid_tx();
        tx.signature_count = 2; // but header says 1
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::SignatureCountMismatch { .. })
        ));
    }

    #[test]
    fn too_many_accounts() {
        let mut tx = valid_tx();
        tx.account_count = 300;
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::TooManyAccounts(300))
        ));
    }

    #[test]
    fn too_many_instructions() {
        let mut tx = valid_tx();
        tx.instructions = (0..65)
            .map(|_| VerifyInstruction {
                program_id_index: 2,
                account_indices: vec![0],
                data_len: 1,
            })
            .collect();
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::TooManyInstructions(65))
        ));
    }

    #[test]
    fn program_id_out_of_bounds() {
        let mut tx = valid_tx();
        tx.instructions[0].program_id_index = 10; // only 3 accounts
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::ProgramIdOutOfBounds { .. })
        ));
    }

    #[test]
    fn account_index_out_of_bounds() {
        let mut tx = valid_tx();
        tx.instructions[0].account_indices = vec![0, 5]; // 5 >= 3
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::AccountIndexOutOfBounds { .. })
        ));
    }

    #[test]
    fn transaction_too_large() {
        let mut tx = valid_tx();
        tx.serialized_size = 2000;
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::TransactionTooLarge(2000))
        ));
    }

    #[test]
    fn too_many_signers() {
        let mut tx = valid_tx();
        tx.num_required_signatures = 5;
        tx.signature_count = 5;
        // but only 3 accounts
        assert!(matches!(
            verify_transaction(&tx),
            Err(TxVerifyError::TooManySigners { .. })
        ));
    }

    #[test]
    fn multiple_instructions_valid() {
        let mut tx = valid_tx();
        tx.instructions.push(VerifyInstruction {
            program_id_index: 2,
            account_indices: vec![0],
            data_len: 5,
        });
        assert!(verify_transaction(&tx).is_ok());
    }

    #[test]
    fn edge_case_max_accounts() {
        let mut tx = valid_tx();
        tx.account_count = MAX_TRANSACTION_ACCOUNTS;
        tx.instructions[0].program_id_index = 255;
        tx.instructions[0].account_indices = vec![0, 255];
        assert!(verify_transaction(&tx).is_ok());
    }
}
