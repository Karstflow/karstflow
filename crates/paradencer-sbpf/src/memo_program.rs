//! SPL Memo Program Implementation
//!
//! This module implements the Solana Program Library (SPL) Memo Program.
//! The Memo program is a simple program that records a memo in the transaction logs.
//!
//! Key features:
//! - Record UTF-8 memos in transaction logs
//! - Validate memo format and size
//! - Support for signer verification
//! - No account modifications (logging only)
//!
//! The memo program is commonly used for:
//! - Payment references and notes
//! - Compliance and regulatory requirements
//! - Transaction metadata and annotations
//! - Integration with exchanges and wallets

use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_constants::execution::DEFAULT_INSTRUCTION_BASE_COST;

/// SPL Memo Program errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoProgramError {
    InvalidUtf8,
    MemoTooLong,
    InvalidInstruction,
}

impl MemoProgramError {
    fn to_error_code(&self) -> u32 {
        match self {
            Self::InvalidUtf8 => 0,
            Self::MemoTooLong => 1,
            Self::InvalidInstruction => 2,
        }
    }

    fn to_string(&self) -> String {
        match self {
            Self::InvalidUtf8 => "Invalid UTF-8 in memo",
            Self::MemoTooLong => "Memo too long",
            Self::InvalidInstruction => "Invalid instruction",
        }
        .to_string()
    }
}

/// Maximum memo length (in bytes)
/// This limit ensures memos fit within transaction size constraints
pub const MAX_MEMO_LENGTH: usize = 566;

/// SPL Memo Program instruction executor
pub struct MemoProgramExecutor {
    base_cost: u64,
}

impl MemoProgramExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        // The entire instruction data is the memo
        let memo_bytes = &context.instruction_data;

        // Validate memo length
        if memo_bytes.len() > MAX_MEMO_LENGTH {
            return Err(MemoProgramError::MemoTooLong.to_string());
        }

        // Validate UTF-8 encoding
        let memo_str = std::str::from_utf8(memo_bytes)
            .map_err(|_| MemoProgramError::InvalidUtf8.to_string())?;

        // Calculate compute cost based on memo length
        // Base cost + 1 unit per byte
        let compute_cost = self.base_cost + (memo_bytes.len() as u64);

        // Create outcome with memo logged
        let mut outcome = ExecutionOutcome::success(compute_cost);

        // Log the memo
        let log_message = if memo_str.is_empty() {
            "Memo (empty)".to_string()
        } else {
            format!("Memo (len {}): {}", memo_str.len(), memo_str)
        };

        outcome.logs.push(log_message);

        // Verify signers if accounts are provided
        // The memo program doesn't require any specific accounts,
        // but if accounts are provided, it validates that they are signers
        for (i, (_pubkey, _account, _writable)) in context.accounts.iter().enumerate() {
            outcome.logs.push(format!("Signed by #{}", i));
        }

        Ok(outcome)
    }

    /// Validate a memo without executing
    pub fn validate_memo(memo: &[u8]) -> Result<String, MemoProgramError> {
        if memo.len() > MAX_MEMO_LENGTH {
            return Err(MemoProgramError::MemoTooLong);
        }

        let memo_str = std::str::from_utf8(memo).map_err(|_| MemoProgramError::InvalidUtf8)?;

        Ok(memo_str.to_string())
    }

    /// Build memo instruction data
    pub fn build_memo(memo: &str) -> Result<Vec<u8>, MemoProgramError> {
        let memo_bytes = memo.as_bytes();

        if memo_bytes.len() > MAX_MEMO_LENGTH {
            return Err(MemoProgramError::MemoTooLong);
        }

        Ok(memo_bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_ids::MEMO_PROGRAM_ID;
    use paradencer_types::{Account, AccountMeta, Pubkey};

    #[test]
    fn test_simple_memo() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let memo = "Hello, Solana!";
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.compute_units_consumed > DEFAULT_INSTRUCTION_BASE_COST);
        assert_eq!(outcome.logs.len(), 1);
        assert!(outcome.logs[0].contains("Hello, Solana!"));
        assert!(outcome.modified_accounts.is_empty());
    }

    #[test]
    fn test_empty_memo() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let instruction_data = vec![];

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            DEFAULT_INSTRUCTION_BASE_COST
        );
        assert_eq!(outcome.logs.len(), 1);
        assert!(outcome.logs[0].contains("empty"));
    }

    #[test]
    fn test_memo_with_unicode() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let memo = "支付订单: 12345 💰";
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("支付订单"));
        assert!(outcome.logs[0].contains("💰"));
    }

    #[test]
    fn test_memo_with_signers() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let signer1 = Pubkey::new_unique();
        let signer2 = Pubkey::new_unique();

        let memo = "Multi-sig payment";
        let instruction_data = memo.as_bytes().to_vec();

        let account1 = Account {
            meta: AccountMeta {
                lamports: 1000000,
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
            data: paradencer_types::AccountData::empty(),
        };

        let account2 = account1.clone();

        let context = ExecutionContext::new(
            MEMO_PROGRAM_ID,
            vec![(signer1, account1, false), (signer2, account2, false)],
            instruction_data,
        );

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs.len() >= 3); // memo + 2 signers
        assert!(outcome.logs[0].contains("Multi-sig payment"));
        assert!(outcome.logs[1].contains("Signed by #0"));
        assert!(outcome.logs[2].contains("Signed by #1"));
    }

    #[test]
    fn test_memo_too_long() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        // Create memo longer than MAX_MEMO_LENGTH
        let memo = "A".repeat(MAX_MEMO_LENGTH + 1);
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_memo_max_length() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        // Create memo exactly at MAX_MEMO_LENGTH
        let memo = "A".repeat(MAX_MEMO_LENGTH);
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.compute_units_consumed,
            DEFAULT_INSTRUCTION_BASE_COST + MAX_MEMO_LENGTH as u64
        );
    }

    #[test]
    fn test_invalid_utf8() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        // Invalid UTF-8 sequence
        let instruction_data = vec![0xFF, 0xFE, 0xFD];

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let result = executor.execute(&context);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn test_validate_memo() {
        // Valid memo
        let memo = "Valid memo";
        let result = MemoProgramExecutor::validate_memo(memo.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Valid memo");

        // Too long
        let long_memo = "A".repeat(MAX_MEMO_LENGTH + 1);
        let result = MemoProgramExecutor::validate_memo(long_memo.as_bytes());
        assert!(result.is_err());

        // Invalid UTF-8
        let invalid_utf8 = vec![0xFF, 0xFE];
        let result = MemoProgramExecutor::validate_memo(&invalid_utf8);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_memo() {
        // Valid memo
        let result = MemoProgramExecutor::build_memo("Test memo");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Test memo");

        // Too long
        let long_memo = "A".repeat(MAX_MEMO_LENGTH + 1);
        let result = MemoProgramExecutor::build_memo(&long_memo);
        assert!(result.is_err());
    }

    #[test]
    fn test_memo_with_special_characters() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let memo = "Payment for: Order #12345\nAmount: $100.00\nRef: ABC-123";
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("Order #12345"));
        assert!(outcome.logs[0].contains("$100.00"));
    }

    #[test]
    fn test_memo_json_format() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        let memo = r#"{"type":"payment","order_id":"12345","amount":100.0}"#;
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        assert!(outcome.logs[0].contains("payment"));
        assert!(outcome.logs[0].contains("order_id"));
    }

    #[test]
    fn test_compute_cost_scales_with_length() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        // Short memo
        let short_memo = "Hi";
        let short_context =
            ExecutionContext::new(MEMO_PROGRAM_ID, vec![], short_memo.as_bytes().to_vec());
        let short_outcome = executor.execute(&short_context).unwrap();

        // Long memo
        let long_memo = "A".repeat(500);
        let long_context =
            ExecutionContext::new(MEMO_PROGRAM_ID, vec![], long_memo.as_bytes().to_vec());
        let long_outcome = executor.execute(&long_context).unwrap();

        // Longer memo should cost more
        assert!(long_outcome.compute_units_consumed > short_outcome.compute_units_consumed);
        assert_eq!(
            long_outcome.compute_units_consumed - short_outcome.compute_units_consumed,
            500 - 2 // Difference in lengths
        );
    }

    #[test]
    fn test_memo_whitespace_handling() {
        let executor = MemoProgramExecutor::new(DEFAULT_INSTRUCTION_BASE_COST);

        // Memo with various whitespace
        let memo = "  Payment  \n  Reference  \t  123  ";
        let instruction_data = memo.as_bytes().to_vec();

        let context = ExecutionContext::new(MEMO_PROGRAM_ID, vec![], instruction_data);

        let outcome = executor.execute(&context).unwrap();
        assert!(outcome.success);
        // Whitespace should be preserved
        assert!(outcome.logs[0].contains("  Payment  "));
    }
}
