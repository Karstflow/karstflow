use super::{ExecutionContext, ExecutionOutcome};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;

/// BPF Loader Deprecated (v1) — the original BPF loader.
///
/// Program ID: BPFLoader1111111111111111111111111111111111
///
/// This is the simplest loader: it supports only Write and Finalize.
/// Once finalized, the account is marked executable and the program
/// can be invoked. No upgrade, no close, no authority management.
///
/// Instruction format (bincode):
///   Write:    [0u32, offset: u32, bytes: Vec<u8>]
///   Finalize: [1u32]

const INSTRUCTION_WRITE: u32 = 0;
const INSTRUCTION_FINALIZE: u32 = 1;

/// Compute cost for the deprecated loader (higher than v2 per spec).
const DEPRECATED_LOADER_COMPUTE_UNITS: u64 = 1_140;

pub struct BpfLoaderDeprecatedExecutor {
    compute_cost: u64,
}

impl BpfLoaderDeprecatedExecutor {
    pub fn new(compute_cost: u64) -> Self {
        Self { compute_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let data = &context.instruction_data;

        if data.len() < 4 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Instruction data too short".to_string(),
            ));
        }

        let discriminant = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match discriminant {
            INSTRUCTION_WRITE => self.process_write(context),
            INSTRUCTION_FINALIZE => self.process_finalize(context),
            _ => Ok(ExecutionOutcome::failure(
                self.compute_cost,
                format!("Unknown instruction: {}", discriminant),
            )),
        }
    }

    /// Write bytes to the program account at a given offset.
    ///
    /// Accounts:
    ///   [0] program account (writable, signer)
    ///
    /// Data layout after discriminant:
    ///   offset: u32
    ///   bytes: Vec<u8> (bincode: u64 length prefix + data)
    fn process_write(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let data = &context.instruction_data;

        if data.len() < 8 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Write instruction data too short".to_string(),
            ));
        }

        let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        // Remaining bytes after discriminant(4) + offset(4) are the payload.
        // In bincode encoding there's a u64 length prefix for the Vec<u8>.
        let payload_start = if data.len() >= 16 {
            // bincode Vec: 8-byte length prefix
            16
        } else {
            8
        };

        if payload_start > data.len() {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Write payload missing".to_string(),
            ));
        }

        let bytes = &data[payload_start..];

        // Account[0] must be writable signer
        let (pubkey, account, writable) = context
            .accounts
            .first()
            .ok_or_else(|| "Missing program account".to_string())?;

        if !writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Program account must be writable".to_string(),
            ));
        }

        if account.meta.executable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Cannot write to finalized program".to_string(),
            ));
        }

        // Write bytes at offset
        let mut account_data = account.data.as_ref().to_vec();
        let end = offset.saturating_add(bytes.len());
        if end > account_data.len() {
            account_data.resize(end, 0);
        }
        account_data[offset..end].copy_from_slice(bytes);

        let mut modified = account.clone();
        modified.data = AccountData::new(account_data);

        Ok(ExecutionOutcome::success(self.compute_cost)
            .with_modified_account(*pubkey, modified)
            .with_log("Write: success".to_string()))
    }

    /// Finalize the program account, marking it executable.
    ///
    /// Accounts:
    ///   [0] program account (writable, signer)
    ///   [1] rent sysvar (optional, ignored)
    fn process_finalize(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let (pubkey, account, writable) = context
            .accounts
            .first()
            .ok_or_else(|| "Missing program account".to_string())?;

        if !writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Program account must be writable".to_string(),
            ));
        }

        if account.meta.executable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Program already finalized".to_string(),
            ));
        }

        if account.data.is_empty() {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Cannot finalize empty program".to_string(),
            ));
        }

        let mut modified = account.clone();
        modified.meta = AccountMeta::new(
            account.meta.lamports,
            context.program_id,
            true, // executable
            account.meta.rent_epoch,
        );

        Ok(ExecutionOutcome::success(self.compute_cost)
            .with_modified_account(*pubkey, modified)
            .with_log("Finalize: program is now executable".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_ids::BPF_LOADER_DEPRECATED_PROGRAM_ID;

    fn test_pubkey(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    fn make_context(accounts: Vec<(Pubkey, Account, bool)>, data: Vec<u8>) -> ExecutionContext {
        ExecutionContext::new(BPF_LOADER_DEPRECATED_PROGRAM_ID, accounts, data)
    }

    fn program_account(data: Vec<u8>, executable: bool) -> Account {
        Account {
            meta: AccountMeta::new(1_000_000, BPF_LOADER_DEPRECATED_PROGRAM_ID, executable, 0),
            data: AccountData::new(data),
        }
    }

    #[test]
    fn write_to_program_account() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0; 64], false);

        // Write 4 bytes at offset 8 (discriminant=0, offset=8, then raw bytes)
        let mut data = vec![0u8; 8]; // discriminant(0) + offset(8)
        data[4] = 8; // offset = 8
        data.extend_from_slice(&[0u8; 8]); // bincode length prefix
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = outcome.modified_accounts.get(&pk).unwrap();
        assert_eq!(modified.data.as_ref()[8..12], [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn write_rejected_for_finalized() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0; 64], true);

        let data = vec![0u8; 16]; // write instruction
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn write_rejected_for_readonly() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0; 64], false);

        let data = vec![0u8; 16];
        let ctx = make_context(vec![(pk, acct, false)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn finalize_marks_executable() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0xEF; 32], false);

        let data = vec![1, 0, 0, 0]; // discriminant = 1 (Finalize)
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = outcome.modified_accounts.get(&pk).unwrap();
        assert!(modified.meta.executable);
    }

    #[test]
    fn finalize_rejected_if_already_executable() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0xEF; 32], true);

        let data = vec![1, 0, 0, 0];
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn finalize_rejected_for_empty_program() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![], false);

        let data = vec![1, 0, 0, 0];
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn unknown_instruction_rejected() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let pk = test_pubkey(1);
        let acct = program_account(vec![0; 64], false);

        let data = vec![99, 0, 0, 0]; // unknown discriminant
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn instruction_data_too_short() {
        let executor = BpfLoaderDeprecatedExecutor::new(1140);
        let ctx = make_context(vec![], vec![1, 2]); // only 2 bytes
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }
}
