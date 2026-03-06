use super::{ExecutionContext, ExecutionOutcome};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};

/// Feature Gate Program — manages feature activation on-chain.
///
/// This is a stateless builtin program that allows validators to
/// signal feature activation. When a feature account is created
/// and funded, it signals that the validator supports that feature.
///
/// Instructions:
///   0 - ActivateFeature: Mark a feature as pending activation
///   1 - RevokePendingActivation: Revoke a pending (not yet activated) feature
///
/// Feature accounts are simple: they hold a single optional u64 (the
/// activation slot). None = pending, Some(slot) = activated at slot.

const INSTRUCTION_ACTIVATE: u32 = 0;
const INSTRUCTION_REVOKE: u32 = 1;

const FEATURE_GATE_COMPUTE_UNITS: u64 = 750;

/// Size of a feature account: Option<u64> in bincode = 1 + 8 = 9 bytes.
pub const FEATURE_ACCOUNT_SIZE: usize = 9;

pub struct FeatureGateProgramExecutor {
    compute_cost: u64,
}

impl FeatureGateProgramExecutor {
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
            INSTRUCTION_ACTIVATE => self.process_activate(context),
            INSTRUCTION_REVOKE => self.process_revoke(context),
            _ => Ok(ExecutionOutcome::failure(
                self.compute_cost,
                format!("Unknown instruction: {}", discriminant),
            )),
        }
    }

    /// Activate a feature.
    ///
    /// Accounts:
    ///   [0] feature account (writable, signer) — the feature pubkey IS the account
    ///
    /// The feature account is initialized with None (pending activation).
    /// The runtime will set the activation slot at epoch boundary.
    fn process_activate(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let (pubkey, account, writable) = context
            .accounts
            .first()
            .ok_or_else(|| "Missing feature account".to_string())?;

        if !writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Feature account must be writable".to_string(),
            ));
        }

        // Feature account data should be uninitialized (all zeros or empty)
        let is_uninitialized =
            account.data.is_empty() || account.data.as_ref().iter().all(|&b| b == 0);

        if !is_uninitialized {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Feature account already initialized".to_string(),
            ));
        }

        // Initialize as pending: bincode Option<u64>::None = [0u8]
        let mut modified = account.clone();
        modified.data = AccountData::new(vec![0u8; FEATURE_ACCOUNT_SIZE]);
        modified.meta = AccountMeta::new(
            account.meta.lamports,
            context.program_id,
            false,
            account.meta.rent_epoch,
        );

        Ok(ExecutionOutcome::success(self.compute_cost)
            .with_modified_account(*pubkey, modified)
            .with_log("ActivateFeature: pending".to_string()))
    }

    /// Revoke a pending feature activation.
    ///
    /// Accounts:
    ///   [0] feature account (writable, signer)
    ///   [1] destination account (writable) — receives lamports
    ///
    /// Only works if the feature has not yet been activated (slot == None).
    /// Closes the feature account and returns lamports to destination.
    fn process_revoke(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 2 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "RevokePendingActivation requires 2 accounts".to_string(),
            ));
        }

        let (feature_pk, feature_acct, feature_writable) = &context.accounts[0];
        let (dest_pk, dest_acct, dest_writable) = &context.accounts[1];

        if !feature_writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Feature account must be writable".to_string(),
            ));
        }

        if !dest_writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Destination account must be writable".to_string(),
            ));
        }

        // Check the feature is pending (not yet activated).
        // Activated features have Option<u64>::Some encoded as [1, slot_bytes...].
        let feature_data = feature_acct.data.as_ref();
        if !feature_data.is_empty() && feature_data[0] != 0 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Cannot revoke already activated feature".to_string(),
            ));
        }

        // Close feature account: transfer lamports to destination
        let mut modified_dest = dest_acct.clone();
        modified_dest.meta = AccountMeta::new(
            dest_acct
                .meta
                .lamports
                .saturating_add(feature_acct.meta.lamports),
            dest_acct.meta.owner,
            dest_acct.meta.executable,
            dest_acct.meta.rent_epoch,
        );

        // Zero out the feature account
        let closed_feature = Account {
            meta: AccountMeta::new(0, Pubkey::default(), false, 0),
            data: AccountData::new(vec![]),
        };

        Ok(ExecutionOutcome::success(self.compute_cost)
            .with_modified_account(*feature_pk, closed_feature)
            .with_modified_account(*dest_pk, modified_dest)
            .with_log("RevokePendingActivation: feature closed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    fn feature_program_id() -> Pubkey {
        test_pubkey(0xFE)
    }

    fn make_context(accounts: Vec<(Pubkey, Account, bool)>, data: Vec<u8>) -> ExecutionContext {
        ExecutionContext::new(feature_program_id(), accounts, data)
    }

    fn empty_account(lamports: u64) -> Account {
        Account {
            meta: AccountMeta::new(lamports, Pubkey::default(), false, 0),
            data: AccountData::new(vec![]),
        }
    }

    #[test]
    fn activate_feature_success() {
        let executor = FeatureGateProgramExecutor::new(750);
        let pk = test_pubkey(1);
        let acct = empty_account(1_000_000);

        let data = vec![0, 0, 0, 0]; // ActivateFeature
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);
        let modified = outcome.modified_accounts.get(&pk).unwrap();
        assert_eq!(modified.data.len(), FEATURE_ACCOUNT_SIZE);
    }

    #[test]
    fn activate_rejects_already_initialized() {
        let executor = FeatureGateProgramExecutor::new(750);
        let pk = test_pubkey(1);
        let acct = Account {
            meta: AccountMeta::new(1_000_000, feature_program_id(), false, 0),
            data: AccountData::new(vec![1, 0, 0, 0, 0, 0, 0, 0, 0]), // Some(0)
        };

        let data = vec![0, 0, 0, 0];
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn activate_rejects_readonly() {
        let executor = FeatureGateProgramExecutor::new(750);
        let pk = test_pubkey(1);
        let acct = empty_account(1_000_000);

        let data = vec![0, 0, 0, 0];
        let ctx = make_context(vec![(pk, acct, false)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn revoke_pending_feature() {
        let executor = FeatureGateProgramExecutor::new(750);
        let feature_pk = test_pubkey(1);
        let dest_pk = test_pubkey(2);
        let feature_acct = Account {
            meta: AccountMeta::new(500_000, feature_program_id(), false, 0),
            data: AccountData::new(vec![0; FEATURE_ACCOUNT_SIZE]),
        };
        let dest_acct = empty_account(100_000);

        let data = vec![1, 0, 0, 0]; // RevokePendingActivation
        let ctx = make_context(
            vec![(feature_pk, feature_acct, true), (dest_pk, dest_acct, true)],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let closed = outcome.modified_accounts.get(&feature_pk).unwrap();
        assert_eq!(closed.meta.lamports, 0);
        assert!(closed.data.is_empty());

        let dest = outcome.modified_accounts.get(&dest_pk).unwrap();
        assert_eq!(dest.meta.lamports, 600_000);
    }

    #[test]
    fn revoke_rejects_activated_feature() {
        let executor = FeatureGateProgramExecutor::new(750);
        let feature_pk = test_pubkey(1);
        let dest_pk = test_pubkey(2);
        let feature_acct = Account {
            meta: AccountMeta::new(500_000, feature_program_id(), false, 0),
            data: AccountData::new(vec![1, 42, 0, 0, 0, 0, 0, 0, 0]), // Some(42)
        };
        let dest_acct = empty_account(100_000);

        let data = vec![1, 0, 0, 0];
        let ctx = make_context(
            vec![(feature_pk, feature_acct, true), (dest_pk, dest_acct, true)],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn revoke_needs_two_accounts() {
        let executor = FeatureGateProgramExecutor::new(750);
        let pk = test_pubkey(1);
        let acct = Account {
            meta: AccountMeta::new(500_000, feature_program_id(), false, 0),
            data: AccountData::new(vec![0; FEATURE_ACCOUNT_SIZE]),
        };

        let data = vec![1, 0, 0, 0];
        let ctx = make_context(vec![(pk, acct, true)], data);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn unknown_instruction_rejected() {
        let executor = FeatureGateProgramExecutor::new(750);
        let ctx = make_context(vec![], vec![99, 0, 0, 0]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }
}
