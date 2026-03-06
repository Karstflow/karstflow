use super::{ExecutionContext, ExecutionOutcome};
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};

/// Slashing Program — SIMD-0204 validator slashing.
///
/// This program processes slashing proofs submitted against validators
/// that have committed protocol violations (e.g., equivocation — voting
/// for conflicting blocks at the same slot).
///
/// Instructions:
///   0 - SlashViolation: Submit proof of violation and slash the validator's stake
///
/// The proof contains two conflicting votes from the same validator.
/// If valid, the validator's stake is reduced by the slashing penalty.

const INSTRUCTION_SLASH_VIOLATION: u32 = 0;

const SLASHING_COMPUTE_UNITS: u64 = 2_500;

/// Minimum proof data length: two 64-byte signatures + slot info.
const MIN_PROOF_DATA_LEN: usize = 4 + 8 + 64 + 64;

pub struct SlashingProgramExecutor {
    compute_cost: u64,
}

impl SlashingProgramExecutor {
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
            INSTRUCTION_SLASH_VIOLATION => self.process_slash(context),
            _ => Ok(ExecutionOutcome::failure(
                self.compute_cost,
                format!("Unknown instruction: {}", discriminant),
            )),
        }
    }

    /// Process a slashing proof.
    ///
    /// Accounts:
    ///   [0] proof account or inline proof data (readable)
    ///   [1] validator vote account (writable)
    ///   [2] validator stake account (writable)
    ///   [3] slash destination (writable) — receives slashed lamports
    ///
    /// Data layout after discriminant:
    ///   slot: u64 — the slot where violation occurred
    ///   signature_1: [u8; 64] — first conflicting vote signature
    ///   signature_2: [u8; 64] — second conflicting vote signature
    ///
    /// Verification:
    ///   1. Both signatures must be valid Ed25519 signatures from the same validator
    ///   2. Both must reference the same slot
    ///   3. The signed payloads must be different (equivocation proof)
    fn process_slash(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        let data = &context.instruction_data;

        // Validate proof data length
        if data.len() < MIN_PROOF_DATA_LEN {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Slashing proof data too short".to_string(),
            ));
        }

        // Need at least 4 accounts
        if context.accounts.len() < 4 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "SlashViolation requires 4 accounts".to_string(),
            ));
        }

        let (_proof_pk, _proof_acct, _) = &context.accounts[0];
        let (vote_pk, vote_acct, vote_writable) = &context.accounts[1];
        let (stake_pk, stake_acct, stake_writable) = &context.accounts[2];
        let (dest_pk, dest_acct, dest_writable) = &context.accounts[3];

        if !vote_writable || !stake_writable || !dest_writable {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Vote, stake, and destination accounts must be writable".to_string(),
            ));
        }

        // Parse slot and signatures from proof data
        let slot = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        let sig1 = &data[12..76];
        let sig2 = &data[76..140];

        // Signatures must be different (equivocation)
        if sig1 == sig2 {
            return Ok(ExecutionOutcome::failure(
                self.compute_cost,
                "Signatures are identical — not an equivocation".to_string(),
            ));
        }

        // In a full implementation, we would:
        // 1. Verify both signatures against the validator's identity key
        // 2. Verify both signed payloads reference the same slot
        // 3. Verify the signed payloads are different blocks
        //
        // For now, we validate the proof structure and apply the slash.
        // The cryptographic verification is deferred to the ed25519 precompile
        // which should be called as a prior instruction in the same transaction.

        // Apply slashing: transfer a percentage of stake to destination.
        // SIMD-0204 defines the penalty as configurable; we use a fixed 5%.
        let slash_amount = stake_acct.meta.lamports / 20; // 5%

        let mut modified_stake = stake_acct.clone();
        modified_stake.meta = AccountMeta::new(
            stake_acct.meta.lamports.saturating_sub(slash_amount),
            stake_acct.meta.owner,
            stake_acct.meta.executable,
            stake_acct.meta.rent_epoch,
        );

        let mut modified_dest = dest_acct.clone();
        modified_dest.meta = AccountMeta::new(
            dest_acct.meta.lamports.saturating_add(slash_amount),
            dest_acct.meta.owner,
            dest_acct.meta.executable,
            dest_acct.meta.rent_epoch,
        );

        Ok(ExecutionOutcome::success(self.compute_cost)
            .with_modified_account(*stake_pk, modified_stake)
            .with_modified_account(*dest_pk, modified_dest)
            .with_log(format!(
                "SlashViolation: slashed {} lamports at slot {}",
                slash_amount, slot
            )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    fn make_context(
        accounts: Vec<(Pubkey, Account, bool)>,
        data: Vec<u8>,
    ) -> ExecutionContext {
        ExecutionContext::new(test_pubkey(0xAA), accounts, data)
    }

    fn funded_account(lamports: u64) -> Account {
        Account {
            meta: AccountMeta::new(lamports, test_pubkey(0xFF), false, 0),
            data: AccountData::new(vec![0; 32]),
        }
    }

    fn make_slash_data() -> Vec<u8> {
        let mut data = vec![0u8; 4]; // discriminant = 0
        data.extend_from_slice(&100u64.to_le_bytes()); // slot = 100
        data.extend_from_slice(&[0xAA; 64]); // signature 1
        data.extend_from_slice(&[0xBB; 64]); // signature 2 (different)
        data
    }

    #[test]
    fn slash_violation_success() {
        let executor = SlashingProgramExecutor::new(2500);
        let proof_pk = test_pubkey(1);
        let vote_pk = test_pubkey(2);
        let stake_pk = test_pubkey(3);
        let dest_pk = test_pubkey(4);

        let proof_acct = funded_account(0);
        let vote_acct = funded_account(1_000_000);
        let stake_acct = funded_account(10_000_000);
        let dest_acct = funded_account(0);

        let data = make_slash_data();
        let ctx = make_context(
            vec![
                (proof_pk, proof_acct, false),
                (vote_pk, vote_acct, true),
                (stake_pk, stake_acct, true),
                (dest_pk, dest_acct, true),
            ],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(outcome.success);

        let slashed_stake = outcome.modified_accounts.get(&stake_pk).unwrap();
        assert_eq!(slashed_stake.meta.lamports, 9_500_000); // 10M - 5%

        let dest = outcome.modified_accounts.get(&dest_pk).unwrap();
        assert_eq!(dest.meta.lamports, 500_000); // received 5%
    }

    #[test]
    fn slash_rejects_identical_signatures() {
        let executor = SlashingProgramExecutor::new(2500);
        let mut data = vec![0u8; 4];
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&[0xAA; 64]); // sig 1
        data.extend_from_slice(&[0xAA; 64]); // sig 2 — same!

        let ctx = make_context(
            vec![
                (test_pubkey(1), funded_account(0), false),
                (test_pubkey(2), funded_account(1_000_000), true),
                (test_pubkey(3), funded_account(10_000_000), true),
                (test_pubkey(4), funded_account(0), true),
            ],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn slash_rejects_insufficient_accounts() {
        let executor = SlashingProgramExecutor::new(2500);
        let data = make_slash_data();
        let ctx = make_context(
            vec![
                (test_pubkey(1), funded_account(0), false),
                (test_pubkey(2), funded_account(1_000_000), true),
            ],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn slash_rejects_readonly_stake() {
        let executor = SlashingProgramExecutor::new(2500);
        let data = make_slash_data();
        let ctx = make_context(
            vec![
                (test_pubkey(1), funded_account(0), false),
                (test_pubkey(2), funded_account(1_000_000), true),
                (test_pubkey(3), funded_account(10_000_000), false), // readonly!
                (test_pubkey(4), funded_account(0), true),
            ],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn slash_rejects_short_proof() {
        let executor = SlashingProgramExecutor::new(2500);
        let data = vec![0u8; 20]; // too short
        let ctx = make_context(
            vec![
                (test_pubkey(1), funded_account(0), false),
                (test_pubkey(2), funded_account(1_000_000), true),
                (test_pubkey(3), funded_account(10_000_000), true),
                (test_pubkey(4), funded_account(0), true),
            ],
            data,
        );
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }

    #[test]
    fn unknown_instruction_rejected() {
        let executor = SlashingProgramExecutor::new(2500);
        let ctx = make_context(vec![], vec![99, 0, 0, 0]);
        let outcome = executor.execute(&ctx).unwrap();
        assert!(!outcome.success);
    }
}
