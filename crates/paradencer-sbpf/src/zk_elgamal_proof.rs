//! ZK ElGamal proof program executor.
//!
//! Verifies zero-knowledge proofs for SPL Token-2022 confidential transfers.
//! Supports 13 instruction types: CloseContextState + 12 proof verification
//! instructions covering ElGamal encryption, Pedersen commitments, sigma
//! proofs, and range proofs.
//!
//! Feature-gated via a 3-way toggle:
//! - `zk_elgamal_proof_program_enabled` must be active
//! - `disable_zk_elgamal_proof_program` can temporarily deactivate it
//! - `reenable_zk_elgamal_proof_program` overrides the disable

use crate::{ExecutionContext, ExecutionOutcome};
use paradencer_ids::features::{
    DISABLE_ZK_ELGAMAL_PROOF_PROGRAM, REENABLE_ZK_ELGAMAL_PROOF_PROGRAM,
    ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
};
use paradencer_ids::ZK_ELGAMAL_PROOF_PROGRAM_ID;
use paradencer_types::{Account, Pubkey};

// ---------------------------------------------------------------------------
// Instruction discriminants (first byte of instruction data)
// ---------------------------------------------------------------------------

const CLOSE_CONTEXT_STATE: u8 = 0;
const VERIFY_ZERO_CIPHERTEXT: u8 = 1;
const VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY: u8 = 2;
const VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY: u8 = 3;
const VERIFY_PUBKEY_VALIDITY: u8 = 4;
const VERIFY_PERCENTAGE_WITH_CAP: u8 = 5;
const VERIFY_BATCHED_RANGE_PROOF_U64: u8 = 6;
const VERIFY_BATCHED_RANGE_PROOF_U128: u8 = 7;
const VERIFY_BATCHED_RANGE_PROOF_U256: u8 = 8;
const VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY: u8 = 9;
const VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY: u8 = 10;
const VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY: u8 = 11;
const VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY: u8 = 12;

// ---------------------------------------------------------------------------
// Compute unit costs per instruction type
// ---------------------------------------------------------------------------

const CU_CLOSE_CONTEXT_STATE: u64 = 3_300;
const CU_VERIFY_ZERO_CIPHERTEXT: u64 = 6_000;
const CU_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY: u64 = 8_000;
const CU_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY: u64 = 6_400;
const CU_VERIFY_PUBKEY_VALIDITY: u64 = 2_600;
const CU_VERIFY_PERCENTAGE_WITH_CAP: u64 = 6_500;
const CU_VERIFY_BATCHED_RANGE_PROOF_U64: u64 = 111_000;
const CU_VERIFY_BATCHED_RANGE_PROOF_U128: u64 = 200_000;
const CU_VERIFY_BATCHED_RANGE_PROOF_U256: u64 = 368_000;
const CU_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY: u64 = 6_400;
const CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY: u64 = 13_000;
const CU_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY: u64 = 8_100;
const CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY: u64 = 16_400;

// ---------------------------------------------------------------------------
// Context state account layout
// ---------------------------------------------------------------------------

/// Size of `ProofContextStateMeta` at the start of a context state account.
/// Layout: proof_type (1) + padding (7) + authority (32) = 40 bytes.
const PROOF_CONTEXT_STATE_META_SIZE: usize = 40;

/// Offset of the authority pubkey within ProofContextStateMeta.
const AUTHORITY_OFFSET: usize = 8;

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// ZK ElGamal proof program executor.
pub struct ZkElGamalProofExecutor {
    base_cost: u64,
}

impl ZkElGamalProofExecutor {
    pub fn new(base_cost: u64) -> Self {
        Self { base_cost }
    }

    pub fn execute(&self, context: &ExecutionContext) -> Result<ExecutionOutcome, String> {
        if context.instruction_data.is_empty() {
            return Err("empty instruction data".to_string());
        }

        let discriminant = context.instruction_data[0];

        match discriminant {
            CLOSE_CONTEXT_STATE => self.process_close_context_state(context),
            VERIFY_ZERO_CIPHERTEXT => self.process_verify_proof(context, CU_VERIFY_ZERO_CIPHERTEXT),
            VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY => {
                self.process_verify_proof(context, CU_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY)
            }
            VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY => {
                self.process_verify_proof(context, CU_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY)
            }
            VERIFY_PUBKEY_VALIDITY => self.process_verify_proof(context, CU_VERIFY_PUBKEY_VALIDITY),
            VERIFY_PERCENTAGE_WITH_CAP => {
                self.process_verify_proof(context, CU_VERIFY_PERCENTAGE_WITH_CAP)
            }
            VERIFY_BATCHED_RANGE_PROOF_U64 => {
                self.process_verify_proof(context, CU_VERIFY_BATCHED_RANGE_PROOF_U64)
            }
            VERIFY_BATCHED_RANGE_PROOF_U128 => {
                self.process_verify_proof(context, CU_VERIFY_BATCHED_RANGE_PROOF_U128)
            }
            VERIFY_BATCHED_RANGE_PROOF_U256 => {
                self.process_verify_proof(context, CU_VERIFY_BATCHED_RANGE_PROOF_U256)
            }
            VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY => {
                self.process_verify_proof(context, CU_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY)
            }
            VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY => self.process_verify_proof(
                context,
                CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY,
            ),
            VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY => {
                self.process_verify_proof(context, CU_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY)
            }
            VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY => self.process_verify_proof(
                context,
                CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY,
            ),
            _ => Err(format!("unknown ZK proof instruction: {discriminant}")),
        }
    }

    /// Close a proof context state account.
    ///
    /// Accounts:
    ///   0. [writable] Context state account (owned by this program)
    ///   1. [writable] Destination account (receives lamports)
    ///   2. [signer]   Authority
    fn process_close_context_state(
        &self,
        context: &ExecutionContext,
    ) -> Result<ExecutionOutcome, String> {
        if context.accounts.len() < 3 {
            return Err("CloseContextState requires 3 accounts".to_string());
        }

        let (ctx_pubkey, ctx_account, ctx_writable) = &context.accounts[0];
        let (dest_pubkey, dest_account, dest_writable) = &context.accounts[1];
        let (_authority_pubkey, _authority_account, authority_signer) = &context.accounts[2];

        if !ctx_writable {
            return Err("context state account must be writable".to_string());
        }
        if !dest_writable {
            return Err("destination account must be writable".to_string());
        }
        if !authority_signer {
            return Err("authority must be signer".to_string());
        }

        // Context state account must be owned by the ZK proof program.
        if ctx_account.meta.owner != ZK_ELGAMAL_PROOF_PROGRAM_ID {
            return Err("context state account not owned by ZK proof program".to_string());
        }

        // Validate authority matches the stored authority in the context state.
        if ctx_account.data.len() < PROOF_CONTEXT_STATE_META_SIZE {
            return Err("context state account too small".to_string());
        }

        let stored_authority_bytes =
            &ctx_account.data.as_slice()[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32];
        let (authority_pubkey, _, _) = &context.accounts[2];
        if stored_authority_bytes != authority_pubkey.as_bytes() {
            return Err("authority mismatch".to_string());
        }

        // Transfer lamports from context state to destination.
        let lamports = ctx_account.meta.lamports;

        // Zero out the context state account and transfer ownership to system program.
        let modified_ctx = Account::new(0, vec![0u8; ctx_account.data.len()], Pubkey::zeroed());

        let mut modified_dest = dest_account.clone();
        modified_dest.meta.lamports = modified_dest.meta.lamports.saturating_add(lamports);

        Ok(ExecutionOutcome::success(CU_CLOSE_CONTEXT_STATE)
            .with_modified_account(*ctx_pubkey, modified_ctx)
            .with_modified_account(*dest_pubkey, modified_dest))
    }

    /// Process a proof verification instruction.
    ///
    /// Currently returns an error indicating proof verification is not yet
    /// implemented (requires solana-zk-sdk integration). The program will
    /// be rejected by the feature gate until enabled on the network.
    ///
    /// TODO: Integrate solana-zk-sdk for actual proof verification.
    fn process_verify_proof(
        &self,
        context: &ExecutionContext,
        compute_units: u64,
    ) -> Result<ExecutionOutcome, String> {
        // Proof data can come from instruction data or an account.
        // If instruction data is exactly 5 bytes (1 discriminant + 4 u32 offset),
        // the proof data is read from an account at the given offset.
        let _proof_data = if context.instruction_data.len() == 5 {
            // Read proof from account.
            if context.accounts.is_empty() {
                return Err("proof data account required".to_string());
            }
            let offset = u32::from_le_bytes(
                context.instruction_data[1..5]
                    .try_into()
                    .map_err(|_| "invalid proof data offset".to_string())?,
            ) as usize;
            let account_data = &context.accounts[0].1.data;
            if offset >= account_data.len() {
                return Err("proof data offset out of bounds".to_string());
            }
            &account_data.as_slice()[offset..]
        } else if context.instruction_data.len() > 1 {
            &context.instruction_data[1..]
        } else {
            return Err("proof data required".to_string());
        };

        // TODO: Deserialize proof data based on discriminant and call verify_proof().
        // This requires integrating solana-zk-sdk which provides the ZkProofData<T>
        // trait with verify_proof() for each proof type.
        //
        // For now, return an error. The program is feature-gated and will only be
        // called when the feature is enabled on the network.
        Err("ZK proof verification not yet implemented".to_string())
    }
}

/// Check whether the ZK ElGamal proof program is active given the current
/// feature set.
///
/// The program is active when:
/// - `zk_elgamal_proof_program_enabled` is active, AND
/// - Either `disable_zk_elgamal_proof_program` is NOT active, OR
///   `reenable_zk_elgamal_proof_program` IS active (override).
pub fn is_zk_elgamal_active(active_features: &[Pubkey]) -> bool {
    let enabled = active_features.contains(&ZK_ELGAMAL_PROOF_PROGRAM_ENABLED);
    if !enabled {
        return false;
    }
    let disabled = active_features.contains(&DISABLE_ZK_ELGAMAL_PROOF_PROGRAM);
    if !disabled {
        return true;
    }
    // Disabled, but check for re-enable override.
    active_features.contains(&REENABLE_ZK_ELGAMAL_PROOF_PROGRAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context(data: Vec<u8>, accounts: Vec<(Pubkey, Account, bool)>) -> ExecutionContext {
        ExecutionContext::new(ZK_ELGAMAL_PROOF_PROGRAM_ID, accounts, data)
    }

    fn make_context_state_account(authority: &Pubkey, lamports: u64) -> Account {
        let mut data = vec![0u8; PROOF_CONTEXT_STATE_META_SIZE + 64];
        // proof_type = 1 (non-zero means initialized).
        data[0] = 1;
        // authority at offset 8.
        data[AUTHORITY_OFFSET..AUTHORITY_OFFSET + 32].copy_from_slice(authority.as_bytes());
        Account::new(lamports, data, ZK_ELGAMAL_PROOF_PROGRAM_ID)
    }

    #[test]
    fn empty_instruction_data_rejected() {
        let executor = ZkElGamalProofExecutor::new(100);
        let ctx = make_context(vec![], vec![]);
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty instruction data"));
    }

    #[test]
    fn unknown_discriminant_rejected() {
        let executor = ZkElGamalProofExecutor::new(100);
        let ctx = make_context(vec![255], vec![]);
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown"));
    }

    #[test]
    fn close_context_state_requires_3_accounts() {
        let executor = ZkElGamalProofExecutor::new(100);
        let ctx = make_context(vec![CLOSE_CONTEXT_STATE], vec![]);
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("3 accounts"));
    }

    #[test]
    fn close_context_state_validates_owner() {
        let executor = ZkElGamalProofExecutor::new(100);
        let authority = Pubkey::new([0xAA; 32]);
        let wrong_owner_account = Account::new(1000, vec![0u8; 100], Pubkey::new([0xFF; 32]));
        let dest = Account::default();
        let auth_account = Account::default();

        let ctx = make_context(
            vec![CLOSE_CONTEXT_STATE],
            vec![
                (Pubkey::new([1; 32]), wrong_owner_account, true),
                (Pubkey::new([2; 32]), dest, true),
                (authority, auth_account, true), // signer
            ],
        );
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not owned"));
    }

    #[test]
    fn close_context_state_validates_authority() {
        let executor = ZkElGamalProofExecutor::new(100);
        let authority = Pubkey::new([0xAA; 32]);
        let wrong_authority = Pubkey::new([0xBB; 32]);

        let ctx_account = make_context_state_account(&authority, 1000);
        let dest = Account::default();
        let auth_account = Account::default();

        let ctx = make_context(
            vec![CLOSE_CONTEXT_STATE],
            vec![
                (Pubkey::new([1; 32]), ctx_account, true),
                (Pubkey::new([2; 32]), dest, true),
                (wrong_authority, auth_account, true),
            ],
        );
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authority mismatch"));
    }

    #[test]
    fn close_context_state_success() {
        let executor = ZkElGamalProofExecutor::new(100);
        let authority = Pubkey::new([0xAA; 32]);
        let ctx_pubkey = Pubkey::new([1; 32]);
        let dest_pubkey = Pubkey::new([2; 32]);

        let ctx_account = make_context_state_account(&authority, 5000);
        let dest = Account::new(100, vec![], Pubkey::zeroed());
        let auth_account = Account::default();

        let ctx = make_context(
            vec![CLOSE_CONTEXT_STATE],
            vec![
                (ctx_pubkey, ctx_account, true),
                (dest_pubkey, dest, true),
                (authority, auth_account, true),
            ],
        );
        let result = executor.execute(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(result.compute_units_consumed, CU_CLOSE_CONTEXT_STATE);

        // Context state account should be zeroed with 0 lamports.
        let modified_ctx = &result.modified_accounts[&ctx_pubkey];
        assert_eq!(modified_ctx.meta.lamports, 0);
        assert!(modified_ctx.data.as_slice().iter().all(|&b| b == 0));

        // Destination should receive the lamports.
        let modified_dest = &result.modified_accounts[&dest_pubkey];
        assert_eq!(modified_dest.meta.lamports, 5100);
    }

    #[test]
    fn verify_proof_returns_not_implemented() {
        let executor = ZkElGamalProofExecutor::new(100);
        // Discriminant 1 = VerifyZeroCiphertext, with some proof data.
        let ctx = make_context(vec![VERIFY_ZERO_CIPHERTEXT, 0, 0, 0, 0, 0], vec![]);
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }

    #[test]
    fn verify_proof_from_account_validates_offset() {
        let executor = ZkElGamalProofExecutor::new(100);
        // 5 bytes = proof from account (1 discriminant + 4 byte offset).
        let mut data = vec![VERIFY_ZERO_CIPHERTEXT];
        data.extend_from_slice(&1000u32.to_le_bytes()); // offset 1000

        let small_account = Account::new(0, vec![0u8; 10], Pubkey::default());

        let ctx = make_context(data, vec![(Pubkey::new([1; 32]), small_account, false)]);
        let result = executor.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("out of bounds"));
    }

    // ── Feature gate tests ──────────────────────────────────────

    #[test]
    fn feature_gate_not_enabled() {
        assert!(!is_zk_elgamal_active(&[]));
    }

    #[test]
    fn feature_gate_enabled() {
        assert!(is_zk_elgamal_active(&[ZK_ELGAMAL_PROOF_PROGRAM_ENABLED]));
    }

    #[test]
    fn feature_gate_disabled() {
        assert!(!is_zk_elgamal_active(&[
            ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
            DISABLE_ZK_ELGAMAL_PROOF_PROGRAM,
        ]));
    }

    #[test]
    fn feature_gate_reenabled() {
        assert!(is_zk_elgamal_active(&[
            ZK_ELGAMAL_PROOF_PROGRAM_ENABLED,
            DISABLE_ZK_ELGAMAL_PROOF_PROGRAM,
            REENABLE_ZK_ELGAMAL_PROOF_PROGRAM,
        ]));
    }

    #[test]
    fn compute_unit_costs_match_agave() {
        // Verify our CU costs match the canonical values.
        assert_eq!(CU_CLOSE_CONTEXT_STATE, 3_300);
        assert_eq!(CU_VERIFY_ZERO_CIPHERTEXT, 6_000);
        assert_eq!(CU_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY, 8_000);
        assert_eq!(CU_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY, 6_400);
        assert_eq!(CU_VERIFY_PUBKEY_VALIDITY, 2_600);
        assert_eq!(CU_VERIFY_PERCENTAGE_WITH_CAP, 6_500);
        assert_eq!(CU_VERIFY_BATCHED_RANGE_PROOF_U64, 111_000);
        assert_eq!(CU_VERIFY_BATCHED_RANGE_PROOF_U128, 200_000);
        assert_eq!(CU_VERIFY_BATCHED_RANGE_PROOF_U256, 368_000);
        assert_eq!(CU_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY, 6_400);
        assert_eq!(
            CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY,
            13_000
        );
        assert_eq!(CU_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY, 8_100);
        assert_eq!(
            CU_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY,
            16_400
        );
    }
}
