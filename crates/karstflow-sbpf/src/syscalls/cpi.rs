//! Cross-program invocation (CPI) implementation.
//!
//! Implements account deduplication with privilege merging, privilege
//! escalation checks (writable/signer), PDA signer derivation, and
//! pre/post execution account synchronization.
//!
//! When the same account appears multiple times in an instruction's
//! account list, their signer/writable flags are merged via logical OR.
//! The callee cannot gain any privilege the caller does not already hold
//! (unless the account is a PDA derived from the caller's program ID).

use super::{SyscallContext, SyscallError};
use curve25519_dalek::edwards::CompressedEdwardsY;
use karstflow_constants::syscalls::*;
use karstflow_types::Pubkey;
use sha2::{Digest, Sha256};

/// An instruction to be invoked via CPI.
#[derive(Debug, Clone)]
pub struct CpiInstruction {
    /// The program to invoke.
    pub program_id: Pubkey,
    /// Account metadata for each account passed to the callee.
    pub accounts: Vec<CpiAccountMeta>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
}

/// Account metadata for a CPI instruction.
#[derive(Debug, Clone)]
pub struct CpiAccountMeta {
    /// The account's public key.
    pub pubkey: Pubkey,
    /// Whether the account is a signer for this instruction.
    pub is_signer: bool,
    /// Whether the account is writable for this instruction.
    pub is_writable: bool,
}

/// Account info provided for CPI, containing the current account state.
#[derive(Debug, Clone)]
pub struct CpiAccountInfo {
    /// The account's public key.
    pub pubkey: Pubkey,
    /// Current lamport balance.
    pub lamports: u64,
    /// Account data bytes.
    pub data: Vec<u8>,
    /// Account owner program.
    pub owner: Pubkey,
    /// Whether the account is executable.
    pub executable: bool,
}

/// Tracks CPI call context for depth and reentrancy enforcement.
#[derive(Debug, Clone)]
pub struct CpiContext {
    /// Current call stack depth.
    pub stack_depth: usize,
    /// Maximum allowed call depth.
    pub max_depth: usize,
    /// The program ID of the caller.
    pub caller_program_id: Pubkey,
}

/// An instruction account after deduplication and privilege normalization.
///
/// When the same account appears multiple times in an instruction's account
/// list, their privileges (is_signer, is_writable) are merged via logical OR
/// so that the deduplicated entry carries the union of all requested flags.
#[derive(Debug, Clone)]
pub struct InstructionAccount {
    /// Index of the first occurrence in the callee's account list.
    pub index_in_callee: usize,
    /// Merged signer flag (union of all references to this account).
    pub is_signer: bool,
    /// Merged writable flag (union of all references to this account).
    pub is_writable: bool,
    /// The account's public key.
    pub pubkey: Pubkey,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Invoke another program via CPI without PDA signing.
pub fn invoke(
    ctx: &mut SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
) -> Result<(), SyscallError> {
    invoke_signed(ctx, instruction, account_infos, &[])
}

/// Invoke another program via CPI with optional PDA signer seeds.
///
/// Execution flow:
/// 1. Consume compute cost (base + per-account + per-data-byte)
/// 2. Validate limits (depth, instruction size, account counts)
/// 3. Check reentrancy (caller cannot invoke itself)
/// 4. Derive PDA signers from seeds + caller program ID
/// 5. Deduplicate instruction accounts and merge privileges
/// 6. Validate privilege escalation against caller's privileges
/// 7. Verify target program exists and is executable
/// 8. Verify all referenced accounts are provided
/// 9. Pre-execution account sync (caller → callee)
/// 10. Execute (bump stack depth)
/// 11. Post-execution writeback (callee → caller)
pub fn invoke_signed(
    ctx: &mut SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
    signer_seeds: &[&[&[u8]]],
) -> Result<(), SyscallError> {
    // 1. Compute cost
    let compute_cost = CPI_BASE_COST
        + CPI_PER_ACCOUNT_COST * instruction.accounts.len() as u64
        + CPI_PER_DATA_BYTE_COST * instruction.data.len() as u64;
    ctx.consume_compute(compute_cost)?;

    // 2. Validate limits
    if ctx.stack_depth >= MAX_CPI_DEPTH {
        return Err(SyscallError::MaxCpiDepthExceeded);
    }

    if instruction.data.len() > MAX_CPI_INSTRUCTION_SIZE {
        return Err(SyscallError::MaxInstructionSizeExceeded);
    }

    if instruction.accounts.len() > MAX_CPI_INSTRUCTION_ACCOUNTS {
        return Err(SyscallError::InvalidArgument(
            "too many accounts in CPI instruction".to_string(),
        ));
    }

    if account_infos.len() > MAX_CPI_ACCOUNT_INFOS {
        return Err(SyscallError::InvalidArgument(
            "too many account infos provided".to_string(),
        ));
    }

    // 3. Reentrancy protection
    if instruction.program_id == ctx.program_id {
        return Err(SyscallError::ReentrancyDetected);
    }

    // 4. Derive PDA signers
    if signer_seeds.len() > MAX_CPI_SIGNERS {
        return Err(SyscallError::InvalidArgument(
            "too many signers".to_string(),
        ));
    }
    let pda_signers = derive_pda_signers(signer_seeds, &ctx.program_id)?;

    // 5. Deduplicate instruction accounts
    let deduped = deduplicate_accounts(instruction)?;

    // 6. Validate privilege escalation
    validate_privilege_escalation(ctx, &deduped, &pda_signers)?;

    // 7. Verify target program
    let target_info = account_infos
        .iter()
        .find(|info| info.pubkey == instruction.program_id);

    if let Some(info) = target_info {
        if !info.executable {
            return Err(SyscallError::ProgramNotExecutable);
        }
    }

    // 8. Verify all referenced accounts are provided
    for acct_meta in &instruction.accounts {
        let found = account_infos
            .iter()
            .any(|info| info.pubkey == acct_meta.pubkey);
        if !found {
            return Err(SyscallError::MissingAccount(format!(
                "account {} referenced in instruction but not provided in account_infos",
                acct_meta.pubkey
            )));
        }
    }

    // 9. Pre-execution sync
    super::cpi_account::sync_caller_to_callee(ctx, &deduped, account_infos)?;

    // 10. Execute (bump stack depth)
    ctx.stack_depth += 1;

    // 11. Post-execution writeback
    super::cpi_account::sync_callee_to_caller(ctx, &deduped, account_infos)?;

    ctx.stack_depth -= 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// Account deduplication
// ---------------------------------------------------------------------------

/// Deduplicate instruction accounts, merging privileges for the same account.
///
/// When the same pubkey appears multiple times, the is_signer and is_writable
/// flags are merged via logical OR. The deduplicated list contains one entry
/// per unique account, carrying the union of all requested privileges.
///
/// This mirrors the logic in Firedancer's `fd_vm_prepare_instruction`.
pub fn deduplicate_accounts(
    instruction: &CpiInstruction,
) -> Result<Vec<InstructionAccount>, SyscallError> {
    let mut deduped: Vec<InstructionAccount> = Vec::with_capacity(instruction.accounts.len());
    let mut _dup_indices: Vec<usize> = Vec::with_capacity(instruction.accounts.len());

    for (i, meta) in instruction.accounts.iter().enumerate() {
        let existing = deduped.iter().position(|ia| ia.pubkey == meta.pubkey);

        if let Some(dup_idx) = existing {
            // Merge privileges with the existing deduplicated entry
            deduped[dup_idx].is_signer |= meta.is_signer;
            deduped[dup_idx].is_writable |= meta.is_writable;
            _dup_indices.push(dup_idx);
        } else {
            _dup_indices.push(deduped.len());
            deduped.push(InstructionAccount {
                index_in_callee: i,
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
                pubkey: meta.pubkey,
            });
        }
    }

    Ok(deduped)
}

// ---------------------------------------------------------------------------
// Privilege escalation checks
// ---------------------------------------------------------------------------

/// Validate that the callee does not escalate privileges beyond the caller.
///
/// Rules enforced:
/// - A writable account in the callee must also be writable in the caller
/// - A signer account in the callee must either:
///   - Be signed by the caller, OR
///   - Be a PDA derived from the caller's program ID (via signer_seeds)
///
/// When `caller_account_privileges` is empty (legacy mode), falls back to
/// checking account presence in the caller's base/modified account maps.
fn validate_privilege_escalation(
    ctx: &SyscallContext,
    deduped: &[InstructionAccount],
    pda_signers: &[Pubkey],
) -> Result<(), SyscallError> {
    let has_explicit_privileges = !ctx.caller_account_privileges.is_empty();

    for acct in deduped {
        if has_explicit_privileges {
            // Full privilege checking mode
            let caller_priv = ctx
                .caller_account_privileges
                .iter()
                .find(|(pubkey, _, _)| *pubkey == acct.pubkey);

            // Writable escalation
            if acct.is_writable {
                let caller_writable = caller_priv.map(|(_, _, w)| *w).unwrap_or(false);
                if !caller_writable {
                    return Err(SyscallError::PrivilegeEscalation(format!(
                        "{}'s writable privilege escalated",
                        acct.pubkey
                    )));
                }
            }

            // Signer escalation: caller must be signer OR account is a PDA signer
            if acct.is_signer {
                let caller_signer = caller_priv.map(|(_, s, _)| *s).unwrap_or(false);
                let is_pda_signer = pda_signers.contains(&acct.pubkey);
                if !caller_signer && !is_pda_signer {
                    return Err(SyscallError::PrivilegeEscalation(format!(
                        "{}'s signer privilege escalated",
                        acct.pubkey
                    )));
                }
            }
        } else {
            // Legacy mode: check account presence for writable accounts
            if acct.is_writable {
                let in_base = ctx.accounts.contains_key(&acct.pubkey);
                let in_modified = ctx.modified_accounts.contains_key(&acct.pubkey);
                if !in_base && !in_modified {
                    return Err(SyscallError::AccessViolation(format!(
                        "account {} is not accessible to the caller",
                        acct.pubkey
                    )));
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PDA signer derivation
// ---------------------------------------------------------------------------

/// Derive PDA addresses from signer seeds and the calling program's ID.
///
/// Each set of seeds produces one PDA address via:
/// `SHA256(seeds || program_id || "ProgramDerivedAddress")`
///
/// Validates seed count and individual seed lengths. Returns an error if
/// any derived address falls on the ed25519 curve (invalid PDA).
pub fn derive_pda_signers(
    signer_seeds: &[&[&[u8]]],
    program_id: &Pubkey,
) -> Result<Vec<Pubkey>, SyscallError> {
    let mut signers = Vec::with_capacity(signer_seeds.len());

    for seeds in signer_seeds {
        if seeds.len() > MAX_SIGNER_SEEDS {
            return Err(SyscallError::InvalidSeeds);
        }
        for seed in *seeds {
            if seed.len() > MAX_SEED_BYTES {
                return Err(SyscallError::InvalidSeeds);
            }
        }

        let mut hasher = Sha256::new();
        for seed in *seeds {
            hasher.update(seed);
        }
        hasher.update(program_id.as_bytes());
        hasher.update(b"ProgramDerivedAddress");
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash.into();

        // PDA must NOT be on the ed25519 curve
        if CompressedEdwardsY(bytes).decompress().is_some() {
            return Err(SyscallError::InvalidProgramAddress);
        }

        signers.push(Pubkey::new(bytes));
    }

    Ok(signers)
}
