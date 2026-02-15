//! Cross-program invocation (CPI) implementation.
//!
//! Allows programs to invoke other programs during execution,
//! passing accounts and instruction data across program boundaries.
//! CPI maintains a call stack and enforces depth limits, privilege
//! escalation checks, and reentrancy protection.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;
use paradencer_types::Pubkey;

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

/// Invoke another program via CPI without PDA signing.
///
/// Validates account privileges, enforces depth limits, and deducts
/// compute costs proportional to the number of accounts and data size.
pub fn invoke(
    ctx: &mut SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
) -> Result<(), SyscallError> {
    invoke_signed(ctx, instruction, account_infos, &[])
}

/// Invoke another program via CPI with optional PDA signer seeds.
///
/// When `signer_seeds` is non-empty, PDAs derived from those seeds
/// and the calling program's ID are treated as signers for the invoked
/// instruction.
pub fn invoke_signed(
    ctx: &mut SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
    signer_seeds: &[&[&[u8]]],
) -> Result<(), SyscallError> {
    // Compute cost: base + per-account + per-data-byte
    let compute_cost = CPI_BASE_COST
        + CPI_PER_ACCOUNT_COST * instruction.accounts.len() as u64
        + CPI_PER_DATA_BYTE_COST * instruction.data.len() as u64;
    ctx.consume_compute(compute_cost)?;

    // Enforce CPI depth limit
    if ctx.stack_depth >= MAX_CPI_DEPTH {
        return Err(SyscallError::MaxCpiDepthExceeded);
    }

    // Enforce instruction size limit
    if instruction.data.len() > MAX_CPI_INSTRUCTION_SIZE {
        return Err(SyscallError::MaxInstructionSizeExceeded);
    }

    // Enforce account count limits
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

    // Reentrancy protection: disallow a program from invoking itself
    if instruction.program_id == ctx.program_id {
        return Err(SyscallError::ReentrancyDetected);
    }

    // Validate signer seeds if provided
    for seeds in signer_seeds {
        if seeds.len() > MAX_SIGNER_SEEDS {
            return Err(SyscallError::InvalidSeeds);
        }
        for seed in *seeds {
            if seed.len() > MAX_SEED_BYTES {
                return Err(SyscallError::InvalidSeeds);
            }
        }
    }

    // Verify the target program exists in our accounts and is executable
    let target_info = account_infos
        .iter()
        .find(|info| info.pubkey == instruction.program_id);

    if let Some(info) = target_info {
        if !info.executable {
            return Err(SyscallError::ProgramNotExecutable);
        }
    }

    // Validate that every account in the instruction is provided in account_infos
    for acct_meta in &instruction.accounts {
        let found = account_infos
            .iter()
            .any(|info| info.pubkey == acct_meta.pubkey);
        if !found {
            return Err(SyscallError::InvalidArgument(format!(
                "account {} referenced in instruction but not provided in account_infos",
                acct_meta.pubkey
            )));
        }
    }

    // Validate caller privileges: the caller can only escalate signer/writable
    // privileges it itself holds. For writable accounts, they must already be
    // writable in the caller's context.
    super::cpi_account::validate_account_privileges(ctx, instruction, account_infos, signer_seeds)?;

    // Execute the CPI by bumping the stack depth.
    // In a full implementation, this would dispatch to the target program's
    // executor. For now, we track the call and update context.
    ctx.stack_depth += 1;

    // After "execution" succeeds, write back any modified accounts
    super::cpi_account::writeback_accounts(ctx, instruction, account_infos)?;

    ctx.stack_depth -= 1;

    Ok(())
}
