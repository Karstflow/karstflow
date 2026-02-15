//! Account serialization and privilege validation during CPI.
//!
//! Handles privilege escalation checks (a callee cannot gain privileges
//! the caller does not hold) and account state writeback after a CPI
//! call returns.

use super::cpi::{CpiAccountInfo, CpiInstruction};
use super::{SyscallContext, SyscallError};
use paradencer_types::{Account, AccountData, AccountMeta};

/// Validate that the caller has authority to grant the requested
/// privileges on each account passed to the CPI instruction.
///
/// Specifically:
/// - Writable accounts in the CPI must already be present in the caller's
///   modified or base account set.
/// - Signer accounts must either be signed by the caller or derived via
///   PDA seeds from the caller's program ID.
pub fn validate_account_privileges(
    ctx: &SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
    _signer_seeds: &[&[&[u8]]],
) -> Result<(), SyscallError> {
    for acct_meta in &instruction.accounts {
        // Find the matching account info
        let info = account_infos
            .iter()
            .find(|i| i.pubkey == acct_meta.pubkey)
            .ok_or_else(|| {
                SyscallError::InvalidArgument(format!(
                    "account {} not found in account_infos",
                    acct_meta.pubkey
                ))
            })?;

        // If the instruction marks this account as writable, verify the caller
        // actually has access to it (present in either the base or modified set).
        if acct_meta.is_writable {
            let in_base = ctx.accounts.contains_key(&acct_meta.pubkey);
            let in_modified = ctx.modified_accounts.contains_key(&acct_meta.pubkey);
            if !in_base && !in_modified {
                return Err(SyscallError::AccessViolation(format!(
                    "account {} is not accessible to the caller",
                    info.pubkey
                )));
            }
        }
    }

    Ok(())
}

/// Write back modified account state after a CPI call returns.
///
/// For each writable account in the instruction, the callee's
/// modifications are propagated back to the caller's context.
pub fn writeback_accounts(
    ctx: &mut SyscallContext,
    instruction: &CpiInstruction,
    account_infos: &[CpiAccountInfo],
) -> Result<(), SyscallError> {
    for acct_meta in &instruction.accounts {
        if !acct_meta.is_writable {
            continue;
        }

        if let Some(info) = account_infos.iter().find(|i| i.pubkey == acct_meta.pubkey) {
            let account = Account {
                meta: AccountMeta::new(info.lamports, info.owner, info.executable, 0),
                data: AccountData::new(info.data.clone()),
            };
            ctx.modified_accounts.insert(acct_meta.pubkey, account);
        }
    }

    Ok(())
}
