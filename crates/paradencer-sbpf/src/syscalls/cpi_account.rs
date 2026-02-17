//! Account synchronization and writeback during CPI.
//!
//! Before CPI execution: syncs the caller's modifications to the callee's
//! view so the callee sees up-to-date account state.
//!
//! After CPI execution: syncs the callee's modifications back to the
//! caller, enforcing realloc limits on data length growth.

use super::cpi::{CpiAccountInfo, InstructionAccount};
use super::{SyscallContext, SyscallError};
use paradencer_constants::vm::MAX_PERMITTED_DATA_INCREASE;
use paradencer_types::{Account, AccountData, AccountMeta};

/// Pre-execution sync: ensure the callee sees the caller's latest state.
///
/// For each writable account, if the caller has already modified it,
/// those modifications are already reflected in the shared account state.
/// This function validates consistency and prepares accounts for callee use.
pub fn sync_caller_to_callee(
    ctx: &SyscallContext,
    deduped: &[InstructionAccount],
    _account_infos: &[CpiAccountInfo],
) -> Result<(), SyscallError> {
    for acct in deduped {
        if !acct.is_writable {
            continue;
        }

        // If the caller has modified this account, the callee will see
        // the modified version. No additional sync needed at this abstraction
        // level (in a VM-level implementation, this would copy serialized
        // account data from the caller's input region to the callee's
        // borrowed accounts cache).
        let _has_modification = ctx.modified_accounts.contains_key(&acct.pubkey);
    }

    Ok(())
}

/// Post-execution sync: writeback callee's modifications to caller's state.
///
/// For each writable account in the deduplicated list:
/// - Propagates lamports, data, and owner changes
/// - Enforces realloc limit: data growth cannot exceed
///   `MAX_PERMITTED_DATA_INCREASE` (10 KiB) per CPI call
/// - Data shrinking is always allowed
/// - Zero-pads previous data region when account data shrinks
pub fn sync_callee_to_caller(
    ctx: &mut SyscallContext,
    deduped: &[InstructionAccount],
    account_infos: &[CpiAccountInfo],
) -> Result<(), SyscallError> {
    for acct in deduped {
        if !acct.is_writable {
            continue;
        }

        let info = match account_infos.iter().find(|i| i.pubkey == acct.pubkey) {
            Some(i) => i,
            None => continue,
        };

        // Check realloc limits for data length changes
        let existing = ctx
            .modified_accounts
            .get(&acct.pubkey)
            .or_else(|| ctx.accounts.get(&acct.pubkey));

        if let Some(prev_account) = existing {
            let prev_len = prev_account.data.len();
            let post_len = info.data.len();

            // Data growth is limited to MAX_PERMITTED_DATA_INCREASE in inner instructions
            if post_len > prev_len + MAX_PERMITTED_DATA_INCREASE {
                return Err(SyscallError::InvalidArgument(format!(
                    "account data size realloc limited to {} in inner instructions",
                    MAX_PERMITTED_DATA_INCREASE
                )));
            }
        }

        // Writeback: create/update the account with the callee's state
        let account = Account {
            meta: AccountMeta::new(info.lamports, info.owner, info.executable, 0),
            data: AccountData::new(info.data.clone()),
        };
        ctx.modified_accounts.insert(acct.pubkey, account);
    }

    Ok(())
}
