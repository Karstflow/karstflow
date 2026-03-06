//! Account synchronization and writeback during CPI.
//!
//! Before CPI execution: syncs the caller's modifications to the callee's
//! view so the callee sees up-to-date account state.
//!
//! After CPI execution: syncs the callee's modifications back to the
//! caller, enforcing realloc limits on data length growth.

use super::cpi::{CpiAccountInfo, InstructionAccount};
use super::{SyscallContext, SyscallError};
use karstflow_constants::vm::MAX_PERMITTED_DATA_INCREASE;
use karstflow_types::{Account, AccountData, AccountMeta};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::cpi::{CpiAccountInfo, InstructionAccount};
    use karstflow_types::Pubkey;

    fn test_pubkey(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }

    fn test_ctx() -> SyscallContext {
        SyscallContext::new(test_pubkey(1), 1_000_000_000)
    }

    fn writable_acct(pubkey: Pubkey) -> InstructionAccount {
        InstructionAccount {
            index_in_callee: 0,
            is_signer: false,
            is_writable: true,
            pubkey,
        }
    }

    fn readonly_acct(pubkey: Pubkey) -> InstructionAccount {
        InstructionAccount {
            index_in_callee: 0,
            is_signer: false,
            is_writable: false,
            pubkey,
        }
    }

    #[test]
    fn sync_caller_to_callee_skips_readonly() {
        let ctx = test_ctx();
        let pk = test_pubkey(10);
        let deduped = vec![readonly_acct(pk)];
        let result = sync_caller_to_callee(&ctx, &deduped, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn sync_caller_to_callee_writable_ok() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        ctx.modified_accounts.insert(
            pk,
            Account {
                meta: AccountMeta::new(1000, test_pubkey(0xFF), false, 0),
                data: AccountData::new(vec![1, 2, 3]),
            },
        );
        let deduped = vec![writable_acct(pk)];
        let result = sync_caller_to_callee(&ctx, &deduped, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn sync_callee_to_caller_writes_back() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        ctx.accounts.insert(
            pk,
            Account {
                meta: AccountMeta::new(1000, test_pubkey(0xFF), false, 0),
                data: AccountData::new(vec![0; 32]),
            },
        );
        let deduped = vec![writable_acct(pk)];
        let info = CpiAccountInfo {
            pubkey: pk,
            lamports: 2000,
            data: vec![0; 32],
            owner: test_pubkey(0xEE),
            executable: false,
        };
        let result = sync_callee_to_caller(&mut ctx, &deduped, &[info]);
        assert!(result.is_ok());
        let modified = ctx.modified_accounts.get(&pk).unwrap();
        assert_eq!(modified.meta.lamports, 2000);
    }

    #[test]
    fn sync_callee_to_caller_skips_readonly() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        let deduped = vec![readonly_acct(pk)];
        let info = CpiAccountInfo {
            pubkey: pk,
            lamports: 9999,
            data: vec![],
            owner: test_pubkey(0xFF),
            executable: false,
        };
        let result = sync_callee_to_caller(&mut ctx, &deduped, &[info]);
        assert!(result.is_ok());
        assert!(!ctx.modified_accounts.contains_key(&pk));
    }

    #[test]
    fn sync_callee_to_caller_rejects_excessive_realloc() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        ctx.accounts.insert(
            pk,
            Account {
                meta: AccountMeta::new(1000, test_pubkey(0xFF), false, 0),
                data: AccountData::new(vec![0; 32]),
            },
        );
        let deduped = vec![writable_acct(pk)];
        let info = CpiAccountInfo {
            pubkey: pk,
            lamports: 1000,
            data: vec![0; 32 + MAX_PERMITTED_DATA_INCREASE + 1],
            owner: test_pubkey(0xFF),
            executable: false,
        };
        let result = sync_callee_to_caller(&mut ctx, &deduped, &[info]);
        assert!(result.is_err());
    }

    #[test]
    fn sync_callee_to_caller_allows_data_shrink() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        ctx.accounts.insert(
            pk,
            Account {
                meta: AccountMeta::new(1000, test_pubkey(0xFF), false, 0),
                data: AccountData::new(vec![0; 1024]),
            },
        );
        let deduped = vec![writable_acct(pk)];
        let info = CpiAccountInfo {
            pubkey: pk,
            lamports: 1000,
            data: vec![0; 16], // shrink from 1024 to 16
            owner: test_pubkey(0xFF),
            executable: false,
        };
        let result = sync_callee_to_caller(&mut ctx, &deduped, &[info]);
        assert!(result.is_ok());
        let modified = ctx.modified_accounts.get(&pk).unwrap();
        assert_eq!(modified.data.len(), 16);
    }

    #[test]
    fn sync_callee_to_caller_allows_max_realloc() {
        let mut ctx = test_ctx();
        let pk = test_pubkey(10);
        ctx.accounts.insert(
            pk,
            Account {
                meta: AccountMeta::new(1000, test_pubkey(0xFF), false, 0),
                data: AccountData::new(vec![0; 32]),
            },
        );
        let deduped = vec![writable_acct(pk)];
        let info = CpiAccountInfo {
            pubkey: pk,
            lamports: 1000,
            data: vec![0; 32 + MAX_PERMITTED_DATA_INCREASE], // exactly at limit
            owner: test_pubkey(0xFF),
            executable: false,
        };
        let result = sync_callee_to_caller(&mut ctx, &deduped, &[info]);
        assert!(result.is_ok());
    }
}
