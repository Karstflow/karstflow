/// Unwritable account set for the pack scheduler.
///
/// Contains consensus-critical accounts that must never be written to
/// by packed transactions. Any transaction that attempts to write to
/// one of these accounts is immediately rejected.
///
/// This list corresponds to Agave's `is_maybe_writable` set as of
/// feature 8U4skmMVnF6k2kMvrWbQuRUT3qQSiTYpSjqmhmgfthZu activation.
use karstflow_ids::{
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID, BPF_LOADER_DEPRECATED_PROGRAM_ID, BPF_LOADER_V2_PROGRAM_ID,
    CLOCK_SYSVAR_ID, COMPUTE_BUDGET_PROGRAM_ID, CONFIG_PROGRAM_ID, ED25519_PRECOMPILE_PROGRAM_ID,
    EPOCH_REWARDS_SYSVAR_ID, EPOCH_SCHEDULE_SYSVAR_ID, FEATURE_PROGRAM_ID, FEES_SYSVAR_ID,
    INSTRUCTIONS_SYSVAR_ID, LAST_RESTART_SLOT_SYSVAR_ID, LOADER_V4_PROGRAM_ID,
    NATIVE_LOADER_PROGRAM_ID, RECENT_BLOCKHASHES_SYSVAR_ID, RENT_SYSVAR_ID, REWARDS_SYSVAR_ID,
    SECP256K1_PRECOMPILE_PROGRAM_ID, SECP256R1_PRECOMPILE_PROGRAM_ID, SLOT_HASHES_SYSVAR_ID,
    SLOT_HISTORY_SYSVAR_ID, STAKE_CONFIG_PROGRAM_ID, STAKE_HISTORY_SYSVAR_ID, STAKE_PROGRAM_ID,
    SYSTEM_PROGRAM_ID, SYSVAR_PROGRAM_ID, UPGRADEABLE_LOADER_PROGRAM_ID, VOTE_PROGRAM_ID,
    ZK_ELGAMAL_PROOF_PROGRAM_ID, ZK_TOKEN_PROOF_PROGRAM_ID,
};
use karstflow_types::Pubkey;

/// Number of unwritable accounts in the set.
pub const UNWRITABLE_COUNT: usize = 31;

/// Complete list of unwritable accounts.
///
/// Transactions that write to any of these accounts are rejected by pack.
/// The list includes sysvars (read-only state) and program accounts (executable).
const UNWRITABLE_ACCOUNTS: [Pubkey; UNWRITABLE_COUNT] = [
    // Sysvars (13)
    CLOCK_SYSVAR_ID,
    EPOCH_REWARDS_SYSVAR_ID,
    EPOCH_SCHEDULE_SYSVAR_ID,
    FEES_SYSVAR_ID,
    INSTRUCTIONS_SYSVAR_ID,
    LAST_RESTART_SLOT_SYSVAR_ID,
    RECENT_BLOCKHASHES_SYSVAR_ID,
    RENT_SYSVAR_ID,
    REWARDS_SYSVAR_ID,
    SLOT_HASHES_SYSVAR_ID,
    SLOT_HISTORY_SYSVAR_ID,
    STAKE_HISTORY_SYSVAR_ID,
    SYSVAR_PROGRAM_ID,
    // Programs (18)
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    BPF_LOADER_V2_PROGRAM_ID,
    BPF_LOADER_DEPRECATED_PROGRAM_ID,
    UPGRADEABLE_LOADER_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
    CONFIG_PROGRAM_ID,
    ED25519_PRECOMPILE_PROGRAM_ID,
    FEATURE_PROGRAM_ID,
    LOADER_V4_PROGRAM_ID,
    SECP256K1_PRECOMPILE_PROGRAM_ID,
    SECP256R1_PRECOMPILE_PROGRAM_ID,
    STAKE_CONFIG_PROGRAM_ID,
    STAKE_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    VOTE_PROGRAM_ID,
    ZK_ELGAMAL_PROOF_PROGRAM_ID,
    ZK_TOKEN_PROOF_PROGRAM_ID,
    NATIVE_LOADER_PROGRAM_ID,
];

/// Check if an account is in the unwritable set.
///
/// Returns `true` if the account must not be written to.
pub fn is_unwritable(account: &Pubkey) -> bool {
    UNWRITABLE_ACCOUNTS.contains(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwritable_count() {
        assert_eq!(UNWRITABLE_ACCOUNTS.len(), UNWRITABLE_COUNT);
    }

    #[test]
    fn sysvars_are_unwritable() {
        assert!(is_unwritable(&CLOCK_SYSVAR_ID));
        assert!(is_unwritable(&RENT_SYSVAR_ID));
        assert!(is_unwritable(&SLOT_HASHES_SYSVAR_ID));
        assert!(is_unwritable(&EPOCH_SCHEDULE_SYSVAR_ID));
        assert!(is_unwritable(&RECENT_BLOCKHASHES_SYSVAR_ID));
    }

    #[test]
    fn programs_are_unwritable() {
        assert!(is_unwritable(&SYSTEM_PROGRAM_ID));
        assert!(is_unwritable(&VOTE_PROGRAM_ID));
        assert!(is_unwritable(&STAKE_PROGRAM_ID));
        assert!(is_unwritable(&COMPUTE_BUDGET_PROGRAM_ID));
        assert!(is_unwritable(&UPGRADEABLE_LOADER_PROGRAM_ID));
    }

    #[test]
    fn zk_programs_are_unwritable() {
        assert!(is_unwritable(&ZK_ELGAMAL_PROOF_PROGRAM_ID));
        assert!(is_unwritable(&ZK_TOKEN_PROOF_PROGRAM_ID));
    }

    #[test]
    fn random_account_is_writable() {
        assert!(!is_unwritable(&Pubkey::new([0xFF; 32])));
        assert!(!is_unwritable(&Pubkey::new([0x01; 32])));
    }

    #[test]
    fn all_entries_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for account in &UNWRITABLE_ACCOUNTS {
            assert!(
                seen.insert(account.as_bytes()),
                "Duplicate unwritable account"
            );
        }
    }
}
