/// Duplicate account detection for the pack scheduler.
///
/// Detects duplicate account addresses in a transaction's account list.
/// Transactions with duplicate accounts are invalid and must be rejected.
/// Supports up to 128 account addresses (the protocol maximum).
///
/// Uses a hash-set approach: inserts each account into a set and detects
/// collisions. The null address (all zeros) is treated specially — at most
/// one occurrence is allowed.
use std::collections::HashSet;

/// Maximum number of account addresses per transaction.
pub const MAX_ACCOUNT_ADDRS: usize = 128;

/// Check whether a transaction's account lists contain duplicate addresses.
///
/// Takes two account lists (typically writable and read-only) that are
/// logically concatenated. Returns `true` if any duplicate is found.
///
/// The null address (all zeros) may appear at most once across both lists.
pub fn has_duplicate_accounts(list0: &[[u8; 32]], list1: &[[u8; 32]]) -> bool {
    let total = list0.len() + list1.len();
    if total > MAX_ACCOUNT_ADDRS {
        return true;
    }

    let mut seen = HashSet::with_capacity(total);

    for account in list0.iter().chain(list1.iter()) {
        if !seen.insert(account) {
            return true;
        }
    }

    false
}

/// Check a single flat account list for duplicates.
pub fn has_duplicate_accounts_flat(accounts: &[[u8; 32]]) -> bool {
    if accounts.len() > MAX_ACCOUNT_ADDRS {
        return true;
    }

    let mut seen = HashSet::with_capacity(accounts.len());

    for account in accounts {
        if !seen.insert(account) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = id;
        a
    }

    #[test]
    fn no_duplicates_returns_false() {
        let list0 = vec![account(1), account(2)];
        let list1 = vec![account(3), account(4)];
        assert!(!has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn duplicate_within_list0() {
        let list0 = vec![account(1), account(2), account(1)];
        let list1 = vec![account(3)];
        assert!(has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn duplicate_within_list1() {
        let list0 = vec![account(1)];
        let list1 = vec![account(3), account(3)];
        assert!(has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn duplicate_across_lists() {
        let list0 = vec![account(1), account(2)];
        let list1 = vec![account(2), account(3)];
        assert!(has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn empty_lists_no_duplicates() {
        assert!(!has_duplicate_accounts(&[], &[]));
        assert!(!has_duplicate_accounts(&[account(1)], &[]));
        assert!(!has_duplicate_accounts(&[], &[account(1)]));
    }

    #[test]
    fn single_null_address_allowed() {
        let list0 = vec![[0u8; 32]];
        let list1 = vec![account(1)];
        assert!(!has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn two_null_addresses_rejected() {
        let list0 = vec![[0u8; 32]];
        let list1 = vec![[0u8; 32]];
        assert!(has_duplicate_accounts(&list0, &list1));
    }

    #[test]
    fn exceeding_max_accounts_rejected() {
        let accounts: Vec<[u8; 32]> = (0..=128u8)
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i;
                a[1] = (i >> 4) | 0x80; // ensure uniqueness past 128
                a
            })
            .collect();
        // 129 accounts in one list
        assert!(has_duplicate_accounts(&accounts, &[]));
    }

    #[test]
    fn max_accounts_exactly_allowed() {
        let accounts: Vec<[u8; 32]> = (0..128u16)
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = (i & 0xFF) as u8;
                a[1] = (i >> 8) as u8;
                a
            })
            .collect();
        assert!(!has_duplicate_accounts(&accounts, &[]));
    }

    #[test]
    fn flat_no_duplicates() {
        let accounts = vec![account(1), account(2), account(3)];
        assert!(!has_duplicate_accounts_flat(&accounts));
    }

    #[test]
    fn flat_with_duplicate() {
        let accounts = vec![account(1), account(2), account(1)];
        assert!(has_duplicate_accounts_flat(&accounts));
    }

    #[test]
    fn flat_exceeding_max_rejected() {
        let accounts: Vec<[u8; 32]> = (0..=128u8)
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i;
                a[1] = (i >> 4) | 0x80;
                a
            })
            .collect();
        assert!(has_duplicate_accounts_flat(&accounts));
    }
}
