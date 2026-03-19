//! Conformance tests for the state diff engine.
//!
//! Verifies that `compare_accounts` correctly detects field-level
//! mismatches, missing accounts, and unexpected accounts.

use crate::diff::compare_accounts;
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_types::{Account, AccountData, AccountMeta, Pubkey};
use std::collections::HashMap;

fn system_account(lamports: u64) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    }
}

fn account_with_owner(lamports: u64, owner: Pubkey) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::empty(),
    }
}

fn account_with_data(lamports: u64, data: Vec<u8>) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(data),
    }
}

// -----------------------------------------------------------------------
// Basic matching
// -----------------------------------------------------------------------

#[test]
fn diff_empty_states_match() {
    let diff = compare_accounts(&HashMap::new(), &HashMap::new());
    assert!(diff.is_empty());
}

#[test]
fn diff_identical_single_account() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, system_account(1000));
    let mut actual = HashMap::new();
    actual.insert(key, system_account(1000));
    let diff = compare_accounts(&expected, &actual);
    assert!(diff.is_empty());
}

#[test]
fn diff_identical_multiple_accounts() {
    let k1 = Pubkey::new_unique();
    let k2 = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(k1, system_account(100));
    expected.insert(k2, system_account(200));
    let mut actual = HashMap::new();
    actual.insert(k1, system_account(100));
    actual.insert(k2, system_account(200));
    let diff = compare_accounts(&expected, &actual);
    assert!(diff.is_empty());
}

// -----------------------------------------------------------------------
// Field mismatches
// -----------------------------------------------------------------------

#[test]
fn diff_detects_lamports_mismatch() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, system_account(100));
    let mut actual = HashMap::new();
    actual.insert(key, system_account(999));
    let diff = compare_accounts(&expected, &actual);
    assert_eq!(diff.account_diffs.len(), 1);
    assert_eq!(diff.account_diffs[0].field, "lamports");
    assert_eq!(diff.account_diffs[0].expected, "100");
    assert_eq!(diff.account_diffs[0].actual, "999");
}

#[test]
fn diff_detects_owner_mismatch() {
    let key = Pubkey::new_unique();
    let owner_a = Pubkey::new_unique();
    let owner_b = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, account_with_owner(100, owner_a));
    let mut actual = HashMap::new();
    actual.insert(key, account_with_owner(100, owner_b));
    let diff = compare_accounts(&expected, &actual);
    assert_eq!(diff.account_diffs.len(), 1);
    assert_eq!(diff.account_diffs[0].field, "owner");
}

#[test]
fn diff_detects_data_mismatch() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, account_with_data(100, vec![1, 2, 3]));
    let mut actual = HashMap::new();
    actual.insert(key, account_with_data(100, vec![4, 5, 6]));
    let diff = compare_accounts(&expected, &actual);
    assert_eq!(diff.account_diffs.len(), 1);
    assert_eq!(diff.account_diffs[0].field, "data");
}

#[test]
fn diff_detects_executable_mismatch() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(
        key,
        Account {
            meta: AccountMeta {
                lamports: 100,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        },
    );
    let mut actual = HashMap::new();
    actual.insert(
        key,
        Account {
            meta: AccountMeta {
                lamports: 100,
                owner: SYSTEM_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        },
    );
    let diff = compare_accounts(&expected, &actual);
    assert_eq!(diff.account_diffs.len(), 1);
    assert_eq!(diff.account_diffs[0].field, "executable");
}

// -----------------------------------------------------------------------
// Missing and unexpected
// -----------------------------------------------------------------------

#[test]
fn diff_detects_missing_expected_account() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, system_account(100));
    let diff = compare_accounts(&expected, &HashMap::new());
    assert_eq!(diff.missing_expected.len(), 1);
    assert_eq!(diff.missing_expected[0], key);
}

#[test]
fn diff_detects_unexpected_actual_account() {
    let key = Pubkey::new_unique();
    let mut actual = HashMap::new();
    actual.insert(key, system_account(100));
    let diff = compare_accounts(&HashMap::new(), &actual);
    assert_eq!(diff.unexpected_modified.len(), 1);
    assert_eq!(diff.unexpected_modified[0], key);
}

// -----------------------------------------------------------------------
// Display
// -----------------------------------------------------------------------

#[test]
fn diff_display_empty_says_match() {
    let diff = compare_accounts(&HashMap::new(), &HashMap::new());
    assert_eq!(format!("{diff}"), "States match");
}

#[test]
fn diff_display_shows_details() {
    let key = Pubkey::new_unique();
    let mut expected = HashMap::new();
    expected.insert(key, system_account(100));
    let mut actual = HashMap::new();
    actual.insert(key, system_account(200));
    let diff = compare_accounts(&expected, &actual);
    let output = format!("{diff}");
    assert!(output.contains("lamports"));
    assert!(output.contains("100"));
    assert!(output.contains("200"));
}
