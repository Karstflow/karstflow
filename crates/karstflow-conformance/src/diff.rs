//! State diff engine for comparing execution outcomes.

use karstflow_types::{Account, Pubkey};
use std::collections::HashMap;
use std::fmt;

/// A single field-level difference between two accounts.
#[derive(Debug, Clone)]
pub struct AccountDiff {
    pub pubkey: Pubkey,
    pub field: String,
    pub expected: String,
    pub actual: String,
}

/// Result of comparing two execution states.
#[derive(Debug, Clone)]
pub struct StateDiff {
    pub account_diffs: Vec<AccountDiff>,
    pub missing_expected: Vec<Pubkey>,
    pub unexpected_modified: Vec<Pubkey>,
}

impl StateDiff {
    pub fn is_empty(&self) -> bool {
        self.account_diffs.is_empty()
            && self.missing_expected.is_empty()
            && self.unexpected_modified.is_empty()
    }
}

impl fmt::Display for StateDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "States match");
        }
        for diff in &self.account_diffs {
            writeln!(
                f,
                "  Account {}: {} expected={} actual={}",
                diff.pubkey, diff.field, diff.expected, diff.actual
            )?;
        }
        for key in &self.missing_expected {
            writeln!(f, "  Missing expected account: {key}")?;
        }
        for key in &self.unexpected_modified {
            writeln!(f, "  Unexpected modified account: {key}")?;
        }
        Ok(())
    }
}

/// Compare expected accounts against actual modified accounts.
pub fn compare_accounts(
    expected: &HashMap<Pubkey, Account>,
    actual: &HashMap<Pubkey, Account>,
) -> StateDiff {
    let mut diffs = Vec::new();
    let mut missing_expected = Vec::new();
    let mut unexpected_modified = Vec::new();

    for (pubkey, exp_account) in expected {
        match actual.get(pubkey) {
            Some(act_account) => {
                if exp_account.meta.lamports != act_account.meta.lamports {
                    diffs.push(AccountDiff {
                        pubkey: *pubkey,
                        field: "lamports".to_string(),
                        expected: exp_account.meta.lamports.to_string(),
                        actual: act_account.meta.lamports.to_string(),
                    });
                }
                if exp_account.meta.owner != act_account.meta.owner {
                    diffs.push(AccountDiff {
                        pubkey: *pubkey,
                        field: "owner".to_string(),
                        expected: exp_account.meta.owner.to_string(),
                        actual: act_account.meta.owner.to_string(),
                    });
                }
                if exp_account.meta.executable != act_account.meta.executable {
                    diffs.push(AccountDiff {
                        pubkey: *pubkey,
                        field: "executable".to_string(),
                        expected: exp_account.meta.executable.to_string(),
                        actual: act_account.meta.executable.to_string(),
                    });
                }
                if exp_account.data.as_ref() != act_account.data.as_ref() {
                    diffs.push(AccountDiff {
                        pubkey: *pubkey,
                        field: "data".to_string(),
                        expected: format!("{} bytes", exp_account.data.as_ref().len()),
                        actual: format!("{} bytes", act_account.data.as_ref().len()),
                    });
                }
            }
            None => {
                missing_expected.push(*pubkey);
            }
        }
    }

    for pubkey in actual.keys() {
        if !expected.contains_key(pubkey) {
            unexpected_modified.push(*pubkey);
        }
    }

    StateDiff {
        account_diffs: diffs,
        missing_expected,
        unexpected_modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::{AccountData, AccountMeta};

    fn make_account(lamports: u64) -> Account {
        Account {
            meta: AccountMeta {
                lamports,
                owner: Pubkey::zeroed(),
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        }
    }

    #[test]
    fn identical_states_produce_empty_diff() {
        let mut a = HashMap::new();
        a.insert(Pubkey::new_unique(), make_account(100));
        let diff = compare_accounts(&a, &a);
        assert!(diff.is_empty());
    }

    #[test]
    fn lamports_mismatch_detected() {
        let key = Pubkey::new_unique();
        let mut expected = HashMap::new();
        expected.insert(key, make_account(100));
        let mut actual = HashMap::new();
        actual.insert(key, make_account(200));
        let diff = compare_accounts(&expected, &actual);
        assert_eq!(diff.account_diffs.len(), 1);
        assert_eq!(diff.account_diffs[0].field, "lamports");
    }

    #[test]
    fn missing_account_detected() {
        let key = Pubkey::new_unique();
        let mut expected = HashMap::new();
        expected.insert(key, make_account(100));
        let actual = HashMap::new();
        let diff = compare_accounts(&expected, &actual);
        assert_eq!(diff.missing_expected.len(), 1);
    }

    #[test]
    fn unexpected_account_detected() {
        let key = Pubkey::new_unique();
        let expected = HashMap::new();
        let mut actual = HashMap::new();
        actual.insert(key, make_account(100));
        let diff = compare_accounts(&expected, &actual);
        assert_eq!(diff.unexpected_modified.len(), 1);
    }
}
