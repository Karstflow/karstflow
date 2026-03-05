/// Epoch reward application to accounts.
///
/// After the rewards calculator determines each validator's share of the
/// inflation pool, this module credits the computed lamports to the
/// corresponding vote and stake accounts in the account database.
///
/// Vote rewards are applied immediately at the epoch boundary. Stake
/// rewards are distributed over multiple slots via the partitioned
/// rewards distributor.
use crate::rewards_distribution::{PendingReward, RewardsDistributor};
use karstflow_storage::{Account, AccountDatabase};
use karstflow_types::Pubkey;

/// Result of applying a batch of rewards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardApplicationResult {
    /// Total lamports distributed in this batch.
    pub total_distributed: u64,
    /// Number of accounts that received rewards.
    pub accounts_credited: u64,
    /// Number of accounts that were skipped (not found or zero reward).
    pub accounts_skipped: u64,
}

/// Apply computed rewards to accounts in the database.
pub struct RewardApplicator;

impl RewardApplicator {
    /// Apply a batch of pending rewards to accounts.
    ///
    /// For each reward entry, loads the account, adds the reward lamports,
    /// and stores the updated account. The `on_modify` callback is invoked
    /// with the pubkey, old account, and new account so the caller can
    /// update incremental hashes (e.g. lattice hash).
    ///
    /// Accounts not found in the database are skipped. Zero-amount rewards
    /// are also skipped.
    pub fn apply_rewards<F>(
        db: &AccountDatabase,
        rewards: &[PendingReward],
        mut on_modify: F,
    ) -> RewardApplicationResult
    where
        F: FnMut(&Pubkey, &Account, &Account),
    {
        let mut total_distributed: u64 = 0;
        let mut accounts_credited: u64 = 0;
        let mut accounts_skipped: u64 = 0;

        for reward in rewards {
            if reward.amount == 0 {
                accounts_skipped += 1;
                continue;
            }

            if let Some(old_account) = db.get_published_account(&reward.account) {
                let mut new_account = old_account.clone();
                new_account.meta.lamports = new_account.meta.lamports.saturating_add(reward.amount);
                on_modify(&reward.account, &old_account, &new_account);
                db.store_published_account(reward.account, new_account);
                total_distributed += reward.amount;
                accounts_credited += 1;
            } else {
                accounts_skipped += 1;
            }
        }

        RewardApplicationResult {
            total_distributed,
            accounts_credited,
            accounts_skipped,
        }
    }

    /// Apply partitioned stake rewards for a single slot.
    ///
    /// Retrieves the rewards assigned to the given slot from the distributor,
    /// credits them to accounts, and marks the slot as distributed.
    /// The `on_modify` callback is forwarded to `apply_rewards` for
    /// incremental hash updates.
    pub fn apply_partition<F>(
        db: &AccountDatabase,
        distributor: &mut RewardsDistributor,
        current_slot: u64,
        on_modify: F,
    ) -> RewardApplicationResult
    where
        F: FnMut(&Pubkey, &Account, &Account),
    {
        let rewards = distributor.rewards_for_slot(current_slot);
        if rewards.is_empty() {
            return RewardApplicationResult {
                total_distributed: 0,
                accounts_credited: 0,
                accounts_skipped: 0,
            };
        }

        // Collect rewards before mutable borrow of distributor
        let rewards_snapshot: Vec<PendingReward> = rewards.to_vec();
        let result = Self::apply_rewards(db, &rewards_snapshot, on_modify);
        distributor.mark_slot_distributed(current_slot);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_processing::RewardType;
    use karstflow_storage::{Account, AccountDatabase, Pubkey};
    use std::sync::Arc;

    fn make_db_with_accounts(count: usize) -> (Arc<AccountDatabase>, Vec<Pubkey>) {
        let db = Arc::new(AccountDatabase::new());
        let mut pubkeys = Vec::new();

        for i in 0..count {
            let pubkey = Pubkey::new_unique();
            let account = Account::new(1_000_000 * (i as u64 + 1), vec![], Pubkey::default());
            db.store_published_account(pubkey, account);
            pubkeys.push(pubkey);
        }

        (db, pubkeys)
    }

    #[test]
    fn apply_rewards_credits_lamports() {
        let (db, pubkeys) = make_db_with_accounts(2);

        let rewards = vec![
            PendingReward {
                account: pubkeys[0],
                amount: 500,
                reward_type: RewardType::Voting,
            },
            PendingReward {
                account: pubkeys[1],
                amount: 1000,
                reward_type: RewardType::Staking,
            },
        ];

        let result = RewardApplicator::apply_rewards(&db, &rewards, |_, _, _| {});

        assert_eq!(result.total_distributed, 1500);
        assert_eq!(result.accounts_credited, 2);
        assert_eq!(result.accounts_skipped, 0);

        let acct0 = db.get_published_account(&pubkeys[0]).unwrap();
        assert_eq!(acct0.meta.lamports, 1_000_000 + 500);

        let acct1 = db.get_published_account(&pubkeys[1]).unwrap();
        assert_eq!(acct1.meta.lamports, 2_000_000 + 1000);
    }

    #[test]
    fn apply_rewards_skips_missing_accounts() {
        let (db, _pubkeys) = make_db_with_accounts(1);
        let missing = Pubkey::new_unique();

        let rewards = vec![PendingReward {
            account: missing,
            amount: 1000,
            reward_type: RewardType::Voting,
        }];

        let result = RewardApplicator::apply_rewards(&db, &rewards, |_, _, _| {});

        assert_eq!(result.total_distributed, 0);
        assert_eq!(result.accounts_credited, 0);
        assert_eq!(result.accounts_skipped, 1);
    }

    #[test]
    fn apply_rewards_skips_zero_amount() {
        let (db, pubkeys) = make_db_with_accounts(1);

        let rewards = vec![PendingReward {
            account: pubkeys[0],
            amount: 0,
            reward_type: RewardType::Voting,
        }];

        let result = RewardApplicator::apply_rewards(&db, &rewards, |_, _, _| {});

        assert_eq!(result.total_distributed, 0);
        assert_eq!(result.accounts_credited, 0);
        assert_eq!(result.accounts_skipped, 1);

        // Balance unchanged
        let acct = db.get_published_account(&pubkeys[0]).unwrap();
        assert_eq!(acct.meta.lamports, 1_000_000);
    }

    #[test]
    fn apply_rewards_empty_batch() {
        let (db, _) = make_db_with_accounts(0);

        let result = RewardApplicator::apply_rewards(&db, &[], |_, _, _| {});

        assert_eq!(result.total_distributed, 0);
        assert_eq!(result.accounts_credited, 0);
        assert_eq!(result.accounts_skipped, 0);
    }

    #[test]
    fn apply_partition_credits_and_marks_distributed() {
        let (db, pubkeys) = make_db_with_accounts(3);

        let pending: Vec<PendingReward> = pubkeys
            .iter()
            .map(|pk| PendingReward {
                account: *pk,
                amount: 100,
                reward_type: RewardType::Staking,
            })
            .collect();

        let mut distributor = RewardsDistributor::new(pending, 1, 50);

        assert!(!distributor.is_complete());

        let result = RewardApplicator::apply_partition(&db, &mut distributor, 50, |_, _, _| {});

        assert_eq!(result.total_distributed, 300);
        assert_eq!(result.accounts_credited, 3);
        assert!(distributor.is_complete());
    }

    #[test]
    fn apply_partition_out_of_range_slot_is_noop() {
        let (db, pubkeys) = make_db_with_accounts(1);

        let pending = vec![PendingReward {
            account: pubkeys[0],
            amount: 100,
            reward_type: RewardType::Staking,
        }];

        let mut distributor = RewardsDistributor::new(pending, 1, 50);

        let result = RewardApplicator::apply_partition(&db, &mut distributor, 99, |_, _, _| {});

        assert_eq!(result.total_distributed, 0);
        assert!(!distributor.is_complete());
    }

    #[test]
    fn apply_partition_multi_slot_distribution() {
        let (db, pubkeys) = make_db_with_accounts(4);

        let pending: Vec<PendingReward> = pubkeys
            .iter()
            .map(|pk| PendingReward {
                account: *pk,
                amount: 250,
                reward_type: RewardType::Staking,
            })
            .collect();

        let mut distributor = RewardsDistributor::new(pending, 4, 100);

        let mut total = 0u64;
        let partition_count = distributor.partition_count();
        for i in 0..partition_count {
            let result =
                RewardApplicator::apply_partition(&db, &mut distributor, 100 + i, |_, _, _| {});
            total += result.total_distributed;
        }

        assert_eq!(total, 1000);
        assert!(distributor.is_complete());

        // Verify balances
        for (i, pk) in pubkeys.iter().enumerate() {
            let acct = db.get_published_account(pk).unwrap();
            assert_eq!(acct.meta.lamports, 1_000_000 * (i as u64 + 1) + 250);
        }
    }

    #[test]
    fn apply_rewards_mixed_found_and_missing() {
        let (db, pubkeys) = make_db_with_accounts(2);
        let missing = Pubkey::new_unique();

        let rewards = vec![
            PendingReward {
                account: pubkeys[0],
                amount: 100,
                reward_type: RewardType::Voting,
            },
            PendingReward {
                account: missing,
                amount: 200,
                reward_type: RewardType::Voting,
            },
            PendingReward {
                account: pubkeys[1],
                amount: 300,
                reward_type: RewardType::Staking,
            },
        ];

        let result = RewardApplicator::apply_rewards(&db, &rewards, |_, _, _| {});

        assert_eq!(result.total_distributed, 400);
        assert_eq!(result.accounts_credited, 2);
        assert_eq!(result.accounts_skipped, 1);
    }

    #[test]
    fn on_modify_callback_receives_old_and_new_accounts() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let (db, pubkeys) = make_db_with_accounts(1);
        let initial_lamports = db.get_published_account(&pubkeys[0]).unwrap().meta.lamports;

        let rewards = vec![PendingReward {
            account: pubkeys[0],
            amount: 7_500,
            reward_type: RewardType::Voting,
        }];

        let callback_count = AtomicU64::new(0);
        let result = RewardApplicator::apply_rewards(&db, &rewards, |pk, old_acc, new_acc| {
            assert_eq!(*pk, pubkeys[0]);
            assert_eq!(old_acc.meta.lamports, initial_lamports);
            assert_eq!(new_acc.meta.lamports, initial_lamports + 7_500);
            callback_count.fetch_add(1, Ordering::Relaxed);
        });

        assert_eq!(result.accounts_credited, 1);
        assert_eq!(callback_count.load(Ordering::Relaxed), 1);
    }
}
