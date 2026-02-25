/// Bank lifecycle: slot completion, rent collection, and epoch boundary hooks.
///
/// Extends Bank with methods for:
/// - Collecting rent from non-exempt accounts when a slot completes
/// - Running epoch boundary processing (rewards, stake history, leader schedule)
/// - Combining these into a single `finish_slot` entry point
use crate::{Bank, BankStatus, EpochProcessor, Rent, RentCollector, StakeHistory, StakeTracker};
use paradencer_constants::economics::DEFAULT_SLOTS_PER_YEAR;
use paradencer_storage::{Account, Pubkey};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Rent collection result
// ---------------------------------------------------------------------------

/// Summary of rent collection across all accounts.
#[derive(Debug, Clone, Default)]
pub struct RentCollectionResult {
    /// Number of accounts examined.
    pub accounts_examined: usize,
    /// Number of rent-exempt accounts.
    pub exempt_accounts: usize,
    /// Number of accounts that paid rent.
    pub rent_paying_accounts: usize,
    /// Total lamports collected.
    pub total_rent_collected: u64,
    /// Total lamports burned from rent.
    pub rent_burned: u64,
    /// Accounts that were fully drained by rent.
    pub accounts_drained: usize,
}

// ---------------------------------------------------------------------------
// Slot finish result
// ---------------------------------------------------------------------------

/// Summary returned from `finish_slot`.
#[derive(Debug, Clone)]
pub struct SlotFinishResult {
    /// Slot that was finished.
    pub slot: u64,
    /// Whether this was an epoch boundary.
    pub is_epoch_boundary: bool,
    /// Rent collected during this slot's freeze.
    pub rent: RentCollectionResult,
    /// Fee distribution summary (leader_share, burn_share).
    pub fees: (u64, u64),
}

// ---------------------------------------------------------------------------
// Bank lifecycle methods
// ---------------------------------------------------------------------------

impl Bank {
    /// Collect rent from all non-exempt accounts.
    ///
    /// Iterates over published accounts in the database, calculates rent due,
    /// deducts from non-exempt accounts, and accumulates results.
    ///
    /// Note: In production, rent collection is partitioned across
    /// slots within an epoch. This simplified version collects from all
    /// accounts at once (suitable for testing and initial integration).
    pub fn collect_rent(&self) -> RentCollectionResult {
        let collector = RentCollector::new(
            self.epoch(),
            (**self.epoch_schedule()).clone(),
            DEFAULT_SLOTS_PER_YEAR,
            *self.rent(),
        );

        let db = self.accounts();

        let mut result = RentCollectionResult::default();
        let burn_percent = self.rent().burn_percent as u64;

        // Stream accounts and collect only those that need rent deduction.
        let mut rent_updates: Vec<(Pubkey, Account, u64)> = Vec::new();

        let _ = db.for_each_published_account(|pubkey, account| {
            result.accounts_examined += 1;
            let collected =
                collector.collect_from_account(account.meta.lamports, account.data.len());

            if collected.is_exempt || collected.rent_collected == 0 {
                result.exempt_accounts += 1;
                return Ok(());
            }

            result.rent_paying_accounts += 1;
            result.total_rent_collected += collected.rent_collected;

            let new_lamports = account
                .meta
                .lamports
                .saturating_sub(collected.rent_collected);
            let mut updated = account.clone();
            updated.meta.lamports = new_lamports;

            if new_lamports == 0 {
                result.accounts_drained += 1;
            }

            rent_updates.push((*pubkey, updated, collected.rent_collected));
            Ok(())
        });

        // Apply rent deductions after streaming is complete.
        for (pubkey, updated, _) in &rent_updates {
            db.store(pubkey, updated);
        }

        // Calculate burned portion.
        result.rent_burned = result
            .total_rent_collected
            .saturating_mul(burn_percent)
            .checked_div(100)
            .unwrap_or(0);

        result
    }

    /// Complete a slot: distribute fees and run epoch boundary processing
    /// if applicable.
    ///
    /// Call this after all transactions and ticks for the slot have been
    /// processed, but before calling `freeze()`. The runtime performs
    /// end-of-slot housekeeping before sealing the bank hash.
    ///
    /// Note: Rent collection is disabled on modern protocol
    /// (`disable_rent_fees_collection` always active). All accounts must
    /// be rent-exempt, enforced during transaction execution.
    pub fn finish_slot(
        &self,
        stake_tracker: &StakeTracker,
        stake_history: &mut StakeHistory,
    ) -> Result<SlotFinishResult, String> {
        if self.status() != BankStatus::Processing {
            return Err("bank not in processing state".to_string());
        }

        // 1. Distribute fees
        let fees = self.distribute_fees().map_err(|e| format!("{:?}", e))?;

        // 2. Rent collection disabled — all accounts must be rent-exempt.
        let rent = RentCollectionResult::default();

        // 3. Epoch boundary processing
        let is_epoch_boundary = self.is_epoch_boundary();
        if is_epoch_boundary {
            let _ = EpochProcessor::process_epoch_boundary(self, stake_tracker, stake_history);
            // Epoch processing errors are non-fatal for slot completion
        }

        Ok(SlotFinishResult {
            slot: self.slot(),
            is_epoch_boundary,
            rent,
            fees,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochSchedule, Inflation, LeaderSchedule, Rent};
    use paradencer_storage::AccountDatabase;
    use std::sync::Arc;

    fn create_test_bank_with_accounts() -> Bank {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());

        let bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Add some accounts: mix of exempt and non-exempt
        let db = bank.accounts();

        // Exempt account (enough lamports for its data size)
        let exempt_key = Pubkey::new_unique();
        let exempt_account = Account::new(10_000_000, vec![0u8; 100], Pubkey::default());
        db.store(&exempt_key, &exempt_account);

        // Non-exempt account (too few lamports for its data size)
        let non_exempt_key = Pubkey::new_unique();
        let non_exempt_account = Account::new(100, vec![0u8; 1000], Pubkey::default());
        db.store(&non_exempt_key, &non_exempt_account);

        // Zero-data account (always exempt)
        let zero_data_key = Pubkey::new_unique();
        let zero_data_account = Account::new(1, vec![], Pubkey::default());
        db.store(&zero_data_key, &zero_data_account);

        bank
    }

    #[test]
    fn collect_rent_identifies_exempt_accounts() {
        let bank = create_test_bank_with_accounts();
        let result = bank.collect_rent();

        assert_eq!(result.accounts_examined, 3);
        // At least one account should be exempt
        assert!(result.exempt_accounts >= 1);
    }

    #[test]
    fn collect_rent_charges_non_exempt_accounts() {
        let bank = create_test_bank_with_accounts();
        let result = bank.collect_rent();

        // The non-exempt account (100 lamports, 1000 bytes data) should pay
        assert!(result.rent_paying_accounts >= 1);
        assert!(result.total_rent_collected > 0);
    }

    #[test]
    fn collect_rent_burns_portion() {
        let bank = create_test_bank_with_accounts();
        let result = bank.collect_rent();

        if result.total_rent_collected > 0 {
            assert!(result.rent_burned > 0);
            assert!(result.rent_burned <= result.total_rent_collected);
        }
    }

    #[test]
    fn collect_rent_does_not_exceed_balance() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // Account with very little balance
        let key = Pubkey::new_unique();
        let account = Account::new(10, vec![0u8; 10_000], Pubkey::default());
        bank.accounts().store(&key, &account);

        let result = bank.collect_rent();

        // Rent should not exceed the account's 10 lamports
        assert!(result.total_rent_collected <= 10);

        // Check the account's remaining balance
        let updated = bank.accounts().get(&key).unwrap();
        assert!(updated.meta.lamports <= 10);
    }

    #[test]
    fn finish_slot_runs_without_error() {
        let bank = create_test_bank_with_accounts();

        let stake_tracker = StakeTracker::new(0);
        let mut stake_history = StakeHistory::new();

        let result = bank.finish_slot(&stake_tracker, &mut stake_history);
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.slot, 0);
        assert!(!summary.is_epoch_boundary); // Genesis is not epoch boundary
    }

    #[test]
    fn finish_slot_rejects_frozen_bank() {
        let bank = create_test_bank_with_accounts();

        // Fill ticks and freeze
        use paradencer_constants::ledger::TICKS_PER_SLOT;
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        let stake_tracker = StakeTracker::new(0);
        let mut stake_history = StakeHistory::new();

        let result = bank.finish_slot(&stake_tracker, &mut stake_history);
        assert!(result.is_err());
    }

    #[test]
    fn finish_slot_collects_fees_and_rent() {
        let bank = create_test_bank_with_accounts();

        // Add some fees
        bank.add_execution_fee(5000);
        bank.add_priority_fee(3000);

        let stake_tracker = StakeTracker::new(0);
        let mut stake_history = StakeHistory::new();

        let result = bank
            .finish_slot(&stake_tracker, &mut stake_history)
            .unwrap();

        // Fees should be distributed
        let (leader_share, burn_share) = result.fees;
        assert!(leader_share + burn_share > 0);

        // Rent should be collected
        assert!(result.rent.accounts_examined > 0);
    }
}
