/// Rent configuration, collection, and epoch-level rent processing.
///
/// Accounts must maintain a minimum balance to avoid rent collection.
/// The minimum balance is calculated based on account data size and rent parameters.
use paradencer_constants::economics::{
    DEFAULT_EXEMPTION_THRESHOLD, DEFAULT_LAMPORTS_PER_BYTE_YEAR, DEFAULT_SLOTS_PER_YEAR,
};

use serde::{Deserialize, Serialize};

use crate::EpochSchedule;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rent {
    /// Annual rent cost per byte in lamports
    pub lamports_per_byte_year: u64,
    /// Threshold multiplier for rent exemption (typically 2.0 for 2 years of rent)
    pub exemption_threshold: f64,
    /// Percentage of collected rent to burn (rest goes to validators)
    pub burn_percent: u8,
}

impl Rent {
    pub fn default_config() -> Self {
        Self {
            lamports_per_byte_year: DEFAULT_LAMPORTS_PER_BYTE_YEAR,
            exemption_threshold: DEFAULT_EXEMPTION_THRESHOLD,
            burn_percent: 50,
        }
    }

    /// Calculate minimum balance required for an account to be rent-exempt.
    ///
    /// Returns the minimum lamports needed based on data size.
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        let base_cost = self.lamports_per_byte_year.saturating_mul(data_len as u64);
        (base_cost as f64 * self.exemption_threshold) as u64
    }

    /// Check if account is rent exempt
    pub fn is_exempt(&self, lamports: u64, data_len: usize) -> bool {
        lamports >= self.minimum_balance(data_len)
    }

    /// Calculate rent due for an account
    /// Returns (rent_due, is_exempt)
    pub fn calculate_due(
        &self,
        lamports: u64,
        data_len: usize,
        epochs_elapsed: u64,
    ) -> (u64, bool) {
        if self.is_exempt(lamports, data_len) {
            return (0, true);
        }

        // Calculate rent for the elapsed epochs
        let rent_per_epoch = self.lamports_per_byte_year.saturating_mul(data_len as u64) / 365; // Approximate
        let total_rent = rent_per_epoch.saturating_mul(epochs_elapsed);

        // Don't charge more than the account balance
        let rent_due = total_rent.min(lamports);

        (rent_due, false)
    }
}

impl Default for Rent {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Result of rent calculation for a single account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RentDue {
    /// Account has sufficient balance for rent exemption; no rent due.
    Exempt,
    /// Account owes the specified amount in lamports.
    Paying(u64),
}

impl RentDue {
    /// Get the lamports due, or 0 if exempt.
    pub fn lamports(&self) -> u64 {
        match self {
            RentDue::Exempt => 0,
            RentDue::Paying(amount) => *amount,
        }
    }

    /// Whether the account is exempt from rent.
    pub fn is_exempt(&self) -> bool {
        matches!(self, RentDue::Exempt)
    }
}

/// Summary of rent collected from a single account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedRent {
    /// Lamports collected as rent
    pub rent_collected: u64,
    /// Size of account data in bytes
    pub account_data_len: usize,
    /// Whether the account was rent-exempt
    pub is_exempt: bool,
}

/// Collects rent from accounts at epoch boundaries.
///
/// At each epoch boundary, accounts that are not rent-exempt have rent deducted
/// from their balance. Accounts that drop to zero lamports are garbage collected.
/// The rent amount depends on account size, epoch duration, and current rent parameters.
#[derive(Debug, Clone)]
pub struct RentCollector {
    /// Current epoch
    pub epoch: u64,
    /// Schedule used to determine epoch boundaries
    pub epoch_schedule: EpochSchedule,
    /// Approximate number of slots per year for annualization
    pub slots_per_year: f64,
    /// Rent configuration parameters
    pub rent: Rent,
}

impl RentCollector {
    /// Create a new rent collector for the given epoch.
    pub fn new(epoch: u64, epoch_schedule: EpochSchedule, slots_per_year: f64, rent: Rent) -> Self {
        Self {
            epoch,
            epoch_schedule,
            slots_per_year,
            rent,
        }
    }

    /// Create a rent collector with default parameters.
    pub fn default_for_epoch(epoch: u64) -> Self {
        Self {
            epoch,
            epoch_schedule: EpochSchedule::default(),
            slots_per_year: DEFAULT_SLOTS_PER_YEAR,
            rent: Rent::default(),
        }
    }

    /// Determine whether an account owes rent and how much.
    ///
    /// Returns `RentDue::Exempt` if the account's balance meets or exceeds
    /// the minimum balance for its data size. Otherwise returns
    /// `RentDue::Paying(amount)` with the number of lamports due for one epoch.
    pub fn calculate_rent_due(&self, lamports: u64, data_len: usize) -> RentDue {
        if self.rent.is_exempt(lamports, data_len) {
            return RentDue::Exempt;
        }

        // Calculate rent for one epoch based on data size and epoch duration
        let slots_in_epoch = self.epoch_schedule.get_slots_in_epoch(self.epoch) as f64;
        let years_per_epoch = slots_in_epoch / self.slots_per_year;

        let annual_rent = self
            .rent
            .lamports_per_byte_year
            .saturating_mul(data_len as u64);
        let rent_due = (annual_rent as f64 * years_per_epoch) as u64;

        // Never charge more than the account holds
        let capped = rent_due.min(lamports);

        if capped == 0 {
            RentDue::Exempt
        } else {
            RentDue::Paying(capped)
        }
    }

    /// Collect rent from an account and return a summary.
    ///
    /// Calculates how much rent is due, caps it at the account balance,
    /// and returns the collection result. The caller is responsible for
    /// actually deducting lamports from the account.
    pub fn collect_from_account(&self, lamports: u64, data_len: usize) -> CollectedRent {
        match self.calculate_rent_due(lamports, data_len) {
            RentDue::Exempt => CollectedRent {
                rent_collected: 0,
                account_data_len: data_len,
                is_exempt: true,
            },
            RentDue::Paying(amount) => CollectedRent {
                rent_collected: amount,
                account_data_len: data_len,
                is_exempt: false,
            },
        }
    }

    /// Check whether an account with the given balance and data size is rent-exempt.
    pub fn is_exempt(&self, lamports: u64, data_len: usize) -> bool {
        self.rent.is_exempt(lamports, data_len)
    }

    /// Get the minimum balance required for rent exemption at the given data size.
    pub fn minimum_balance(&self, data_len: usize) -> u64 {
        self.rent.minimum_balance(data_len)
    }

    /// Advance to the next epoch.
    pub fn advance_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rent_calculates_minimum_balance() {
        let rent = Rent::default_config();

        // 100 bytes * 3480 lamports/byte/year * 2.0 threshold
        let min_balance = rent.minimum_balance(100);
        assert_eq!(min_balance, 696_000);
    }

    #[test]
    fn rent_exemption_check() {
        let rent = Rent::default_config();

        assert!(rent.is_exempt(696_000, 100));
        assert!(rent.is_exempt(700_000, 100));
        assert!(!rent.is_exempt(600_000, 100));
    }

    #[test]
    fn rent_calculates_due_for_exempt_account() {
        let rent = Rent::default_config();
        let (due, exempt) = rent.calculate_due(1_000_000, 100, 10);

        assert_eq!(due, 0);
        assert!(exempt);
    }

    #[test]
    fn rent_calculates_due_for_non_exempt_account() {
        let rent = Rent::default_config();
        let (due, exempt) = rent.calculate_due(100_000, 100, 1);

        assert!(due > 0);
        assert!(!exempt);
    }

    #[test]
    fn rent_does_not_exceed_balance() {
        let rent = Rent::default_config();
        let balance = 1_000;
        let (due, _) = rent.calculate_due(balance, 100, 1000);

        assert!(due <= balance);
    }

    // RentDue tests

    #[test]
    fn rent_due_exempt_returns_zero_lamports() {
        let due = RentDue::Exempt;
        assert_eq!(due.lamports(), 0);
        assert!(due.is_exempt());
    }

    #[test]
    fn rent_due_paying_returns_amount() {
        let due = RentDue::Paying(5000);
        assert_eq!(due.lamports(), 5000);
        assert!(!due.is_exempt());
    }

    // RentCollector tests

    #[test]
    fn rent_collector_identifies_exempt_accounts() {
        let collector = RentCollector::default_for_epoch(0);
        let min_balance = collector.minimum_balance(100);

        assert!(collector.is_exempt(min_balance, 100));
        assert!(collector.is_exempt(min_balance + 1, 100));
        assert!(!collector.is_exempt(min_balance - 1, 100));
    }

    #[test]
    fn rent_collector_calculates_rent_for_non_exempt() {
        let collector = RentCollector::default_for_epoch(0);

        // Account well below exemption threshold
        let result = collector.calculate_rent_due(1000, 100);
        match result {
            RentDue::Paying(amount) => {
                assert!(amount > 0);
                assert!(amount <= 1000); // Cannot exceed balance
            }
            RentDue::Exempt => panic!("Expected rent due, got exempt"),
        }
    }

    #[test]
    fn rent_collector_exempt_accounts_pay_nothing() {
        let collector = RentCollector::default_for_epoch(0);
        let min_balance = collector.minimum_balance(100);

        let result = collector.calculate_rent_due(min_balance, 100);
        assert!(result.is_exempt());
        assert_eq!(result.lamports(), 0);
    }

    #[test]
    fn rent_collector_collects_from_account() {
        let collector = RentCollector::default_for_epoch(0);

        // Non-exempt account
        let collected = collector.collect_from_account(1000, 100);
        assert!(!collected.is_exempt);
        assert!(collected.rent_collected > 0);
        assert_eq!(collected.account_data_len, 100);

        // Exempt account
        let min_bal = collector.minimum_balance(100);
        let collected = collector.collect_from_account(min_bal, 100);
        assert!(collected.is_exempt);
        assert_eq!(collected.rent_collected, 0);
    }

    #[test]
    fn rent_collector_advances_epoch() {
        let mut collector = RentCollector::default_for_epoch(5);
        assert_eq!(collector.epoch, 5);

        collector.advance_epoch();
        assert_eq!(collector.epoch, 6);
    }

    #[test]
    fn rent_collector_zero_data_accounts_are_exempt() {
        let collector = RentCollector::default_for_epoch(0);

        // Zero-length data accounts should be exempt even with 0 lamports
        let result = collector.calculate_rent_due(0, 0);
        assert!(result.is_exempt());
    }

    #[test]
    fn rent_collector_caps_rent_at_balance() {
        let collector = RentCollector::default_for_epoch(0);

        // Very small balance, large data -- rent should be capped
        let result = collector.calculate_rent_due(10, 10_000);
        assert_eq!(result.lamports(), 10);
    }
}
