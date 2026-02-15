/// Rent configuration and collection logic.
///
/// Accounts must maintain a minimum balance to avoid rent collection.
/// The minimum balance is calculated based on account data size and rent parameters.

#[derive(Debug, Clone, Copy, PartialEq)]
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
            lamports_per_byte_year: 3_480,
            exemption_threshold: 2.0,
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
}
