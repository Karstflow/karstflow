/// Inflation configuration for epoch rewards distribution.
///
/// Controls how new tokens are minted and distributed to validators and foundation
/// over time, with decreasing inflation rates.
use karstflow_constants::economics::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Inflation {
    /// Starting inflation rate when network launches
    pub initial_rate: f64,
    /// Minimum inflation rate (floor that inflation cannot go below)
    pub terminal_rate: f64,
    /// Annual reduction factor for inflation rate
    pub tapering_rate: f64,
    /// Portion of inflation allocated to foundation
    pub foundation_portion: f64,
    /// Duration in years for foundation rewards
    pub foundation_duration_years: f64,
}

impl Inflation {
    pub fn default_config() -> Self {
        Self {
            initial_rate: INFLATION_INITIAL_RATE,
            terminal_rate: INFLATION_TERMINAL_RATE,
            tapering_rate: INFLATION_TAPER_RATE,
            foundation_portion: INFLATION_FOUNDATION_RATE,
            foundation_duration_years: INFLATION_FOUNDATION_TERM,
        }
    }

    /// Calculate total inflation rate for a given year.
    ///
    /// Inflation starts at initial_rate and decreases each year by tapering_rate
    /// until it reaches terminal_rate floor.
    pub fn total_rate(&self, year: f64) -> f64 {
        if year == 0.0 {
            return self.initial_rate;
        }

        let tapered = self.initial_rate * (1.0 - self.tapering_rate).powf(year);
        if tapered > self.terminal_rate {
            tapered
        } else {
            self.terminal_rate
        }
    }

    /// Calculate foundation's share of inflation for a given year.
    ///
    /// Foundation receives a portion of total inflation for a limited duration,
    /// after which it receives nothing.
    pub fn foundation_rate(&self, year: f64) -> f64 {
        if year < self.foundation_duration_years {
            self.foundation_portion * self.total_rate(year)
        } else {
            0.0
        }
    }

    /// Calculate validators' share of inflation for a given year.
    ///
    /// Validators receive the remainder after foundation allocation.
    pub fn validator_rate(&self, year: f64) -> f64 {
        self.total_rate(year) - self.foundation_rate(year)
    }
}

impl Default for Inflation {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflation_total_rate_decreases_with_taper() {
        let inflation = Inflation::default_config();

        let rate_year_0 = inflation.total_rate(0.0);
        let rate_year_1 = inflation.total_rate(1.0);
        let rate_year_2 = inflation.total_rate(2.0);

        assert_eq!(rate_year_0, inflation.initial_rate);
        assert!(rate_year_1 < rate_year_0);
        assert!(rate_year_2 < rate_year_1);
    }

    #[test]
    fn inflation_total_rate_floors_at_terminal() {
        let inflation = Inflation::default_config();

        // After many years, should reach terminal rate
        let rate_year_100 = inflation.total_rate(100.0);
        assert!((rate_year_100 - inflation.terminal_rate).abs() < 0.0001);
    }

    #[test]
    fn inflation_foundation_rate_expires() {
        let inflation = Inflation::default_config();

        let before_term = inflation.foundation_rate(inflation.foundation_duration_years - 1.0);
        let after_term = inflation.foundation_rate(inflation.foundation_duration_years + 1.0);

        assert!(before_term > 0.0);
        assert_eq!(after_term, 0.0);
    }

    #[test]
    fn inflation_validator_rate_is_remainder() {
        let inflation = Inflation::default_config();

        let year = 2.0;
        let total = inflation.total_rate(year);
        let foundation = inflation.foundation_rate(year);
        let validator = inflation.validator_rate(year);

        assert!((total - (foundation + validator)).abs() < 0.00001);
    }
}
