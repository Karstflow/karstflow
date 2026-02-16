/// Fee calculation, rate governance, and collection for transactions.
///
/// Manages transaction fee rates based on network congestion and economic policy.
/// Fees serve multiple purposes:
/// - Spam prevention (economic cost to submit transactions)
/// - Network sustainability (validator compensation)
/// - Economic burn (deflationary pressure via fee burning)
use paradencer_constants::economics::*;

/// Simple fee calculator based on lamports per signature.
///
/// Associates a blockhash with a specific fee rate. When users create transactions,
/// they reference a recent blockhash, which locks in the fee rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeCalculator {
    /// Cost in lamports for each signature on a transaction
    pub lamports_per_signature: u64,
}

impl FeeCalculator {
    /// Create a new fee calculator with specified rate.
    pub fn new(lamports_per_signature: u64) -> Self {
        Self {
            lamports_per_signature,
        }
    }

    /// Calculate total fee for a transaction with given signature count.
    pub fn calculate_fee(&self, num_signatures: u64) -> u64 {
        self.lamports_per_signature.saturating_mul(num_signatures)
    }

    /// Check if an account has sufficient balance to pay fee.
    pub fn can_pay_fee(&self, balance: u64, num_signatures: u64) -> bool {
        let fee = self.calculate_fee(num_signatures);
        balance >= fee
    }
}

impl Default for FeeCalculator {
    fn default() -> Self {
        Self::new(LAMPORTS_PER_SIGNATURE)
    }
}

/// Governs fee rate adjustments based on network congestion.
///
/// Implements dynamic fee adjustment:
/// - Fees increase when network is congested (high signature count)
/// - Fees decrease when network is underutilized (low signature count)
/// - Bounded by min/max limits to prevent extreme values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRateGovernor {
    /// Target fee rate (lamports per signature)
    pub target_lamports_per_signature: u64,
    /// Target number of signatures per slot for equilibrium
    pub target_signatures_per_slot: u64,
    /// Minimum allowed fee rate
    pub min_lamports_per_signature: u64,
    /// Maximum allowed fee rate
    pub max_lamports_per_signature: u64,
    /// Percentage of fees to burn (0-100)
    pub burn_percent: u8,
}

impl FeeRateGovernor {
    /// Create a new fee rate governor with custom parameters.
    pub fn new(
        target_lamports_per_signature: u64,
        target_signatures_per_slot: u64,
        min_lamports_per_signature: u64,
        max_lamports_per_signature: u64,
        burn_percent: u8,
    ) -> Self {
        Self {
            target_lamports_per_signature,
            target_signatures_per_slot,
            min_lamports_per_signature,
            max_lamports_per_signature,
            burn_percent: burn_percent.min(100), // Cap at 100%
        }
    }

    /// Create fee calculator based on current slot signature count.
    ///
    /// Adjusts fees based on congestion:
    /// - If signatures > target: increase fees
    /// - If signatures < target: decrease fees
    pub fn create_fee_calculator(&self, signatures_in_slot: u64) -> FeeCalculator {
        let lamports_per_signature = if signatures_in_slot == 0 {
            // No signatures, use target rate
            self.target_lamports_per_signature
        } else if signatures_in_slot < self.target_signatures_per_slot {
            // Under target, decrease fees proportionally
            let ratio = signatures_in_slot as f64 / self.target_signatures_per_slot as f64;
            let adjusted = (self.target_lamports_per_signature as f64 * ratio) as u64;
            adjusted.max(self.min_lamports_per_signature)
        } else if signatures_in_slot > self.target_signatures_per_slot {
            // Over target, increase fees proportionally
            let ratio = signatures_in_slot as f64 / self.target_signatures_per_slot as f64;
            let adjusted = (self.target_lamports_per_signature as f64 * ratio) as u64;
            adjusted.min(self.max_lamports_per_signature)
        } else {
            // At target, use target rate
            self.target_lamports_per_signature
        };

        FeeCalculator::new(lamports_per_signature)
    }

    /// Calculate how much of a fee should be burned vs collected.
    ///
    /// Returns (burned_amount, collected_amount).
    pub fn split_fee(&self, total_fee: u64) -> (u64, u64) {
        let burned = (total_fee as u128)
            .saturating_mul(self.burn_percent as u128)
            .wrapping_div(100)
            .min(total_fee as u128) as u64;

        let collected = total_fee.saturating_sub(burned);

        (burned, collected)
    }

    /// Get the percentage of fees that are collected (not burned).
    pub fn collect_percent(&self) -> u8 {
        100u8.saturating_sub(self.burn_percent)
    }
}

impl Default for FeeRateGovernor {
    fn default() -> Self {
        Self::new(
            LAMPORTS_PER_SIGNATURE,
            DEFAULT_TARGET_SIGNATURES_PER_SLOT,
            MIN_LAMPORTS_PER_SIGNATURE,
            MAX_LAMPORTS_PER_SIGNATURE,
            DEFAULT_FEE_BURN_PERCENT,
        )
    }
}

/// Accumulates transaction fees collected during a slot and tracks distribution.
///
/// Separates execution fees (subject to burning) from priority fees (fully
/// distributed to the leader). At slot boundary, fees are split between the
/// slot leader and the burn account according to protocol rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeCollector {
    /// Total execution fees collected this slot
    pub total_fees: u64,
    /// Total lamports burned from execution fees
    pub total_burned: u64,
    /// Total lamports distributed to the slot leader
    pub leader_rewards: u64,
}

impl FeeCollector {
    /// Create a new fee collector with zero balances.
    pub fn new() -> Self {
        Self {
            total_fees: 0,
            total_burned: 0,
            leader_rewards: 0,
        }
    }

    /// Record a fee payment from a processed transaction.
    ///
    /// The fee is added to the running total. Distribution happens
    /// when `distribute` is called at the end of the slot.
    pub fn collect_fee(&mut self, fee: u64) {
        self.total_fees = self.total_fees.saturating_add(fee);
    }

    /// Calculate how fees should be split between leader and burn.
    ///
    /// Returns (leader_share, burn_share). The leader receives
    /// `FEE_LEADER_SHARE_PERCENT` of collected fees; the remainder is burned
    /// to reduce total supply.
    pub fn distribute(&self) -> (u64, u64) {
        let burn_share = self
            .total_fees
            .saturating_mul(FEE_BURN_PERCENT)
            .checked_div(100)
            .unwrap_or(0);

        let leader_share = self.total_fees.saturating_sub(burn_share);

        (leader_share, burn_share)
    }

    /// Finalize distribution: compute shares, record them, and return amounts.
    ///
    /// After calling this, `total_burned` and `leader_rewards` reflect the
    /// actual distribution. Returns (leader_share, burn_share).
    pub fn finalize(&mut self) -> (u64, u64) {
        let (leader_share, burn_share) = self.distribute();
        self.leader_rewards = self.leader_rewards.saturating_add(leader_share);
        self.total_burned = self.total_burned.saturating_add(burn_share);
        (leader_share, burn_share)
    }

    /// Reset collector state for a new slot.
    pub fn reset(&mut self) {
        self.total_fees = 0;
        self.total_burned = 0;
        self.leader_rewards = 0;
    }

    /// Check if any fees have been collected.
    pub fn has_fees(&self) -> bool {
        self.total_fees > 0
    }
}

impl Default for FeeCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_calculator_creates_with_rate() {
        let calc = FeeCalculator::new(5000);
        assert_eq!(calc.lamports_per_signature, 5000);
    }

    #[test]
    fn fee_calculator_calculates_single_signature() {
        let calc = FeeCalculator::new(5000);
        let fee = calc.calculate_fee(1);
        assert_eq!(fee, 5000);
    }

    #[test]
    fn fee_calculator_calculates_multiple_signatures() {
        let calc = FeeCalculator::new(5000);
        let fee = calc.calculate_fee(3);
        assert_eq!(fee, 15000); // 3 * 5000
    }

    #[test]
    fn fee_calculator_checks_sufficient_balance() {
        let calc = FeeCalculator::new(5000);

        assert!(calc.can_pay_fee(10000, 1)); // 10000 >= 5000
        assert!(calc.can_pay_fee(5000, 1)); // 5000 >= 5000 (exact)
        assert!(!calc.can_pay_fee(4999, 1)); // 4999 < 5000
    }

    #[test]
    fn fee_calculator_default_uses_standard_rate() {
        let calc = FeeCalculator::default();
        assert_eq!(calc.lamports_per_signature, LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn fee_rate_governor_creates_with_params() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 100000, 50);

        assert_eq!(governor.target_lamports_per_signature, 5000);
        assert_eq!(governor.target_signatures_per_slot, 20000);
        assert_eq!(governor.min_lamports_per_signature, 0);
        assert_eq!(governor.max_lamports_per_signature, 100000);
        assert_eq!(governor.burn_percent, 50);
    }

    #[test]
    fn fee_rate_governor_caps_burn_percent() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 100000, 150);
        assert_eq!(governor.burn_percent, 100); // Capped at 100%
    }

    #[test]
    fn fee_rate_governor_creates_calculator_at_target() {
        let governor = FeeRateGovernor::default();

        let calc = governor.create_fee_calculator(DEFAULT_TARGET_SIGNATURES_PER_SLOT);

        assert_eq!(calc.lamports_per_signature, LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn fee_rate_governor_decreases_fee_when_underutilized() {
        let governor = FeeRateGovernor::default();

        // Half the target signatures
        let calc = governor.create_fee_calculator(DEFAULT_TARGET_SIGNATURES_PER_SLOT / 2);

        // Fee should be lower than target
        assert!(calc.lamports_per_signature < LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn fee_rate_governor_increases_fee_when_congested() {
        let governor = FeeRateGovernor::default();

        // Double the target signatures
        let calc = governor.create_fee_calculator(DEFAULT_TARGET_SIGNATURES_PER_SLOT * 2);

        // Fee should be higher than target
        assert!(calc.lamports_per_signature > LAMPORTS_PER_SIGNATURE);
    }

    #[test]
    fn fee_rate_governor_respects_minimum() {
        let governor = FeeRateGovernor::new(5000, 20000, 1000, 100000, 50);

        // Very low signature count
        let calc = governor.create_fee_calculator(1);

        // Should not go below minimum
        assert!(calc.lamports_per_signature >= governor.min_lamports_per_signature);
    }

    #[test]
    fn fee_rate_governor_respects_maximum() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 10000, 50);

        // Very high signature count
        let calc = governor.create_fee_calculator(1_000_000);

        // Should not exceed maximum
        assert!(calc.lamports_per_signature <= governor.max_lamports_per_signature);
    }

    #[test]
    fn fee_rate_governor_splits_fee_with_50_percent_burn() {
        let governor = FeeRateGovernor::default(); // 50% burn

        let (burned, collected) = governor.split_fee(10000);

        assert_eq!(burned, 5000); // 50% burned
        assert_eq!(collected, 5000); // 50% collected
        assert_eq!(burned + collected, 10000); // Total matches
    }

    #[test]
    fn fee_rate_governor_splits_fee_with_100_percent_burn() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 100000, 100);

        let (burned, collected) = governor.split_fee(10000);

        assert_eq!(burned, 10000); // 100% burned
        assert_eq!(collected, 0); // 0% collected
    }

    #[test]
    fn fee_rate_governor_splits_fee_with_zero_burn() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 100000, 0);

        let (burned, collected) = governor.split_fee(10000);

        assert_eq!(burned, 0); // 0% burned
        assert_eq!(collected, 10000); // 100% collected
    }

    #[test]
    fn fee_rate_governor_calculates_collect_percent() {
        let governor = FeeRateGovernor::new(5000, 20000, 0, 100000, 30);

        assert_eq!(governor.collect_percent(), 70); // 100 - 30
    }

    #[test]
    fn fee_rate_governor_handles_zero_signatures() {
        let governor = FeeRateGovernor::default();

        let calc = governor.create_fee_calculator(0);

        // Should use target rate when no signatures
        assert_eq!(
            calc.lamports_per_signature,
            governor.target_lamports_per_signature
        );
    }

    // FeeCollector tests

    #[test]
    fn fee_collector_starts_empty() {
        let collector = FeeCollector::new();
        assert_eq!(collector.total_fees, 0);
        assert_eq!(collector.total_burned, 0);
        assert_eq!(collector.leader_rewards, 0);
        assert!(!collector.has_fees());
    }

    #[test]
    fn fee_collector_accumulates_fees() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(1000);
        collector.collect_fee(2000);
        collector.collect_fee(500);

        assert_eq!(collector.total_fees, 3500);
        assert!(collector.has_fees());
    }

    #[test]
    fn fee_collector_distributes_evenly_at_50_percent() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(10000);

        let (leader, burned) = collector.distribute();
        assert_eq!(leader, 5000);
        assert_eq!(burned, 5000);
        assert_eq!(leader + burned, 10000);
    }

    #[test]
    fn fee_collector_handles_odd_amounts() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(101);

        let (leader, burned) = collector.distribute();
        // 101 * 50 / 100 = 50 burned, 51 to leader
        assert_eq!(burned, 50);
        assert_eq!(leader, 51);
        assert_eq!(leader + burned, 101);
    }

    #[test]
    fn fee_collector_finalize_records_distribution() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(10000);

        let (leader, burned) = collector.finalize();
        assert_eq!(leader, 5000);
        assert_eq!(burned, 5000);
        assert_eq!(collector.leader_rewards, 5000);
        assert_eq!(collector.total_burned, 5000);
    }

    #[test]
    fn fee_collector_resets_to_zero() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(10000);
        collector.finalize();

        collector.reset();

        assert_eq!(collector.total_fees, 0);
        assert_eq!(collector.total_burned, 0);
        assert_eq!(collector.leader_rewards, 0);
        assert!(!collector.has_fees());
    }

    #[test]
    fn fee_collector_handles_zero_fees() {
        let collector = FeeCollector::new();
        let (leader, burned) = collector.distribute();
        assert_eq!(leader, 0);
        assert_eq!(burned, 0);
    }

    #[test]
    fn fee_collector_handles_large_amounts() {
        let mut collector = FeeCollector::new();
        collector.collect_fee(u64::MAX / 2);
        collector.collect_fee(u64::MAX / 2);

        // Should saturate, not overflow
        let (leader, burned) = collector.distribute();
        assert!(leader > 0);
        assert!(burned > 0);
    }
}
