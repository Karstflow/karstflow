/// Epoch rewards calculation for validator compensation.
///
/// This module calculates staking rewards distributed to validators and
/// their delegators at epoch boundaries. Rewards are based on:
/// - Total network capitalization (circulating supply)
/// - Inflation rate for the current epoch
/// - Validator performance (vote credits earned)
/// - Stake weight (amount delegated to validator)
use crate::Inflation;

/// Lamports per SOL constant.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Number of blocks used for reward calculation and vote account updates.
/// Stake account distribution begins after this many blocks.
pub const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

/// Number of stake accounts to store per block during partitioned distribution.
/// Target: 64 rewards per entry/tick, with minimum 64 entries per block = 4096 total.
pub const STAKE_ACCOUNTS_PER_BLOCK: usize = 4096;

/// Maximum factor of reward blocks relative to epoch length.
pub const MAX_REWARD_BLOCKS_FACTOR: u64 = 10;

/// Calculates total validator rewards for an epoch.
///
/// This is the foundation for rewards distribution. The total amount is then
/// split among validators based on their performance (vote credits) and stake weight.
pub fn calculate_epoch_rewards(
    capitalization: u64,
    inflation: &Inflation,
    epoch: u64,
    slots_in_epoch: u64,
) -> EpochRewards {
    // Calculate epoch duration in years
    // Assumes ~2.5 slots per second (Solana mainnet target)
    const SLOTS_PER_SECOND: f64 = 2.5;
    const SECONDS_PER_YEAR: f64 = 365.25 * 24.0 * 60.0 * 60.0;

    let epoch_duration_years = (slots_in_epoch as f64) / (SLOTS_PER_SECOND * SECONDS_PER_YEAR);

    // Get inflation rates for this epoch
    // Convert epoch to approximate year (assuming 2 epochs per day)
    let year = (epoch as f64) / 730.0;

    let total_rate = inflation.total_rate(year);
    let validator_rate = inflation.validator_rate(year);
    let foundation_rate = inflation.foundation_rate(year);

    // Calculate total inflation for the epoch
    let total_inflation = (capitalization as f64 * total_rate * epoch_duration_years) as u64;

    // Split between validators and foundation
    let validator_rewards = (capitalization as f64 * validator_rate * epoch_duration_years) as u64;
    let foundation_rewards = total_inflation.saturating_sub(validator_rewards);

    EpochRewards {
        total_rewards: total_inflation,
        validator_rewards,
        foundation_rewards,
        capitalization,
        epoch_duration_years,
        validator_rate,
        foundation_rate,
    }
}

/// Calculate number of blocks needed for partitioned reward distribution.
///
/// Returns the number of slots over which stake account rewards will be distributed.
/// Limited by MAX_REWARD_BLOCKS_FACTOR to prevent rewards taking too long.
pub fn calculate_reward_blocks(num_stake_accounts: usize, slots_in_epoch: u64) -> u64 {
    if num_stake_accounts == 0 {
        return 0;
    }

    // Calculate partitions needed (round up division)
    let num_partitions =
        (num_stake_accounts + STAKE_ACCOUNTS_PER_BLOCK - 1) / STAKE_ACCOUNTS_PER_BLOCK;

    // Add calculation block + distribution blocks
    let total_blocks = REWARD_CALCULATION_NUM_BLOCKS + num_partitions as u64;

    // Limit to fraction of epoch
    let max_blocks = slots_in_epoch / MAX_REWARD_BLOCKS_FACTOR;
    total_blocks.min(max_blocks)
}

/// Summary of epoch rewards calculation.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochRewards {
    /// Total rewards minted this epoch (inflation)
    pub total_rewards: u64,
    /// Portion allocated to validators and delegators
    pub validator_rewards: u64,
    /// Portion allocated to foundation
    pub foundation_rewards: u64,
    /// Total network capitalization used for calculation
    pub capitalization: u64,
    /// Duration of epoch in years (for rate calculation)
    pub epoch_duration_years: f64,
    /// Validator inflation rate applied
    pub validator_rate: f64,
    /// Foundation inflation rate applied
    pub foundation_rate: f64,
}

impl EpochRewards {
    /// Create a zero rewards structure (for genesis or no inflation).
    pub fn zero(capitalization: u64) -> Self {
        Self {
            total_rewards: 0,
            validator_rewards: 0,
            foundation_rewards: 0,
            capitalization,
            epoch_duration_years: 0.0,
            validator_rate: 0.0,
            foundation_rate: 0.0,
        }
    }
}

/// Calculate stake points for a validator delegation.
///
/// Points represent the weighted contribution of stake over time.
/// More credits earned = more points = higher reward share.
pub fn calculate_stake_points(stake_amount: u64, credits_earned: u64, total_credits: u64) -> u128 {
    if total_credits == 0 {
        return 0;
    }

    // Points = stake * (credits_earned / total_credits)
    // Use u128 to avoid overflow
    let stake = stake_amount as u128;
    let credits = credits_earned as u128;
    let total = total_credits as u128;

    (stake * credits) / total
}

/// Calculate reward for a stake account based on points.
///
/// Distributes total validator rewards proportionally to stake points.
pub fn calculate_stake_reward(
    stake_points: u128,
    total_points: u128,
    total_validator_rewards: u64,
) -> u64 {
    if total_points == 0 {
        return 0;
    }

    let rewards = total_validator_rewards as u128;
    let reward = (stake_points * rewards) / total_points;

    // Cap at u64::MAX (shouldn't happen in practice)
    reward.min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewards_calculates_epoch_total() {
        let inflation = Inflation::default_config();
        let capitalization = 1_000_000 * LAMPORTS_PER_SOL; // 1M SOL
        let slots_in_epoch = 432_000; // 2 days at 2.5 slots/sec

        let rewards = calculate_epoch_rewards(capitalization, &inflation, 0, slots_in_epoch);

        // Should have non-zero rewards
        assert!(rewards.total_rewards > 0);
        assert!(rewards.validator_rewards > 0);

        // Total should equal validator + foundation
        assert_eq!(
            rewards.total_rewards,
            rewards.validator_rewards + rewards.foundation_rewards
        );
    }

    #[test]
    fn rewards_split_matches_inflation_config() {
        let inflation = Inflation::default_config();
        let capitalization = 1_000_000 * LAMPORTS_PER_SOL;
        let slots_in_epoch = 432_000;

        let rewards = calculate_epoch_rewards(capitalization, &inflation, 0, slots_in_epoch);

        // Validator rate should be higher than foundation (typical config)
        assert!(rewards.validator_rate > rewards.foundation_rate);

        // Foundation should get smaller portion
        assert!(rewards.foundation_rewards < rewards.validator_rewards);
    }

    #[test]
    fn rewards_decrease_over_time() {
        let inflation = Inflation::default_config();
        let capitalization = 1_000_000 * LAMPORTS_PER_SOL;
        let slots_in_epoch = 432_000;

        // Epoch 0 (year 0)
        let rewards_year_0 = calculate_epoch_rewards(capitalization, &inflation, 0, slots_in_epoch);

        // Epoch 730 (year 1, ~2 epochs per day)
        let rewards_year_1 =
            calculate_epoch_rewards(capitalization, &inflation, 730, slots_in_epoch);

        // Rewards should decrease due to tapering
        assert!(rewards_year_1.total_rewards < rewards_year_0.total_rewards);
    }

    #[test]
    fn rewards_handles_zero_capitalization() {
        let inflation = Inflation::default_config();
        let capitalization = 0;
        let slots_in_epoch = 432_000;

        let rewards = calculate_epoch_rewards(capitalization, &inflation, 0, slots_in_epoch);

        assert_eq!(rewards.total_rewards, 0);
        assert_eq!(rewards.validator_rewards, 0);
        assert_eq!(rewards.foundation_rewards, 0);
    }

    #[test]
    fn reward_blocks_calculates_partitions() {
        let slots_in_epoch = 432_000;

        // Small number of accounts - 1 partition
        let blocks = calculate_reward_blocks(100, slots_in_epoch);
        assert_eq!(blocks, REWARD_CALCULATION_NUM_BLOCKS + 1);

        // Exactly one block's worth
        let blocks = calculate_reward_blocks(STAKE_ACCOUNTS_PER_BLOCK, slots_in_epoch);
        assert_eq!(blocks, REWARD_CALCULATION_NUM_BLOCKS + 1);

        // Two blocks worth
        let blocks = calculate_reward_blocks(STAKE_ACCOUNTS_PER_BLOCK + 1, slots_in_epoch);
        assert_eq!(blocks, REWARD_CALCULATION_NUM_BLOCKS + 2);
    }

    #[test]
    fn reward_blocks_respects_max_factor() {
        let slots_in_epoch = 1000;

        // Many accounts would exceed max_blocks
        let max_blocks = slots_in_epoch / MAX_REWARD_BLOCKS_FACTOR;
        let blocks = calculate_reward_blocks(1_000_000, slots_in_epoch);

        assert!(blocks <= max_blocks);
    }

    #[test]
    fn reward_blocks_handles_zero_accounts() {
        let blocks = calculate_reward_blocks(0, 432_000);
        assert_eq!(blocks, 0);
    }

    #[test]
    fn stake_points_calculates_proportionally() {
        let stake = 1000;
        let credits_earned = 50;
        let total_credits = 100;

        let points = calculate_stake_points(stake, credits_earned, total_credits);

        // Should get 50% of stake as points
        assert_eq!(points, 500);
    }

    #[test]
    fn stake_points_handles_zero_credits() {
        let points = calculate_stake_points(1000, 50, 0);
        assert_eq!(points, 0);
    }

    #[test]
    fn stake_points_handles_full_credits() {
        let stake = 1000;
        let credits = 100;

        let points = calculate_stake_points(stake, credits, credits);

        // Should get full stake as points
        assert_eq!(points, 1000);
    }

    #[test]
    fn stake_reward_distributes_proportionally() {
        let total_rewards = 1000;

        // Validator with 60% of points gets 60% of rewards
        let points = 600;
        let total_points = 1000;

        let reward = calculate_stake_reward(points, total_points, total_rewards);
        assert_eq!(reward, 600);
    }

    #[test]
    fn stake_reward_handles_zero_points() {
        let reward = calculate_stake_reward(100, 0, 1000);
        assert_eq!(reward, 0);
    }

    #[test]
    fn stake_reward_handles_equal_split() {
        let total_rewards = 1000;
        let total_points = 2;

        // Two validators with equal points
        let reward1 = calculate_stake_reward(1, total_points, total_rewards);
        let reward2 = calculate_stake_reward(1, total_points, total_rewards);

        assert_eq!(reward1, 500);
        assert_eq!(reward2, 500);
    }
}
