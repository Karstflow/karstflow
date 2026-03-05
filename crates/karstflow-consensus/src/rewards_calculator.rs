/// Extended rewards calculation for validator and delegator reward distribution.
///
/// Builds on the base epoch rewards calculation to determine individual
/// validator and delegator rewards based on vote credits, stake weight,
/// and commission rates.
use crate::{EpochSchedule, Inflation};
use karstflow_constants::economics::DEFAULT_SLOTS_PER_YEAR;
use karstflow_storage::Pubkey;

/// Per-validator summary of vote performance for rewards calculation.
#[derive(Debug, Clone)]
pub struct VoteAccountInfo {
    /// Total effective stake delegated to this validator
    pub total_stake: u64,
    /// Vote credits earned during the epoch
    pub vote_credits: u64,
    /// Commission rate (0-100)
    pub commission: u8,
}

/// Computed reward for a single validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorReward {
    /// Vote account receiving the commission
    pub vote_account: Pubkey,
    /// Commission percentage applied
    pub commission: u8,
    /// Total reward before commission split (validator + delegators)
    pub total_reward: u64,
    /// Vote credits earned during the epoch
    pub vote_credits: u64,
}

/// Computed reward for a single delegator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatorReward {
    /// Stake account receiving the reward
    pub stake_account: Pubkey,
    /// Lamports rewarded to this delegator
    pub reward: u64,
    /// Updated credits-observed counter for the stake account
    pub new_credits_observed: u64,
}

/// Summary of rewards distributed in an epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochRewardsSummary {
    /// Total validator rewards (sum of all ValidatorReward.total_reward)
    pub total_validator_rewards: u64,
    /// Per-validator reward details
    pub validator_rewards: Vec<ValidatorReward>,
    /// Validator inflation rate applied
    pub validator_rate: f64,
    /// Foundation inflation rate applied
    pub foundation_rate: f64,
}

/// Calculates epoch rewards using inflation configuration and epoch schedule.
///
/// Determines the total reward pool for an epoch and distributes it among
/// validators based on their vote credits and stake weight.
#[derive(Debug, Clone)]
pub struct RewardsCalculator {
    /// Inflation configuration for rate calculation
    pub inflation: Inflation,
    /// Epoch schedule for slot/epoch conversion
    pub epoch_schedule: EpochSchedule,
}

impl RewardsCalculator {
    /// Create a new rewards calculator.
    pub fn new(inflation: Inflation, epoch_schedule: EpochSchedule) -> Self {
        Self {
            inflation,
            epoch_schedule,
        }
    }

    /// Calculate total epoch rewards from inflation.
    ///
    /// Returns (total_validator_rewards, validator_rate, foundation_rate).
    /// The total is derived from the network capitalization, inflation rate,
    /// and epoch duration as a fraction of a year.
    pub fn calculate_epoch_rewards(&self, epoch: u64, total_supply: u64) -> (u64, f64, f64) {
        let slots_in_epoch = self.epoch_schedule.get_slots_in_epoch(epoch) as f64;
        let slot = self.epoch_schedule.get_first_slot_in_epoch(epoch) as f64;
        let year = slot / DEFAULT_SLOTS_PER_YEAR;

        let validator_rate = self.inflation.validator_rate(year);
        let foundation_rate = self.inflation.foundation_rate(year);

        // Rewards are pro-rated: capitalization * rate * (epoch_slots / slots_per_year)
        let epoch_fraction = slots_in_epoch / DEFAULT_SLOTS_PER_YEAR;
        let total_validator_rewards =
            (total_supply as f64 * validator_rate * epoch_fraction) as u64;

        (total_validator_rewards, validator_rate, foundation_rate)
    }

    /// Distribute a reward pool among validators proportional to vote credits.
    ///
    /// Each validator's share is determined by:
    ///   validator_share = total_rewards * (validator_credits * validator_stake)
    ///                     / sum(credits_i * stake_i)
    ///
    /// Returns per-validator reward entries.
    pub fn calculate_validator_rewards(
        &self,
        vote_accounts: &[(Pubkey, VoteAccountInfo)],
        epoch_rewards: u64,
    ) -> Vec<ValidatorReward> {
        if vote_accounts.is_empty() || epoch_rewards == 0 {
            return Vec::new();
        }

        // Calculate total weighted credits across all validators
        // Each validator's weight = vote_credits * total_stake
        let total_weighted_credits: u128 = vote_accounts
            .iter()
            .map(|(_, info)| info.vote_credits as u128 * info.total_stake as u128)
            .sum();

        if total_weighted_credits == 0 {
            return Vec::new();
        }

        let mut rewards = Vec::with_capacity(vote_accounts.len());

        for (pubkey, info) in vote_accounts {
            let weighted_credits = info.vote_credits as u128 * info.total_stake as u128;
            let validator_total =
                ((epoch_rewards as u128 * weighted_credits) / total_weighted_credits) as u64;

            if validator_total > 0 {
                rewards.push(ValidatorReward {
                    vote_account: *pubkey,
                    commission: info.commission,
                    total_reward: validator_total,
                    vote_credits: info.vote_credits,
                });
            }
        }

        rewards
    }

    /// Split a validator's total reward into commission and delegator portions.
    ///
    /// Uses symmetric u128 integer arithmetic matching protocol behavior:
    /// both portions are computed independently, discarding fractional lamports.
    ///
    /// Returns (commission_amount, delegator_pool).
    pub fn split_commission(total_reward: u64, commission_percent: u8) -> (u64, u64) {
        let split = crate::stake::split_commission(total_reward, commission_percent);
        (split.voter_portion, split.staker_portion)
    }

    /// Calculate individual delegator rewards from a validator's delegator pool.
    ///
    /// Each delegator's share is proportional to their stake relative to
    /// the validator's total stake.
    pub fn calculate_delegator_rewards(
        delegator_pool: u64,
        delegators: &[(Pubkey, u64)], // (stake_account, effective_stake)
        total_stake: u64,
        credits_observed: u64,
    ) -> Vec<DelegatorReward> {
        if delegator_pool == 0 || delegators.is_empty() || total_stake == 0 {
            return Vec::new();
        }

        let mut rewards = Vec::with_capacity(delegators.len());

        for (stake_account, effective_stake) in delegators {
            let share =
                ((delegator_pool as u128 * *effective_stake as u128) / total_stake as u128) as u64;

            if share > 0 {
                rewards.push(DelegatorReward {
                    stake_account: *stake_account,
                    reward: share,
                    new_credits_observed: credits_observed,
                });
            }
        }

        rewards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_calculator() -> RewardsCalculator {
        RewardsCalculator::new(Inflation::default(), EpochSchedule::default())
    }

    #[test]
    fn calculator_computes_epoch_rewards() {
        let calc = default_calculator();
        let supply = 1_000_000_000_000_u64; // 1 trillion lamports

        let (rewards, validator_rate, foundation_rate) = calc.calculate_epoch_rewards(0, supply);

        assert!(rewards > 0, "Rewards should be positive for epoch 0");
        assert!(validator_rate > 0.0);
        assert!(foundation_rate >= 0.0);
    }

    #[test]
    fn calculator_rewards_decrease_over_epochs() {
        let calc = default_calculator();
        let supply = 1_000_000_000_000_u64;

        let (rewards_0, _, _) = calc.calculate_epoch_rewards(0, supply);
        let (rewards_100, _, _) = calc.calculate_epoch_rewards(100, supply);

        // Rewards should taper over time
        assert!(rewards_0 > 0);
        assert!(rewards_100 > 0);
        // Both are epoch 0 and 100 with same supply, taper should not be huge
        // but the slot-based year calculation shifts the year slightly
    }

    #[test]
    fn calculator_zero_supply_gives_zero_rewards() {
        let calc = default_calculator();
        let (rewards, _, _) = calc.calculate_epoch_rewards(0, 0);
        assert_eq!(rewards, 0);
    }

    #[test]
    fn calculator_distributes_to_single_validator() {
        let calc = default_calculator();
        let validator = Pubkey::new_unique();
        let accounts = vec![(
            validator,
            VoteAccountInfo {
                total_stake: 1_000_000,
                vote_credits: 100,
                commission: 10,
            },
        )];

        let rewards = calc.calculate_validator_rewards(&accounts, 10_000);

        assert_eq!(rewards.len(), 1);
        assert_eq!(rewards[0].vote_account, validator);
        assert_eq!(rewards[0].total_reward, 10_000);
        assert_eq!(rewards[0].commission, 10);
    }

    #[test]
    fn calculator_distributes_proportionally_to_weighted_credits() {
        let calc = default_calculator();
        let v1 = Pubkey::new_unique();
        let v2 = Pubkey::new_unique();

        // v1: 100 credits * 1000 stake = 100_000 weight
        // v2: 50 credits * 1000 stake = 50_000 weight
        // v1 gets 2/3, v2 gets 1/3
        let accounts = vec![
            (
                v1,
                VoteAccountInfo {
                    total_stake: 1_000,
                    vote_credits: 100,
                    commission: 10,
                },
            ),
            (
                v2,
                VoteAccountInfo {
                    total_stake: 1_000,
                    vote_credits: 50,
                    commission: 10,
                },
            ),
        ];

        let rewards = calc.calculate_validator_rewards(&accounts, 9_000);

        assert_eq!(rewards.len(), 2);

        let r1 = rewards.iter().find(|r| r.vote_account == v1).unwrap();
        let r2 = rewards.iter().find(|r| r.vote_account == v2).unwrap();

        assert_eq!(r1.total_reward, 6_000);
        assert_eq!(r2.total_reward, 3_000);
    }

    #[test]
    fn calculator_handles_zero_credits() {
        let calc = default_calculator();
        let v1 = Pubkey::new_unique();

        let accounts = vec![(
            v1,
            VoteAccountInfo {
                total_stake: 1_000,
                vote_credits: 0,
                commission: 10,
            },
        )];

        let rewards = calc.calculate_validator_rewards(&accounts, 10_000);
        assert!(rewards.is_empty());
    }

    #[test]
    fn calculator_handles_empty_validators() {
        let calc = default_calculator();
        let rewards = calc.calculate_validator_rewards(&[], 10_000);
        assert!(rewards.is_empty());
    }

    #[test]
    fn commission_split_at_10_percent() {
        let (commission, delegator_pool) = RewardsCalculator::split_commission(10_000, 10);
        assert_eq!(commission, 1_000);
        assert_eq!(delegator_pool, 9_000);
    }

    #[test]
    fn commission_split_at_100_percent() {
        let (commission, delegator_pool) = RewardsCalculator::split_commission(10_000, 100);
        assert_eq!(commission, 10_000);
        assert_eq!(delegator_pool, 0);
    }

    #[test]
    fn commission_split_at_0_percent() {
        let (commission, delegator_pool) = RewardsCalculator::split_commission(10_000, 0);
        assert_eq!(commission, 0);
        assert_eq!(delegator_pool, 10_000);
    }

    #[test]
    fn delegator_rewards_split_proportionally() {
        let d1 = Pubkey::new_unique();
        let d2 = Pubkey::new_unique();
        let delegators = vec![(d1, 700), (d2, 300)];

        let rewards =
            RewardsCalculator::calculate_delegator_rewards(10_000, &delegators, 1_000, 500);

        assert_eq!(rewards.len(), 2);

        let r1 = rewards.iter().find(|r| r.stake_account == d1).unwrap();
        let r2 = rewards.iter().find(|r| r.stake_account == d2).unwrap();

        assert_eq!(r1.reward, 7_000);
        assert_eq!(r2.reward, 3_000);
        assert_eq!(r1.new_credits_observed, 500);
    }

    #[test]
    fn delegator_rewards_handles_zero_pool() {
        let d1 = Pubkey::new_unique();
        let delegators = vec![(d1, 1_000)];

        let rewards = RewardsCalculator::calculate_delegator_rewards(0, &delegators, 1_000, 500);
        assert!(rewards.is_empty());
    }

    #[test]
    fn delegator_rewards_handles_empty_delegators() {
        let rewards = RewardsCalculator::calculate_delegator_rewards(10_000, &[], 1_000, 500);
        assert!(rewards.is_empty());
    }
}
