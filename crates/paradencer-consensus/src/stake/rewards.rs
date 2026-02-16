/// Stake reward calculation for delegators.
///
/// Calculates the rewards earned by a stake account based on vote credits
/// earned by the validator, the delegation amount, commission rate, and
/// the total reward pool for the epoch.
use crate::stake::delegation::StakeAccount;

/// Result of calculating rewards for a stake account.
#[derive(Debug, Clone, PartialEq)]
pub struct StakeRewardResult {
    /// Lamports earned by the staker (after commission)
    pub staker_reward: u64,
    /// Lamports earned by the validator (commission)
    pub voter_reward: u64,
    /// Updated credits_observed for the stake account
    pub new_credits_observed: u64,
}

/// Calculate rewards for a single stake account over an epoch.
///
/// Returns the staker and voter portions of the reward, based on the
/// vote account credits earned during the epoch and the commission rate.
///
/// Returns None if there are no new credits to claim.
pub fn calculate_stake_rewards(
    stake: &StakeAccount,
    vote_credits_current: u64,
    vote_credits_previous: u64,
    commission: u8,
    total_validator_rewards: u64,
    total_points: u128,
) -> Option<StakeRewardResult> {
    // Credits earned since last observed
    let credits_earned = vote_credits_current.saturating_sub(stake.credits_observed);

    if credits_earned == 0 {
        return None;
    }

    // Calculate this stake's share of the total reward pool
    let stake_points =
        (stake.delegation.stake_amount as u128).checked_mul(credits_earned as u128)?;

    if total_points == 0 {
        return None;
    }

    let reward = stake_points
        .checked_mul(total_validator_rewards as u128)?
        .checked_div(total_points)?;

    let reward = reward.min(u64::MAX as u128) as u64;

    if reward == 0 {
        return None;
    }

    // Split between voter (commission) and staker
    let commission_fraction = (commission as f64) / 100.0;
    let voter_reward = (reward as f64 * commission_fraction) as u64;
    let staker_reward = reward.saturating_sub(voter_reward);

    Some(StakeRewardResult {
        staker_reward,
        voter_reward,
        new_credits_observed: vote_credits_current,
    })
}

/// Calculate the total points for a set of stake accounts.
///
/// Points represent each stake account's weighted contribution to the
/// reward pool. More stake and more credits earned = more points.
pub fn calculate_total_points(
    stakes: &[(StakeAccount, u64, u64)], // (stake, current_credits, prev_credits)
) -> u128 {
    let mut total_points: u128 = 0;

    for (stake, current_credits, _prev_credits) in stakes {
        let credits_earned = current_credits.saturating_sub(stake.credits_observed);
        let points = (stake.delegation.stake_amount as u128) * (credits_earned as u128);
        total_points = total_points.saturating_add(points);
    }

    total_points
}
