/// Stake reward calculation for delegators.
///
/// Calculates rewards earned by stake accounts based on vote epoch credits,
/// delegation amount, commission rate, and the total reward pool.
///
/// Commission is split using symmetric u128 integer arithmetic to match
/// protocol behavior: both voter and staker portions are computed
/// independently, discarding fractional lamports from each side.
use crate::stake::delegation::StakeAccount;
use paradencer_constants::economics::MAX_COMMISSION_PERCENT;

/// Result of splitting a reward between voter (commission) and staker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommissionSplit {
    /// Lamports to the vote account (commission)
    pub voter_portion: u64,
    /// Lamports to the stake account (remainder)
    pub staker_portion: u64,
    /// True when the split actually divides the reward (0 < commission < 100).
    /// When false, one party receives the entire reward and rounding
    /// cannot cause either portion to be zero.
    pub is_split: bool,
}

/// Split a reward amount between voter (commission) and staker.
///
/// Uses symmetric u128 integer arithmetic: each portion is computed
/// independently as `amount * fraction / 100`, discarding fractional
/// lamports from both sides. This means voter + staker may be less
/// than the original amount by up to 1 lamport (the "dust").
pub fn split_commission(on: u64, commission: u8) -> CommissionSplit {
    let clamped = commission.min(MAX_COMMISSION_PERCENT);

    if clamped == 0 {
        return CommissionSplit {
            voter_portion: 0,
            staker_portion: on,
            is_split: false,
        };
    }

    if clamped == MAX_COMMISSION_PERCENT {
        return CommissionSplit {
            voter_portion: on,
            staker_portion: 0,
            is_split: false,
        };
    }

    // Symmetric computation — each side computed independently
    let voter_portion = (on as u128 * clamped as u128 / 100) as u64;
    let staker_portion = (on as u128 * (100 - clamped) as u128 / 100) as u64;

    CommissionSplit {
        voter_portion,
        staker_portion,
        is_split: true,
    }
}

/// A single entry in a vote account's epoch credit history.
///
/// Each entry records cumulative credits at the end of an epoch and the
/// previous epoch's cumulative credits, allowing the calculation of credits
/// earned during that specific epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCreditEntry {
    /// Epoch this entry covers.
    pub epoch: u64,
    /// Cumulative credits at the end of this epoch.
    pub credits: u64,
    /// Cumulative credits at the start of this epoch (end of previous).
    pub prev_credits: u64,
}

/// Result of calculating stake points and updated credits tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointsCalculation {
    /// Weighted stake points (stake_amount * earned_credits summed per epoch).
    pub points: u128,
    /// Updated credits_observed for the stake account.
    pub new_credits_observed: u64,
    /// If true, credits must be updated even though no reward is due.
    /// Occurs when the vote account has fewer credits than the stake account
    /// (which shouldn't happen, but must be handled for consistency).
    pub force_credits_update_with_skipped_reward: bool,
}

/// Calculate stake points and updated credits from epoch credit history.
///
/// Iterates through the vote account's epoch credit history, computing
/// weighted points for each epoch where new credits were earned. The
/// effective stake amount for each epoch accounts for activation/deactivation.
///
/// Handles three special cases:
/// - Vote credits < stake credits: force update, skip reward
/// - Vote credits == stake credits: no update needed
/// - Normal: accumulate points per epoch with proper credit clamping
pub fn calculate_points_and_credits(
    stake: &StakeAccount,
    epoch_credits: &[EpochCreditEntry],
    effective_stake_fn: impl Fn(u64) -> u64,
) -> PointsCalculation {
    if epoch_credits.is_empty() {
        return PointsCalculation {
            points: 0,
            new_credits_observed: stake.credits_observed,
            force_credits_update_with_skipped_reward: false,
        };
    }

    let credits_in_stake = stake.credits_observed;
    let credits_in_vote = epoch_credits.last().unwrap().credits;

    // Vote account has fewer credits than stake — something is wrong, force update
    if credits_in_vote < credits_in_stake {
        return PointsCalculation {
            points: 0,
            new_credits_observed: credits_in_vote,
            force_credits_update_with_skipped_reward: true,
        };
    }

    // Vote account has same credits — nothing to do
    if credits_in_vote == credits_in_stake {
        return PointsCalculation {
            points: 0,
            new_credits_observed: credits_in_vote,
            force_credits_update_with_skipped_reward: false,
        };
    }

    // Accumulate points per epoch
    let mut points: u128 = 0;
    let mut new_credits_observed = credits_in_stake;

    for entry in epoch_credits {
        let final_epoch_credits = entry.credits;
        let initial_epoch_credits = entry.prev_credits;

        // Determine earned credits for this epoch, accounting for credits_in_stake position
        let earned_credits: u128 = if credits_in_stake < initial_epoch_credits {
            // Stake was already caught up past this epoch's start —
            // full epoch credits count
            (final_epoch_credits - initial_epoch_credits) as u128
        } else if credits_in_stake < final_epoch_credits {
            // Stake credits fall within this epoch — only count
            // credits from new_credits_observed to the end
            (final_epoch_credits - new_credits_observed) as u128
        } else {
            // Stake already observed beyond this epoch — skip
            0
        };

        new_credits_observed = new_credits_observed.max(final_epoch_credits);

        let stake_amount = effective_stake_fn(entry.epoch);
        points += stake_amount as u128 * earned_credits;
    }

    PointsCalculation {
        points,
        new_credits_observed,
        force_credits_update_with_skipped_reward: false,
    }
}

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
/// Ties together points calculation, force-update logic, reward computation
/// from the total reward pool, and commission splitting.
///
/// Returns None when no reward is due but credits may still need updating.
/// In that case, `force_result` returns just the credits update.
pub fn calculate_stake_rewards(
    stake: &StakeAccount,
    epoch_credits: &[EpochCreditEntry],
    commission: u8,
    rewarded_epoch: u64,
    total_rewards: u64,
    total_points: u128,
    effective_stake_fn: impl Fn(u64) -> u64,
) -> Option<StakeRewardResult> {
    let mut calc = calculate_points_and_credits(stake, epoch_credits, effective_stake_fn);

    // Drive credits_observed forward unconditionally when rewards are
    // disabled or when this is the stake's activation epoch
    if total_rewards == 0 || stake.delegation.activation_epoch == rewarded_epoch {
        calc.force_credits_update_with_skipped_reward = true;
    }

    if calc.force_credits_update_with_skipped_reward {
        return Some(StakeRewardResult {
            staker_reward: 0,
            voter_reward: 0,
            new_credits_observed: calc.new_credits_observed,
        });
    }

    if calc.points == 0 || total_points == 0 {
        return None;
    }

    // reward = (points * total_rewards) / total_points
    let reward_u128 = calc
        .points
        .checked_mul(total_rewards as u128)?
        .checked_div(total_points)?;

    if reward_u128 > u64::MAX as u128 {
        return None;
    }
    let reward = reward_u128 as u64;
    if reward == 0 {
        return None;
    }

    let split = split_commission(reward, commission);

    // If the split actually divides the reward but either portion rounds
    // to zero, skip entirely to avoid rewarding only one party
    if split.is_split && (split.voter_portion == 0 || split.staker_portion == 0) {
        return None;
    }

    Some(StakeRewardResult {
        staker_reward: split.staker_portion,
        voter_reward: split.voter_portion,
        new_credits_observed: calc.new_credits_observed,
    })
}

/// Calculate the total points for a set of stake accounts.
///
/// Points represent each stake account's weighted contribution to the
/// reward pool. More stake and more credits earned = more points.
pub fn calculate_total_points(
    stakes: &[(StakeAccount, Vec<EpochCreditEntry>)],
    effective_stake_fn: impl Fn(&StakeAccount, u64) -> u64,
) -> u128 {
    let mut total_points: u128 = 0;

    for (stake, epoch_credits) in stakes {
        let calc =
            calculate_points_and_credits(stake, epoch_credits, |epoch| {
                effective_stake_fn(stake, epoch)
            });
        total_points = total_points.saturating_add(calc.points);
    }

    total_points
}
