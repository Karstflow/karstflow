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
        let calc = calculate_points_and_credits(stake, epoch_credits, |epoch| {
            effective_stake_fn(stake, epoch)
        });
        total_points = total_points.saturating_add(calc.points);
    }

    total_points
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake::delegation::Delegation;
    use paradencer_storage::Pubkey;

    fn make_stake(amount: u64, credits: u64) -> StakeAccount {
        let d = Delegation::new(Pubkey::new_unique(), amount, 0);
        StakeAccount::new(d, credits)
    }

    fn make_credits(entries: &[(u64, u64, u64)]) -> Vec<EpochCreditEntry> {
        entries
            .iter()
            .map(|&(epoch, credits, prev)| EpochCreditEntry {
                epoch,
                credits,
                prev_credits: prev,
            })
            .collect()
    }

    // --- split_commission ---

    #[test]
    fn split_commission_zero_gives_all_to_staker() {
        let split = split_commission(1000, 0);
        assert_eq!(split.voter_portion, 0);
        assert_eq!(split.staker_portion, 1000);
        assert!(!split.is_split);
    }

    #[test]
    fn split_commission_100_gives_all_to_voter() {
        let split = split_commission(1000, 100);
        assert_eq!(split.voter_portion, 1000);
        assert_eq!(split.staker_portion, 0);
        assert!(!split.is_split);
    }

    #[test]
    fn split_commission_50_splits_evenly() {
        let split = split_commission(1000, 50);
        assert_eq!(split.voter_portion, 500);
        assert_eq!(split.staker_portion, 500);
        assert!(split.is_split);
    }

    #[test]
    fn split_commission_10_percent() {
        let split = split_commission(1000, 10);
        assert_eq!(split.voter_portion, 100);
        assert_eq!(split.staker_portion, 900);
        assert!(split.is_split);
    }

    #[test]
    fn split_commission_clamps_above_100() {
        let split = split_commission(1000, 200);
        // Should clamp to 100%
        assert_eq!(split.voter_portion, 1000);
        assert_eq!(split.staker_portion, 0);
    }

    #[test]
    fn split_commission_symmetric_rounding() {
        // 33% of 100 lamports: voter=33, staker=67 (not 100-33=67)
        let split = split_commission(100, 33);
        assert_eq!(split.voter_portion, 33);
        assert_eq!(split.staker_portion, 67);
        // Both computed independently, so they sum to 100 in this case
        assert_eq!(split.voter_portion + split.staker_portion, 100);
    }

    #[test]
    fn split_commission_dust_possible() {
        // 33% of 10: voter=3, staker=6 (3+6=9, dust=1)
        let split = split_commission(10, 33);
        assert_eq!(split.voter_portion, 3);
        assert_eq!(split.staker_portion, 6);
        assert!(split.voter_portion + split.staker_portion <= 10);
    }

    // --- calculate_points_and_credits ---

    #[test]
    fn points_empty_credits() {
        let stake = make_stake(1000, 0);
        let calc = calculate_points_and_credits(&stake, &[], |_| 1000);
        assert_eq!(calc.points, 0);
        assert!(!calc.force_credits_update_with_skipped_reward);
    }

    #[test]
    fn points_normal_credits() {
        let stake = make_stake(1000, 0);
        // Epoch 5: credits went from 0 to 100
        let credits = make_credits(&[(5, 100, 0)]);
        let calc = calculate_points_and_credits(&stake, &credits, |_| 1000);
        // 1000 stake * 100 credits = 100_000 points
        assert_eq!(calc.points, 100_000);
        assert_eq!(calc.new_credits_observed, 100);
    }

    #[test]
    fn points_multi_epoch() {
        let stake = make_stake(1000, 0);
        let credits = make_credits(&[
            (5, 100, 0),   // earned 100
            (6, 250, 100), // earned 150
        ]);
        let calc = calculate_points_and_credits(&stake, &credits, |_| 1000);
        // 1000*100 + 1000*150 = 250_000
        assert_eq!(calc.points, 250_000);
        assert_eq!(calc.new_credits_observed, 250);
    }

    #[test]
    fn points_vote_credits_less_than_stake_forces_update() {
        let stake = make_stake(1000, 200);
        // Vote account has only 100 credits, less than stake's 200
        let credits = make_credits(&[(5, 100, 50)]);
        let calc = calculate_points_and_credits(&stake, &credits, |_| 1000);
        assert_eq!(calc.points, 0);
        assert!(calc.force_credits_update_with_skipped_reward);
        assert_eq!(calc.new_credits_observed, 100);
    }

    #[test]
    fn points_same_credits_no_work() {
        let stake = make_stake(1000, 100);
        let credits = make_credits(&[(5, 100, 50)]);
        let calc = calculate_points_and_credits(&stake, &credits, |_| 1000);
        assert_eq!(calc.points, 0);
        assert!(!calc.force_credits_update_with_skipped_reward);
    }

    // --- calculate_stake_rewards ---

    #[test]
    fn rewards_normal_calculation() {
        let stake = make_stake(10_000, 0);
        let credits = make_credits(&[(5, 100, 0)]);
        let total_points: u128 = 10_000 * 100; // same as stake's points
        let total_rewards = 500;

        let result =
            calculate_stake_rewards(&stake, &credits, 10, 5, total_rewards, total_points, |_| {
                10_000
            });

        let r = result.unwrap();
        // Full reward (only stake in pool), 10% commission
        assert_eq!(r.staker_reward + r.voter_reward, 500);
        assert_eq!(r.voter_reward, 50); // 10% of 500
        assert_eq!(r.staker_reward, 450); // 90% of 500
    }

    #[test]
    fn rewards_zero_total_rewards_forces_credit_update() {
        let stake = make_stake(10_000, 0);
        let credits = make_credits(&[(5, 100, 0)]);

        let result = calculate_stake_rewards(&stake, &credits, 10, 5, 0, 1_000_000, |_| 10_000);

        let r = result.unwrap();
        assert_eq!(r.staker_reward, 0);
        assert_eq!(r.voter_reward, 0);
        assert_eq!(r.new_credits_observed, 100);
    }

    #[test]
    fn rewards_activation_epoch_forces_credit_update() {
        let stake = make_stake(10_000, 0);
        let credits = make_credits(&[(0, 100, 0)]);

        // rewarded_epoch == activation_epoch (0)
        let result = calculate_stake_rewards(&stake, &credits, 10, 0, 500, 1_000_000, |_| 10_000);

        let r = result.unwrap();
        assert_eq!(r.staker_reward, 0);
        assert_eq!(r.voter_reward, 0);
    }

    #[test]
    fn rewards_none_when_zero_points() {
        let stake = make_stake(10_000, 100);
        // Credits same as observed — no new credits
        let credits = make_credits(&[(5, 100, 50)]);
        let result = calculate_stake_rewards(&stake, &credits, 10, 5, 500, 1_000_000, |_| 10_000);
        assert!(result.is_none());
    }

    #[test]
    fn rewards_none_when_split_rounds_to_zero() {
        let stake = make_stake(1, 0);
        let credits = make_credits(&[(5, 1, 0)]);
        // Very small reward: 1 point out of huge total
        let result = calculate_stake_rewards(&stake, &credits, 50, 5, 1, 1_000_000_000, |_| 1);
        // Reward rounds to 0
        assert!(result.is_none());
    }

    // --- calculate_total_points ---

    #[test]
    fn total_points_across_stakes() {
        let s1 = make_stake(1000, 0);
        let c1 = make_credits(&[(5, 100, 0)]); // 1000*100 = 100_000
        let s2 = make_stake(2000, 0);
        let c2 = make_credits(&[(5, 50, 0)]); // 2000*50 = 100_000

        let stakes = vec![(s1, c1), (s2, c2)];
        let total = calculate_total_points(&stakes, |s, _| s.delegation.stake_amount);
        assert_eq!(total, 200_000);
    }
}
