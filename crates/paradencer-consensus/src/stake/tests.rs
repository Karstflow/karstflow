use super::*;
use crate::stake_history::{StakeHistory, StakeHistoryEntry};
use paradencer_storage::Pubkey;

// -- AuthorityType tests --

#[test]
fn authority_type_roundtrips_discriminant() {
    assert_eq!(
        AuthorityType::from_discriminant(AuthorityType::Staker.to_discriminant()),
        Some(AuthorityType::Staker)
    );
    assert_eq!(
        AuthorityType::from_discriminant(AuthorityType::Withdrawer.to_discriminant()),
        Some(AuthorityType::Withdrawer)
    );
    assert_eq!(AuthorityType::from_discriminant(99), None);
}

// -- Authorized tests --

#[test]
fn authorized_checks_signer_for_staker() {
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let auth = Authorized::new(staker, withdrawer);

    assert!(auth.check(&[staker], AuthorityType::Staker));
    assert!(!auth.check(&[withdrawer], AuthorityType::Staker));
    assert!(!auth.check(&[], AuthorityType::Staker));
}

#[test]
fn authorized_checks_signer_for_withdrawer() {
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let auth = Authorized::new(staker, withdrawer);

    assert!(auth.check(&[withdrawer], AuthorityType::Withdrawer));
    assert!(!auth.check(&[staker], AuthorityType::Withdrawer));
}

#[test]
fn authorized_staker_can_be_changed_by_staker_or_withdrawer() {
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let new_staker = Pubkey::new_unique();

    let mut auth = Authorized::new(staker, withdrawer);
    auth.authorize(&[staker], new_staker, AuthorityType::Staker)
        .unwrap();
    assert_eq!(auth.staker, new_staker);

    let newer_staker = Pubkey::new_unique();
    auth.authorize(&[withdrawer], newer_staker, AuthorityType::Staker)
        .unwrap();
    assert_eq!(auth.staker, newer_staker);
}

#[test]
fn authorized_withdrawer_requires_withdrawer_signature() {
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let new_withdrawer = Pubkey::new_unique();

    let mut auth = Authorized::new(staker, withdrawer);

    // Staker alone cannot change withdrawer
    let result = auth.authorize(&[staker], new_withdrawer, AuthorityType::Withdrawer);
    assert_eq!(result, Err(StakeError::MissingRequiredSignature));

    // Withdrawer can change it
    auth.authorize(&[withdrawer], new_withdrawer, AuthorityType::Withdrawer)
        .unwrap();
    assert_eq!(auth.withdrawer, new_withdrawer);
}

#[test]
fn authorized_auto_sets_both_to_same_key() {
    let key = Pubkey::new_unique();
    let auth = Authorized::auto(key);
    assert_eq!(auth.staker, key);
    assert_eq!(auth.withdrawer, key);
}

// -- Lockup tests --

#[test]
fn lockup_not_in_force_when_defaults() {
    let lockup = Lockup::default();
    assert!(!lockup.is_in_force(0, 0, None));
}

#[test]
fn lockup_enforced_by_timestamp() {
    let lockup = Lockup::new(1000, 0, Pubkey::zeroed());
    assert!(lockup.is_in_force(999, 100, None));
    assert!(!lockup.is_in_force(1000, 100, None));
    assert!(!lockup.is_in_force(1001, 100, None));
}

#[test]
fn lockup_enforced_by_epoch() {
    let lockup = Lockup::new(0, 10, Pubkey::zeroed());
    assert!(lockup.is_in_force(0, 9, None));
    assert!(!lockup.is_in_force(0, 10, None));
}

#[test]
fn lockup_custodian_can_bypass() {
    let custodian = Pubkey::new_unique();
    let lockup = Lockup::new(1000, 100, custodian);
    // Without custodian signature, locked
    assert!(lockup.is_in_force(0, 0, None));
    // Random signer cannot bypass
    let random = Pubkey::new_unique();
    assert!(lockup.is_in_force(0, 0, Some(&random)));
    // Custodian can bypass
    assert!(!lockup.is_in_force(0, 0, Some(&custodian)));
}

// -- Meta tests --

#[test]
fn meta_creates_with_defaults() {
    let auth = Authorized::auto(Pubkey::new_unique());
    let meta = Meta::with_authorized(1000, auth.clone());
    assert_eq!(meta.rent_exempt_reserve, 1000);
    assert_eq!(meta.authorized, auth);
    assert_eq!(meta.lockup, Lockup::default());
}

// -- StakeFlags tests --

#[test]
fn stake_flags_empty_is_zero() {
    assert_eq!(StakeFlags::EMPTY.bits, 0);
}

#[test]
fn stake_flags_contains_and_insert() {
    let mut flags = StakeFlags::EMPTY;
    assert!(!flags.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));

    flags.insert(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION);
    assert!(flags.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));
}

#[test]
fn stake_flags_remove() {
    let mut flags = StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION;
    flags.remove(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION);
    assert_eq!(flags, StakeFlags::EMPTY);
}

#[test]
fn stake_flags_union() {
    let a = StakeFlags::EMPTY;
    let b = StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION;
    let c = a.union(b);
    assert!(c.contains(StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION));
}

// -- StakeState tests --

#[test]
fn stake_state_discriminants() {
    assert_eq!(StakeState::Uninitialized.discriminant(), 0);
    assert_eq!(StakeState::Initialized(Meta::default()).discriminant(), 1);
    let delegation = Delegation::new(Pubkey::new_unique(), 1000, 0);
    let stake = StakeAccount::new(delegation, 0);
    assert_eq!(
        StakeState::Delegated(Meta::default(), stake, StakeFlags::EMPTY).discriminant(),
        2
    );
    assert_eq!(StakeState::RewardsPool.discriminant(), 3);
}

#[test]
fn stake_state_accessors() {
    let meta = Meta::default();
    let delegation = Delegation::new(Pubkey::new_unique(), 1000, 0);
    let stake = StakeAccount::new(delegation, 0);
    let state = StakeState::Delegated(meta, stake, StakeFlags::EMPTY);

    assert!(state.meta().is_some());
    assert!(state.stake().is_some());
    assert!(state.flags().is_some());
    assert!(state.is_delegated());
    assert!(state.is_initialized());
    assert!(!state.is_uninitialized());
}

#[test]
fn stake_state_uninitialized_accessors() {
    let state = StakeState::Uninitialized;
    assert!(state.meta().is_none());
    assert!(state.stake().is_none());
    assert!(state.flags().is_none());
    assert!(!state.is_delegated());
    assert!(!state.is_initialized());
    assert!(state.is_uninitialized());
}

// -- Delegation tests --

#[test]
fn delegation_new_sets_defaults() {
    let voter = Pubkey::new_unique();
    let d = Delegation::new(voter, 1000, 5);
    assert_eq!(d.voter_pubkey, voter);
    assert_eq!(d.stake_amount, 1000);
    assert_eq!(d.activation_epoch, 5);
    assert_eq!(d.deactivation_epoch, u64::MAX);
    assert!(!d.is_deactivated());
    assert!(!d.is_bootstrap());
}

#[test]
fn delegation_deactivate_marks_epoch() {
    let mut d = Delegation::new(Pubkey::new_unique(), 1000, 0);
    d.deactivate(10);
    assert_eq!(d.deactivation_epoch, 10);
    assert!(d.is_deactivated());
}

#[test]
fn delegation_effective_stake_without_history_is_full_after_activation() {
    let d = Delegation::new(Pubkey::new_unique(), 1000, 5);
    // Without history, assume fully activated after activation epoch
    assert_eq!(d.effective_stake(4, None, None), 0); // before activation
                                                     // At activation epoch, all is activating (effective = 0 from activation_status)
    assert_eq!(d.effective_stake(5, None, None), 0);
    // After activation, fully effective (no history = instant)
    assert_eq!(d.effective_stake(6, None, None), 1000);
}

#[test]
fn delegation_effective_stake_deactivated_without_history() {
    let mut d = Delegation::new(Pubkey::new_unique(), 1000, 0);
    d.deactivate(5);
    // Before deactivation
    assert_eq!(d.effective_stake(4, None, None), 1000);
    // At deactivation epoch
    assert_eq!(d.effective_stake(5, None, None), 1000);
    // After deactivation without history -> fully deactivated
    assert_eq!(d.effective_stake(6, None, None), 0);
}

#[test]
fn delegation_activation_status_at_activation_epoch() {
    let d = Delegation::new(Pubkey::new_unique(), 1000, 5);
    let status = d.activation_status(5, None, None);
    assert_eq!(status.effective, 0);
    assert_eq!(status.activating, 1000);
    assert_eq!(status.deactivating, 0);
}

#[test]
fn delegation_activation_status_before_activation() {
    let d = Delegation::new(Pubkey::new_unique(), 1000, 5);
    let status = d.activation_status(3, None, None);
    assert_eq!(status.effective, 0);
    assert_eq!(status.activating, 0);
    assert_eq!(status.deactivating, 0);
}

#[test]
fn delegation_activation_with_history_warmup() {
    let d = Delegation::new(Pubkey::new_unique(), 1000, 5);
    let mut history = StakeHistory::new();
    // At epoch 5, cluster has some activating stake
    history.add(5, StakeHistoryEntry::new(10000, 2000, 0));
    history.add(6, StakeHistoryEntry::new(10500, 1500, 0));

    let status = d.activation_status(7, Some(&history), None);
    // Should have some effective stake from warmup
    assert!(status.effective > 0);
}

#[test]
fn delegation_deactivation_at_deactivation_epoch() {
    let mut d = Delegation::new(Pubkey::new_unique(), 1000, 0);
    d.deactivate(5);
    let status = d.activation_status(5, None, None);
    // At deactivation epoch: effective = full amount, deactivating = full amount
    assert_eq!(status.effective, 1000);
    assert_eq!(status.deactivating, 1000);
    assert_eq!(status.activating, 0);
}

#[test]
fn delegation_bootstrap_is_immediately_effective() {
    let mut d = Delegation::new(Pubkey::new_unique(), 1000, u64::MAX);
    // Bootstrap stake has activation_epoch = MAX
    assert!(d.is_bootstrap());
    assert_eq!(d.effective_stake(0, None, None), 1000);
    assert_eq!(d.effective_stake(100, None, None), 1000);

    // Even with deactivation set
    d.deactivate(5);
    assert_eq!(d.effective_stake(4, None, None), 1000);
}

#[test]
fn delegation_activated_and_deactivated_same_epoch_has_zero_effective() {
    let d = Delegation {
        voter_pubkey: Pubkey::new_unique(),
        stake_amount: 1000,
        activation_epoch: 5,
        deactivation_epoch: 5,
        warmup_cooldown_rate: 0.25,
    };
    let status = d.activation_status(5, None, None);
    assert_eq!(status.effective, 0);
    assert_eq!(status.activating, 0);
}

// -- StakeAccount tests --

#[test]
fn stake_account_split_reduces_delegation() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1000, 0);
    let mut stake = StakeAccount::new(delegation, 100);

    let new_stake = stake.split(400, 400).unwrap();
    assert_eq!(stake.delegation.stake_amount, 600);
    assert_eq!(new_stake.delegation.stake_amount, 400);
    assert_eq!(new_stake.credits_observed, 100);
}

#[test]
fn stake_account_split_fails_if_insufficient() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1000, 0);
    let mut stake = StakeAccount::new(delegation, 100);

    let result = stake.split(1001, 1001);
    assert_eq!(result, Err(StakeError::InsufficientStake));
}

#[test]
fn stake_account_merge_combines_amounts() {
    let voter = Pubkey::new_unique();
    let delegation1 = Delegation::new(voter, 600, 0);
    let delegation2 = Delegation::new(voter, 400, 0);
    let mut stake1 = StakeAccount::new(delegation1, 100);
    let stake2 = StakeAccount::new(delegation2, 200);

    stake1.merge(&stake2).unwrap();
    assert_eq!(stake1.delegation.stake_amount, 1000);
    assert_eq!(stake1.credits_observed, 200); // takes max
}

#[test]
fn stake_account_merge_fails_different_voters() {
    let delegation1 = Delegation::new(Pubkey::new_unique(), 600, 0);
    let delegation2 = Delegation::new(Pubkey::new_unique(), 400, 0);
    let mut stake1 = StakeAccount::new(delegation1, 100);
    let stake2 = StakeAccount::new(delegation2, 200);

    let result = stake1.merge(&stake2);
    assert_eq!(result, Err(StakeError::MergeMismatch));
}

// -- Serialization roundtrip tests --

#[test]
fn serialize_uninitialized_roundtrips() {
    let state = StakeState::Uninitialized;
    let data = serialize_stake_state(&state);
    let deserialized = deserialize_stake_state(&data).unwrap();
    assert_eq!(deserialized, state);
}

#[test]
fn serialize_initialized_roundtrips() {
    let staker = Pubkey::new_unique();
    let withdrawer = Pubkey::new_unique();
    let custodian = Pubkey::new_unique();
    let meta = Meta::new(
        2282880,
        Authorized::new(staker, withdrawer),
        Lockup::new(1000, 10, custodian),
    );
    let state = StakeState::Initialized(meta.clone());

    let data = serialize_stake_state(&state);
    let deserialized = deserialize_stake_state(&data).unwrap();

    match deserialized {
        StakeState::Initialized(m) => {
            assert_eq!(m.rent_exempt_reserve, meta.rent_exempt_reserve);
            assert_eq!(m.authorized, meta.authorized);
            assert_eq!(m.lockup, meta.lockup);
        }
        _ => panic!("Expected Initialized"),
    }
}

#[test]
fn serialize_delegated_roundtrips() {
    let staker = Pubkey::new_unique();
    let voter = Pubkey::new_unique();
    let meta = Meta::with_authorized(2282880, Authorized::auto(staker));
    let delegation = Delegation::new(voter, 5_000_000_000, 100);
    let stake = StakeAccount::new(delegation, 42);
    let flags = StakeFlags::MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION;
    let state = StakeState::Delegated(meta.clone(), stake.clone(), flags);

    let data = serialize_stake_state(&state);
    let deserialized = deserialize_stake_state(&data).unwrap();

    match deserialized {
        StakeState::Delegated(m, s, f) => {
            assert_eq!(m.rent_exempt_reserve, meta.rent_exempt_reserve);
            assert_eq!(s.delegation.voter_pubkey, voter);
            assert_eq!(s.delegation.stake_amount, 5_000_000_000);
            assert_eq!(s.credits_observed, 42);
            assert_eq!(f, flags);
        }
        _ => panic!("Expected Delegated"),
    }
}

#[test]
fn serialize_rewards_pool_roundtrips() {
    let state = StakeState::RewardsPool;
    let data = serialize_stake_state(&state);
    let deserialized = deserialize_stake_state(&data).unwrap();
    assert_eq!(deserialized, state);
}

#[test]
fn deserialize_too_short_data_errors() {
    let result = deserialize_stake_state(&[0, 0]);
    assert_eq!(result, Err(StakeError::AccountDataTooSmall));
}

#[test]
fn deserialize_invalid_discriminant_errors() {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&99u32.to_le_bytes());
    let result = deserialize_stake_state(&data);
    assert_eq!(result, Err(StakeError::InvalidAccountData));
}

// -- Warmup/Cooldown rate tests --

#[test]
fn warmup_cooldown_returns_default_rate_without_feature() {
    let rate = warmup_cooldown_rate(100, None);
    assert!((rate - 0.25).abs() < f64::EPSILON);
}

#[test]
fn warmup_cooldown_returns_default_before_activation() {
    let rate = warmup_cooldown_rate(99, Some(100));
    assert!((rate - 0.25).abs() < f64::EPSILON);
}

#[test]
fn warmup_cooldown_returns_new_rate_at_activation() {
    let rate = warmup_cooldown_rate(100, Some(100));
    assert!((rate - 0.09).abs() < f64::EPSILON);
}

#[test]
fn warmup_cooldown_returns_new_rate_after_activation() {
    let rate = warmup_cooldown_rate(200, Some(100));
    assert!((rate - 0.09).abs() < f64::EPSILON);
}

// -- Rewards tests --

fn make_epoch_credits(credits: u64, prev_credits: u64, epoch: u64) -> Vec<EpochCreditEntry> {
    vec![EpochCreditEntry {
        epoch,
        credits,
        prev_credits,
    }]
}

fn identity_stake(amount: u64) -> impl Fn(u64) -> u64 {
    move |_epoch| amount
}

#[test]
fn rewards_returns_none_for_zero_credits() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 0);
    let stake = StakeAccount::new(delegation, 100);

    // Credits == observed credits -> no new credits -> None (no reward)
    let credits = make_epoch_credits(100, 0, 1);
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        10,
        1,
        1_000_000,
        1000,
        identity_stake(1_000_000),
    );
    assert!(result.is_none());
}

#[test]
fn rewards_calculates_proportional_reward() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(100, 0, 1);
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        10,
        1,
        1_000_000,
        100_000_000,
        identity_stake(1_000_000),
    );
    assert!(result.is_some());

    let result = result.unwrap();
    assert!(result.staker_reward > 0);
    assert!(result.voter_reward > 0);
    assert_eq!(result.new_credits_observed, 100);

    // Voter gets 10% commission via u128 arithmetic
    let total = result.staker_reward + result.voter_reward;
    let expected_voter = (total as u128 * 10 / 100) as u64;
    assert!(
        (result.voter_reward as i64 - expected_voter as i64).unsigned_abs() <= 1,
        "voter_reward={} expected={}",
        result.voter_reward,
        expected_voter
    );
}

#[test]
fn rewards_zero_commission_gives_all_to_staker() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(100, 0, 1);
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        0,
        1,
        1_000_000,
        100_000_000,
        identity_stake(1_000_000),
    );
    let result = result.unwrap();
    assert_eq!(result.voter_reward, 0);
    assert!(result.staker_reward > 0);
}

#[test]
fn rewards_returns_none_for_zero_total_points() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(100, 0, 1);
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        10,
        1,
        1_000_000,
        0,
        identity_stake(1_000_000),
    );
    assert!(result.is_none());
}

// -- Commission split tests --

#[test]
fn commission_split_zero_percent() {
    let split = rewards::split_commission(10_000, 0);
    assert_eq!(split.voter_portion, 0);
    assert_eq!(split.staker_portion, 10_000);
    assert!(!split.is_split);
}

#[test]
fn commission_split_100_percent() {
    let split = rewards::split_commission(10_000, 100);
    assert_eq!(split.voter_portion, 10_000);
    assert_eq!(split.staker_portion, 0);
    assert!(!split.is_split);
}

#[test]
fn commission_split_symmetric_u128_arithmetic() {
    // 33% commission on 100 lamports:
    // voter = 100 * 33 / 100 = 33
    // staker = 100 * 67 / 100 = 67
    // Total = 100 (no dust in this case)
    let split = rewards::split_commission(100, 33);
    assert_eq!(split.voter_portion, 33);
    assert_eq!(split.staker_portion, 67);
    assert!(split.is_split);
}

#[test]
fn commission_split_discards_fractional_from_both_sides() {
    // 33% commission on 10 lamports:
    // voter = 10 * 33 / 100 = 3 (3.3 truncated)
    // staker = 10 * 67 / 100 = 6 (6.7 truncated)
    // Total = 9 (1 lamport "dust" discarded)
    let split = rewards::split_commission(10, 33);
    assert_eq!(split.voter_portion, 3);
    assert_eq!(split.staker_portion, 6);
    assert!(split.is_split);
    // Dust: 10 - 3 - 6 = 1
    assert_eq!(10 - split.voter_portion - split.staker_portion, 1);
}

#[test]
fn commission_split_clamps_above_100() {
    // Commission > 100 is treated as 100
    let split = rewards::split_commission(10_000, 150);
    assert_eq!(split.voter_portion, 10_000);
    assert_eq!(split.staker_portion, 0);
    assert!(!split.is_split);
}

// -- Points calculation tests --

#[test]
fn points_calculation_empty_credits() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let calc = rewards::calculate_points_and_credits(&stake, &[], identity_stake(1_000));
    assert_eq!(calc.points, 0);
    assert_eq!(calc.new_credits_observed, 0);
    assert!(!calc.force_credits_update_with_skipped_reward);
}

#[test]
fn points_calculation_vote_credits_less_than_stake() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000, 0);
    let stake = StakeAccount::new(delegation, 100);

    // Vote account has only 50 credits but stake expects 100
    let credits = make_epoch_credits(50, 0, 1);
    let calc = rewards::calculate_points_and_credits(&stake, &credits, identity_stake(1_000));

    assert_eq!(calc.points, 0);
    assert_eq!(calc.new_credits_observed, 50);
    assert!(calc.force_credits_update_with_skipped_reward);
}

#[test]
fn points_calculation_multi_epoch_credits() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = vec![
        EpochCreditEntry {
            epoch: 1,
            credits: 50,
            prev_credits: 0,
        },
        EpochCreditEntry {
            epoch: 2,
            credits: 120,
            prev_credits: 50,
        },
        EpochCreditEntry {
            epoch: 3,
            credits: 200,
            prev_credits: 120,
        },
    ];

    let calc = rewards::calculate_points_and_credits(&stake, &credits, identity_stake(1_000));

    // 50 earned in epoch 1 + 70 in epoch 2 + 80 in epoch 3 = 200 total credits
    // points = 1000 * 200 = 200_000
    assert_eq!(calc.points, 200_000);
    assert_eq!(calc.new_credits_observed, 200);
}

#[test]
fn points_calculation_partial_epoch_credits() {
    // Stake observed 30 credits, epoch history starts at 0->50
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000, 0);
    let stake = StakeAccount::new(delegation, 30);

    let credits = vec![EpochCreditEntry {
        epoch: 1,
        credits: 50,
        prev_credits: 0,
    }];

    let calc = rewards::calculate_points_and_credits(&stake, &credits, identity_stake(1_000));

    // credits_in_stake (30) >= initial (0) but < final (50)
    // earned = final - new_credits_observed = 50 - 30 = 20
    assert_eq!(calc.points, 20_000);
    assert_eq!(calc.new_credits_observed, 50);
}

// -- Full reward calculation tests --

#[test]
fn rewards_activation_epoch_forces_credits_update() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 5);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(100, 0, 5);
    // rewarded_epoch == activation_epoch => force credits update
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        10,
        5, // activation epoch
        1_000_000,
        100_000_000,
        identity_stake(1_000_000),
    );
    let result = result.unwrap();
    assert_eq!(result.staker_reward, 0);
    assert_eq!(result.voter_reward, 0);
    assert_eq!(result.new_credits_observed, 100);
}

#[test]
fn rewards_zero_total_rewards_forces_credits_update() {
    let delegation = Delegation::new(Pubkey::new_unique(), 1_000_000, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(100, 0, 1);
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        10,
        1,
        0, // zero total rewards
        100_000_000,
        identity_stake(1_000_000),
    );
    let result = result.unwrap();
    assert_eq!(result.staker_reward, 0);
    assert_eq!(result.voter_reward, 0);
    assert_eq!(result.new_credits_observed, 100);
}

#[test]
fn rewards_fractional_split_skips_tiny_reward() {
    // With 1 lamport reward and 50% commission:
    // voter = 1 * 50 / 100 = 0
    // staker = 1 * 50 / 100 = 0
    // is_split=true but both are 0 => skip
    let delegation = Delegation::new(Pubkey::new_unique(), 1, 0);
    let stake = StakeAccount::new(delegation, 0);

    let credits = make_epoch_credits(1, 0, 1);
    // total_points = 1 * 1 = 1, total_rewards = 1 => reward = 1
    let result = rewards::calculate_stake_rewards(
        &stake,
        &credits,
        50,
        1,
        1,
        1,
        identity_stake(1),
    );
    // With is_split=true and voter_portion=0 or staker_portion=0 => None
    assert!(result.is_none());
}

// -- Total points aggregation tests --

#[test]
fn total_points_aggregates_multiple_stakes() {
    let d1 = Delegation::new(Pubkey::new_unique(), 1_000, 0);
    let d2 = Delegation::new(Pubkey::new_unique(), 2_000, 0);
    let s1 = StakeAccount::new(d1, 0);
    let s2 = StakeAccount::new(d2, 0);

    let c1 = vec![EpochCreditEntry {
        epoch: 1,
        credits: 100,
        prev_credits: 0,
    }];
    let c2 = vec![EpochCreditEntry {
        epoch: 1,
        credits: 50,
        prev_credits: 0,
    }];

    let stakes = vec![(s1, c1), (s2, c2)];
    let total = rewards::calculate_total_points(&stakes, |stake, _epoch| {
        stake.delegation.stake_amount
    });

    // s1: 1000 * 100 = 100_000, s2: 2000 * 50 = 100_000
    assert_eq!(total, 200_000);
}

// -- StakeTracker tests --

#[test]
fn tracker_aggregates_stake_by_voter() {
    let mut tracker = StakeTracker::new(10);
    let voter1 = Pubkey::new_unique();
    let voter2 = Pubkey::new_unique();

    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 1000, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 500, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter2, 800, 0));

    assert_eq!(tracker.total_stake_for_voter(&voter1), 1500);
    assert_eq!(tracker.total_stake_for_voter(&voter2), 800);
    assert_eq!(tracker.total_stake(), 2300);
}

#[test]
fn tracker_provides_stake_by_vote_account_map() {
    let mut tracker = StakeTracker::new(10);
    let voter1 = Pubkey::new_unique();
    let voter2 = Pubkey::new_unique();

    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 1000, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 500, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter2, 800, 0));

    let stakes = tracker.stake_by_vote_account();
    assert_eq!(stakes.get(&voter1), Some(&1500));
    assert_eq!(stakes.get(&voter2), Some(&800));
}

#[test]
fn tracker_removes_delegation() {
    let mut tracker = StakeTracker::new(10);
    let voter = Pubkey::new_unique();
    let stake_key = Pubkey::new_unique();

    tracker.add_delegation(stake_key, Delegation::new(voter, 1000, 0));
    assert_eq!(tracker.delegation_count(), 1);

    tracker.remove_delegation(&stake_key);
    assert_eq!(tracker.delegation_count(), 0);
}

#[test]
fn tracker_lists_delegations_for_voter() {
    let mut tracker = StakeTracker::new(10);
    let voter1 = Pubkey::new_unique();
    let voter2 = Pubkey::new_unique();

    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 1000, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter1, 500, 0));
    tracker.add_delegation(Pubkey::new_unique(), Delegation::new(voter2, 800, 0));

    assert_eq!(tracker.delegations_for_voter(&voter1).len(), 2);
    assert_eq!(tracker.delegations_for_voter(&voter2).len(), 1);
}

// -- StakeError tests --

#[test]
fn stake_error_display_formats() {
    assert_eq!(format!("{}", StakeError::LockupInForce), "lockup in force");
    assert_eq!(
        format!("{}", StakeError::InsufficientStake),
        "insufficient stake"
    );
}

#[test]
fn stake_error_codes_match_constants() {
    assert_eq!(StakeError::NoCreditsToRedeem.to_error_code(), 0);
    assert_eq!(StakeError::LockupInForce.to_error_code(), 1);
    assert_eq!(StakeError::AlreadyDeactivated.to_error_code(), 2);
    assert_eq!(StakeError::EpochRewardsActive.to_error_code(), 16);
}
