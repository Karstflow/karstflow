//! Inflation start slot derivation.
//!
//! Inflation does not begin at slot 0 on a cluster that switched it on partway
//! through its life. The rate curve is a function of elapsed time *since
//! inflation started*, so the epoch reward amount depends on locating that
//! start slot, and the start slot is carried by the activation slots of three
//! features rather than by a boolean any of them expose.
//!
//! The earliest activation slot among the full-inflation triggers wins; absent
//! those, `pico_inflation`'s slot; absent that, slot 0. The result is then
//! aligned back to the first slot of the epoch *preceding* the one it lands in,
//! which is the value the reward calculation consumes.

use crate::epoch_schedule::EpochSchedule;
use crate::features::{known_features, FeatureSet};

/// Slot at which inflation began, from the feature activation slots.
///
/// Returns the earliest activation slot among the features that trigger full
/// inflation, falling back to `pico_inflation`'s activation slot, and finally
/// to `0` when none of them has activated.
///
/// Full inflation is triggered by a *pair* — both `full_inflation_vote` and
/// `full_inflation_enable` must be active, and the slot taken is `enable`'s —
/// or, independently, by `devnet_and_testnet`.
pub fn inflation_start_slot(features: &FeatureSet) -> u64 {
    let paired_full_inflation = (features.is_active(&known_features::full_inflation_vote())
        && features.is_active(&known_features::full_inflation_enable()))
    .then(|| features.activated_slot(&known_features::full_inflation_enable()))
    .flatten();

    let devnet_and_testnet = features.activated_slot(&known_features::devnet_and_testnet());

    match (paired_full_inflation, devnet_and_testnet) {
        (Some(paired), Some(devnet)) => paired.min(devnet),
        (Some(slot), None) | (None, Some(slot)) => slot,
        (None, None) => features
            .activated_slot(&known_features::pico_inflation())
            .unwrap_or(0),
    }
}

/// Inflation start slot aligned to the reward accrual boundary.
///
/// Rewards accrue from the first slot of the epoch *before* the epoch in which
/// inflation started, so an activation partway through an epoch does not
/// produce a partial first accrual period.
pub fn inflation_start_slot_aligned_to_rewards(
    features: &FeatureSet,
    epoch_schedule: &EpochSchedule,
) -> u64 {
    let start_slot = inflation_start_slot(features);
    let start_epoch = epoch_schedule.get_epoch(start_slot);
    epoch_schedule.get_first_slot_in_epoch(start_epoch.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_schedule::{EpochSchedule, EpochScheduleConfig};

    fn schedule() -> EpochSchedule {
        EpochSchedule::default()
    }

    #[test]
    fn no_inflation_feature_active_starts_at_zero() {
        let features = FeatureSet::with_known_features();

        assert_eq!(inflation_start_slot(&features), 0);
    }

    #[test]
    fn pico_inflation_alone_supplies_the_start_slot() {
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::pico_inflation(), 5_000);

        assert_eq!(inflation_start_slot(&features), 5_000);
    }

    #[test]
    fn devnet_and_testnet_supplies_the_start_slot() {
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::devnet_and_testnet(), 900);

        assert_eq!(inflation_start_slot(&features), 900);
    }

    #[test]
    fn full_inflation_needs_both_halves_of_the_pair() {
        // `enable` on its own must not trigger full inflation; without `vote`
        // the pair is incomplete and the fallback applies.
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::full_inflation_enable(), 700);
        features.activate(known_features::pico_inflation(), 5_000);

        assert_eq!(
            inflation_start_slot(&features),
            5_000,
            "an unpaired `enable` must not supply the start slot"
        );

        features.activate(known_features::full_inflation_vote(), 1_000_000);

        assert_eq!(
            inflation_start_slot(&features),
            700,
            "once paired, `enable`'s slot wins over pico"
        );
    }

    #[test]
    fn earliest_full_inflation_trigger_wins() {
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::full_inflation_vote(), 0);
        features.activate(known_features::full_inflation_enable(), 8_000);
        features.activate(known_features::devnet_and_testnet(), 3_000);

        assert_eq!(inflation_start_slot(&features), 3_000);
    }

    #[test]
    fn full_inflation_takes_precedence_over_pico() {
        // pico is earlier in slot terms, but a full-inflation trigger outranks
        // it regardless of ordering.
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::pico_inflation(), 10);
        features.activate(known_features::devnet_and_testnet(), 90_000);

        assert_eq!(inflation_start_slot(&features), 90_000);
    }

    #[test]
    fn all_features_active_at_zero_starts_at_zero() {
        // Dev-mode genesis activates every feature at slot 0, which must land
        // on the same answer as no features at all.
        let features = FeatureSet::all_active();

        assert_eq!(inflation_start_slot(&features), 0);
    }

    #[test]
    fn alignment_backs_up_one_epoch_from_the_activation_epoch() {
        let schedule = schedule();
        let slots_per_epoch = schedule.get_slots_in_epoch(10);

        // Activate partway through a normal epoch well past warmup.
        let activation_epoch = 10;
        let activation_slot = schedule.get_first_slot_in_epoch(activation_epoch) + 17;

        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::devnet_and_testnet(), activation_slot);

        let aligned = inflation_start_slot_aligned_to_rewards(&features, &schedule);

        assert_eq!(
            aligned,
            schedule.get_first_slot_in_epoch(activation_epoch - 1),
            "alignment must land on the first slot of the preceding epoch"
        );
        assert!(
            aligned + slots_per_epoch <= activation_slot,
            "aligned start must precede the activation slot by at least an epoch"
        );
    }

    #[test]
    fn alignment_saturates_at_epoch_zero() {
        // An activation inside epoch 0 has no preceding epoch to back up into.
        let schedule = schedule();
        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::devnet_and_testnet(), 1);

        assert_eq!(
            inflation_start_slot_aligned_to_rewards(&features, &schedule),
            0
        );
    }

    #[test]
    fn alignment_of_an_unactivated_set_is_zero() {
        let schedule = schedule();
        let features = FeatureSet::with_known_features();

        assert_eq!(
            inflation_start_slot_aligned_to_rewards(&features, &schedule),
            0
        );
    }

    #[test]
    fn alignment_uses_the_schedule_it_is_given() {
        // A different epoch length must move the aligned boundary; otherwise the
        // schedule argument is decorative.
        let short = EpochSchedule::new(EpochScheduleConfig {
            slots_per_epoch: 64,
            warmup: false,
            ..EpochScheduleConfig::default()
        });
        let long = EpochSchedule::new(EpochScheduleConfig {
            slots_per_epoch: 8_192,
            warmup: false,
            ..EpochScheduleConfig::default()
        });

        let mut features = FeatureSet::with_known_features();
        features.activate(known_features::devnet_and_testnet(), 20_000);

        assert_ne!(
            inflation_start_slot_aligned_to_rewards(&features, &short),
            inflation_start_slot_aligned_to_rewards(&features, &long),
        );
    }
}
