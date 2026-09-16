//! Feature activation logic.
//!
//! Handles the process of scanning feature accounts and activating
//! features at the appropriate slot. Feature activation is checked
//! once per slot during bank processing.

use super::FeatureSet;
use karstflow_types::Pubkey;

/// Represents a pending or completed feature activation.
#[derive(Debug, Clone)]
pub struct FeatureActivation {
    /// Unique identifier for this feature (also the feature account address).
    pub feature_id: Pubkey,
    /// Slot at which this feature was activated; `None` if still pending.
    pub activation_slot: Option<u64>,
    /// Human-readable description of what this feature does.
    pub description: &'static str,
    /// Whether the feature has been cleaned up (behavior hardcoded into the runtime).
    /// Cleaned-up features are always active regardless of on-chain state.
    pub cleaned_up: bool,
    /// Whether the feature has been reverted upstream — permanently abandoned
    /// and never to activate. For a reverted feature, the absence of its
    /// behavior is correct rather than a gap.
    pub reverted: bool,
}

/// Process feature activations for the given slot.
///
/// Iterates over all inactive features in the set and checks whether
/// their corresponding on-chain account exists. If so, the feature
/// is activated at the current slot.
///
/// The `feature_account_exists` callback should return `true` if the
/// feature account has been created on-chain (indicating a stake-
/// weighted activation vote).
pub fn process_feature_activations(
    feature_set: &mut FeatureSet,
    slot: u64,
    feature_account_exists: &dyn Fn(&Pubkey) -> bool,
) {
    // Collect inactive features that should be activated.
    // We collect first to avoid borrowing conflicts.
    let to_activate: Vec<Pubkey> = feature_set
        .inactive_features()
        .filter(|id| feature_account_exists(id))
        .copied()
        .collect();

    for feature_id in to_activate {
        feature_set.activate(feature_id, slot);
    }
}

/// Rent parameters after applying every activation hook that fires in this slot.
///
/// Returns `None` when no hook fires, which is the case for all but a handful of
/// slots in the chain's lifetime.
///
/// These features are not gates. A gate is read on every execution and branches;
/// these rewrite the bank's rent parameters once, in the slot they activate, and
/// every later slot inherits the rewritten value. That is why they key off
/// [`FeatureSet::just_activated`] rather than `is_active`.
///
/// The blocks are independent rather than exclusive, so more than one can fire in
/// a single slot and the later write to a field wins. The order below is
/// transcribed from the reference implementation and is load-bearing:
/// `deprecate_rent_exemption_threshold` scales `lamports_per_byte_year`, and a
/// `set_lamports_per_byte_to_*` feature activating in the same slot overwrites
/// that same field afterwards.
pub fn rent_after_activation_hooks(
    feature_set: &FeatureSet,
    slot: u64,
    rent: crate::Rent,
) -> Option<crate::Rent> {
    use crate::features::known_features as kf;
    use karstflow_constants::economics as econ;

    let mut updated = rent;
    let mut changed = false;

    // SIMD-0194: fold the exemption threshold into the per-byte rate, then flatten
    // the threshold. The bank's burn percentage is set here too because on the
    // live clusters it differs from the sysvar's, and the sysvar inherits it at
    // activation.
    if feature_set.just_activated(&kf::deprecate_rent_exemption_threshold(), slot) {
        updated.lamports_per_byte_year =
            (updated.lamports_per_byte_year as f64 * updated.exemption_threshold) as u64;
        updated.exemption_threshold = econ::SIMD_0194_EXEMPTION_THRESHOLD;
        updated.burn_percent = econ::SIMD_0194_BURN_PERCENT;
        changed = true;
    }

    // SIMD-0437 steps the per-byte rate down, then SIMD-0438 restores the legacy
    // value if the reduction has to be undone. Listed in activation order.
    let per_byte_features = [
        (
            kf::set_lamports_per_byte_to_6333(),
            econ::LAMPORTS_PER_BYTE_YEAR_6333,
        ),
        (
            kf::set_lamports_per_byte_to_5080(),
            econ::LAMPORTS_PER_BYTE_YEAR_5080,
        ),
        (
            kf::set_lamports_per_byte_to_2575(),
            econ::LAMPORTS_PER_BYTE_YEAR_2575,
        ),
        (
            kf::set_lamports_per_byte_to_1322(),
            econ::LAMPORTS_PER_BYTE_YEAR_1322,
        ),
        (
            kf::set_lamports_per_byte_to_696(),
            econ::LAMPORTS_PER_BYTE_YEAR_696,
        ),
        (
            kf::set_lamports_per_byte_to_6960(),
            econ::LAMPORTS_PER_BYTE_YEAR_6960,
        ),
    ];
    for (feature_id, lamports_per_byte_year) in per_byte_features {
        if feature_set.just_activated(&feature_id, slot) {
            updated.lamports_per_byte_year = lamports_per_byte_year;
            changed = true;
        }
    }

    changed.then_some(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_types::Pubkey;

    fn test_pubkey(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    #[test]
    fn activates_features_whose_accounts_exist() {
        let mut fs = FeatureSet::new();
        let f1 = test_pubkey(1);
        let f2 = test_pubkey(2);
        fs.inactive.insert(f1);
        fs.inactive.insert(f2);

        let existing = [f1];
        process_feature_activations(&mut fs, 100, &|id| existing.contains(id));

        assert!(fs.is_active(&f1));
        assert_eq!(fs.activated_slot(&f1), Some(100));
        assert!(!fs.is_active(&f2));
        assert_eq!(fs.inactive_count(), 1);
    }

    #[test]
    fn noop_when_no_features_match() {
        let mut fs = FeatureSet::new();
        let f1 = test_pubkey(1);
        fs.inactive.insert(f1);

        process_feature_activations(&mut fs, 50, &|_| false);

        assert!(!fs.is_active(&f1));
        assert_eq!(fs.inactive_count(), 1);
    }

    #[test]
    fn activates_all_when_all_accounts_exist() {
        let mut fs = FeatureSet::new();
        let f1 = test_pubkey(1);
        let f2 = test_pubkey(2);
        let f3 = test_pubkey(3);
        fs.inactive.insert(f1);
        fs.inactive.insert(f2);
        fs.inactive.insert(f3);

        process_feature_activations(&mut fs, 200, &|_| true);

        assert!(fs.is_active(&f1));
        assert!(fs.is_active(&f2));
        assert!(fs.is_active(&f3));
        assert_eq!(fs.inactive_count(), 0);
        assert_eq!(fs.active_count(), 3);
    }

    #[test]
    fn does_not_reactivate_already_active_features() {
        let mut fs = FeatureSet::new();
        let f1 = test_pubkey(1);
        fs.activate(f1, 10);

        process_feature_activations(&mut fs, 50, &|_| true);

        assert_eq!(fs.activated_slot(&f1), Some(10));
    }

    #[test]
    fn empty_inactive_set_is_noop() {
        let mut fs = FeatureSet::new();
        process_feature_activations(&mut fs, 100, &|_| true);
        assert_eq!(fs.active_count(), 0);
    }

    // -- Activation hooks --------------------------------------------------
    //
    // Every feature set below is built explicitly. The dev-mode default
    // activates everything at slot 0, under which a hook that fires once and a
    // hook that fires every slot are indistinguishable.

    use crate::features::known_features as kf;
    use karstflow_constants::economics as econ;

    /// A feature set with exactly the given features activated at `slot`.
    fn activated_at(slot: u64, features: &[karstflow_types::Pubkey]) -> FeatureSet {
        let mut fs = FeatureSet::new();
        for id in features {
            fs.activate(*id, slot);
        }
        fs
    }

    fn default_rent() -> crate::Rent {
        crate::Rent::default_config()
    }

    #[test]
    fn just_activated_is_true_only_in_the_activation_slot() {
        let mut fs = FeatureSet::new();
        let id = test_pubkey(7);
        fs.activate(id, 10);

        assert!(fs.just_activated(&id, 10));
        // The distinguishing assertion: `is_active` stays true forever, so a
        // hook keyed off it would re-fire on every later slot.
        assert!(!fs.just_activated(&id, 11));
        assert!(fs.is_active(&id));
    }

    #[test]
    fn just_activated_is_false_for_an_unknown_feature() {
        let fs = FeatureSet::new();
        assert!(!fs.just_activated(&test_pubkey(7), 10));
    }

    #[test]
    fn no_hook_fires_when_nothing_activated_in_this_slot() {
        let fs = activated_at(5, &[kf::deprecate_rent_exemption_threshold()]);
        // Active, but activated in slot 5 — slot 6 must leave rent untouched.
        assert_eq!(rent_after_activation_hooks(&fs, 6, default_rent()), None);
        assert_eq!(
            rent_after_activation_hooks(&FeatureSet::new(), 6, default_rent()),
            None
        );
    }

    #[test]
    fn simd_0194_folds_the_threshold_into_the_per_byte_rate() {
        let fs = activated_at(3, &[kf::deprecate_rent_exemption_threshold()]);
        let updated = rent_after_activation_hooks(&fs, 3, default_rent()).expect("hook fires");

        // 3480 * 2.0 — the exemption cost is unchanged, it just moves out of the
        // multiplier and into the rate.
        assert_eq!(updated.lamports_per_byte_year, 6_960);
        assert_eq!(updated.exemption_threshold, 1.0);
        assert_eq!(updated.burn_percent, 50);
        assert_eq!(
            updated.minimum_balance(100),
            default_rent().minimum_balance(100),
            "folding the multiplier must not move the exemption minimum"
        );
    }

    #[test]
    fn each_set_lamports_per_byte_feature_sets_its_own_value() {
        let cases = [
            (
                kf::set_lamports_per_byte_to_6333(),
                econ::LAMPORTS_PER_BYTE_YEAR_6333,
            ),
            (
                kf::set_lamports_per_byte_to_5080(),
                econ::LAMPORTS_PER_BYTE_YEAR_5080,
            ),
            (
                kf::set_lamports_per_byte_to_2575(),
                econ::LAMPORTS_PER_BYTE_YEAR_2575,
            ),
            (
                kf::set_lamports_per_byte_to_1322(),
                econ::LAMPORTS_PER_BYTE_YEAR_1322,
            ),
            (
                kf::set_lamports_per_byte_to_696(),
                econ::LAMPORTS_PER_BYTE_YEAR_696,
            ),
            (
                kf::set_lamports_per_byte_to_6960(),
                econ::LAMPORTS_PER_BYTE_YEAR_6960,
            ),
        ];
        for (id, expected) in cases {
            let fs = activated_at(9, &[id]);
            let updated = rent_after_activation_hooks(&fs, 9, default_rent()).expect("hook fires");
            assert_eq!(updated.lamports_per_byte_year, expected);
            // Only the rate moves; these features do not touch the threshold.
            assert_eq!(
                updated.exemption_threshold,
                default_rent().exemption_threshold
            );
        }
    }

    #[test]
    fn hooks_firing_in_one_slot_apply_in_reference_order() {
        // Nothing prevents several of these activating together, and the blocks
        // are independent rather than exclusive, so the last write to the rate
        // wins. 6960 is listed after 6333, so 6960 is the surviving value.
        let fs = activated_at(
            4,
            &[
                kf::deprecate_rent_exemption_threshold(),
                kf::set_lamports_per_byte_to_6333(),
                kf::set_lamports_per_byte_to_6960(),
            ],
        );
        let updated = rent_after_activation_hooks(&fs, 4, default_rent()).expect("hooks fire");

        assert_eq!(
            updated.lamports_per_byte_year,
            econ::LAMPORTS_PER_BYTE_YEAR_6960
        );
        // SIMD-0194's other two writes are not overwritten by the rate features.
        assert_eq!(updated.exemption_threshold, 1.0);
        assert_eq!(updated.burn_percent, econ::SIMD_0194_BURN_PERCENT);
    }
}
