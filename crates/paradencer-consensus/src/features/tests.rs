//! Tests for the feature gate system.

use super::known_features;
use super::*;
use paradencer_types::Pubkey;

#[test]
fn create_empty_feature_set() {
    let fs = FeatureSet::new();
    assert_eq!(fs.active_count(), 0);
    assert_eq!(fs.inactive_count(), 0);
}

#[test]
fn activate_feature() {
    let mut fs = FeatureSet::new();
    let feature = Pubkey::new_unique();

    fs.activate(feature, 100);

    assert!(fs.is_active(&feature));
    assert_eq!(fs.active_count(), 1);
}

#[test]
fn is_active_returns_true_after_activation() {
    let mut fs = FeatureSet::new();
    let feature = Pubkey::new_unique();

    assert!(!fs.is_active(&feature));
    fs.activate(feature, 50);
    assert!(fs.is_active(&feature));
}

#[test]
fn is_active_returns_false_for_unknown_feature() {
    let fs = FeatureSet::new();
    let unknown = Pubkey::new_unique();

    assert!(!fs.is_active(&unknown));
}

#[test]
fn activated_slot_returns_correct_slot() {
    let mut fs = FeatureSet::new();
    let feature = Pubkey::new_unique();

    assert_eq!(fs.activated_slot(&feature), None);

    fs.activate(feature, 42);
    assert_eq!(fs.activated_slot(&feature), Some(42));
}

#[test]
fn was_active_at_slot_checks_correctly() {
    let mut fs = FeatureSet::new();
    let feature = Pubkey::new_unique();

    fs.activate(feature, 100);

    // Active at the exact activation slot
    assert!(fs.was_active_at_slot(&feature, 100));
    // Active at a later slot
    assert!(fs.was_active_at_slot(&feature, 200));
    // Not active before the activation slot
    assert!(!fs.was_active_at_slot(&feature, 99));
    // Not active for unknown feature
    assert!(!fs.was_active_at_slot(&Pubkey::new_unique(), 200));
}

#[test]
fn all_active_creates_fully_activated_set() {
    let fs = FeatureSet::all_active();

    // All known features should be active at slot 0
    let known = known_features::all_known_features();
    assert!(known.len() > 0);

    for feature in &known {
        assert!(
            fs.is_active(&feature.feature_id),
            "Feature '{}' should be active in all_active set",
            feature.description
        );
        assert_eq!(fs.activated_slot(&feature.feature_id), Some(0));
    }

    assert_eq!(fs.inactive_count(), 0);
}

#[test]
fn with_known_features_registers_all_inactive() {
    let fs = FeatureSet::with_known_features();
    let known = known_features::all_known_features();

    assert_eq!(fs.active_count(), 0);
    assert_eq!(fs.inactive_count(), known.len());

    for feature in &known {
        assert!(!fs.is_active(&feature.feature_id));
    }
}

#[test]
fn activate_moves_from_inactive_to_active() {
    let mut fs = FeatureSet::with_known_features();
    let known = known_features::all_known_features();
    let initial_inactive = fs.inactive_count();

    assert!(initial_inactive > 0);

    let feature_id = known[0].feature_id;
    fs.activate(feature_id, 500);

    assert!(fs.is_active(&feature_id));
    assert_eq!(fs.active_count(), 1);
    assert_eq!(fs.inactive_count(), initial_inactive - 1);
}

#[test]
fn process_feature_activations_activates_existing_accounts() {
    let mut fs = FeatureSet::with_known_features();
    let known = known_features::all_known_features();

    // Simulate that the first 3 feature accounts exist on-chain
    let existing_features: std::collections::HashSet<Pubkey> =
        known.iter().take(3).map(|f| f.feature_id).collect();

    process_feature_activations(&mut fs, 100, &|id| existing_features.contains(id));

    assert_eq!(fs.active_count(), 3);
    for feature in known.iter().take(3) {
        assert!(fs.is_active(&feature.feature_id));
        assert_eq!(fs.activated_slot(&feature.feature_id), Some(100));
    }

    // Remaining features should still be inactive
    for feature in known.iter().skip(3) {
        assert!(!fs.is_active(&feature.feature_id));
    }
}

#[test]
fn process_feature_activations_no_op_when_no_accounts() {
    let mut fs = FeatureSet::with_known_features();
    let initial_active = fs.active_count();
    let initial_inactive = fs.inactive_count();

    process_feature_activations(&mut fs, 50, &|_| false);

    assert_eq!(fs.active_count(), initial_active);
    assert_eq!(fs.inactive_count(), initial_inactive);
}

#[test]
fn feature_id_is_deterministic() {
    let id1 = known_features::feature_id("test_feature");
    let id2 = known_features::feature_id("test_feature");
    assert_eq!(id1, id2);
}

#[test]
fn different_names_produce_different_ids() {
    let id1 = known_features::feature_id("feature_a");
    let id2 = known_features::feature_id("feature_b");
    assert_ne!(id1, id2);
}

#[test]
fn known_features_are_unique() {
    let features = known_features::all_known_features();
    let ids: std::collections::HashSet<Pubkey> = features.iter().map(|f| f.feature_id).collect();

    assert_eq!(ids.len(), features.len(), "Duplicate feature IDs detected");
}

#[test]
fn active_features_iterator() {
    let mut fs = FeatureSet::new();
    let f1 = Pubkey::new_unique();
    let f2 = Pubkey::new_unique();

    fs.activate(f1, 10);
    fs.activate(f2, 20);

    let active: Vec<_> = fs.active_features().collect();
    assert_eq!(active.len(), 2);
}

#[test]
fn double_activate_updates_slot() {
    let mut fs = FeatureSet::new();
    let feature = Pubkey::new_unique();

    fs.activate(feature, 100);
    assert_eq!(fs.activated_slot(&feature), Some(100));

    fs.activate(feature, 200);
    assert_eq!(fs.activated_slot(&feature), Some(200));
    assert_eq!(fs.active_count(), 1);
}
