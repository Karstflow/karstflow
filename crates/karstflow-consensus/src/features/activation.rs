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
}
