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
