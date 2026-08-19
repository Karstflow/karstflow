//! Feature gate system for runtime behavior control.
//!
//! Features are activated by slot number and control runtime behavior
//! changes across the network. Once activated, a feature cannot be
//! deactivated. The feature set is per-bank state that tracks which
//! features are currently active and at what slot they were enabled.

mod activation;
pub mod core_bpf_migration;
pub mod core_bpf_upgrade;
pub mod known_features;

#[cfg(test)]
mod tests;

pub use activation::{process_feature_activations, rent_after_activation_hooks, FeatureActivation};

use karstflow_types::Pubkey;
use std::collections::{HashMap, HashSet};

/// Set of active and inactive features for a given bank.
///
/// Each feature is identified by a unique `Pubkey`. When a feature
/// account is created on-chain, the runtime activates the corresponding
/// feature at the current slot. After activation, the feature remains
/// permanently active.
#[derive(Debug, Clone)]
pub struct FeatureSet {
    /// Features that have been activated, mapped to their activation slot.
    active: HashMap<Pubkey, u64>,
    /// Features that are known but not yet activated.
    inactive: HashSet<Pubkey>,
}

impl FeatureSet {
    /// Create an empty feature set with no known features.
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            inactive: HashSet::new(),
        }
    }

    /// Create a feature set with all known features registered as inactive.
    pub fn with_known_features() -> Self {
        let all = known_features::all_known_features();
        let inactive: HashSet<Pubkey> = all.iter().map(|f| f.feature_id).collect();

        Self {
            active: HashMap::new(),
            inactive,
        }
    }

    /// Create a feature set with all known features active at slot 0.
    ///
    /// Useful for testing where all features should be enabled.
    pub fn all_active() -> Self {
        let all = known_features::all_known_features();
        let active: HashMap<Pubkey, u64> = all.iter().map(|f| (f.feature_id, 0)).collect();

        Self {
            active,
            inactive: HashSet::new(),
        }
    }

    /// Check whether the given feature is currently active.
    pub fn is_active(&self, feature_id: &Pubkey) -> bool {
        self.active.contains_key(feature_id)
    }

    /// Get the slot at which the given feature was activated.
    ///
    /// Returns `None` if the feature has not been activated.
    pub fn activated_slot(&self, feature_id: &Pubkey) -> Option<u64> {
        self.active.get(feature_id).copied()
    }

    /// Whether the given feature activated in exactly this slot.
    ///
    /// Distinct from [`is_active`](Self::is_active), which stays true for every
    /// later slot. Some features are not branches but one-shot state mutations
    /// applied at the boundary they activate on; those need to fire once and
    /// never again, which is what this answers.
    pub fn just_activated(&self, feature_id: &Pubkey, slot: u64) -> bool {
        self.activated_slot(feature_id) == Some(slot)
    }

    /// Activate a feature at the specified slot.
    ///
    /// Moves the feature from inactive to active. If the feature is
    /// not in the inactive set, it is still recorded as active.
    pub fn activate(&mut self, feature_id: Pubkey, slot: u64) {
        self.inactive.remove(&feature_id);
        self.active.insert(feature_id, slot);
    }

    /// Get the number of currently active features.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Get the number of known but inactive features.
    pub fn inactive_count(&self) -> usize {
        self.inactive.len()
    }

    /// Iterate over all active features and their activation slots.
    pub fn active_features(&self) -> impl Iterator<Item = (&Pubkey, &u64)> {
        self.active.iter()
    }

    /// Check whether a feature was active at or before a specific slot.
    ///
    /// Returns `true` if the feature was activated at a slot less than
    /// or equal to the given slot.
    pub fn was_active_at_slot(&self, feature_id: &Pubkey, slot: u64) -> bool {
        self.active
            .get(feature_id)
            .is_some_and(|&activation_slot| activation_slot <= slot)
    }

    /// Get all inactive feature IDs.
    pub fn inactive_features(&self) -> impl Iterator<Item = &Pubkey> {
        self.inactive.iter()
    }
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self::new()
    }
}
