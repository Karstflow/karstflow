//! Constants for the feature gate system.
//!
//! Features control runtime behavior changes across the network.
//! Once activated at a given slot, a feature cannot be deactivated.

/// Number of slots after activation before a feature takes effect.
pub const FEATURE_ACTIVATION_DELAY_SLOTS: u64 = 0;

/// Maximum number of concurrently active features.
pub const MAX_ACTIVE_FEATURES: usize = 1000;
