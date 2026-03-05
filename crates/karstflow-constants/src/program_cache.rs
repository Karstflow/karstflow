//! Constants for compiled program cache.

/// Default maximum entries in program cache.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 256;

/// Maximum size of a single cached program (bytes).
pub const MAX_PROGRAM_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Cache eviction threshold (percentage of max before eviction).
pub const EVICTION_THRESHOLD_PERCENT: usize = 90;

/// Slot offset applied to program deployments for visibility delay.
///
/// A program deployed at slot N becomes visible at slot N + offset.
/// This ensures deployed programs are validated against the feature set
/// of the next slot, which matters at epoch boundaries where features
/// activate.
pub const DELAY_VISIBILITY_SLOT_OFFSET: u64 = 1;
