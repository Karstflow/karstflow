//! Constants for compiled program cache.

/// Default maximum entries in program cache.
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 256;

/// Maximum size of a single cached program (bytes).
pub const MAX_PROGRAM_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Cache eviction threshold (percentage of max before eviction).
pub const EVICTION_THRESHOLD_PERCENT: usize = 90;
