/// Default number of entries in the transaction dedup cache.
/// Must be a power of 2 for efficient ring indexing.
/// 4M entries at 8 bytes per tag uses ~32 MB for the ring buffer
/// plus ~64 MB for the sparse hash map (2x sparsity).
pub const DEFAULT_CACHE_DEPTH: usize = 4_194_304; // 2^22

/// Sparsity factor for the open-addressing hash map relative to the
/// ring buffer depth. Map capacity = depth * SPARSE_FACTOR.
/// Higher values reduce collision rates at the cost of memory.
pub const SPARSE_FACTOR: u32 = 2;

/// Sentinel value representing an empty slot in the hash map.
/// Tags equal to this value are treated as always-unique and never
/// stored, since they would be indistinguishable from empty slots.
pub const NULL_TAG: u64 = 0;
