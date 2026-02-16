//! Constants for persistent ledger storage (blockstore).

/// Maximum shreds per slot (data + coding).
pub const MAX_SHREDS_PER_SLOT: usize = 32_768;

/// Maximum data shreds per slot.
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 16_384;

/// Maximum coding shreds per slot.
pub const MAX_CODING_SHREDS_PER_SLOT: usize = 16_384;

/// Number of roots to retain before pruning.
pub const DEFAULT_ROOTS_TO_RETAIN: u64 = 1_000;

/// Column family name for slot metadata.
pub const CF_SLOT_META: &str = "slot_meta";

/// Column family name for data shreds.
pub const CF_DATA_SHRED: &str = "data_shred";

/// Column family name for coding shreds.
pub const CF_CODE_SHRED: &str = "code_shred";

/// Column family name for dead slots.
pub const CF_DEAD_SLOTS: &str = "dead_slots";

/// Column family name for duplicate slots.
pub const CF_DUPLICATE_SLOTS: &str = "duplicate_slots";

/// Column family name for roots.
pub const CF_ROOTS: &str = "roots";

/// Column family name for erasure coding metadata.
pub const CF_ERASURE_META: &str = "erasure_meta";

/// Column family name for block height records.
pub const CF_BLOCK_HEIGHT: &str = "block_height";

/// Maximum block assembly attempts before marking dead.
pub const MAX_BLOCK_ASSEMBLY_RETRIES: usize = 3;
