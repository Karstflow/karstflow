// Constants for the persistent storage backend.

// Column family names

/// Column family for published account records (key=pubkey, value=encoded account).
pub const CF_ACCOUNTS: &str = "accounts";

/// Column family for account metadata (owner index, slot tracking).
pub const CF_ACCOUNT_META: &str = "account_meta";

/// Column family for general key-value metadata.
pub const CF_METADATA: &str = "metadata";

/// Column family for slot metadata in the persistent blockstore.
pub const CF_SLOT_META: &str = "slot_meta";

/// Column family for persisted data shreds.
pub const CF_DATA_SHRED: &str = "data_shred";

/// Column family for persisted coding shreds.
pub const CF_CODE_SHRED: &str = "code_shred";

/// Column family for root slot markers.
pub const CF_ROOTS: &str = "roots";

/// Column family for dead slot markers.
pub const CF_DEAD_SLOTS: &str = "dead_slots";

/// Column family for duplicate slot markers.
pub const CF_DUPLICATE_SLOTS: &str = "duplicate_slots";

/// Column family for erasure coding metadata.
pub const CF_ERASURE_META: &str = "erasure_meta";

/// Column family for block height records.
pub const CF_BLOCK_HEIGHT: &str = "block_height";

// Metadata keys (stored in CF_METADATA)

/// Key for the latest persisted slot number.
pub const META_KEY_LATEST_SLOT: &[u8] = b"latest_slot";

/// Key for the total persisted account count.
pub const META_KEY_ACCOUNT_COUNT: &[u8] = b"account_count";

/// Key for total lamports across all persisted accounts.
pub const META_KEY_TOTAL_LAMPORTS: &[u8] = b"total_lamports";

/// Key for the SHA-256 state hash at the latest persisted slot.
pub const META_KEY_STATE_HASH: &[u8] = b"state_hash";

// Limits and defaults

/// Maximum number of key-value pairs in a single write batch.
pub const MAX_WRITE_BATCH_SIZE: usize = 10_000;

/// Default storage cache size (256 MB).
pub const DEFAULT_CACHE_SIZE_BYTES: u64 = 256 * 1024 * 1024;

/// Default flush interval in milliseconds.
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1_000;

/// Fanout factor for the accounts Merkle hash tree.
///
/// All per-account SHA-256 hashes are divided into this many chunks,
/// each chunk is hashed separately, and the chunk hashes are combined
/// to produce the final accounts hash.
pub const ACCOUNTS_HASH_FANOUT: usize = 16;

/// All standard column families created on database open.
pub const STANDARD_COLUMN_FAMILIES: &[&str] = &[
    CF_ACCOUNTS,
    CF_ACCOUNT_META,
    CF_METADATA,
    CF_SLOT_META,
    CF_DATA_SHRED,
    CF_CODE_SHRED,
    CF_ROOTS,
    CF_DEAD_SLOTS,
    CF_DUPLICATE_SLOTS,
    CF_ERASURE_META,
    CF_BLOCK_HEIGHT,
];
