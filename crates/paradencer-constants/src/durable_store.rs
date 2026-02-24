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

// File format constants

/// Magic number at the start of each column family file ("PDFS" in ASCII).
pub const CF_FILE_MAGIC: u32 = 0x5044_4653;

/// Current file format version (v2 = CRC32 checksums).
pub const CF_FILE_FORMAT_VERSION: u16 = 2;

/// Size of the per-file header: magic(4) + version(2) + flags(2) + reserved(8).
pub const CF_FILE_HEADER_SIZE: usize = 16;

// Record format constants

/// Size of each record header: crc32(4) + status(1) + key_len(4) + value_len(4).
pub const RECORD_HEADER_SIZE: usize = 13;

/// Record status: active key-value pair.
pub const RECORD_STATUS_ACTIVE: u8 = 0;

/// Record status: tombstone marking a deleted key.
pub const RECORD_STATUS_DELETED: u8 = 1;

/// Maximum value size per record (256 MB).
pub const MAX_RECORD_VALUE_SIZE: u32 = 256 * 1024 * 1024;

// Write-Ahead Log constants

/// Sentinel value marking a complete WAL entry.
pub const WAL_ENTRY_SENTINEL: u32 = 0x454E_4421; // "END!"

/// WAL operation type: put a key-value pair.
pub const WAL_OP_PUT: u8 = 0;

/// WAL operation type: delete a key.
pub const WAL_OP_DELETE: u8 = 1;

/// WAL file name within the data directory.
pub const WAL_FILE_NAME: &str = "wal.log";

// Compaction thresholds

/// Dead space ratio above which compaction is recommended (50%).
pub const COMPACTION_DEAD_SPACE_RATIO: f64 = 0.5;

/// Minimum dead bytes before compaction is worth attempting (1 MB).
/// Avoids compacting tiny files where the overhead exceeds the benefit.
pub const COMPACTION_MIN_DEAD_BYTES: u64 = 1024 * 1024;

/// Default auto-compaction check interval in milliseconds (60 seconds).
pub const AUTO_COMPACTION_INTERVAL_MS: u64 = 60_000;

/// Default maximum entries in the published account LRU cache.
///
/// With average ~200 bytes per account, 1M entries ≈ 200 MB of cached
/// account data in memory. Accounts beyond this limit are served from disk.
pub const DEFAULT_PUBLISHED_CACHE_MAX_ENTRIES: usize = 1_000_000;

// Background maintenance defaults

/// Default interval between auto-compaction checks (5 minutes).
pub const MAINTENANCE_COMPACT_INTERVAL_SECS: u64 = 300;

/// Default interval between durability flushes (30 seconds).
pub const MAINTENANCE_FLUSH_INTERVAL_SECS: u64 = 30;

/// Default minimum slot age for blockstore data compaction.
///
/// Slots older than the current root minus this many slots are eligible
/// for compaction. A conservative default avoids removing data needed
/// by in-progress consensus.
pub const MAINTENANCE_DEFAULT_RETAIN_SLOTS: u64 = 1000;
