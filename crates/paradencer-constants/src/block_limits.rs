//! Block-level resource limits for transaction scheduling.
//!
//! These constants define the maximum compute units, account data growth,
//! and other per-block limits that prevent any single block from consuming
//! excessive resources.

/// Maximum total compute units per block.
pub const MAX_BLOCK_COMPUTE_UNITS: u64 = 48_000_000;

/// Maximum compute units for vote transactions per block.
pub const MAX_VOTE_COMPUTE_UNITS: u64 = 36_000_000;

/// Maximum compute units per writable account per block.
pub const MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS: u64 = 12_000_000;

/// Cost of acquiring a write lock on an account.
pub const WRITE_LOCK_COST: u64 = 300;

/// Maximum account data size delta per block (bytes).
pub const MAX_ACCOUNT_DATA_SIZE_DELTA: i64 = 100_000_000; // 100MB

/// Number of shards for the transaction cache.
pub const TRANSACTION_CACHE_SHARDS: usize = 64;

/// Default maximum entries in transaction cache.
pub const DEFAULT_TRANSACTION_CACHE_MAX_ENTRIES: usize = 1_000_000;

/// Base cost for signature verification.
pub const SIGNATURE_COST: u64 = 720;

/// Base cost per transaction (overhead).
pub const TRANSACTION_BASE_COST: u64 = 3000;

/// Cost per instruction in a transaction.
pub const INSTRUCTION_BASE_COST: u64 = 200;

// ---------------------------------------------------------------------------
// Pack / scheduler constants
// ---------------------------------------------------------------------------

/// Maximum data bytes per block (derived from shred limits).
pub const MAX_DATA_BYTES_PER_BLOCK: u64 = 27_539_200; // ~26.3 MiB

/// Fee per signature used by the pack scheduler.
pub const PACK_FEE_PER_SIGNATURE: u64 = 5000;

/// Default capacity of the pending transaction pool.
pub const DEFAULT_PENDING_POOL_CAPACITY: usize = 32_768;

/// Maximum age (in slots) before a pending transaction is expired.
pub const MAX_PENDING_TRANSACTION_AGE_SLOTS: u64 = 150;
