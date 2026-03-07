//! Block-level resource limits for transaction scheduling.
//!
//! These constants define the maximum compute units, account data growth,
//! and other per-block limits that prevent any single block from consuming
//! excessive resources.

/// Maximum total compute units per block (legacy, pre-SIMD-0207).
pub const MAX_BLOCK_COMPUTE_UNITS_LEGACY: u64 = 48_000_000;

/// Maximum total compute units per block (SIMD-0207).
pub const MAX_BLOCK_COMPUTE_UNITS_SIMD_0207: u64 = 50_000_000;

/// Maximum total compute units per block (SIMD-0256).
pub const MAX_BLOCK_COMPUTE_UNITS_SIMD_0256: u64 = 60_000_000;

/// Maximum total compute units per block (SIMD-0286, current).
pub const MAX_BLOCK_COMPUTE_UNITS_SIMD_0286: u64 = 100_000_000;

/// Default maximum total compute units per block.
///
/// This should be resolved at runtime based on active feature flags.
/// Use `MAX_BLOCK_COMPUTE_UNITS_SIMD_0207` as the safe default for
/// networks that have activated SIMD-0207 but not yet SIMD-0256/0286.
pub const MAX_BLOCK_COMPUTE_UNITS: u64 = MAX_BLOCK_COMPUTE_UNITS_SIMD_0207;

/// Maximum compute units for vote transactions per block.
pub const MAX_VOTE_COMPUTE_UNITS: u64 = 36_000_000;

/// Maximum compute units per writable account per block.
pub const MAX_WRITABLE_ACCOUNT_COMPUTE_UNITS: u64 = 12_000_000;

/// Maximum writable account compute units after raise_account_cu_limit
/// feature activation (SIMD-0306): 40% of block limit.
///
/// Computed at runtime as `block_limit * 40 / 100`.
pub const ACCOUNT_CU_LIMIT_RATIO_PERCENT: u64 = 40;

/// Cost of acquiring a write lock on an account.
pub const WRITE_LOCK_COST: u64 = 300;

/// Maximum account data size delta per block (bytes).
pub const MAX_ACCOUNT_DATA_SIZE_DELTA: i64 = 100_000_000; // 100MB

/// Number of shards for the transaction cache.
pub const TRANSACTION_CACHE_SHARDS: usize = 64;

/// Default maximum entries in transaction cache.
pub const DEFAULT_TRANSACTION_CACHE_MAX_ENTRIES: usize = 1_000_000;

/// Number of bytes stored per message hash in the transaction cache.
///
/// Only the first 20 bytes of the SHA-256 message hash are used for
/// deduplication. This matches the Solana protocol's status cache format
/// and provides sufficient collision resistance (~2^-160).
pub const MESSAGE_HASH_PREFIX_BYTES: usize = 20;

/// Base cost for signature verification.
pub const SIGNATURE_COST: u64 = 720;

/// Base cost per transaction (overhead).
pub const TRANSACTION_BASE_COST: u64 = 3000;

/// Cost per instruction in a transaction.
pub const INSTRUCTION_BASE_COST: u64 = 200;

// ---------------------------------------------------------------------------
// Pack / scheduler constants
// ---------------------------------------------------------------------------

/// Maximum number of account keys a transaction may lock.
///
/// With the `increase_tx_account_lock_limit` feature active, this is 128.
/// The legacy limit (64) is not used in current protocol versions.
pub const MAX_TRANSACTION_ACCOUNT_LOCKS: usize = 128;

/// Maximum number of accounts per instruction (SIMD-0406).
///
/// When `limit_instruction_accounts` is active, transactions with any
/// instruction referencing more than 255 accounts are rejected.
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 255;

/// Maximum data bytes per block (derived from shred limits).
pub const MAX_DATA_BYTES_PER_BLOCK: u64 = 27_539_200; // ~26.3 MiB

/// Fee per signature used by the pack scheduler.
pub const PACK_FEE_PER_SIGNATURE: u64 = 5000;

/// Default capacity of the pending transaction pool.
pub const DEFAULT_PENDING_POOL_CAPACITY: usize = 32_768;

/// Maximum age (in slots) before a pending transaction is expired.
pub const MAX_PENDING_TRANSACTION_AGE_SLOTS: u64 = 150;

// ---------------------------------------------------------------------------
// Transaction cost model (consensus-critical)
// ---------------------------------------------------------------------------

/// Cost per writable account lock (CU). Each writable account in a
/// transaction adds this fixed cost to the total.
pub const COST_PER_WRITABLE_ACCOUNT: u64 = 300;

/// Number of instruction data bytes that cost 1 compute unit.
/// Actual cost = instruction_data_bytes / INSTRUCTION_DATA_BYTES_PER_CU.
pub const INSTRUCTION_DATA_BYTES_PER_CU: u64 = 4;

/// Fixed execution cost for simple vote transactions (CU).
pub const SIMPLE_VOTE_EXECUTION_COST: u64 = 2_100;

/// Maximum compute units allocated to a single builtin program instruction.
pub const MAX_BUILTIN_PROGRAM_COST: u64 = 200_000;

/// Per-signature cost for Ed25519 precompile verification (CU).
pub const ED25519_PRECOMPILE_COST_PER_SIGNATURE: u64 = 2_400;

/// Per-signature cost for secp256k1 precompile verification (CU).
pub const SECP256K1_PRECOMPILE_COST_PER_SIGNATURE: u64 = 6_690;

/// Per-signature cost for secp256r1 precompile verification (CU).
pub const SECP256R1_PRECOMPILE_COST_PER_SIGNATURE: u64 = 4_800;

/// Heap cost per kilobyte (CU) when a transaction requests heap via
/// the Compute Budget program.
pub const HEAP_COST_PER_KILOBYTE: u64 = 8;

/// Page size (bytes) for loaded accounts data cost calculation.
pub const LOADED_ACCOUNTS_DATA_COST_DIVISOR: u64 = 32_768;

/// Compute units charged per page of loaded account data.
///
/// Formula: cost_cu = ceil(loaded_bytes / DIVISOR) * PAGE_COST
pub const LOADED_ACCOUNTS_DATA_PAGE_COST: u64 = 8;

/// Percentage of signature fees that are burned (not distributed).
pub const TRANSACTION_FEE_BURN_PERCENT: u64 = 50;

/// Maximum microblock compute units (CU). Each microblock is bounded
/// by this limit to allow fine-grained pacing.
pub const MAX_CUS_PER_MICROBLOCK: u64 = 1_600_000;

/// Minimum interval between microblock emissions in nanoseconds.
///
/// Prevents bursty microblock production that could overwhelm
/// execution tiles. At 50us, this allows up to ~20K microblocks/sec.
pub const DEFAULT_MICROBLOCK_PACE_NS: u64 = 50_000;

// ---------------------------------------------------------------------------
// Runtime bounds
// ---------------------------------------------------------------------------

/// Maximum number of vote accounts in the system.
pub const MAX_VOTE_ACCOUNTS: usize = 40_200;

/// Expected number of active vote accounts (for sizing hints).
pub const EXPECTED_VOTE_ACCOUNTS: usize = 2_048;

/// Maximum number of stake accounts in the system.
pub const MAX_STAKE_ACCOUNTS: usize = 3_000_000;

/// Expected number of active stake accounts (for sizing hints).
pub const EXPECTED_STAKE_ACCOUNTS: usize = 2_000_000;

/// BLS proof-of-possession verification cost charged by the vote
/// program for authorize instructions (SIMD-0387).
pub const BLS_PROOF_OF_POSSESSION_VERIFICATION_CU: u64 = 34_500;

/// Upper bound on execution CUs used by any vote instruction.
///
/// The authorize instruction charges the default vote cost plus
/// BLS proof-of-possession verification.
pub const VOTE_MAX_COMPUTE_UNITS: u64 =
    SIMPLE_VOTE_EXECUTION_COST + BLS_PROOF_OF_POSSESSION_VERIFICATION_CU;

/// Fixed cost for a simple vote transaction before `remove_simple_vote_from_cost_model`.
///
/// When the feature is NOT active, simple votes have this fixed cost
/// instead of going through the full cost model.
pub const SIMPLE_VOTE_USAGE_COST: u64 = 3_428;

/// Upper bound cost for simple vote transactions (used in pack scheduling).
///
/// Computed as:
///   2 signatures * 720          =  1,440
///   35 writable accounts * 300  = 10,500
///   vote max CU (36,600)        = 36,600
///   loaded accounts data cost   = 16,384
///   max instruction data cost   =    265
///   Total                       = 65,189
pub const SIMPLE_VOTE_COST_UPPER_BOUND: u64 = 65_189;
