/// Maximum concurrent in-flight repair requests.
pub const MAX_INFLIGHT_REQUESTS: usize = 65_536;

/// Minimum interval before re-requesting the same (slot, shred_idx) pair.
pub const REQUEST_DEDUP_INTERVAL_MS: u64 = 60;

/// Default timeout for a single repair request before it's considered lost.
pub const REQUEST_TIMEOUT_MS: u64 = 5_000;

/// Latency threshold separating fast peers from slow peers.
pub const FAST_PEER_LATENCY_MS: u64 = 80;

/// Maximum ancestor depth for orphan resolution requests.
pub const ORPHAN_ANCESTOR_DEPTH: usize = 10;

/// Maximum number of tracked slots in the repair forest.
pub const MAX_FOREST_SLOTS: usize = 8_192;

/// Maximum shreds per slot for bitset tracking.
pub const MAX_SHREDS_PER_SLOT: u32 = 32_768;

/// Maximum FEC sets per slot.
pub const MAX_FEC_SETS_PER_SLOT: u32 = 4_096;

/// Fraction of round-robin stages allocated to slow peers (1 out of 7).
pub const SLOW_PEER_STAGE_FRACTION: usize = 1;

/// Total round-robin stages for peer selection.
pub const PEER_SELECTION_STAGES: usize = 7;

/// Maximum requests per peer per second (server-side rate limit).
pub const DEFAULT_PEER_RATE_LIMIT: u32 = 100;

/// Protocol version for repair messages.
pub const PROTOCOL_VERSION: u16 = 1;
