// Gossip protocol constants for the CRDS (Cluster Replicated Data Store).

// ---------------------------------------------------------------------------
// CRDS table limits
// ---------------------------------------------------------------------------

/// Maximum number of contact info entries in the CRDS side table.
pub const MAX_CONTACT_INFO_ENTRIES: usize = 32_768;

/// Maximum number of entries in the main CRDS table.
/// Should be large enough to hold all value types from the cluster.
pub const MAX_CRDS_TABLE_ENTRIES: usize = 65_536;

/// Maximum number of purged entry hashes to track.
pub const MAX_PURGED_ENTRIES: usize = 8_192;

/// Maximum number of failed insert hashes to track.
pub const MAX_FAILED_INSERT_ENTRIES: usize = 4_096;

// ---------------------------------------------------------------------------
// CRDS value types (discriminants)
// ---------------------------------------------------------------------------

/// Deprecated: Legacy contact info format.
pub const VALUE_TYPE_LEGACY_CONTACT_INFO: u8 = 0;
/// Vote transaction gossip.
pub const VALUE_TYPE_VOTE: u8 = 1;
/// Lowest available slot for a node.
pub const VALUE_TYPE_LOWEST_SLOT: u8 = 2;
/// Deprecated: Legacy snapshot hash format.
pub const VALUE_TYPE_LEGACY_SNAPSHOT_HASHES: u8 = 3;
/// Deprecated: Account hashes format.
pub const VALUE_TYPE_ACCOUNT_HASHES: u8 = 4;
/// Slots available in current epoch.
pub const VALUE_TYPE_EPOCH_SLOTS: u8 = 5;
/// Deprecated: Legacy version format.
pub const VALUE_TYPE_LEGACY_VERSION: u8 = 6;
/// Client version information.
pub const VALUE_TYPE_VERSION: u8 = 7;
/// Node instance token (duplicate detection).
pub const VALUE_TYPE_NODE_INSTANCE: u8 = 8;
/// Duplicate shred proof.
pub const VALUE_TYPE_DUPLICATE_SHRED: u8 = 9;
/// Incremental snapshot hashes.
pub const VALUE_TYPE_INCREMENTAL_SNAPSHOT_HASHES: u8 = 10;
/// Current contact info format.
pub const VALUE_TYPE_CONTACT_INFO: u8 = 11;
/// Restart protocol: last voted fork slots.
pub const VALUE_TYPE_RESTART_LAST_VOTED_FORK_SLOTS: u8 = 12;
/// Restart protocol: heaviest fork.
pub const VALUE_TYPE_RESTART_HEAVIEST_FORK: u8 = 13;
/// Total number of CRDS value types.
pub const VALUE_TYPE_COUNT: usize = 14;

// ---------------------------------------------------------------------------
// Expiration durations (nanoseconds)
// ---------------------------------------------------------------------------

/// Slot duration in nanoseconds (400ms).
pub const SLOT_DURATION_NANOS: i64 = 400_000_000;

/// Staked entry expiration: 48 hours (432000 slots * 400ms).
pub const STAKED_EXPIRE_DURATION_NANOS: i64 = 432_000 * SLOT_DURATION_NANOS;

/// Unstaked entry expiration: 15 seconds.
pub const UNSTAKED_EXPIRE_DURATION_NANOS: i64 = 15_000_000_000;

/// Purged entry retention: 60 seconds.
pub const PURGED_EXPIRE_DURATION_NANOS: i64 = 60_000_000_000;

/// Failed insert retention: 20 seconds.
pub const FAILED_INSERT_EXPIRE_DURATION_NANOS: i64 = 20_000_000_000;

/// Contact info freshness threshold: 60 seconds.
/// Peers not refreshed within this window are downweighted.
pub const FRESH_THRESHOLD_NANOS: i64 = 60_000_000_000;

// ---------------------------------------------------------------------------
// Peer scoring and sampling
// ---------------------------------------------------------------------------

/// Base weight for peer scoring (added to stake).
pub const PEER_SCORE_BASE_WEIGHT: u64 = 100;

/// Downweight factor for offline/stale peers.
pub const OFFLINE_PEER_DOWNWEIGHT_FACTOR: u64 = 100;

/// Maximum number of active set peers for push gossip.
pub const ACTIVE_SET_MAX_PEERS: usize = 12;

/// Number of active set rotation buckets.
pub const ACTIVE_SET_BUCKET_COUNT: usize = 25;

/// Total weighted peer samplers: 1 (pull request) + 25 (active set buckets).
pub const TOTAL_PEER_SAMPLERS: usize = 1 + ACTIVE_SET_BUCKET_COUNT;

// ---------------------------------------------------------------------------
// Bloom filter parameters
// ---------------------------------------------------------------------------

/// Default bloom filter false positive rate (10%).
pub const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.1;

/// Number of hash functions in bloom filter.
pub const BLOOM_NUM_KEYS: usize = 8;

/// Maximum bloom filter size in bits.
pub const BLOOM_MAX_BITS: usize = 8_192;

// ---------------------------------------------------------------------------
// Gossip protocol limits
// ---------------------------------------------------------------------------

/// Maximum gossip MTU (bytes).
pub const GOSSIP_MTU: usize = 1_232;

/// Maximum CRDS value payload size.
pub const CRDS_VALUE_MAX_SIZE: usize = 1_188;

/// Maximum number of CRDS values per gossip message.
pub const MAX_VALUES_PER_MESSAGE: usize = 18;

/// Push gossip fanout.
pub const PUSH_FANOUT: usize = 6;

/// Pull gossip fanout.
pub const PULL_FANOUT: usize = 3;

/// Push gossip interval (milliseconds).
pub const PUSH_INTERVAL_MS: u64 = 100;

/// Pull request interval (milliseconds).
pub const PULL_INTERVAL_MS: u64 = 32;

/// Prune interval (milliseconds).
pub const PRUNE_INTERVAL_MS: u64 = 10_000;

/// Prune origin timeout (milliseconds). After this duration, a prune
/// entry expires and the origin may be forwarded to that destination again.
pub const PRUNE_TIMEOUT_MS: u64 = 30_000;

/// Maximum number of prune entries per destination node.
/// Prevents unbounded memory growth from excessive prune messages.
pub const MAX_PRUNE_ENTRIES_PER_DEST: usize = 256;

/// Maximum cluster size for gossip protocol capacity planning.
pub const MAX_CLUSTER_SIZE: usize = 5_000;

/// Interval for polling gossip CRDS for new vote entries (milliseconds).
pub const GOSSIP_VOTE_POLL_INTERVAL_MS: u64 = 200;

/// Ping interval (milliseconds).
pub const PING_INTERVAL_MS: u64 = 5_000;

/// ContactInfo self-refresh interval (milliseconds).
/// The validator re-signs and queues its own ContactInfo for broadcast
/// at this rate to maintain freshness across the cluster.
pub const CONTACT_INFO_REFRESH_INTERVAL_MS: u64 = 7_500;

/// Maximum number of vote entries per validator in the CRDS table.
/// Each vote index (0..MAX_VOTE_ENTRIES) is a separate CRDS key slot.
pub const MAX_VOTE_ENTRIES: u8 = 32;

/// Maximum number of duplicate shred proof entries per validator.
pub const MAX_DUPLICATE_SHRED_ENTRIES: u16 = 512;

// ---------------------------------------------------------------------------
// Contact info socket types
// ---------------------------------------------------------------------------

/// Number of socket address types per contact info.
pub const CONTACT_INFO_SOCKET_COUNT: usize = 14;

/// Socket type indices.
pub const SOCKET_GOSSIP: usize = 0;
pub const SOCKET_SERVE_REPAIR_QUIC: usize = 1;
pub const SOCKET_RPC: usize = 2;
pub const SOCKET_RPC_PUBSUB: usize = 3;
pub const SOCKET_SERVE_REPAIR: usize = 4;
pub const SOCKET_TPU: usize = 5;
pub const SOCKET_TPU_FORWARDS: usize = 6;
pub const SOCKET_TPU_FORWARDS_QUIC: usize = 7;
pub const SOCKET_TPU_QUIC: usize = 8;
pub const SOCKET_TPU_VOTE: usize = 9;
pub const SOCKET_TVU: usize = 10;
pub const SOCKET_TVU_QUIC: usize = 11;
pub const SOCKET_TPU_VOTE_QUIC: usize = 12;
pub const SOCKET_ALPENGLOW: usize = 13;

// ---------------------------------------------------------------------------
// Gossip message types
// ---------------------------------------------------------------------------

/// Pull request message type.
pub const MSG_TYPE_PULL_REQUEST: u8 = 0;
/// Pull response message type.
pub const MSG_TYPE_PULL_RESPONSE: u8 = 1;
/// Push message type.
pub const MSG_TYPE_PUSH: u8 = 2;
/// Prune message type.
pub const MSG_TYPE_PRUNE: u8 = 3;
/// Ping message type.
pub const MSG_TYPE_PING: u8 = 4;
/// Pong message type.
pub const MSG_TYPE_PONG: u8 = 5;

// ---------------------------------------------------------------------------
// Gossip update tags (published to consumers)
// ---------------------------------------------------------------------------

/// Update: new or updated contact info.
pub const UPDATE_TAG_CONTACT_INFO: u8 = 0;
/// Update: contact info removed (eviction or expiration).
pub const UPDATE_TAG_CONTACT_INFO_REMOVE: u8 = 1;
/// Update: lowest slot changed.
pub const UPDATE_TAG_LOWEST_SLOT: u8 = 2;
/// Update: vote received via gossip.
pub const UPDATE_TAG_VOTE: u8 = 3;
/// Update: duplicate shred proof received.
pub const UPDATE_TAG_DUPLICATE_SHRED: u8 = 4;
/// Update: snapshot hashes received.
pub const UPDATE_TAG_SNAPSHOT_HASHES: u8 = 5;

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

/// Maximum serialized size of a single CRDS data entry.
pub const MAX_CRDS_OBJECT_SIZE: usize = 928;

/// Maximum number of prune target nodes per prune message.
pub const MAX_PRUNE_DATA_NODES: usize = 32;

/// Size of the ping/pong token in bytes.
pub const PING_TOKEN_SIZE: usize = 32;

/// Prefix for pong hash derivation: SHA256(prefix || token).
pub const PING_PONG_HASH_PREFIX: &[u8] = b"SOLANA_PING_PONG";

/// Maximum wallclock value in milliseconds (sanity bound).
pub const MAX_WALLCLOCK_MS: u64 = 1_000_000_000_000_000;

/// Number of duplicate shred proof chunks per complete proof.
pub const DUPLICATE_SHRED_MAX_CHUNKS: u16 = 16;

// ---------------------------------------------------------------------------
// Outbound data budget (pull response rate limiting)
// ---------------------------------------------------------------------------

/// Budget replenishment interval in nanoseconds (100ms).
pub const BUDGET_REPLENISH_INTERVAL_NS: u64 = 100_000_000;

/// Bytes replenished per staked validator per interval.
pub const BUDGET_BYTES_PER_INTERVAL: u64 = 1_024;

/// Maximum accumulation multiplier (burst capacity).
pub const BUDGET_MAX_MULTIPLE: u64 = 5;

/// Minimum assumed staked validators for budget calculation.
pub const BUDGET_MIN_STAKED: u64 = 2;
