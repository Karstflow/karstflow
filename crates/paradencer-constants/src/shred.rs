/// Reed-Solomon shard size for FEC encoding/decoding.
/// Both data and coding shards use this size (matches DATA_SHRED_PAYLOAD_SIZE).
pub const FEC_RS_SHARD_SIZE: usize = 1051;

/// Maximum number of data shreds in a single FEC set.
pub const MAX_FEC_DATA_SHREDS: usize = 67;

/// Maximum number of coding shreds in a single FEC set.
pub const MAX_FEC_CODING_SHREDS: usize = 67;

/// Default number of data shreds per FEC set.
pub const DEFAULT_FEC_DATA_SHREDS: usize = 32;

/// Default number of coding shreds per FEC set.
pub const DEFAULT_FEC_CODING_SHREDS: usize = 32;
