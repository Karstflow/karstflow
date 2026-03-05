/// Maximum supported fanout for the turbine broadcast tree.
/// Limits the number of children per node at each layer.
pub const MAX_FANOUT: usize = 1536;

/// Default fanout used on mainnet for both layer1 and layer2.
pub const DEFAULT_FANOUT: usize = 200;

/// Maximum number of shreds processed in a single destination batch.
/// Derived from MAX_FEC_DATA_SHREDS (67 data + 67 code = 134 total).
pub const MAX_DEST_BATCH_SIZE: usize = 134;

/// Shred type discriminant for data shreds in destination seed computation.
/// Used as part of the SHA-256 input: (slot, type_byte, shred_index, leader_pubkey).
pub const DEST_SEED_TYPE_DATA: u8 = 0xA5;

/// Shred type discriminant for coding shreds in destination seed computation.
pub const DEST_SEED_TYPE_CODE: u8 = 0x5A;

/// Total size of the destination seed input in bytes.
/// Layout: slot(8) + type(1) + index(4) + leader_pubkey(32) = 45 bytes.
pub const DEST_SEED_INPUT_SIZE: usize = 45;

/// Maximum number of layers in the turbine tree.
/// Layer 0 = leader, Layer 1 = fanout children, Layer 2 = fanout² leaves.
pub const MAX_TREE_LAYERS: usize = 2;
