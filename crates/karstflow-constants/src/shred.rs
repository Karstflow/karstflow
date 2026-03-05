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

// ---------------------------------------------------------------------------
// Shred wire-format constants
// ---------------------------------------------------------------------------

/// Maximum shred size in bytes (IPv6 MTU minus UDP/IP headers).
/// Code shreds always use this size.
pub const SHRED_MAX_SIZE: usize = 1228;

/// Minimum shred size in bytes. Merkle data shreds always use this size.
pub const SHRED_MIN_SIZE: usize = 1203;

/// Ed25519 signature size at the start of every shred.
pub const SHRED_SIGNATURE_BYTES: usize = 64;

/// Data shred header size: sig(64) + variant(1) + slot(8) + idx(4) + ver(2) + fec(4) + parent(2) + flags(1) + size(2).
pub const SHRED_DATA_HEADER_BYTES: usize = 88;

/// Code shred header size: sig(64) + variant(1) + slot(8) + idx(4) + ver(2) + fec(4) + data_cnt(2) + code_cnt(2) + pos(2).
pub const SHRED_CODE_HEADER_BYTES: usize = 89;

// ---------------------------------------------------------------------------
// Shred variant byte encoding
//
// Upper nibble (bits 7-4) = shred type.
// Lower nibble (bits 3-0) = Merkle proof node count (0 for legacy).
// ---------------------------------------------------------------------------

/// Mask for the shred type (upper nibble).
pub const SHRED_TYPE_MASK: u8 = 0xF0;

/// Mask for the Merkle proof node count (lower nibble).
pub const SHRED_PROOF_COUNT_MASK: u8 = 0x0F;

/// Legacy data shred type.
pub const SHRED_TYPE_LEGACY_DATA: u8 = 0xA0;

/// Legacy coding shred type.
pub const SHRED_TYPE_LEGACY_CODE: u8 = 0x50;

/// Merkle data shred type (non-chained).
pub const SHRED_TYPE_MERKLE_DATA: u8 = 0x80;

/// Merkle coding shred type (non-chained).
pub const SHRED_TYPE_MERKLE_CODE: u8 = 0x40;

/// Merkle data shred with chained root.
pub const SHRED_TYPE_MERKLE_DATA_CHAINED: u8 = 0x90;

/// Merkle coding shred with chained root.
pub const SHRED_TYPE_MERKLE_CODE_CHAINED: u8 = 0x60;

/// Merkle data shred with chained root and retransmitter signature.
pub const SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED: u8 = 0xB0;

/// Merkle coding shred with chained root and retransmitter signature.
pub const SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED: u8 = 0x70;

/// Legacy data shred lower nibble (fixed value).
pub const SHRED_LEGACY_DATA_NIBBLE: u8 = 0x05;

/// Legacy code shred lower nibble (fixed value).
pub const SHRED_LEGACY_CODE_NIBBLE: u8 = 0x0A;

/// Data type bitmask: all data shred types have bit 7 set.
pub const SHRED_TYPEMASK_DATA: u8 = SHRED_TYPE_MERKLE_DATA; // 0x80

/// Code type bitmask: all code shred types have bit 6 set.
pub const SHRED_TYPEMASK_CODE: u8 = SHRED_TYPE_MERKLE_CODE; // 0x40

// ---------------------------------------------------------------------------
// Merkle proof constants
// ---------------------------------------------------------------------------

/// Size of a single Merkle proof node in bytes (truncated SHA-256).
pub const MERKLE_PROOF_NODE_BYTES: usize = 20;

/// Full Merkle root size in bytes (used for chained root, Ed25519 verification).
pub const MERKLE_ROOT_BYTES: usize = 32;

/// Maximum Merkle proof depth (layers) in the binary tree.
pub const MERKLE_MAX_PROOF_DEPTH: usize = 15;

/// Domain prefix for Merkle leaf hashing (26 bytes).
/// SHA-256(prefix || shred_data_after_signature)
pub const MERKLE_LEAF_PREFIX: [u8; 26] = *b"\x00SOLANA_MERKLE_SHREDS_LEAF";

/// Domain prefix for Merkle interior node hashing (26 bytes).
/// SHA-256(prefix || left_child || right_child)
pub const MERKLE_NODE_PREFIX: [u8; 26] = *b"\x01SOLANA_MERKLE_SHREDS_NODE";

/// Base merkle-protected byte count for data shreds (before subtracting per-depth overhead).
/// `merkle_protected_sz = DATA_MERKLE_PROTECTED_BASE - MERKLE_PROOF_NODE_BYTES * depth - SHRED_SIGNATURE_BYTES * is_resigned`
pub const DATA_MERKLE_PROTECTED_BASE: usize = 1139;

/// Base merkle-protected byte count for code shreds.
/// `merkle_protected_sz = CODE_MERKLE_PROTECTED_BASE - MERKLE_PROOF_NODE_BYTES * depth - SHRED_SIGNATURE_BYTES * is_resigned`
pub const CODE_MERKLE_PROTECTED_BASE: usize = 1164;

// ---------------------------------------------------------------------------
// FEC resolver pool constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrently in-progress FEC sets in the resolver pool.
/// When this limit is reached, the oldest incomplete FEC set is evicted.
pub const FEC_RESOLVER_DEPTH: usize = 32;

/// Number of completed FEC set buffers retained before recycling.
/// Buffers remain in the completed queue until consumed, then return to free.
pub const FEC_RESOLVER_COMPLETE_DEPTH: usize = 512;

/// Number of recently-completed FEC set signatures tracked for duplicate detection.
/// Prevents processing the same FEC set twice from different retransmit paths.
pub const FEC_RESOLVER_DONE_DEPTH: usize = 4096;

/// Maximum total data payload size in a single FEC set (bytes).
/// Derived from max data shreds (67) * max payload per shred (~955 bytes).
pub const FEC_SET_MAX_DATA_SIZE: usize = 63_985;
