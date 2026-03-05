//! Constants for the centralized signing service.
//!
//! The signing service manages validator identity and authorized voter
//! keypairs, providing cryptographic signing for shreds, votes, gossip,
//! and repair messages.

/// Maximum number of authorized voter keypairs the signing service can hold.
/// Matches the maximum number of authorized voters tracked across epoch boundaries.
pub const MAX_AUTHORIZED_VOTERS: usize = 16;

/// Maximum request payload size for signing requests (bytes).
pub const SIGN_REQUEST_MAX_PAYLOAD: usize = 2048;

/// Ed25519 signature size (bytes).
pub const SIGNATURE_SIZE: usize = 64;

/// Shred signing payload size: 32-byte merkle root.
pub const SHRED_SIGN_PAYLOAD_SIZE: usize = 32;

/// Gossip signing maximum payload size.
pub const GOSSIP_SIGN_MAX_PAYLOAD: usize = 2048;

/// Repair signing payload size: 96 bytes (nonce + slot + shred index).
pub const REPAIR_SIGN_PAYLOAD_SIZE: usize = 96;

/// Ping/pong signing payload size: 96 bytes (token + from + purpose).
pub const PING_SIGN_PAYLOAD_SIZE: usize = 96;
