//! Wire-compatible types for the Solana repair protocol.
//!
//! This module provides serialization-compatible types that match the
//! exact binary layout used by Solana validators for repair messages.
//! Internal repair logic (forest, policy, coordinator) remains unchanged —
//! these types serve as a bidirectional adapter between internal
//! representations and the network wire format.

pub mod convert;
pub mod protocol;
pub mod response;

pub use protocol::{WireRepairProtocol, WireRepairRequestHeader};
pub use response::{
    decode_ancestor_response, decode_shred_response, encode_ancestor_response,
    encode_shred_response, WireAncestorHashesResponse,
};
