//! Wire-compatible types for the Solana gossip protocol.
//!
//! This module provides serialization-compatible types that match the
//! exact binary layout used by Solana validators. Internal gossip logic
//! (CRDS table, bloom filter, sampler) remains unchanged — these types
//! serve as a bidirectional adapter between internal representations
//! and the network wire format.

pub mod bloom;
pub mod contact_info;
pub mod convert;
pub mod crds_data;
pub mod crds_value;
pub mod ping_pong;
pub mod protocol;
pub mod prune;
pub mod varint;

pub use bloom::{WireBloom, WireCrdsFilter};
pub use contact_info::WireContactInfo;
pub use crds_data::WireCrdsData;
pub use crds_value::WireCrdsValue;
pub use ping_pong::{WirePing, WirePong};
pub use protocol::WireProtocol;
pub use prune::WirePruneData;
