//! Shred types and utilities
//!
//! This module provides data structures and parsing utilities for Solana shreds,
//! which are the atomic units of block propagation in the network.
//!
//! # Overview
//!
//! Shreds are packets containing fragments of blocks that are transmitted over
//! the network. They come in two main types:
//!
//! - **Data shreds**: Contain actual transaction data and entries
//! - **Coding shreds**: Contain Reed-Solomon erasure codes for recovery
//!
//! Each type can be either Legacy (pre-Merkle) or Merkle-authenticated.
//!
//! # Example
//!
//! ```rust
//! use karstflow_types::shred::{ShredParser, Shred};
//!
//! // Parse a shred from raw network bytes
//! let raw_data: &[u8] = &[/* ... */];
//! # let raw_data = &[0u8; 200];
//! // let shred = ShredParser::parse(raw_data)?;
//!
//! // Check shred type
//! // if shred.is_data() {
//! //     println!("Data shred for slot {}", shred.slot());
//! // }
//! ```

mod codec;
mod parser;
mod types;

#[cfg(test)]
mod tests;

pub use parser::{ShredParseError, ShredParseResult, ShredParser};
pub use types::{
    CodingShredHeader, DataShredHeader, FecSetId, MerkleProof, Shred, ShredCommonHeader,
    ShredMetadata, ShredVariant, CODING_SHRED_PAYLOAD_SIZE, DATA_SHRED_PAYLOAD_SIZE,
    MAX_CODING_SHREDS_PER_FEC_BLOCK, MAX_DATA_SHREDS_PER_FEC_BLOCK, MERKLE_MAX_PROOF_DEPTH,
    MERKLE_PROOF_NODE_BYTES, SHRED_CODE_FLAG, SHRED_CODE_HEADER_BYTES, SHRED_DATA_FLAG,
    SHRED_DATA_HEADER_BYTES, SHRED_HEADER_SIZE, SHRED_LAST_IN_SLOT, SHRED_LEGACY_CODE_NIBBLE,
    SHRED_LEGACY_DATA_NIBBLE, SHRED_MAX_SIZE, SHRED_MIN_SIZE, SHRED_PAYLOAD_SIZE,
    SHRED_PROOF_COUNT_MASK, SHRED_SIGNATURE_BYTES, SHRED_SIZE, SHRED_TYPEMASK_CODE,
    SHRED_TYPEMASK_DATA, SHRED_TYPE_LEGACY_CODE, SHRED_TYPE_LEGACY_DATA, SHRED_TYPE_MASK,
    SHRED_TYPE_MERKLE_CODE, SHRED_TYPE_MERKLE_CODE_CHAINED,
    SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED, SHRED_TYPE_MERKLE_DATA,
    SHRED_TYPE_MERKLE_DATA_CHAINED, SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED, SIGNATURE_SIZE,
};
