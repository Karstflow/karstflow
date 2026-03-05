//! Constants for the Address Lookup Table (ALT) program.
//!
//! Address lookup tables allow transactions to reference more accounts
//! than the message format would otherwise permit by storing reusable
//! address lists on-chain.

/// Maximum number of addresses in a single lookup table.
pub const MAX_ADDRESSES: usize = 256;

/// Size of lookup table metadata in bytes.
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Number of slots a deactivated table must wait before it can be closed.
pub const TABLE_DEACTIVATION_COOLDOWN: u64 = 512;

// Instruction discriminants
pub const INSTRUCTION_CREATE: u32 = 0;
pub const INSTRUCTION_FREEZE: u32 = 1;
pub const INSTRUCTION_EXTEND: u32 = 2;
pub const INSTRUCTION_DEACTIVATE: u32 = 3;
pub const INSTRUCTION_CLOSE: u32 = 4;

// Compute costs
pub const COMPUTE_COST_CREATE: u64 = 750;
pub const COMPUTE_COST_FREEZE: u64 = 300;
pub const COMPUTE_COST_EXTEND: u64 = 500;
pub const COMPUTE_COST_EXTEND_PER_ADDRESS: u64 = 50;
pub const COMPUTE_COST_DEACTIVATE: u64 = 300;
pub const COMPUTE_COST_CLOSE: u64 = 300;
