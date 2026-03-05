//! Constants for the Config program.
//!
//! The Config program stores configuration data on-chain, typically
//! used for validator configuration and other metadata.

pub const INSTRUCTION_STORE: u32 = 0;

/// Maximum size of configuration data in bytes.
pub const MAX_CONFIG_DATA_SIZE: usize = 10_240;

// Compute costs
pub const COMPUTE_COST_STORE: u64 = 450;
