/// Constants for the Compute Budget program.
///
/// The Compute Budget program processes per-transaction resource limits
/// including compute unit caps, priority fees, heap size, and loaded
/// accounts data size.

// Instruction discriminants (single-byte tags)
pub const INSTRUCTION_REQUEST_HEAP_FRAME: u8 = 1;
pub const INSTRUCTION_SET_COMPUTE_UNIT_LIMIT: u8 = 2;
pub const INSTRUCTION_SET_COMPUTE_UNIT_PRICE: u8 = 3;
pub const INSTRUCTION_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u8 = 4;

// Compute costs
pub const COMPUTE_COST_BASE: u64 = 150;
