/// Constants for sysvar accounts and their data sizes.
///
/// System variables (sysvars) are special accounts maintained by the runtime
/// that provide network state to on-chain programs. These constants define
/// capacity limits and serialized data sizes for each sysvar.

/// Maximum number of slot hashes stored in the SlotHashes sysvar.
pub const MAX_SLOT_HASHES: usize = 512;

/// Maximum number of recent blockhashes stored.
pub const MAX_RECENT_BLOCKHASHES: usize = 300;

/// Number of bits in the SlotHistory bitvector, covering approximately 1M slots.
pub const SLOT_HISTORY_BITS: usize = 1024 * 1024;

/// Maximum number of instructions allowed per transaction.
pub const MAX_INSTRUCTIONS_PER_TRANSACTION: usize = 64;

/// Sysvar account data sizes used for rent exemption calculations.
pub const CLOCK_SYSVAR_SIZE: usize = 40;
pub const EPOCH_SCHEDULE_SYSVAR_SIZE: usize = 33;
pub const RENT_SYSVAR_SIZE: usize = 17;
pub const SLOT_HASHES_SYSVAR_SIZE: usize = 20_480;
pub const SLOT_HISTORY_SYSVAR_SIZE: usize = 131_097;
pub const STAKE_HISTORY_SYSVAR_SIZE: usize = 16_392;
pub const RECENT_BLOCKHASHES_SYSVAR_SIZE: usize = 12_032;
pub const LAST_RESTART_SLOT_SYSVAR_SIZE: usize = 8;
pub const EPOCH_REWARDS_SYSVAR_SIZE: usize = 80;
