//! Constants for the BPF Upgradeable Loader program.
//!
//! Defines instruction discriminants, state discriminants, on-chain sizes,
//! and compute costs matching the Solana protocol specification.

// ── State discriminants (bincode u32 tags) ──────────────────────────────

/// Uninitialized account.
pub const STATE_UNINITIALIZED: u32 = 0;
/// Buffer account holding uploaded program data.
pub const STATE_BUFFER: u32 = 1;
/// Deployed program account (points to ProgramData).
pub const STATE_PROGRAM: u32 = 2;
/// ProgramData account (holds ELF binary and metadata).
pub const STATE_PROGRAM_DATA: u32 = 3;

// ── Instruction discriminants (bincode u32 tags) ────────────────────────

/// Initialize an uninitialized account as a buffer with an authority.
pub const INSTRUCTION_INITIALIZE_BUFFER: u32 = 0;
/// Write program data into a buffer at a given offset.
pub const INSTRUCTION_WRITE: u32 = 1;
/// Deploy a program from a buffer with a maximum data length.
pub const INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN: u32 = 2;
/// Upgrade a deployed program with new data from a buffer.
pub const INSTRUCTION_UPGRADE: u32 = 3;
/// Transfer authority of a buffer or program.
pub const INSTRUCTION_SET_AUTHORITY: u32 = 4;
/// Close a buffer, uninitialized, or program account.
pub const INSTRUCTION_CLOSE: u32 = 5;
/// Extend a program's data capacity.
pub const INSTRUCTION_EXTEND_PROGRAM: u32 = 6;
/// Transfer authority with new authority co-signing.
pub const INSTRUCTION_SET_AUTHORITY_CHECKED: u32 = 7;
/// Extend a program's data capacity with authority check.
pub const INSTRUCTION_EXTEND_PROGRAM_CHECKED: u32 = 9;

// ── On-chain account data sizes (bincode-encoded) ───────────────────────

/// Uninitialized: just the u32 discriminant.
pub const SIZE_OF_UNINITIALIZED: usize = 4;

/// Buffer metadata: disc(4) + option_tag(1) + authority(32) = 37 bytes.
/// The actual program binary data follows this header.
pub const SIZE_OF_BUFFER_METADATA: usize = 37;

/// Program account: disc(4) + programdata_address(32) = 36 bytes total.
pub const SIZE_OF_PROGRAM: usize = 36;

/// ProgramData metadata: disc(4) + slot(8) + option_tag(1) + authority(32) = 45 bytes.
/// The actual ELF binary follows this header.
pub const SIZE_OF_PROGRAMDATA_METADATA: usize = 45;

// ── Limits ──────────────────────────────────────────────────────────────

/// Maximum permitted account data length (10 MiB).
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

// ── Compute costs ───────────────────────────────────────────────────────

pub const COMPUTE_COST_INITIALIZE_BUFFER: u64 = 500;
pub const COMPUTE_COST_WRITE: u64 = 1_000;
pub const COMPUTE_COST_DEPLOY: u64 = 2_000;
pub const COMPUTE_COST_UPGRADE: u64 = 2_000;
pub const COMPUTE_COST_SET_AUTHORITY: u64 = 500;
pub const COMPUTE_COST_CLOSE: u64 = 500;
pub const COMPUTE_COST_EXTEND_PROGRAM: u64 = 1_500;
pub const COMPUTE_COST_SET_AUTHORITY_CHECKED: u64 = 500;
pub const DEFAULT_COMPUTE_UNITS: u64 = 750;
