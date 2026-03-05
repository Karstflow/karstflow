/// Default compute units consumed by loader v4 management instructions.
pub const DEFAULT_COMPUTE_UNITS: u64 = 2_000;

/// Number of slots a program must wait before it can be retracted or redeployed.
pub const DEPLOYMENT_COOLDOWN_SLOTS: u64 = 1;

/// Byte offset where the ELF program data starts within a loader v4 program account.
/// The first 48 bytes are the loader v4 state header.
pub const PROGRAM_DATA_OFFSET: usize = 48;

/// Size of the upgradeable loader programdata metadata header.
/// Used when copying from an upgradeable-loader-owned source program.
pub const UPGRADEABLE_PROGRAMDATA_METADATA_SIZE: usize = 45;

/// Loader v4 program status discriminants.
pub const STATUS_RETRACTED: u64 = 0;
pub const STATUS_DEPLOYED: u64 = 1;
pub const STATUS_FINALIZED: u64 = 2;

/// Loader v4 instruction discriminants (bincode enum tags).
pub const INSTRUCTION_WRITE: u32 = 0;
pub const INSTRUCTION_COPY: u32 = 1;
pub const INSTRUCTION_SET_PROGRAM_LENGTH: u32 = 2;
pub const INSTRUCTION_DEPLOY: u32 = 3;
pub const INSTRUCTION_RETRACT: u32 = 4;
pub const INSTRUCTION_TRANSFER_AUTHORITY: u32 = 5;
pub const INSTRUCTION_FINALIZE: u32 = 6;
