//! Cached program entry types.
//!
//! Represents the different kinds of programs that can be cached,
//! including builtins, loaded BPF/SBF programs, and tombstones for
//! programs that failed to load.

use paradencer_types::Pubkey;

/// Type of cached program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramType {
    /// Native builtin program (System, Vote, Stake, etc.).
    Builtin,
    /// BPF/SBF loaded program.
    Loaded,
    /// Program that failed to load (tombstone to avoid retrying).
    FailedToLoad(String),
    /// Program is being closed/undeployed.
    Closing,
}

/// A cached program ready for execution.
#[derive(Debug, Clone)]
pub struct CachedProgram {
    /// Type of this program.
    pub program_type: ProgramType,
    /// Raw ELF bytes (for loaded programs).
    pub elf_bytes: Option<Vec<u8>>,
    /// Size of the program data.
    pub data_size: usize,
    /// Account owner (typically BPF Loader).
    pub owner: Pubkey,
    /// Slot at which this version was deployed.
    pub deployment_slot: u64,
    /// Slot at which this version expires (if any).
    pub expiration_slot: Option<u64>,
}

impl CachedProgram {
    /// Create a cached builtin program entry.
    pub fn builtin(owner: Pubkey) -> Self {
        Self {
            program_type: ProgramType::Builtin,
            elf_bytes: None,
            data_size: 0,
            owner,
            deployment_slot: 0,
            expiration_slot: None,
        }
    }

    /// Create a cached loaded BPF/SBF program entry.
    pub fn loaded(elf_bytes: Vec<u8>, owner: Pubkey, deployment_slot: u64) -> Self {
        let data_size = elf_bytes.len();
        Self {
            program_type: ProgramType::Loaded,
            elf_bytes: Some(elf_bytes),
            data_size,
            owner,
            deployment_slot,
            expiration_slot: None,
        }
    }

    /// Create a tombstone for a program that failed to load.
    pub fn failed(reason: String, owner: Pubkey) -> Self {
        Self {
            program_type: ProgramType::FailedToLoad(reason),
            elf_bytes: None,
            data_size: 0,
            owner,
            deployment_slot: 0,
            expiration_slot: None,
        }
    }

    /// Check if this program can be executed.
    pub fn is_executable(&self) -> bool {
        matches!(
            self.program_type,
            ProgramType::Builtin | ProgramType::Loaded
        )
    }
}
