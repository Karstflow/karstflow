//! Syscall registry and dispatch for sBPF program execution.
//!
//! Programs running in the sBPF virtual machine can invoke syscalls
//! to interact with the runtime. This module provides the registry
//! of all available syscalls and their dispatch logic.

mod cpi;
mod cpi_account;
mod crypto;
mod curve;
mod hash_ops;
mod logging;
mod memory;
mod pda;
mod return_data;
mod runtime;

#[cfg(test)]
mod tests;

pub use cpi::{
    deduplicate_accounts, derive_pda_signers, invoke, invoke_signed, CpiAccountInfo,
    CpiAccountMeta, CpiContext, CpiInstruction, InstructionAccount,
};
pub use crypto::{keccak256, secp256k1_recover, sha256};
pub use curve::alt_bn128;
pub use curve::curve25519;
pub use hash_ops::blake3_hash;
pub use logging::{sol_log, sol_log_compute_units, sol_log_data};
pub use memory::{sol_memcmp, sol_memcpy, sol_memmove, sol_memset};
pub use pda::{create_program_address, try_find_program_address};
pub use return_data::{get_return_data, set_return_data};
pub use runtime::{
    get_clock, get_epoch_schedule, get_processed_sibling_instruction, get_rent, get_stack_height,
    ClockInfo, EpochScheduleInfo, ProcessedInstruction, RentInfo,
};

use paradencer_types::{Account, Pubkey};
use std::collections::HashMap;

/// Context provided to syscalls during execution.
///
/// Tracks compute budget consumption, logging, account state, and
/// CPI stack depth throughout program execution.
pub struct SyscallContext {
    /// Remaining compute units available for the program.
    pub compute_meter: u64,
    /// Current CPI stack depth.
    pub stack_depth: usize,
    /// Program ID of the currently executing program.
    pub program_id: Pubkey,
    /// Logs accumulated during execution.
    pub logs: Vec<String>,
    /// Return data from the last CPI call (program_id, data).
    pub return_data: Option<(Pubkey, Vec<u8>)>,
    /// Account state accessible to the program.
    pub accounts: HashMap<Pubkey, Account>,
    /// Accounts that have been modified during execution.
    pub modified_accounts: HashMap<Pubkey, Account>,
    /// Privilege metadata for accounts in the caller's instruction.
    /// Each entry is (pubkey, is_signer, is_writable).
    /// When empty, privilege checks fall back to account presence checks.
    pub caller_account_privileges: Vec<(Pubkey, bool, bool)>,
}

impl SyscallContext {
    /// Create a new context for the given program with a compute budget.
    pub fn new(program_id: Pubkey, compute_budget: u64) -> Self {
        Self {
            compute_meter: compute_budget,
            stack_depth: 0,
            program_id,
            logs: Vec::new(),
            return_data: None,
            accounts: HashMap::new(),
            modified_accounts: HashMap::new(),
            caller_account_privileges: Vec::new(),
        }
    }

    /// Deduct compute units from the meter.
    ///
    /// Returns an error if insufficient compute units remain.
    pub fn consume_compute(&mut self, units: u64) -> Result<(), SyscallError> {
        if self.compute_meter < units {
            self.compute_meter = 0;
            return Err(SyscallError::ComputeBudgetExceeded);
        }
        self.compute_meter -= units;
        Ok(())
    }
}

/// Errors that can occur during syscall execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallError {
    /// The program exceeded its compute budget.
    ComputeBudgetExceeded,
    /// An invalid argument was passed to the syscall.
    InvalidArgument(String),
    /// The program tried to access memory outside its bounds.
    AccessViolation(String),
    /// CPI stack depth limit exceeded.
    MaxCpiDepthExceeded,
    /// Return data exceeds the maximum allowed size.
    MaxReturnDataSizeExceeded,
    /// CPI instruction data exceeds the maximum allowed size.
    MaxInstructionSizeExceeded,
    /// An account could not be borrowed (already borrowed mutably).
    AccountBorrowFailed,
    /// A program attempted to invoke itself recursively.
    ReentrancyDetected,
    /// The derived address is on the ed25519 curve and is invalid as a PDA.
    InvalidProgramAddress,
    /// One or more seeds exceeded the allowed limits.
    InvalidSeeds,
    /// Insufficient lamports for the requested operation.
    InsufficientFunds,
    /// The target program account is not marked as executable.
    ProgramNotExecutable,
    /// A callee attempted to gain privileges the caller does not hold.
    PrivilegeEscalation(String),
    /// An account referenced in the instruction was not found.
    MissingAccount(String),
    /// The target program is not authorized for CPI invocation.
    ProgramNotSupported,
}

impl std::fmt::Display for SyscallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComputeBudgetExceeded => write!(f, "compute budget exceeded"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
            Self::AccessViolation(msg) => write!(f, "access violation: {}", msg),
            Self::MaxCpiDepthExceeded => write!(f, "CPI depth limit exceeded"),
            Self::MaxReturnDataSizeExceeded => write!(f, "return data size limit exceeded"),
            Self::MaxInstructionSizeExceeded => write!(f, "instruction size limit exceeded"),
            Self::AccountBorrowFailed => write!(f, "account borrow failed"),
            Self::ReentrancyDetected => write!(f, "program reentrancy detected"),
            Self::InvalidProgramAddress => write!(f, "invalid program address"),
            Self::InvalidSeeds => write!(f, "invalid seeds"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::ProgramNotExecutable => write!(f, "program is not executable"),
            Self::PrivilegeEscalation(msg) => write!(f, "privilege escalation: {}", msg),
            Self::MissingAccount(msg) => write!(f, "missing account: {}", msg),
            Self::ProgramNotSupported => write!(f, "program not supported for CPI"),
        }
    }
}
