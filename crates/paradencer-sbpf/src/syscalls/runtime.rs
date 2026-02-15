//! Runtime syscalls for accessing system variables (sysvars).
//!
//! These syscalls provide programs with read access to chain state
//! such as the current slot, epoch schedule, and rent parameters.

use super::{SyscallContext, SyscallError};
use paradencer_constants::syscalls::*;
use paradencer_types::Pubkey;

/// Clock sysvar information returned to programs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockInfo {
    /// Current slot being processed.
    pub slot: u64,
    /// Current epoch.
    pub epoch: u64,
    /// Approximate Unix timestamp of the current slot.
    pub unix_timestamp: i64,
    /// Epoch for which the leader schedule is available.
    pub leader_schedule_epoch: u64,
    /// Unix timestamp of the first slot in the current epoch.
    pub epoch_start_timestamp: i64,
}

/// Epoch schedule sysvar information.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochScheduleInfo {
    /// Number of slots in each epoch.
    pub slots_per_epoch: u64,
    /// Offset of the leader schedule from the start of the epoch.
    pub leader_schedule_slot_offset: u64,
    /// Whether the cluster is in the warmup phase.
    pub warmup: bool,
    /// First epoch that is not in the warmup phase.
    pub first_normal_epoch: u64,
    /// First slot of the first normal epoch.
    pub first_normal_slot: u64,
}

/// Rent sysvar information.
#[derive(Debug, Clone, PartialEq)]
pub struct RentInfo {
    /// Lamports charged per byte-year of storage.
    pub lamports_per_byte_year: u64,
    /// Minimum balance multiplier for rent exemption.
    pub exemption_threshold: f64,
    /// Percentage of rent collected that is burned.
    pub burn_percent: u8,
}

/// A previously processed sibling instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedInstruction {
    /// The program that processed the instruction.
    pub program_id: Pubkey,
    /// The instruction data.
    pub data: Vec<u8>,
    /// The accounts referenced by the instruction.
    pub accounts: Vec<Pubkey>,
}

/// Get current clock sysvar values.
///
/// Returns default placeholder values. In a full implementation, the
/// context would be populated with real chain state.
pub fn get_clock(ctx: &mut SyscallContext) -> Result<ClockInfo, SyscallError> {
    ctx.consume_compute(GET_SYSVAR_COST)?;

    // In a real implementation, this reads from the sysvar cache.
    Ok(ClockInfo {
        slot: 0,
        epoch: 0,
        unix_timestamp: 0,
        leader_schedule_epoch: 0,
        epoch_start_timestamp: 0,
    })
}

/// Get epoch schedule sysvar values.
pub fn get_epoch_schedule(ctx: &mut SyscallContext) -> Result<EpochScheduleInfo, SyscallError> {
    ctx.consume_compute(GET_SYSVAR_COST)?;

    Ok(EpochScheduleInfo {
        slots_per_epoch: paradencer_constants::ledger::SLOTS_PER_EPOCH,
        leader_schedule_slot_offset: paradencer_constants::consensus::LEADER_SCHEDULE_SLOT_OFFSET,
        warmup: false,
        first_normal_epoch: 0,
        first_normal_slot: 0,
    })
}

/// Get rent sysvar values.
pub fn get_rent(ctx: &mut SyscallContext) -> Result<RentInfo, SyscallError> {
    ctx.consume_compute(GET_SYSVAR_COST)?;

    Ok(RentInfo {
        lamports_per_byte_year: paradencer_constants::economics::RENT_EXEMPTION_LAMPORTS_PER_BYTE,
        exemption_threshold: 2.0,
        burn_percent: paradencer_constants::economics::DEFAULT_FEE_BURN_PERCENT,
    })
}

/// Get the current CPI stack height.
///
/// Returns 0 at the top level, incrementing with each nested CPI call.
pub fn get_stack_height(ctx: &mut SyscallContext) -> Result<u64, SyscallError> {
    ctx.consume_compute(GET_STACK_HEIGHT_COST)?;
    Ok(ctx.stack_depth as u64)
}

/// Get a previously processed sibling instruction by index.
///
/// Sibling instructions are instructions processed earlier in the same
/// transaction. Returns `None` if the index is out of range.
pub fn get_processed_sibling_instruction(
    ctx: &mut SyscallContext,
    _index: u64,
) -> Result<Option<ProcessedInstruction>, SyscallError> {
    ctx.consume_compute(GET_PROCESSED_SIBLING_INSTRUCTION_COST)?;

    // In a real implementation, this would look up the instruction
    // from the transaction's instruction trace. For now, return None.
    Ok(None)
}
