//! Runtime syscalls for accessing system variables (sysvars).
//!
//! These syscalls provide programs with read access to chain state
//! such as the current slot, epoch schedule, and rent parameters.

use super::{SyscallContext, SyscallError};
use karstflow_constants::syscalls::*;
use karstflow_types::Pubkey;

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
        slots_per_epoch: karstflow_constants::ledger::SLOTS_PER_EPOCH,
        leader_schedule_slot_offset: karstflow_constants::consensus::LEADER_SCHEDULE_SLOT_OFFSET,
        warmup: false,
        first_normal_epoch: 0,
        first_normal_slot: 0,
    })
}

/// Get rent sysvar values.
pub fn get_rent(ctx: &mut SyscallContext) -> Result<RentInfo, SyscallError> {
    ctx.consume_compute(GET_SYSVAR_COST)?;

    Ok(RentInfo {
        lamports_per_byte_year: karstflow_constants::economics::RENT_EXEMPTION_LAMPORTS_PER_BYTE,
        exemption_threshold: 2.0,
        burn_percent: karstflow_constants::economics::DEFAULT_FEE_BURN_PERCENT,
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
    index: u64,
) -> Result<Option<ProcessedInstruction>, SyscallError> {
    ctx.consume_compute(GET_PROCESSED_SIBLING_INSTRUCTION_COST)?;

    // Look up the instruction from the transaction's sibling instruction
    // trace stored in the sysvar snapshot. This is populated by the
    // consensus layer before execution.
    // NOTE: The snapshot-based lookup requires a reference to the snapshot,
    // which the SyscallContext doesn't currently hold. The actual dispatch-level
    // handler reads from VmState.sysvar_snapshot directly. This function
    // remains as the high-level interface that the dispatch handler delegates to.
    let _ = index;
    Ok(None)
}

/// Epoch rewards sysvar information.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochRewardsInfo {
    /// Whether rewards distribution is currently active.
    pub active: bool,
    /// Total rewards for the epoch in lamports.
    pub total_rewards: u64,
    /// Rewards already distributed.
    pub distributed_rewards: u64,
    /// Block height at which distribution completes.
    pub distribution_complete_block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(budget: u64) -> SyscallContext {
        SyscallContext::new(Pubkey::new([0u8; 32]), budget)
    }

    #[test]
    fn get_clock_returns_default_values() {
        let mut c = ctx(100_000);
        let clock = get_clock(&mut c).unwrap();
        assert_eq!(clock.slot, 0);
        assert_eq!(clock.epoch, 0);
        assert_eq!(clock.unix_timestamp, 0);
    }

    #[test]
    fn get_clock_consumes_compute() {
        let mut c = ctx(5);
        assert!(get_clock(&mut c).is_err());
    }

    #[test]
    fn get_epoch_schedule_returns_constants() {
        let mut c = ctx(100_000);
        let schedule = get_epoch_schedule(&mut c).unwrap();
        assert_eq!(
            schedule.slots_per_epoch,
            karstflow_constants::ledger::SLOTS_PER_EPOCH
        );
        assert_eq!(
            schedule.leader_schedule_slot_offset,
            karstflow_constants::consensus::LEADER_SCHEDULE_SLOT_OFFSET
        );
        assert!(!schedule.warmup);
    }

    #[test]
    fn get_epoch_schedule_consumes_compute() {
        let mut c = ctx(5);
        assert!(get_epoch_schedule(&mut c).is_err());
    }

    #[test]
    fn get_rent_returns_configured_values() {
        let mut c = ctx(100_000);
        let rent = get_rent(&mut c).unwrap();
        assert_eq!(
            rent.lamports_per_byte_year,
            karstflow_constants::economics::RENT_EXEMPTION_LAMPORTS_PER_BYTE
        );
        assert!((rent.exemption_threshold - 2.0).abs() < f64::EPSILON);
        assert_eq!(
            rent.burn_percent,
            karstflow_constants::economics::DEFAULT_FEE_BURN_PERCENT
        );
    }

    #[test]
    fn get_rent_consumes_compute() {
        let mut c = ctx(5);
        assert!(get_rent(&mut c).is_err());
    }

    #[test]
    fn get_stack_height_returns_current_depth() {
        let mut c = ctx(100_000);
        let height = get_stack_height(&mut c).unwrap();
        assert_eq!(height, 0);

        c.stack_depth = 3;
        let height = get_stack_height(&mut c).unwrap();
        assert_eq!(height, 3);
    }

    #[test]
    fn get_stack_height_consumes_compute() {
        let mut c = ctx(4);
        assert!(get_stack_height(&mut c).is_err());
    }

    #[test]
    fn get_processed_sibling_instruction_returns_none() {
        let mut c = ctx(100_000);
        let result = get_processed_sibling_instruction(&mut c, 0).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_processed_sibling_instruction_consumes_compute() {
        let mut c = ctx(5);
        assert!(get_processed_sibling_instruction(&mut c, 0).is_err());
    }

    #[test]
    fn clock_info_equality() {
        let c1 = ClockInfo {
            slot: 100,
            epoch: 5,
            unix_timestamp: 1234567890,
            leader_schedule_epoch: 6,
            epoch_start_timestamp: 1234500000,
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn epoch_rewards_info_construction() {
        let info = EpochRewardsInfo {
            active: true,
            total_rewards: 1_000_000,
            distributed_rewards: 500_000,
            distribution_complete_block_height: 42,
        };
        assert!(info.active);
        assert_eq!(info.total_rewards, 1_000_000);
        assert_eq!(info.distributed_rewards, 500_000);
    }
}
