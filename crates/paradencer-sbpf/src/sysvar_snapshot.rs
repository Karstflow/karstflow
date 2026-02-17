/// Frozen sysvar state for a single execution context.
///
/// Copied once at instruction boundary, then served from stack
/// to every sysvar syscall. No locks, no allocations in the hot path.
///
/// This type lives in `paradencer-sbpf` so the VM layer has no
/// dependency on `paradencer-consensus`. The consensus layer builds
/// a snapshot from its `SysvarCache` and passes it in.
#[derive(Debug, Clone)]
pub struct SysvarSnapshot {
    // Clock
    pub slot: u64,
    pub epoch: u64,
    pub unix_timestamp: i64,
    pub epoch_start_timestamp: i64,
    pub leader_schedule_epoch: u64,
    // EpochSchedule
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
    // Rent
    pub lamports_per_byte_year: u64,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
    // LastRestartSlot
    pub last_restart_slot: u64,
}

impl Default for SysvarSnapshot {
    fn default() -> Self {
        Self {
            slot: 0,
            epoch: 0,
            unix_timestamp: 0,
            epoch_start_timestamp: 0,
            leader_schedule_epoch: 0,
            slots_per_epoch: 0,
            leader_schedule_slot_offset: 0,
            warmup: false,
            first_normal_epoch: 0,
            first_normal_slot: 0,
            lamports_per_byte_year: 0,
            exemption_threshold: 0.0,
            burn_percent: 0,
            last_restart_slot: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zeros() {
        let snap = SysvarSnapshot::default();
        assert_eq!(snap.slot, 0);
        assert_eq!(snap.epoch, 0);
        assert_eq!(snap.unix_timestamp, 0);
        assert_eq!(snap.epoch_start_timestamp, 0);
        assert_eq!(snap.leader_schedule_epoch, 0);
        assert_eq!(snap.slots_per_epoch, 0);
        assert_eq!(snap.leader_schedule_slot_offset, 0);
        assert!(!snap.warmup);
        assert_eq!(snap.first_normal_epoch, 0);
        assert_eq!(snap.first_normal_slot, 0);
        assert_eq!(snap.lamports_per_byte_year, 0);
        assert_eq!(snap.exemption_threshold, 0.0);
        assert_eq!(snap.burn_percent, 0);
        assert_eq!(snap.last_restart_slot, 0);
    }

    #[test]
    fn round_trip_values() {
        let snap = SysvarSnapshot {
            slot: 12345,
            epoch: 7,
            unix_timestamp: 1700000000,
            epoch_start_timestamp: 1699000000,
            leader_schedule_epoch: 8,
            slots_per_epoch: 432000,
            leader_schedule_slot_offset: 432000,
            warmup: true,
            first_normal_epoch: 14,
            first_normal_slot: 524256,
            lamports_per_byte_year: 3480,
            exemption_threshold: 2.0,
            burn_percent: 50,
            last_restart_slot: 100,
        };
        assert_eq!(snap.slot, 12345);
        assert_eq!(snap.epoch, 7);
        assert_eq!(snap.unix_timestamp, 1700000000);
        assert_eq!(snap.epoch_start_timestamp, 1699000000);
        assert_eq!(snap.leader_schedule_epoch, 8);
        assert_eq!(snap.slots_per_epoch, 432000);
        assert!(snap.warmup);
        assert_eq!(snap.first_normal_epoch, 14);
        assert_eq!(snap.first_normal_slot, 524256);
        assert_eq!(snap.lamports_per_byte_year, 3480);
        assert_eq!(snap.exemption_threshold, 2.0);
        assert_eq!(snap.burn_percent, 50);
        assert_eq!(snap.last_restart_slot, 100);
    }
}
