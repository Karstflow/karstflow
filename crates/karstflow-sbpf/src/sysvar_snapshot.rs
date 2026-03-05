/// Frozen sysvar state for a single execution context.
///
/// Copied once at instruction boundary, then served from stack
/// to every sysvar syscall. No locks, no allocations in the hot path.
///
/// This type lives in `karstflow-sbpf` so the VM layer has no
/// dependency on `karstflow-consensus`. The consensus layer builds
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
    // RecentBlockhashes — most recent blockhash for nonce derivation
    pub recent_blockhash: [u8; 32],
    /// Lamports per signature from the most recent blockhash entry.
    pub lamports_per_signature: u64,
    // EpochRewards
    /// Whether rewards distribution is currently active.
    pub epoch_rewards_active: bool,
    /// Total rewards for the epoch in lamports.
    pub epoch_rewards_total_rewards: u64,
    /// Rewards already distributed.
    pub epoch_rewards_distributed_rewards: u64,
    /// Distribution complete epoch.
    pub epoch_rewards_distribution_complete_block_height: u64,
    // Generic sysvar data — raw serialized bytes keyed by sysvar address.
    // Populated by consensus layer for sol_get_sysvar access.
    pub sysvar_data: std::collections::HashMap<[u8; 32], Vec<u8>>,
    // Epoch stake — total stake per vote account at epoch boundary.
    pub epoch_stake: std::collections::HashMap<[u8; 32], u64>,
    // Processed sibling instructions for the current transaction.
    pub sibling_instructions: Vec<SiblingInstruction>,
    /// Active feature gate IDs for the current slot.
    /// Used by the execution layer to check feature-gated behavior
    /// (e.g., enabling/disabling syscalls, instruction variants, or
    /// VM execution modes based on network-wide feature activation).
    pub active_features: std::collections::HashSet<[u8; 32]>,
}

/// A previously processed instruction within the same transaction.
#[derive(Debug, Clone)]
pub struct SiblingInstruction {
    /// Program ID that processed this instruction.
    pub program_id: [u8; 32],
    /// Instruction data.
    pub data: Vec<u8>,
    /// Account keys referenced.
    pub accounts: Vec<[u8; 32]>,
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
            recent_blockhash: [0u8; 32],
            lamports_per_signature: 0,
            epoch_rewards_active: false,
            epoch_rewards_total_rewards: 0,
            epoch_rewards_distributed_rewards: 0,
            epoch_rewards_distribution_complete_block_height: 0,
            sysvar_data: std::collections::HashMap::new(),
            epoch_stake: std::collections::HashMap::new(),
            sibling_instructions: Vec::new(),
            active_features: std::collections::HashSet::new(),
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
        assert_eq!(snap.recent_blockhash, [0u8; 32]);
        assert_eq!(snap.lamports_per_signature, 0);
        assert!(!snap.epoch_rewards_active);
        assert_eq!(snap.epoch_rewards_total_rewards, 0);
        assert_eq!(snap.epoch_rewards_distributed_rewards, 0);
        assert_eq!(snap.epoch_rewards_distribution_complete_block_height, 0);
        assert!(snap.sysvar_data.is_empty());
        assert!(snap.epoch_stake.is_empty());
        assert!(snap.sibling_instructions.is_empty());
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
            recent_blockhash: [0xAB; 32],
            lamports_per_signature: 5000,
            epoch_rewards_active: true,
            epoch_rewards_total_rewards: 1_000_000,
            epoch_rewards_distributed_rewards: 500_000,
            epoch_rewards_distribution_complete_block_height: 200,
            sysvar_data: std::collections::HashMap::new(),
            epoch_stake: std::collections::HashMap::new(),
            sibling_instructions: Vec::new(),
            active_features: std::collections::HashSet::new(),
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
        assert_eq!(snap.recent_blockhash, [0xAB; 32]);
        assert_eq!(snap.lamports_per_signature, 5000);
        assert!(snap.epoch_rewards_active);
        assert_eq!(snap.epoch_rewards_total_rewards, 1_000_000);
        assert_eq!(snap.epoch_rewards_distributed_rewards, 500_000);
        assert_eq!(snap.epoch_rewards_distribution_complete_block_height, 200);
    }
}
