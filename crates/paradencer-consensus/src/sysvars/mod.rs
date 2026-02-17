//! Thread-safe sysvar cache with per-bank state.
//!
//! Maintains the current state of all system variables (sysvars)
//! that programs can read during execution. Updated at slot and epoch
//! boundaries by the runtime.

mod clock_sysvar;
mod epoch_rewards_sysvar;
mod epoch_schedule_sysvar;
mod instructions_sysvar;
mod last_restart_slot;
mod recent_blockhashes;
mod rent_sysvar;
mod slot_hashes;
mod slot_history;
mod stake_history_sysvar;

#[cfg(test)]
mod tests;

pub use clock_sysvar::ClockSysvar;
pub use epoch_rewards_sysvar::EpochRewardsSysvar;
pub use epoch_schedule_sysvar::EpochScheduleSysvar;
pub use instructions_sysvar::{InstructionsSysvar, SerializedInstruction};
pub use last_restart_slot::LastRestartSlotSysvar;
pub use recent_blockhashes::{RecentBlockhashEntry, RecentBlockhashesSysvar};
pub use rent_sysvar::RentSysvar;
pub use slot_hashes::{SlotHashEntry, SlotHashesSysvar};
pub use slot_history::SlotHistorySysvar;
pub use stake_history_sysvar::StakeHistorySysvar;

use crate::{Clock, EpochRewards, EpochSchedule, Rent, StakeHistory, StakeHistoryEntry};
use paradencer_ids::{
    CLOCK_SYSVAR_ID, EPOCH_REWARDS_SYSVAR_ID, EPOCH_SCHEDULE_SYSVAR_ID,
    LAST_RESTART_SLOT_SYSVAR_ID, RECENT_BLOCKHASHES_SYSVAR_ID, RENT_SYSVAR_ID,
    SLOT_HASHES_SYSVAR_ID, SLOT_HISTORY_SYSVAR_ID, STAKE_HISTORY_SYSVAR_ID, SYSVAR_PROGRAM_ID,
};
use paradencer_types::{Account, AccountMeta, Pubkey};
use std::sync::RwLock;

/// Central cache for all sysvar state.
///
/// Each field is independently locked so that readers of one sysvar
/// do not block writers of another. The cache is intended to be shared
/// via `Arc<SysvarCache>` across the runtime.
#[derive(Debug)]
pub struct SysvarCache {
    clock: RwLock<ClockSysvar>,
    epoch_schedule: RwLock<EpochScheduleSysvar>,
    rent: RwLock<RentSysvar>,
    slot_hashes: RwLock<SlotHashesSysvar>,
    slot_history: RwLock<SlotHistorySysvar>,
    stake_history: RwLock<StakeHistorySysvar>,
    recent_blockhashes: RwLock<RecentBlockhashesSysvar>,
    epoch_rewards: RwLock<EpochRewardsSysvar>,
    last_restart_slot: RwLock<LastRestartSlotSysvar>,
}

impl SysvarCache {
    /// Create a new sysvar cache initialized with genesis values.
    pub fn new(clock: Clock, epoch_schedule: EpochSchedule, rent: Rent) -> Self {
        Self {
            clock: RwLock::new(ClockSysvar::new(clock)),
            epoch_schedule: RwLock::new(EpochScheduleSysvar::new(epoch_schedule)),
            rent: RwLock::new(RentSysvar::new(rent)),
            slot_hashes: RwLock::new(SlotHashesSysvar::new()),
            slot_history: RwLock::new(SlotHistorySysvar::new()),
            stake_history: RwLock::new(StakeHistorySysvar::default()),
            recent_blockhashes: RwLock::new(RecentBlockhashesSysvar::new()),
            epoch_rewards: RwLock::new(EpochRewardsSysvar::inactive()),
            last_restart_slot: RwLock::new(LastRestartSlotSysvar::default()),
        }
    }

    // -----------------------------------------------------------------------
    // Clock operations
    // -----------------------------------------------------------------------

    /// Update the clock sysvar for a new slot.
    ///
    /// Called once per slot by the runtime. Advances the slot counter, updates
    /// epoch boundaries, and sets the estimated network timestamp.
    pub fn update_clock(&self, slot: u64, epoch: u64, timestamp: i64) {
        let mut guard = self.clock.write().unwrap();
        guard.clock.slot = slot;
        guard.clock.unix_timestamp = timestamp;
        if epoch > guard.clock.epoch {
            guard.clock.epoch = epoch;
            guard.clock.epoch_start_timestamp = timestamp;
            guard.clock.leader_schedule_epoch = epoch.saturating_add(1);
        }
    }

    /// Read a snapshot of the current clock state.
    pub fn clock(&self) -> Clock {
        self.clock.read().unwrap().clock
    }

    // -----------------------------------------------------------------------
    // EpochSchedule operations
    // -----------------------------------------------------------------------

    /// Read the epoch schedule configuration.
    pub fn epoch_schedule(&self) -> EpochSchedule {
        self.epoch_schedule.read().unwrap().schedule
    }

    // -----------------------------------------------------------------------
    // Rent operations
    // -----------------------------------------------------------------------

    /// Read the rent configuration.
    pub fn rent(&self) -> Rent {
        self.rent.read().unwrap().rent
    }

    // -----------------------------------------------------------------------
    // SlotHashes operations
    // -----------------------------------------------------------------------

    /// Record a new slot-hash pair.
    ///
    /// Called once per slot after the bank hash is computed.
    pub fn update_slot_hashes(&self, slot: u64, hash: [u8; 32]) {
        self.slot_hashes.write().unwrap().add(slot, hash);
    }

    /// Read the slot hashes sysvar.
    pub fn slot_hashes(&self) -> SlotHashesSysvar {
        self.slot_hashes.read().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // SlotHistory operations
    // -----------------------------------------------------------------------

    /// Mark a slot as processed in the slot history bitvector.
    pub fn update_slot_history(&self, slot: u64) {
        self.slot_history.write().unwrap().set(slot);
    }

    /// Read the slot history sysvar.
    pub fn slot_history(&self) -> SlotHistorySysvar {
        self.slot_history.read().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // StakeHistory operations
    // -----------------------------------------------------------------------

    /// Read the stake history sysvar.
    pub fn stake_history(&self) -> StakeHistory {
        self.stake_history.read().unwrap().history.clone()
    }

    // -----------------------------------------------------------------------
    // RecentBlockhashes operations
    // -----------------------------------------------------------------------

    /// Add a blockhash to the recent blockhashes sysvar.
    pub fn update_recent_blockhashes(&self, blockhash: [u8; 32], lamports_per_signature: u64) {
        self.recent_blockhashes
            .write()
            .unwrap()
            .add(blockhash, lamports_per_signature);
    }

    /// Read the recent blockhashes sysvar.
    pub fn recent_blockhashes(&self) -> RecentBlockhashesSysvar {
        self.recent_blockhashes.read().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // EpochRewards operations
    // -----------------------------------------------------------------------

    /// Activate epoch rewards distribution with the given reward summary.
    pub fn set_epoch_rewards(&self, rewards: EpochRewards) {
        *self.epoch_rewards.write().unwrap() = EpochRewardsSysvar::active(rewards);
    }

    /// Clear epoch rewards after distribution completes.
    pub fn clear_epoch_rewards(&self) {
        *self.epoch_rewards.write().unwrap() = EpochRewardsSysvar::inactive();
    }

    /// Check whether epoch rewards distribution is currently active.
    pub fn is_epoch_rewards_active(&self) -> bool {
        self.epoch_rewards.read().unwrap().is_active()
    }

    // -----------------------------------------------------------------------
    // LastRestartSlot operations
    // -----------------------------------------------------------------------

    /// Record the slot of the most recent cluster restart.
    pub fn set_last_restart_slot(&self, slot: u64) {
        *self.last_restart_slot.write().unwrap() = LastRestartSlotSysvar::new(slot);
    }

    /// Read the last restart slot value.
    pub fn last_restart_slot(&self) -> u64 {
        self.last_restart_slot.read().unwrap().slot
    }

    // -----------------------------------------------------------------------
    // Epoch boundary handler
    // -----------------------------------------------------------------------

    /// Perform all updates required when crossing an epoch boundary.
    ///
    /// This adds a new entry to the stake history and is called after
    /// rewards have been calculated for the completed epoch.
    pub fn on_epoch_boundary(&self, new_epoch: u64, entry: StakeHistoryEntry) {
        self.stake_history
            .write()
            .unwrap()
            .history
            .add(new_epoch, entry);
    }

    // -----------------------------------------------------------------------
    // Account serialization
    // -----------------------------------------------------------------------

    /// Produce a full `Account` for the sysvar identified by `pubkey`.
    ///
    /// Returns `None` if the pubkey does not match any known sysvar address.
    /// The returned account has:
    /// - `owner` set to the sysvar program ID
    /// - `executable` = false
    /// - `rent_epoch` = 0
    /// - `lamports` = 1 (sysvars are rent-exempt by protocol rule)
    pub fn get_sysvar_account(&self, pubkey: &Pubkey) -> Option<Account> {
        let data = self.serialize_sysvar(pubkey)?;
        Some(Account::new_with_meta(
            AccountMeta::new(1, SYSVAR_PROGRAM_ID, false, 0),
            data,
        ))
    }

    /// Serialize just the data portion of the requested sysvar.
    fn serialize_sysvar(&self, pubkey: &Pubkey) -> Option<Vec<u8>> {
        if *pubkey == CLOCK_SYSVAR_ID {
            Some(self.clock.read().unwrap().to_bytes())
        } else if *pubkey == EPOCH_SCHEDULE_SYSVAR_ID {
            Some(self.epoch_schedule.read().unwrap().to_bytes())
        } else if *pubkey == RENT_SYSVAR_ID {
            Some(self.rent.read().unwrap().to_bytes())
        } else if *pubkey == SLOT_HASHES_SYSVAR_ID {
            Some(self.slot_hashes.read().unwrap().to_bytes())
        } else if *pubkey == SLOT_HISTORY_SYSVAR_ID {
            Some(self.slot_history.read().unwrap().to_bytes())
        } else if *pubkey == STAKE_HISTORY_SYSVAR_ID {
            Some(self.stake_history.read().unwrap().to_bytes())
        } else if *pubkey == RECENT_BLOCKHASHES_SYSVAR_ID {
            Some(self.recent_blockhashes.read().unwrap().to_bytes())
        } else if *pubkey == EPOCH_REWARDS_SYSVAR_ID {
            Some(self.epoch_rewards.read().unwrap().to_bytes())
        } else if *pubkey == LAST_RESTART_SLOT_SYSVAR_ID {
            Some(self.last_restart_slot.read().unwrap().to_bytes())
        } else {
            None
        }
    }
}

impl Default for SysvarCache {
    fn default() -> Self {
        Self::new(Clock::default(), EpochSchedule::default(), Rent::default())
    }
}
