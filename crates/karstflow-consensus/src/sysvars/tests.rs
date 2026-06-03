use super::*;
use crate::{Clock, EpochRewards, EpochSchedule, Rent, StakeHistory, StakeHistoryEntry};
use karstflow_constants::sysvars::{MAX_RECENT_BLOCKHASHES, MAX_SLOT_HASHES, SLOT_HISTORY_BITS};
use karstflow_ids::{
    CLOCK_SYSVAR_ID, EPOCH_REWARDS_SYSVAR_ID, EPOCH_SCHEDULE_SYSVAR_ID,
    LAST_RESTART_SLOT_SYSVAR_ID, RECENT_BLOCKHASHES_SYSVAR_ID, RENT_SYSVAR_ID,
    SLOT_HASHES_SYSVAR_ID, SLOT_HISTORY_SYSVAR_ID, STAKE_HISTORY_SYSVAR_ID, SYSVAR_PROGRAM_ID,
};
use karstflow_types::Pubkey;

// -----------------------------------------------------------------------
// SysvarCache creation and defaults
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_creates_with_defaults() {
    let cache = SysvarCache::default();
    let clock = cache.clock();
    assert_eq!(clock.slot, 0);
    assert_eq!(clock.epoch, 0);
    assert_eq!(clock.unix_timestamp, 0);
}

#[test]
fn sysvar_cache_creates_with_genesis_values() {
    let clock = Clock::new(1_700_000_000);
    let epoch_schedule = EpochSchedule::default();
    let rent = Rent::default_config();

    let cache = SysvarCache::new(clock, epoch_schedule, rent);
    let c = cache.clock();
    assert_eq!(c.slot, 0);
    assert_eq!(c.epoch, 0);
    assert_eq!(c.unix_timestamp, 1_700_000_000);

    let r = cache.rent();
    assert_eq!(r.lamports_per_byte_year, 3_480);
}

// -----------------------------------------------------------------------
// Clock updates
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_updates_clock_slot() {
    let cache = SysvarCache::default();
    cache.update_clock(42, 0, Some(1000));
    let c = cache.clock();
    assert_eq!(c.slot, 42);
    assert_eq!(c.unix_timestamp, 1000);
    assert_eq!(c.epoch, 0);
}

#[test]
fn sysvar_cache_clock_keeps_previous_timestamp_when_no_estimate() {
    let cache = SysvarCache::default();
    cache.update_clock(42, 0, Some(1000));
    // No estimate available for the next slot → keep the previous timestamp
    // rather than inventing wall-clock time (would diverge consensus).
    cache.update_clock(43, 0, None);
    let c = cache.clock();
    assert_eq!(c.slot, 43);
    assert_eq!(c.unix_timestamp, 1000);
}

#[test]
fn sysvar_cache_clock_epoch_boundary_keeps_timestamp_when_no_estimate() {
    let cache = SysvarCache::default();
    cache.update_clock(42, 0, Some(1000));
    // Crossing an epoch boundary with no estimate must anchor
    // epoch_start_timestamp to the kept (previous) timestamp.
    cache.update_clock(100, 1, None);
    let c = cache.clock();
    assert_eq!(c.epoch, 1);
    assert_eq!(c.unix_timestamp, 1000);
    assert_eq!(c.epoch_start_timestamp, 1000);
}

#[test]
fn sysvar_cache_updates_clock_epoch_boundary() {
    let cache = SysvarCache::default();
    cache.update_clock(100, 1, Some(2000));
    let c = cache.clock();
    assert_eq!(c.slot, 100);
    assert_eq!(c.epoch, 1);
    assert_eq!(c.epoch_start_timestamp, 2000);
    assert_eq!(c.leader_schedule_epoch, 2);
}

#[test]
fn sysvar_cache_clock_epoch_does_not_go_backward() {
    let cache = SysvarCache::default();
    cache.update_clock(100, 1, Some(2000));
    // Attempt to set a lower epoch (should not regress).
    cache.update_clock(101, 0, Some(2001));
    let c = cache.clock();
    assert_eq!(c.epoch, 1); // Still epoch 1.
}

#[test]
fn sysvar_cache_clock_advances_multiple_epochs() {
    let cache = SysvarCache::default();
    cache.update_clock(10, 0, Some(1000));
    cache.update_clock(500, 1, Some(2000));
    cache.update_clock(1000, 2, Some(3000));

    let c = cache.clock();
    assert_eq!(c.slot, 1000);
    assert_eq!(c.epoch, 2);
    assert_eq!(c.epoch_start_timestamp, 3000);
    assert_eq!(c.leader_schedule_epoch, 3);
}

// -----------------------------------------------------------------------
// SlotHashes
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_updates_slot_hashes() {
    let cache = SysvarCache::default();
    let hash = [1u8; 32];
    cache.update_slot_hashes(10, hash);

    let sh = cache.slot_hashes();
    assert_eq!(sh.len(), 1);
    assert_eq!(sh.get(10), Some(&hash));
}

#[test]
fn slot_hashes_insertion_order_descending() {
    let mut sh = SlotHashesSysvar::new();
    sh.add(1, [1u8; 32]);
    sh.add(2, [2u8; 32]);
    sh.add(3, [3u8; 32]);

    let slots: Vec<u64> = sh.iter().map(|e| e.slot).collect();
    assert_eq!(slots, vec![3, 2, 1]);
}

#[test]
fn slot_hashes_respects_capacity() {
    let mut sh = SlotHashesSysvar::new();
    for i in 0..MAX_SLOT_HASHES + 50 {
        sh.add(i as u64, [i as u8; 32]);
    }
    assert_eq!(sh.len(), MAX_SLOT_HASHES);
    // The oldest entries should have been evicted.
    assert!(!sh.contains(0));
    assert!(sh.contains((MAX_SLOT_HASHES + 49) as u64));
}

#[test]
fn slot_hashes_most_recent_and_oldest() {
    let mut sh = SlotHashesSysvar::new();
    sh.add(10, [10u8; 32]);
    sh.add(20, [20u8; 32]);

    assert_eq!(sh.most_recent().unwrap().slot, 20);
    assert_eq!(sh.oldest().unwrap().slot, 10);
}

#[test]
fn slot_hashes_serialization_roundtrip() {
    let mut sh = SlotHashesSysvar::new();
    sh.add(5, [5u8; 32]);
    sh.add(10, [10u8; 32]);

    let bytes = sh.to_bytes();
    let restored = SlotHashesSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.get(5), Some(&[5u8; 32]));
    assert_eq!(restored.get(10), Some(&[10u8; 32]));
}

// -----------------------------------------------------------------------
// SlotHistory
// -----------------------------------------------------------------------

#[test]
fn slot_history_set_and_check() {
    let mut sh = SlotHistorySysvar::new();
    sh.set(0);
    sh.set(5);
    sh.set(100);

    assert!(sh.check(0));
    assert!(sh.check(5));
    assert!(sh.check(100));
    assert!(!sh.check(1));
    assert!(!sh.check(99));
}

#[test]
fn slot_history_evicts_old_slots_on_advance() {
    let mut sh = SlotHistorySysvar::new();
    sh.set(0);
    // Advance well past the window.
    sh.set(SLOT_HISTORY_BITS as u64 + 100);
    // Slot 0 should have been evicted.
    assert!(!sh.check(0));
    assert!(sh.check(SLOT_HISTORY_BITS as u64 + 100));
}

#[test]
fn slot_history_ignores_slots_before_base() {
    let mut sh = SlotHistorySysvar::new();
    sh.set(1000);
    // Force a shift that moves base_slot forward.
    sh.set(1000 + SLOT_HISTORY_BITS as u64 + 1);
    // Setting a slot older than base_slot should be silently ignored.
    sh.set(500);
    assert!(!sh.check(500));
}

#[test]
fn slot_history_serialization_roundtrip() {
    let mut sh = SlotHistorySysvar::new();
    sh.set(7);
    sh.set(42);
    sh.set(999);

    let bytes = sh.to_bytes();
    let restored = SlotHistorySysvar::from_bytes(&bytes).unwrap();
    assert!(restored.check(7));
    assert!(restored.check(42));
    assert!(restored.check(999));
    assert!(!restored.check(8));
}

#[test]
fn slot_history_base_and_next_slot() {
    let mut sh = SlotHistorySysvar::new();
    assert_eq!(sh.base_slot(), 0);
    assert_eq!(sh.next_slot(), 0);

    sh.set(10);
    assert_eq!(sh.next_slot(), 11);
}

// -----------------------------------------------------------------------
// StakeHistory sysvar serialization
// -----------------------------------------------------------------------

#[test]
fn stake_history_sysvar_serialization_roundtrip() {
    let mut history = StakeHistory::new();
    history.add(5, StakeHistoryEntry::new(1000, 200, 50));
    history.add(6, StakeHistoryEntry::new(1200, 100, 30));

    let sysvar = StakeHistorySysvar::new(history);
    let bytes = sysvar.to_bytes();
    let restored = StakeHistorySysvar::from_bytes(&bytes).unwrap();

    assert_eq!(restored.history.len(), 2);
    assert_eq!(
        restored.history.get(5),
        Some(&StakeHistoryEntry::new(1000, 200, 50))
    );
    assert_eq!(
        restored.history.get(6),
        Some(&StakeHistoryEntry::new(1200, 100, 30))
    );
}

#[test]
fn stake_history_sysvar_empty_roundtrip() {
    let sysvar = StakeHistorySysvar::default();
    let bytes = sysvar.to_bytes();
    let restored = StakeHistorySysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.history.len(), 0);
}

// -----------------------------------------------------------------------
// Clock sysvar serialization
// -----------------------------------------------------------------------

#[test]
fn clock_sysvar_serialization_roundtrip() {
    let clock = Clock {
        slot: 42,
        epoch_start_timestamp: 1_700_000_000,
        epoch: 3,
        leader_schedule_epoch: 4,
        unix_timestamp: 1_700_000_100,
    };

    let sysvar = ClockSysvar::new(clock);
    let bytes = sysvar.to_bytes();
    assert_eq!(bytes.len(), 40);

    let restored = ClockSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.clock, clock);
}

#[test]
fn clock_sysvar_rejects_short_data() {
    assert!(ClockSysvar::from_bytes(&[0u8; 39]).is_none());
}

// -----------------------------------------------------------------------
// EpochSchedule sysvar serialization
// -----------------------------------------------------------------------

#[test]
fn epoch_schedule_sysvar_serialization_roundtrip() {
    let schedule = EpochSchedule::default();
    let sysvar = EpochScheduleSysvar::new(schedule);
    let bytes = sysvar.to_bytes();
    assert_eq!(bytes.len(), 33);

    let restored = EpochScheduleSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.schedule, schedule);
}

// -----------------------------------------------------------------------
// Rent sysvar serialization
// -----------------------------------------------------------------------

#[test]
fn rent_sysvar_serialization_roundtrip() {
    let rent = Rent {
        lamports_per_byte_year: 3_480,
        exemption_threshold: 2.0,
        burn_percent: 50,
    };

    let sysvar = RentSysvar::new(rent);
    let bytes = sysvar.to_bytes();
    assert_eq!(bytes.len(), 17);

    let restored = RentSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.rent, rent);
}

// -----------------------------------------------------------------------
// Epoch boundary updates
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_epoch_boundary_adds_stake_history() {
    let cache = SysvarCache::default();
    let entry = StakeHistoryEntry::new(10_000, 500, 200);
    cache.on_epoch_boundary(1, entry);

    let history = cache.stake_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(1), Some(&entry));
}

#[test]
fn sysvar_cache_multiple_epoch_boundaries() {
    let cache = SysvarCache::default();
    for epoch in 0..5 {
        cache.on_epoch_boundary(epoch, StakeHistoryEntry::new(10_000 + epoch * 100, 0, 0));
    }
    let history = cache.stake_history();
    assert_eq!(history.len(), 5);
    assert_eq!(history.get(0), Some(&StakeHistoryEntry::new(10_000, 0, 0)));
    assert_eq!(history.get(4), Some(&StakeHistoryEntry::new(10_400, 0, 0)));
}

// -----------------------------------------------------------------------
// get_sysvar_account
// -----------------------------------------------------------------------

#[test]
fn sysvar_account_clock_has_correct_owner() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&CLOCK_SYSVAR_ID).unwrap();
    assert_eq!(account.meta.owner, SYSVAR_PROGRAM_ID);
    assert!(!account.meta.executable);
    assert_eq!(account.meta.lamports, 1);
}

#[test]
fn sysvar_account_epoch_schedule_returns_data() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&EPOCH_SCHEDULE_SYSVAR_ID).unwrap();
    assert_eq!(account.data.len(), 33);
}

#[test]
fn sysvar_account_rent_returns_data() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&RENT_SYSVAR_ID).unwrap();
    assert_eq!(account.data.len(), 17);
}

#[test]
fn sysvar_account_slot_hashes_returns_data() {
    let cache = SysvarCache::default();
    cache.update_slot_hashes(1, [1u8; 32]);
    let account = cache.get_sysvar_account(&SLOT_HASHES_SYSVAR_ID).unwrap();
    // 8 bytes count + 1 * (8 + 32)
    assert_eq!(account.data.len(), 8 + 40);
}

#[test]
fn sysvar_account_slot_history_returns_data() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&SLOT_HISTORY_SYSVAR_ID).unwrap();
    assert!(!account.data.is_empty());
}

#[test]
fn sysvar_account_stake_history_returns_data() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&STAKE_HISTORY_SYSVAR_ID).unwrap();
    // Empty history: just 8 bytes for count.
    assert_eq!(account.data.len(), 8);
}

#[test]
fn sysvar_account_recent_blockhashes_returns_data() {
    let cache = SysvarCache::default();
    let account = cache
        .get_sysvar_account(&RECENT_BLOCKHASHES_SYSVAR_ID)
        .unwrap();
    // Empty: just 8 bytes for count.
    assert_eq!(account.data.len(), 8);
}

#[test]
fn sysvar_account_epoch_rewards_returns_data() {
    let cache = SysvarCache::default();
    let account = cache.get_sysvar_account(&EPOCH_REWARDS_SYSVAR_ID).unwrap();
    // Inactive: 1 byte (0).
    assert_eq!(account.data.len(), 1);
}

#[test]
fn sysvar_account_last_restart_slot_returns_data() {
    let cache = SysvarCache::default();
    let account = cache
        .get_sysvar_account(&LAST_RESTART_SLOT_SYSVAR_ID)
        .unwrap();
    assert_eq!(account.data.len(), 8);
}

#[test]
fn sysvar_account_unknown_pubkey_returns_none() {
    let cache = SysvarCache::default();
    let unknown = Pubkey::new_unique();
    assert!(cache.get_sysvar_account(&unknown).is_none());
}

#[test]
fn sysvar_account_clock_roundtrip_through_account() {
    let cache = SysvarCache::new(
        Clock::new(1_700_000_000),
        EpochSchedule::default(),
        Rent::default(),
    );
    cache.update_clock(50, 0, Some(1_700_000_050));

    let account = cache.get_sysvar_account(&CLOCK_SYSVAR_ID).unwrap();
    let restored = ClockSysvar::from_bytes(account.data.as_slice()).unwrap();
    assert_eq!(restored.clock.slot, 50);
    assert_eq!(restored.clock.unix_timestamp, 1_700_000_050);
}

// -----------------------------------------------------------------------
// LastRestartSlot
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_sets_last_restart_slot() {
    let cache = SysvarCache::default();
    assert_eq!(cache.last_restart_slot(), 0);

    cache.set_last_restart_slot(999);
    assert_eq!(cache.last_restart_slot(), 999);
}

#[test]
fn last_restart_slot_serialization_roundtrip() {
    let sysvar = LastRestartSlotSysvar::new(42);
    let bytes = sysvar.to_bytes();
    assert_eq!(bytes.len(), 8);

    let restored = LastRestartSlotSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.slot, 42);
}

// -----------------------------------------------------------------------
// EpochRewards
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_epoch_rewards_lifecycle() {
    let cache = SysvarCache::default();
    assert!(!cache.is_epoch_rewards_active());

    let rewards = EpochRewards {
        total_rewards: 1000,
        validator_rewards: 800,
        foundation_rewards: 200,
        capitalization: 1_000_000,
        epoch_duration_years: 0.005,
        validator_rate: 0.06,
        foundation_rate: 0.02,
    };
    cache.set_epoch_rewards(rewards);
    assert!(cache.is_epoch_rewards_active());

    cache.clear_epoch_rewards();
    assert!(!cache.is_epoch_rewards_active());
}

#[test]
fn epoch_rewards_sysvar_active_serialization_roundtrip() {
    let rewards = EpochRewards {
        total_rewards: 5000,
        validator_rewards: 4000,
        foundation_rewards: 1000,
        capitalization: 500_000_000,
        epoch_duration_years: 0.0055,
        validator_rate: 0.065,
        foundation_rate: 0.015,
    };
    let sysvar = EpochRewardsSysvar::active(rewards.clone());
    let bytes = sysvar.to_bytes();
    let restored = EpochRewardsSysvar::from_bytes(&bytes).unwrap();

    assert!(restored.is_active());
    let r = restored.rewards.unwrap();
    assert_eq!(r.total_rewards, rewards.total_rewards);
    assert_eq!(r.validator_rewards, rewards.validator_rewards);
    assert_eq!(r.foundation_rewards, rewards.foundation_rewards);
    assert_eq!(r.capitalization, rewards.capitalization);
}

#[test]
fn epoch_rewards_sysvar_inactive_serialization_roundtrip() {
    let sysvar = EpochRewardsSysvar::inactive();
    let bytes = sysvar.to_bytes();
    let restored = EpochRewardsSysvar::from_bytes(&bytes).unwrap();
    assert!(!restored.is_active());
}

// -----------------------------------------------------------------------
// RecentBlockhashes
// -----------------------------------------------------------------------

#[test]
fn recent_blockhashes_add_and_iterate() {
    let mut rbh = RecentBlockhashesSysvar::new();
    rbh.add([1u8; 32], 5000);
    rbh.add([2u8; 32], 5000);

    assert_eq!(rbh.len(), 2);
    let first = rbh.iter().next().unwrap();
    assert_eq!(first.blockhash, [2u8; 32]); // Most recent first.
}

#[test]
fn recent_blockhashes_capacity_limit() {
    let mut rbh = RecentBlockhashesSysvar::new();
    for i in 0..(MAX_RECENT_BLOCKHASHES + 50) {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        rbh.add(hash, 5000);
    }
    assert_eq!(rbh.len(), MAX_RECENT_BLOCKHASHES);
}

#[test]
fn recent_blockhashes_serialization_roundtrip() {
    let mut rbh = RecentBlockhashesSysvar::new();
    rbh.add([10u8; 32], 5000);
    rbh.add([20u8; 32], 6000);

    let bytes = rbh.to_bytes();
    let restored = RecentBlockhashesSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.len(), 2);

    let entries: Vec<_> = restored.iter().collect();
    assert_eq!(entries[0].blockhash, [20u8; 32]);
    assert_eq!(entries[0].lamports_per_signature, 6000);
    assert_eq!(entries[1].blockhash, [10u8; 32]);
    assert_eq!(entries[1].lamports_per_signature, 5000);
}

// -----------------------------------------------------------------------
// Instructions sysvar
// -----------------------------------------------------------------------

#[test]
fn instructions_sysvar_load_and_access() {
    let instructions = vec![
        SerializedInstruction {
            program_id_index: 0,
            account_indices: vec![1, 2],
            data: vec![0xAA, 0xBB],
        },
        SerializedInstruction {
            program_id_index: 3,
            account_indices: vec![4],
            data: vec![0xCC],
        },
    ];
    let sysvar = InstructionsSysvar::load(instructions).unwrap();

    assert_eq!(sysvar.len(), 2);
    assert_eq!(sysvar.get(0).unwrap().program_id_index, 0);
    assert_eq!(sysvar.get(1).unwrap().data, vec![0xCC]);
    assert!(sysvar.get(2).is_none());
}

#[test]
fn instructions_sysvar_tracks_current_index() {
    let mut sysvar = InstructionsSysvar::new();
    assert_eq!(sysvar.current_index(), 0);

    sysvar.set_current_index(3);
    assert_eq!(sysvar.current_index(), 3);
}

#[test]
fn instructions_sysvar_serialization_roundtrip() {
    let instructions = vec![SerializedInstruction {
        program_id_index: 1,
        account_indices: vec![2, 3, 4],
        data: vec![0x01, 0x02],
    }];
    let mut sysvar = InstructionsSysvar::load(instructions).unwrap();
    sysvar.set_current_index(0);

    let bytes = sysvar.to_bytes();
    let restored = InstructionsSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.current_index(), 0);
    let ix = restored.get(0).unwrap();
    assert_eq!(ix.program_id_index, 1);
    assert_eq!(ix.account_indices, vec![2, 3, 4]);
    assert_eq!(ix.data, vec![0x01, 0x02]);
}

#[test]
fn instructions_sysvar_rejects_too_many_instructions() {
    let instructions = (0..65)
        .map(|i| SerializedInstruction {
            program_id_index: i as u8,
            account_indices: vec![],
            data: vec![],
        })
        .collect();
    assert!(InstructionsSysvar::load(instructions).is_none());
}

// -----------------------------------------------------------------------
// Concurrent access
// -----------------------------------------------------------------------

#[test]
fn sysvar_cache_concurrent_read_write() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(SysvarCache::default());

    let writer = {
        let cache = cache.clone();
        thread::spawn(move || {
            for i in 0..100u64 {
                cache.update_clock(i, 0, Some(i as i64 * 10));
                cache.update_slot_hashes(i, [i as u8; 32]);
                cache.update_slot_history(i);
            }
        })
    };

    let reader = {
        let cache = cache.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                let _ = cache.clock();
                let _ = cache.slot_hashes();
                let _ = cache.slot_history();
                let _ = cache.get_sysvar_account(&CLOCK_SYSVAR_ID);
            }
        })
    };

    writer.join().unwrap();
    reader.join().unwrap();

    // After writer completes, the last slot written should be 99.
    let c = cache.clock();
    assert_eq!(c.slot, 99);
}

#[test]
fn sysvar_cache_concurrent_epoch_boundary() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(SysvarCache::default());
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let cache = cache.clone();
            thread::spawn(move || {
                for epoch in (t * 10)..(t * 10 + 10) {
                    cache.on_epoch_boundary(epoch, StakeHistoryEntry::new(1000 + epoch * 10, 0, 0));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    let history = cache.stake_history();
    assert_eq!(history.len(), 40); // 4 threads * 10 epochs each.
}

// -----------------------------------------------------------------------
// Edge cases and deserialization failures
// -----------------------------------------------------------------------

#[test]
fn slot_hashes_empty_serialization() {
    let sh = SlotHashesSysvar::new();
    let bytes = sh.to_bytes();
    let restored = SlotHashesSysvar::from_bytes(&bytes).unwrap();
    assert!(restored.is_empty());
}

#[test]
fn slot_history_empty_check() {
    let sh = SlotHistorySysvar::new();
    assert!(!sh.check(0));
    assert!(!sh.check(100));
}

#[test]
fn clock_sysvar_default_serialization() {
    let sysvar = ClockSysvar::default();
    let bytes = sysvar.to_bytes();
    let restored = ClockSysvar::from_bytes(&bytes).unwrap();
    assert_eq!(restored.clock, Clock::default());
}

#[test]
fn last_restart_slot_rejects_short_data() {
    assert!(LastRestartSlotSysvar::from_bytes(&[0u8; 7]).is_none());
}

#[test]
fn epoch_rewards_rejects_truncated_active_data() {
    // Active flag but not enough data for the fields.
    let bad = vec![1u8, 0, 0, 0, 0, 0];
    assert!(EpochRewardsSysvar::from_bytes(&bad).is_none());
}

#[test]
fn recent_blockhashes_empty_roundtrip() {
    let rbh = RecentBlockhashesSysvar::new();
    let bytes = rbh.to_bytes();
    let restored = RecentBlockhashesSysvar::from_bytes(&bytes).unwrap();
    assert!(restored.is_empty());
}
