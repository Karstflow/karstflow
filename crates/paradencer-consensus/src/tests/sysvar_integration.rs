/// Integration tests for sysvar lifecycle and Bank wiring.
///
/// Tests that sysvars are updated correctly during slot processing,
/// inherited by child banks, and resolvable during transaction execution.
#[cfg(test)]
mod tests {
    use crate::sysvars::SysvarCache;
    use crate::{Bank, Clock, EpochSchedule, Inflation, LeaderSchedule, Rent};
    use paradencer_constants::ledger::TICKS_PER_SLOT;
    use paradencer_ids::{CLOCK_SYSVAR_ID, SLOT_HASHES_SYSVAR_ID, SLOT_HISTORY_SYSVAR_ID};
    use paradencer_storage::{AccountDatabase, Pubkey};
    use std::sync::Arc;

    fn create_test_leader_schedule(epoch: u64) -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        Arc::new(LeaderSchedule::new(epoch, &[(validator, 1000)]).unwrap())
    }

    fn create_bank_with_sysvars() -> Bank {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let sysvars = Arc::new(SysvarCache::new(
            Clock::default(),
            EpochSchedule::default(),
            Rent::default(),
        ));

        let mut bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000,
            Rent::default(),
            Inflation::default(),
        );
        bank.set_sysvar_cache(sysvars);
        bank
    }

    #[test]
    fn finish_slot_updates_clock_sysvar() {
        let bank = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let sysvars = bank.sysvar_cache().unwrap();
        let clock = sysvars.clock();
        assert_eq!(clock.slot, bank.slot());
        assert_eq!(clock.epoch, bank.epoch());
        assert!(clock.unix_timestamp > 0);
    }

    #[test]
    fn finish_slot_updates_slot_hashes() {
        let bank = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let sysvars = bank.sysvar_cache().unwrap();
        let slot_hashes = sysvars.slot_hashes();
        assert_eq!(slot_hashes.len(), 1);
        assert!(slot_hashes.contains(bank.slot()));
    }

    #[test]
    fn finish_slot_updates_slot_history() {
        let bank = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let sysvars = bank.sysvar_cache().unwrap();
        let slot_history = sysvars.slot_history();
        assert!(slot_history.check(bank.slot()));
    }

    #[test]
    fn finish_slot_updates_recent_blockhashes() {
        let bank = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let sysvars = bank.sysvar_cache().unwrap();
        let recent = sysvars.recent_blockhashes();
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn sysvar_cache_inherited_by_child_bank() {
        let parent = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        let child = Bank::new_from_parent(&parent, 1, create_test_leader_schedule(0));
        assert!(child.sysvar_cache().is_some());

        // Child shares the same sysvar cache
        let child_clock = child.sysvar_cache().unwrap().clock();
        assert_eq!(child_clock.slot, parent.slot());
    }

    #[test]
    fn sysvar_accounts_resolvable_via_get_sysvar_account() {
        let bank = create_bank_with_sysvars();

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let sysvars = bank.sysvar_cache().unwrap();

        // Clock sysvar should be resolvable
        let clock_account = sysvars.get_sysvar_account(&CLOCK_SYSVAR_ID);
        assert!(clock_account.is_some());
        let clock_acc = clock_account.unwrap();
        assert_eq!(clock_acc.data.len(), 40); // Clock is 40 bytes

        // SlotHashes sysvar
        let slot_hashes_account = sysvars.get_sysvar_account(&SLOT_HASHES_SYSVAR_ID);
        assert!(slot_hashes_account.is_some());

        // SlotHistory sysvar
        let slot_history_account = sysvars.get_sysvar_account(&SLOT_HISTORY_SYSVAR_ID);
        assert!(slot_history_account.is_some());

        // Unknown pubkey returns None
        let unknown = Pubkey::new_unique();
        assert!(sysvars.get_sysvar_account(&unknown).is_none());
    }

    #[test]
    fn multiple_slots_accumulate_sysvar_state() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let sysvars = Arc::new(SysvarCache::new(
            Clock::default(),
            EpochSchedule::default(),
            Rent::default(),
        ));

        let mut parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule.clone(),
            1_000_000,
            Rent::default(),
            Inflation::default(),
        );
        parent.set_sysvar_cache(sysvars);

        // Process genesis slot
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        // Create and process a few child slots
        let mut current = parent;
        for slot in 1..5u64 {
            let child = Bank::new_from_parent(&current, slot, leader_schedule.clone());
            for _ in 0..TICKS_PER_SLOT {
                child.register_tick().unwrap();
            }
            child.finish_slot().unwrap();
            current = child;
        }

        let sysvars = current.sysvar_cache().unwrap();

        // Clock should reflect the latest slot
        let clock = sysvars.clock();
        assert_eq!(clock.slot, 4);

        // Slot hashes should have 5 entries (slots 0-4)
        let slot_hashes = sysvars.slot_hashes();
        assert_eq!(slot_hashes.len(), 5);

        // Slot history should have all 5 slots set
        let slot_history = sysvars.slot_history();
        for slot in 0..5u64 {
            assert!(slot_history.check(slot));
        }
    }

    #[test]
    fn genesis_bank_has_sysvar_cache() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert!(bank.sysvar_cache().is_some());

        // Clock should reflect genesis slot/epoch
        let clock = bank.sysvar_cache().unwrap().clock();
        assert_eq!(clock.slot, 0);
        assert_eq!(clock.epoch, 0);

        // finish_slot should still work
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        let result = bank.finish_slot();
        assert!(result.is_ok());
    }
}
