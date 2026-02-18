use super::{Bank, BankStatus};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BankForks {
    banks: HashMap<u64, Arc<Bank>>,
    root_slot: u64,
    working_bank: Arc<Bank>,
}

impl BankForks {
    pub fn new(root_bank: Bank) -> Self {
        let root_slot = root_bank.slot();
        let root_bank = Arc::new(root_bank);

        let mut banks = HashMap::new();
        banks.insert(root_slot, root_bank.clone());

        Self {
            banks,
            root_slot,
            working_bank: root_bank,
        }
    }

    /// Initialize BankForks from a snapshot-restored bank.
    ///
    /// The snapshot bank becomes the root and working bank.
    /// Unlike `new()`, this validates that the bank's slot, epoch,
    /// and status are consistent with a restored snapshot.
    pub fn new_from_snapshot(snapshot_bank: Bank) -> Result<Self, BankForksError> {
        if snapshot_bank.status() != BankStatus::Rooted {
            return Err(BankForksError::SnapshotBankNotRooted);
        }

        let root_slot = snapshot_bank.slot();
        let bank = Arc::new(snapshot_bank);
        let mut banks = HashMap::new();
        banks.insert(root_slot, bank.clone());

        Ok(Self {
            banks,
            root_slot,
            working_bank: bank,
        })
    }

    pub fn root_slot(&self) -> u64 {
        self.root_slot
    }

    pub fn root_bank(&self) -> Option<Arc<Bank>> {
        self.banks.get(&self.root_slot).cloned()
    }

    pub fn working_bank(&self) -> Arc<Bank> {
        self.working_bank.clone()
    }

    pub fn get(&self, slot: u64) -> Option<Arc<Bank>> {
        self.banks.get(&slot).cloned()
    }

    pub fn insert(&mut self, bank: Bank) -> Result<(), BankForksError> {
        let slot = bank.slot();

        if slot <= self.root_slot {
            return Err(BankForksError::SlotBelowRoot {
                slot,
                root_slot: self.root_slot,
            });
        }

        if self.banks.contains_key(&slot) {
            return Err(BankForksError::SlotAlreadyExists(slot));
        }

        let parent_slot = bank.parent_slot();
        if let Some(parent_slot) = parent_slot {
            if !self.banks.contains_key(&parent_slot) {
                return Err(BankForksError::ParentNotFound { slot, parent_slot });
            }
        }

        self.banks.insert(slot, Arc::new(bank));
        Ok(())
    }

    pub fn set_root(&mut self, new_root_slot: u64) -> Result<(), BankForksError> {
        if new_root_slot <= self.root_slot {
            return Err(BankForksError::RootNotAdvancing {
                current_root: self.root_slot,
                new_root: new_root_slot,
            });
        }

        let new_root_bank = self
            .banks
            .get(&new_root_slot)
            .ok_or(BankForksError::RootBankNotFound(new_root_slot))?;

        if new_root_bank.status() != BankStatus::Rooted {
            return Err(BankForksError::BankNotRooted(new_root_slot));
        }

        self.banks.retain(|slot, _| *slot >= new_root_slot);

        self.root_slot = new_root_slot;
        Ok(())
    }

    pub fn set_working_bank(&mut self, slot: u64) -> Result<(), BankForksError> {
        let bank = self
            .banks
            .get(&slot)
            .ok_or(BankForksError::BankNotFound(slot))?
            .clone();

        self.working_bank = bank;
        Ok(())
    }

    pub fn prune_non_rooted(&mut self, keep_above_slot: u64) {
        let root_slot = self.root_slot;
        let ancestors = self.collect_ancestors(self.working_bank.slot());

        self.banks.retain(|slot, bank| {
            *slot == root_slot
                || *slot > keep_above_slot
                || bank.status() == BankStatus::Rooted
                || ancestors.contains(slot)
        });
    }

    pub fn descendants(&self, slot: u64) -> Vec<u64> {
        self.banks
            .keys()
            .filter(|&&s| {
                if s <= slot {
                    return false;
                }
                self.is_ancestor(slot, s)
            })
            .copied()
            .collect()
    }

    pub fn is_ancestor(&self, ancestor_slot: u64, slot: u64) -> bool {
        if ancestor_slot >= slot {
            return false;
        }

        let mut current_slot = slot;
        while current_slot > ancestor_slot {
            if let Some(bank) = self.banks.get(&current_slot) {
                if let Some(parent_slot) = bank.parent_slot() {
                    if parent_slot == ancestor_slot {
                        return true;
                    }
                    current_slot = parent_slot;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        false
    }

    pub fn highest_slot(&self) -> u64 {
        self.banks.keys().copied().max().unwrap_or(self.root_slot)
    }

    pub fn len(&self) -> usize {
        self.banks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.banks.is_empty()
    }

    fn collect_ancestors(&self, slot: u64) -> Vec<u64> {
        let mut ancestors = Vec::new();
        let mut current_slot = slot;

        while let Some(bank) = self.banks.get(&current_slot) {
            if let Some(parent_slot) = bank.parent_slot() {
                ancestors.push(parent_slot);
                current_slot = parent_slot;
            } else {
                break;
            }
        }

        ancestors
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankForksError {
    SlotBelowRoot { slot: u64, root_slot: u64 },
    SlotAlreadyExists(u64),
    ParentNotFound { slot: u64, parent_slot: u64 },
    RootNotAdvancing { current_root: u64, new_root: u64 },
    RootBankNotFound(u64),
    BankNotRooted(u64),
    BankNotFound(u64),
    SnapshotBankNotRooted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochSchedule, LeaderSchedule};
    use paradencer_storage::{AccountDatabase, Pubkey};

    fn create_test_leader_schedule(epoch: u64) -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        Arc::new(LeaderSchedule::new(epoch, &validators).unwrap())
    }

    fn create_genesis_bank() -> Bank {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);
        Bank::new_genesis(accounts, epoch_schedule, leader_schedule)
    }

    #[test]
    fn bank_forks_initializes_with_genesis() {
        let genesis = create_genesis_bank();
        let genesis_slot = genesis.slot();

        let forks = BankForks::new(genesis);

        assert_eq!(forks.root_slot(), genesis_slot);
        assert_eq!(forks.working_bank().slot(), genesis_slot);
        assert_eq!(forks.len(), 1);
    }

    #[test]
    fn bank_forks_inserts_child_bank() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        assert!(forks.insert(child).is_ok());
        assert_eq!(forks.len(), 2);
        assert!(forks.get(1).is_some());
    }

    #[test]
    fn bank_forks_rejects_duplicate_slot() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child1 = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());
        let child2 = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        assert!(forks.insert(child1).is_ok());
        assert_eq!(
            forks.insert(child2),
            Err(BankForksError::SlotAlreadyExists(1))
        );
    }

    #[test]
    fn bank_forks_rejects_orphan_bank() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let intermediate = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());

        let orphan = Bank::new_from_parent(&intermediate, 100, leader_schedule);

        assert!(matches!(
            forks.insert(orphan),
            Err(BankForksError::ParentNotFound { .. })
        ));
    }

    #[test]
    fn bank_forks_sets_root() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

        for _ in 0..paradencer_constants::ledger::TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.freeze().unwrap();
        child.mark_rooted().unwrap();

        forks.insert(child).unwrap();
        assert!(forks.set_root(1).is_ok());
        assert_eq!(forks.root_slot(), 1);
    }

    #[test]
    fn bank_forks_prunes_on_set_root() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let parent_bank = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(0);

        let bank1 = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());
        for _ in 0..paradencer_constants::ledger::TICKS_PER_SLOT {
            bank1.register_tick().unwrap();
        }
        bank1.freeze().unwrap();
        bank1.mark_rooted().unwrap();
        forks.insert(bank1).unwrap();

        let bank2 = Bank::new_from_parent(&parent_bank, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        assert_eq!(forks.len(), 3);

        forks.set_root(1).unwrap();

        assert_eq!(forks.len(), 2);
        assert!(forks.get(0).is_none());
        assert!(forks.get(1).is_some());
        assert!(forks.get(2).is_some());
    }

    #[test]
    fn bank_forks_tracks_descendants() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();

        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        let descendants = forks.descendants(0);
        assert_eq!(descendants.len(), 2);
        assert!(descendants.contains(&1));
        assert!(descendants.contains(&2));

        let descendants = forks.descendants(1);
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&2));
    }

    // -- Snapshot restore integration tests --

    fn make_snapshot_bank(slot: u64, epoch: u64) -> Bank {
        use paradencer_storage::{
            EpochScheduleConfig as SnapEpochSchedule, FeeRateConfig, InflationConfig,
            RecentBlockhash, RentConfig, SnapshotBankState, StakeSummary,
        };

        let ticks_per_slot = 64u64;
        let tick_height = slot * ticks_per_slot + ticks_per_slot;

        let state = SnapshotBankState {
            recent_blockhashes: vec![RecentBlockhash {
                hash: [0xAA; 32],
                lamports_per_signature: 5000,
                hash_index: 100,
                timestamp: 1_000_000,
            }],
            last_blockhash: Some([0xAA; 32]),
            max_blockhash_age: 300,
            last_blockhash_index: 100,
            slot,
            parent_slot: slot.saturating_sub(1),
            block_height: slot,
            epoch,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            transaction_count: 50_000,
            tick_height,
            max_tick_height: tick_height,
            signature_count: 25_000,
            capitalization: 500_000_000_000,
            accounts_data_len: 1_000_000,
            hashes_per_tick: Some(12500),
            ticks_per_slot,
            ns_per_slot: 400_000_000,
            genesis_creation_time: 1_700_000_000,
            slots_per_year: 78_892_314.0,
            collector_id: [0x33; 32],
            collector_fees: 0,
            fee_rate_governor: FeeRateConfig {
                target_lamports_per_signature: 10_000,
                target_signatures_per_slot: 20_000,
                min_lamports_per_signature: 5_000,
                max_lamports_per_signature: 100_000,
                burn_percent: 50,
            },
            rent: RentConfig {
                lamports_per_byte_year: 3_480,
                exemption_threshold: 2.0,
                burn_percent: 50,
                collector_epoch: epoch,
                collector_slots_per_year: 78_892_314.0,
            },
            collected_rent: 0,
            epoch_schedule: SnapEpochSchedule {
                slots_per_epoch: 432_000,
                leader_schedule_slot_offset: 432_000,
                warmup: false,
                first_normal_epoch: 0,
                first_normal_slot: 0,
            },
            inflation: InflationConfig {
                initial: 0.08,
                terminal: 0.015,
                taper: 0.15,
                foundation: 0.05,
                foundation_term: 7.0,
            },
            hard_forks: vec![],
            ancestor_count: 0,
            stake_summary: StakeSummary::default(),
            is_delta: true,
        };

        let accounts = Arc::new(AccountDatabase::new());
        let leader_schedule = create_test_leader_schedule(epoch);
        Bank::new_from_snapshot(accounts, &state, leader_schedule)
    }

    #[test]
    fn bank_forks_from_snapshot_bank() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        assert_eq!(forks.root_slot(), 1000);
        assert_eq!(forks.working_bank().slot(), 1000);
        assert_eq!(forks.len(), 1);
    }

    #[test]
    fn bank_forks_snapshot_rejects_non_rooted() {
        // A genesis bank is in Processing status, not Rooted
        let genesis = create_genesis_bank();
        let result = BankForks::new_from_snapshot(genesis);
        assert!(matches!(result, Err(BankForksError::SnapshotBankNotRooted)));
    }

    #[test]
    fn bank_forks_snapshot_accepts_child_slot() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let mut forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        let parent = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(2);
        let child = Bank::new_from_parent(&parent, 1001, leader_schedule);

        assert!(forks.insert(child).is_ok());
        assert_eq!(forks.len(), 2);
        assert!(forks.get(1001).is_some());
    }

    #[test]
    fn bank_forks_snapshot_full_lifecycle() {
        let snap_bank = make_snapshot_bank(1000, 2);
        let mut forks = BankForks::new_from_snapshot(snap_bank).unwrap();

        // Create child from snapshot root
        let parent = forks.working_bank();
        let leader_schedule = create_test_leader_schedule(2);
        let child = Bank::new_from_parent(&parent, 1001, leader_schedule);

        // Complete, freeze, and root the child
        for _ in 0..paradencer_constants::ledger::TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.freeze().unwrap();
        child.mark_rooted().unwrap();

        forks.insert(child).unwrap();

        // Advance root to the child
        assert!(forks.set_root(1001).is_ok());
        assert_eq!(forks.root_slot(), 1001);

        // Old snapshot root should be pruned
        assert!(forks.get(1000).is_none());
        assert!(forks.get(1001).is_some());
    }

    #[test]
    fn bank_forks_checks_ancestry() {
        let genesis = create_genesis_bank();
        let mut forks = BankForks::new(genesis);

        let leader_schedule = create_test_leader_schedule(0);
        let bank0 = forks.working_bank();

        let bank1 = Bank::new_from_parent(&bank0, 1, leader_schedule.clone());
        forks.insert(bank1).unwrap();

        let bank1_ref = forks.get(1).unwrap();
        let bank2 = Bank::new_from_parent(&bank1_ref, 2, leader_schedule);
        forks.insert(bank2).unwrap();

        assert!(forks.is_ancestor(0, 1));
        assert!(forks.is_ancestor(0, 2));
        assert!(forks.is_ancestor(1, 2));
        assert!(!forks.is_ancestor(1, 1));
        assert!(!forks.is_ancestor(2, 1));
    }
}
