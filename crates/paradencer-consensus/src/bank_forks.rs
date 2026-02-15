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
        let mut child = Bank::new_from_parent(&parent_bank, 1, leader_schedule);

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

        let mut bank1 = Bank::new_from_parent(&parent_bank, 1, leader_schedule.clone());
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
