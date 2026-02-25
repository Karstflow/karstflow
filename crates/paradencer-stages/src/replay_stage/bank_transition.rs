use paradencer_consensus::{
    Bank, BankForks, BankForksError, BankFreezeError, BankStatus, ForkChoice,
    SlotFinalizationResult,
};
use std::sync::{Arc, Mutex, RwLock};

/// Errors that can occur during bank transitions
#[derive(Debug, Clone)]
pub enum BankTransitionError {
    /// Bank not found for slot
    BankNotFound(u64),
    /// Parent bank not found
    ParentNotFound(u64),
    /// Bank already exists for slot
    BankAlreadyExists(u64),
    /// Bank is not in correct state for operation
    InvalidBankState {
        slot: u64,
        expected: BankStatus,
        actual: BankStatus,
    },
    /// Bank forks error
    BankForksError(String),
    /// Fork choice error
    ForkChoiceError(String),
    /// Bank is already frozen
    BankAlreadyFrozen(u64),
    /// Bank is not complete (missing ticks)
    BankNotComplete { slot: u64, ticks_remaining: u64 },
    /// Cannot freeze root bank
    CannotFreezeRoot(u64),
    /// Leader schedule not available
    LeaderScheduleNotAvailable(u64),
    /// Slot finalization failed
    FinalizationFailed { slot: u64, error: String },
}

impl From<BankForksError> for BankTransitionError {
    fn from(err: BankForksError) -> Self {
        BankTransitionError::BankForksError(format!("{:?}", err))
    }
}

/// Manages bank lifecycle transitions during replay
///
/// Handles:
/// - Getting working banks for slots
/// - Creating child banks from parents
/// - Freezing banks when slots complete
/// - Coordinating with fork choice
pub struct BankTransition {
    /// Bank forks manager
    pub bank_forks: Arc<RwLock<BankForks>>,
    /// Fork choice engine
    pub fork_choice: Arc<Mutex<ForkChoice>>,
}

impl BankTransition {
    pub fn new(bank_forks: Arc<RwLock<BankForks>>, fork_choice: Arc<Mutex<ForkChoice>>) -> Self {
        Self {
            bank_forks,
            fork_choice,
        }
    }

    /// Get the working bank for a slot
    ///
    /// Returns the bank if it exists, otherwise returns BankNotFound error
    pub fn get_working_bank(&self, slot: u64) -> Result<Arc<Bank>, BankTransitionError> {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks
            .get(slot)
            .ok_or(BankTransitionError::BankNotFound(slot))
    }

    /// Get the current working bank (highest slot)
    pub fn get_current_working_bank(&self) -> Arc<Bank> {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.working_bank()
    }

    /// Create a child bank from a parent slot
    ///
    /// This is called when we need to replay a block at a new slot that doesn't
    /// have a bank yet. The parent must exist in bank_forks.
    pub fn create_child_bank(
        &mut self,
        parent_slot: u64,
        slot: u64,
    ) -> Result<Arc<Bank>, BankTransitionError> {
        // Get parent bank
        let parent_bank = {
            let bank_forks = self.bank_forks.read().unwrap();
            bank_forks
                .get(parent_slot)
                .ok_or(BankTransitionError::ParentNotFound(parent_slot))?
        };

        // Verify parent is frozen
        if !parent_bank.is_frozen() {
            return Err(BankTransitionError::InvalidBankState {
                slot: parent_slot,
                expected: BankStatus::Frozen,
                actual: parent_bank.status(),
            });
        }

        // Get leader schedule for new slot
        // For now, reuse parent's leader schedule
        // In production, this would query the proper leader schedule for the slot's epoch
        let leader_schedule = parent_bank.leader_schedule().clone();

        // Create child bank
        let child_bank = Bank::new_from_parent(&parent_bank, slot, leader_schedule);

        // Insert into bank forks
        let mut bank_forks = self.bank_forks.write().unwrap();
        bank_forks.insert(child_bank)?;

        // Add to fork choice
        let mut fork_choice = self.fork_choice.lock().unwrap();
        fork_choice.add_fork(slot, Some(parent_slot));

        // Get the newly inserted bank
        Ok(bank_forks.get(slot).unwrap())
    }

    /// Freeze a bank when its slot is complete.
    ///
    /// Calls `Bank::finish_slot()` which performs: fee distribution, sysvar
    /// updates, blockhash registration, epoch boundary processing, and
    /// freezes the bank. A bank must be frozen before children can be created.
    pub fn freeze_bank(
        &mut self,
        slot: u64,
    ) -> Result<SlotFinalizationResult, BankTransitionError> {
        let bank = self.get_working_bank(slot)?;

        // Check if already frozen
        if bank.is_frozen() {
            return Err(BankTransitionError::BankAlreadyFrozen(slot));
        }

        // Check if bank is complete (all ticks registered)
        if !bank.is_complete() {
            return Err(BankTransitionError::BankNotComplete {
                slot,
                ticks_remaining: bank.ticks_remaining(),
            });
        }

        // Finalize the slot: distributes fees, updates sysvars, registers
        // blockhash, processes epoch boundary if needed, then freezes.
        let result = bank.finish_slot().map_err(|e| match e {
            BankFreezeError::AlreadyFrozen => BankTransitionError::BankAlreadyFrozen(slot),
            BankFreezeError::IncompleteSlot { .. } => BankTransitionError::BankNotComplete {
                slot,
                ticks_remaining: bank.ticks_remaining(),
            },
        })?;

        Ok(result)
    }

    /// Get or create a bank for a slot
    ///
    /// If the bank exists, return it. Otherwise, create it from parent.
    pub fn get_or_create_bank(
        &mut self,
        slot: u64,
        parent_slot: u64,
    ) -> Result<Arc<Bank>, BankTransitionError> {
        match self.get_working_bank(slot) {
            Ok(bank) => Ok(bank),
            Err(BankTransitionError::BankNotFound(_)) => self.create_child_bank(parent_slot, slot),
            Err(e) => Err(e),
        }
    }

    /// Check if a bank exists for a slot
    pub fn has_bank(&self, slot: u64) -> bool {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.get(slot).is_some()
    }

    /// Get the root slot
    pub fn root_slot(&self) -> u64 {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.root_slot()
    }

    /// Get the root bank
    pub fn root_bank(&self) -> Option<Arc<Bank>> {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.root_bank()
    }

    /// Set a new root
    ///
    /// This prunes all banks below the new root and marks the root bank as rooted.
    pub fn set_root(&mut self, new_root_slot: u64) -> Result<(), BankTransitionError> {
        let mut bank_forks = self.bank_forks.write().unwrap();
        bank_forks.set_root(new_root_slot).map(|_| ())?;
        Ok(())
    }

    /// Get the highest slot in bank forks
    pub fn highest_slot(&self) -> u64 {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.highest_slot()
    }

    /// Check if a slot is an ancestor of another slot
    pub fn is_ancestor(&self, ancestor_slot: u64, slot: u64) -> bool {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.is_ancestor(ancestor_slot, slot)
    }

    /// Get all descendant slots of a given slot
    pub fn descendants(&self, slot: u64) -> Vec<u64> {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.descendants(slot)
    }

    /// Select the best fork to build on using fork choice
    ///
    /// Returns the slot of the heaviest fork tip
    pub fn select_best_fork(&self) -> Option<u64> {
        let fork_choice = self.fork_choice.lock().unwrap();
        fork_choice.best_slot()
    }

    /// Prune non-rooted forks to save memory
    ///
    /// Keeps banks above a certain slot threshold and all rooted banks
    pub fn prune_non_rooted(&mut self, keep_above_slot: u64) {
        let mut bank_forks = self.bank_forks.write().unwrap();
        bank_forks.prune_non_rooted(keep_above_slot);
    }

    /// Get bank count
    pub fn bank_count(&self) -> usize {
        let bank_forks = self.bank_forks.read().unwrap();
        bank_forks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_consensus::{EpochSchedule, LeaderSchedule};
    use paradencer_storage::{AccountDatabase, Pubkey};

    fn create_test_bank_forks() -> Arc<RwLock<BankForks>> {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());
        let genesis = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        Arc::new(RwLock::new(BankForks::new(genesis)))
    }

    #[test]
    fn bank_transition_gets_working_bank() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let transition = BankTransition::new(bank_forks, fork_choice);

        let bank = transition.get_working_bank(0).unwrap();
        assert_eq!(bank.slot(), 0);
    }

    #[test]
    fn bank_transition_creates_child_bank() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let mut transition = BankTransition::new(bank_forks, fork_choice);

        // Freeze parent bank first
        let parent_bank = transition.get_working_bank(0).unwrap();
        // Would need to complete ticks and freeze here in real scenario

        // For testing, we'll check the error case
        let result = transition.create_child_bank(0, 1);
        // Expecting error because parent is not frozen
        assert!(result.is_err());
    }

    #[test]
    fn bank_transition_checks_bank_existence() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let transition = BankTransition::new(bank_forks, fork_choice);

        assert!(transition.has_bank(0));
        assert!(!transition.has_bank(1));
    }

    #[test]
    fn bank_transition_tracks_root() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let transition = BankTransition::new(bank_forks, fork_choice);

        assert_eq!(transition.root_slot(), 0);
        assert!(transition.root_bank().is_some());
    }

    #[test]
    fn bank_transition_gets_highest_slot() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let transition = BankTransition::new(bank_forks, fork_choice);

        assert_eq!(transition.highest_slot(), 0);
    }

    #[test]
    fn bank_transition_counts_banks() {
        let bank_forks = create_test_bank_forks();
        let fork_choice = Arc::new(Mutex::new(ForkChoice::new(1000)));
        let transition = BankTransition::new(bank_forks, fork_choice);

        assert_eq!(transition.bank_count(), 1);
    }
}
