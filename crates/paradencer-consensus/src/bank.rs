use super::{EpochSchedule, Inflation, LeaderSchedule, Rent};
use paradencer_constants::economics::FEE_BURN_PERCENT;
use paradencer_constants::ledger::{GENESIS_EPOCH, GENESIS_SLOT, TICKS_PER_SLOT};
use paradencer_storage::{AccountDatabase, Pubkey};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BankStatus {
    Processing,
    Frozen,
    Rooted,
}

impl BankStatus {
    fn to_u8(self) -> u8 {
        match self {
            BankStatus::Processing => 0,
            BankStatus::Frozen => 1,
            BankStatus::Rooted => 2,
        }
    }

    fn from_u8(val: u8) -> Self {
        match val {
            0 => BankStatus::Processing,
            1 => BankStatus::Frozen,
            2 => BankStatus::Rooted,
            _ => BankStatus::Processing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotInfo {
    pub slot: u64,
    pub epoch: u64,
    pub slot_index: u64,
    pub ticks_per_slot: u64,
}

#[derive(Debug)]
pub struct Bank {
    slot: u64,
    parent_slot: Option<u64>,
    parent_hash: [u8; 32],

    status: AtomicU8,
    tick_height: AtomicU64,
    max_tick_height: u64,

    epoch: u64,
    slot_index: u64,
    epoch_schedule: Arc<EpochSchedule>,
    leader_schedule: Arc<LeaderSchedule>,

    accounts: Arc<AccountDatabase>,
    transaction_count: AtomicU64,

    // Fee collection
    execution_fees: AtomicU64,
    priority_fees: AtomicU64,

    // Economic configuration
    capitalization: AtomicU64,
    rent: Rent,
    inflation: Inflation,
}

impl Bank {
    pub fn new_genesis(
        accounts: Arc<AccountDatabase>,
        epoch_schedule: Arc<EpochSchedule>,
        leader_schedule: Arc<LeaderSchedule>,
    ) -> Self {
        Self::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            0, // Initial capitalization
            Rent::default(),
            Inflation::default(),
        )
    }

    pub fn new_genesis_with_config(
        accounts: Arc<AccountDatabase>,
        epoch_schedule: Arc<EpochSchedule>,
        leader_schedule: Arc<LeaderSchedule>,
        capitalization: u64,
        rent: Rent,
        inflation: Inflation,
    ) -> Self {
        let slot = GENESIS_SLOT;
        let epoch = GENESIS_EPOCH;
        let slot_index = 0;
        let tick_height = 0;
        let max_tick_height = TICKS_PER_SLOT;

        Self {
            slot,
            parent_slot: None,
            parent_hash: [0u8; 32],
            status: AtomicU8::new(BankStatus::Processing.to_u8()),
            tick_height: AtomicU64::new(tick_height),
            max_tick_height,
            epoch,
            slot_index,
            epoch_schedule,
            leader_schedule,
            accounts,
            transaction_count: AtomicU64::new(0),
            execution_fees: AtomicU64::new(0),
            priority_fees: AtomicU64::new(0),
            capitalization: AtomicU64::new(capitalization),
            rent,
            inflation,
        }
    }

    pub fn new_from_parent(parent: &Bank, slot: u64, leader_schedule: Arc<LeaderSchedule>) -> Self {
        let (epoch, slot_index) = parent.epoch_schedule.get_epoch_and_slot_index(slot);
        let tick_height = parent.tick_height.load(Ordering::Relaxed);
        let max_tick_height = tick_height.saturating_add(TICKS_PER_SLOT);

        let parent_hash = parent.hash();

        Self {
            slot,
            parent_slot: Some(parent.slot),
            parent_hash,
            status: AtomicU8::new(BankStatus::Processing.to_u8()),
            tick_height: AtomicU64::new(tick_height),
            max_tick_height,
            epoch,
            slot_index,
            epoch_schedule: parent.epoch_schedule.clone(),
            leader_schedule,
            accounts: parent.accounts.clone(),
            transaction_count: AtomicU64::new(0),
            execution_fees: AtomicU64::new(0),
            priority_fees: AtomicU64::new(0),
            capitalization: AtomicU64::new(parent.capitalization.load(Ordering::Relaxed)),
            rent: parent.rent,
            inflation: parent.inflation,
        }
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn parent_slot(&self) -> Option<u64> {
        self.parent_slot
    }

    pub fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn slot_index(&self) -> u64 {
        self.slot_index
    }

    pub fn tick_height(&self) -> u64 {
        self.tick_height.load(Ordering::Relaxed)
    }

    pub fn max_tick_height(&self) -> u64 {
        self.max_tick_height
    }

    pub fn ticks_remaining(&self) -> u64 {
        self.max_tick_height
            .saturating_sub(self.tick_height.load(Ordering::Relaxed))
    }

    pub fn is_complete(&self) -> bool {
        self.tick_height.load(Ordering::Relaxed) >= self.max_tick_height
    }

    pub fn status(&self) -> BankStatus {
        BankStatus::from_u8(self.status.load(Ordering::Relaxed))
    }

    pub fn is_frozen(&self) -> bool {
        let status = BankStatus::from_u8(self.status.load(Ordering::Relaxed));
        matches!(status, BankStatus::Frozen | BankStatus::Rooted)
    }

    pub fn transaction_count(&self) -> u64 {
        self.transaction_count.load(Ordering::Relaxed)
    }

    pub fn accounts(&self) -> &Arc<AccountDatabase> {
        &self.accounts
    }

    pub fn leader_schedule(&self) -> &Arc<LeaderSchedule> {
        &self.leader_schedule
    }

    pub fn epoch_schedule(&self) -> &Arc<EpochSchedule> {
        &self.epoch_schedule
    }

    pub fn slot_info(&self) -> SlotInfo {
        SlotInfo {
            slot: self.slot,
            epoch: self.epoch,
            slot_index: self.slot_index,
            ticks_per_slot: TICKS_PER_SLOT,
        }
    }

    pub fn get_leader(&self) -> Option<Pubkey> {
        self.leader_schedule.get_leader(self.slot_index)
    }

    /// Check whether this bank is at an epoch boundary.
    ///
    /// Returns true when the bank's epoch differs from its parent's epoch,
    /// indicating that epoch-boundary processing (rewards, feature activation,
    /// leader schedule rotation, etc.) should be triggered.
    pub fn is_epoch_boundary(&self) -> bool {
        if self.slot == GENESIS_SLOT {
            return false;
        }

        match self.parent_slot {
            Some(parent_slot) => {
                let parent_epoch = self.epoch_schedule.get_epoch(parent_slot);
                self.epoch > parent_epoch
            }
            None => false,
        }
    }

    pub fn register_tick(&self) -> Result<(), BankTickError> {
        if self.is_frozen() {
            return Err(BankTickError::BankFrozen);
        }

        if self.is_complete() {
            return Err(BankTickError::MaxTickHeightReached);
        }

        self.tick_height.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn register_transaction(&self) -> Result<(), BankTransactionError> {
        if self.is_frozen() {
            return Err(BankTransactionError::BankFrozen);
        }

        self.transaction_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn freeze(&self) -> Result<(), BankFreezeError> {
        if self.is_frozen() {
            return Err(BankFreezeError::AlreadyFrozen);
        }

        if !self.is_complete() {
            return Err(BankFreezeError::IncompleteSlot {
                current_ticks: self.tick_height(),
                required_ticks: self.max_tick_height,
            });
        }

        self.status
            .store(BankStatus::Frozen.to_u8(), Ordering::Relaxed);
        Ok(())
    }

    pub fn mark_rooted(&self) -> Result<(), BankRootError> {
        if self.status() != BankStatus::Frozen {
            return Err(BankRootError::NotFrozen);
        }

        self.status
            .store(BankStatus::Rooted.to_u8(), Ordering::Relaxed);
        Ok(())
    }

    // Fee collection methods

    /// Add execution fee from a processed transaction.
    pub fn add_execution_fee(&self, fee: u64) {
        self.execution_fees.fetch_add(fee, Ordering::Relaxed);
    }

    /// Add priority fee from a processed transaction.
    pub fn add_priority_fee(&self, fee: u64) {
        self.priority_fees.fetch_add(fee, Ordering::Relaxed);
    }

    /// Get total execution fees collected this slot.
    pub fn execution_fees(&self) -> u64 {
        self.execution_fees.load(Ordering::Relaxed)
    }

    /// Get total priority fees collected this slot.
    pub fn priority_fees(&self) -> u64 {
        self.priority_fees.load(Ordering::Relaxed)
    }

    /// Collect accumulated fees and prepare distribution to leader.
    ///
    /// Burns 50% of execution fees to reduce total supply.
    /// Returns (total_collected, burned_amount, distributed_to_leader).
    pub fn collect_fees(&self, _leader: Pubkey) -> Result<(u64, u64, u64), BankFeeError> {
        if self.is_frozen() {
            return Err(BankFeeError::BankFrozen);
        }

        let execution_fees = self.execution_fees.swap(0, Ordering::Relaxed);
        let priority_fees = self.priority_fees.swap(0, Ordering::Relaxed);

        // Burn 50% of execution fees
        let burn = execution_fees / 2;
        let fees_to_distribute = priority_fees.saturating_add(execution_fees - burn);

        // Reduce capitalization by burned amount
        self.capitalization.fetch_sub(burn, Ordering::Relaxed);

        // TODO: Actually credit the leader account when we have account modification
        // For now, just return the amounts
        let total_collected = execution_fees.saturating_add(priority_fees);

        Ok((total_collected, burn, fees_to_distribute))
    }

    /// Distribute accumulated fees: burn a portion and credit the leader.
    ///
    /// This is a higher-level convenience that combines fee collection and
    /// capitalization adjustment. Returns (leader_share, burn_share).
    pub fn distribute_fees(&self) -> Result<(u64, u64), BankFeeError> {
        if self.is_frozen() {
            return Err(BankFeeError::BankFrozen);
        }

        let execution_fees = self.execution_fees.swap(0, Ordering::Relaxed);
        let priority_fees = self.priority_fees.swap(0, Ordering::Relaxed);
        let total_fees = execution_fees.saturating_add(priority_fees);

        if total_fees == 0 {
            return Ok((0, 0));
        }

        let burn_share = total_fees
            .saturating_mul(FEE_BURN_PERCENT)
            .checked_div(100)
            .unwrap_or(0);
        let leader_share = total_fees.saturating_sub(burn_share);

        // Reduce capitalization by burned amount
        self.capitalization.fetch_sub(burn_share, Ordering::Relaxed);

        Ok((leader_share, burn_share))
    }

    // Economic configuration accessors

    pub fn capitalization(&self) -> u64 {
        self.capitalization.load(Ordering::Relaxed)
    }

    pub fn set_capitalization(&self, capitalization: u64) {
        self.capitalization.store(capitalization, Ordering::Relaxed);
    }

    pub fn rent(&self) -> &Rent {
        &self.rent
    }

    pub fn inflation(&self) -> &Inflation {
        &self.inflation
    }

    /// Calculate inflation rewards for the current epoch.
    ///
    /// Returns (validator_rewards_lamports, validator_rate, foundation_rate).
    pub fn calculate_epoch_inflation_rewards(&self, slots_per_year: f64) -> (u64, f64, f64) {
        let epoch_slots = self.epoch_schedule.get_slots_in_epoch(self.epoch);
        let year = (self.slot as f64) / slots_per_year;

        let validator_rate = self.inflation.validator_rate(year);
        let foundation_rate = self.inflation.foundation_rate(year);

        // Calculate rewards based on capitalization and rates
        let validator_rewards = (self.capitalization.load(Ordering::Relaxed) as f64
            * validator_rate
            * (epoch_slots as f64 / slots_per_year)) as u64;

        (validator_rewards, validator_rate, foundation_rate)
    }

    pub fn hash(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let tick_height = self.tick_height.load(Ordering::Relaxed);
        let transaction_count = self.transaction_count.load(Ordering::Relaxed);

        let mut hasher = DefaultHasher::new();
        self.slot.hash(&mut hasher);
        self.parent_hash.hash(&mut hasher);
        tick_height.hash(&mut hasher);
        transaction_count.hash(&mut hasher);

        let hash_u64 = hasher.finish();
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&hash_u64.to_le_bytes());
        result[8..16].copy_from_slice(&self.slot.to_le_bytes());
        result[16..24].copy_from_slice(&tick_height.to_le_bytes());
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankTickError {
    BankFrozen,
    MaxTickHeightReached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankTransactionError {
    BankFrozen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankFreezeError {
    AlreadyFrozen,
    IncompleteSlot {
        current_ticks: u64,
        required_ticks: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankRootError {
    NotFrozen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankFeeError {
    BankFrozen,
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::ledger::SLOTS_PER_EPOCH;
    use paradencer_storage::Pubkey;

    fn create_test_leader_schedule(epoch: u64) -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        Arc::new(LeaderSchedule::new(epoch, &validators).unwrap())
    }

    #[test]
    fn bank_genesis_initializes_correctly() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert_eq!(bank.slot(), GENESIS_SLOT);
        assert_eq!(bank.epoch(), GENESIS_EPOCH);
        assert_eq!(bank.parent_slot(), None);
        assert_eq!(bank.tick_height(), 0);
        assert_eq!(bank.max_tick_height(), TICKS_PER_SLOT);
        assert_eq!(bank.status(), BankStatus::Processing);
        assert_eq!(bank.transaction_count(), 0);
        assert!(!bank.is_frozen());
        assert!(!bank.is_complete());
    }

    #[test]
    fn bank_registers_ticks_correctly() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for i in 1..=TICKS_PER_SLOT {
            assert!(bank.register_tick().is_ok());
            assert_eq!(bank.tick_height(), i);
            assert_eq!(bank.ticks_remaining(), TICKS_PER_SLOT - i);
        }

        assert!(bank.is_complete());
        assert_eq!(
            bank.register_tick(),
            Err(BankTickError::MaxTickHeightReached)
        );
    }

    #[test]
    fn bank_registers_transactions_correctly() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert!(bank.register_transaction().is_ok());
        assert_eq!(bank.transaction_count(), 1);

        assert!(bank.register_transaction().is_ok());
        assert_eq!(bank.transaction_count(), 2);
    }

    #[test]
    fn bank_freezes_only_when_complete() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert!(matches!(
            bank.freeze(),
            Err(BankFreezeError::IncompleteSlot { .. })
        ));

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }

        assert!(bank.freeze().is_ok());
        assert_eq!(bank.status(), BankStatus::Frozen);
        assert!(bank.is_frozen());
    }

    #[test]
    fn bank_rejects_operations_after_freeze() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        assert_eq!(bank.register_tick(), Err(BankTickError::BankFrozen));
        assert_eq!(
            bank.register_transaction(),
            Err(BankTransactionError::BankFrozen)
        );
    }

    #[test]
    fn bank_can_be_marked_rooted() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert_eq!(bank.mark_rooted(), Err(BankRootError::NotFrozen));

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        assert!(bank.mark_rooted().is_ok());
        assert_eq!(bank.status(), BankStatus::Rooted);
    }

    #[test]
    fn bank_child_inherits_from_parent() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut parent = Bank::new_genesis(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule.clone(),
        );

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        let child_leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent, 1, child_leader_schedule);

        assert_eq!(child.slot(), 1);
        assert_eq!(child.parent_slot(), Some(0));
        assert_eq!(child.tick_height(), parent.tick_height());
        assert_eq!(
            child.max_tick_height(),
            parent.tick_height() + TICKS_PER_SLOT
        );
        assert_eq!(child.status(), BankStatus::Processing);
        assert!(!child.is_frozen());
    }

    #[test]
    fn bank_computes_hash_consistently() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank1 = Bank::new_genesis(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule.clone(),
        );
        let bank2 = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert_eq!(bank1.hash(), bank2.hash());
    }

    #[test]
    fn bank_hash_changes_with_state() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let hash_before = bank.hash();
        bank.register_tick().unwrap();
        let hash_after = bank.hash();

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn bank_fee_collection_adds_fees() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        bank.add_execution_fee(1000);
        bank.add_priority_fee(500);

        assert_eq!(bank.execution_fees(), 1000);
        assert_eq!(bank.priority_fees(), 500);

        bank.add_execution_fee(2000);
        bank.add_priority_fee(1500);

        assert_eq!(bank.execution_fees(), 3000);
        assert_eq!(bank.priority_fees(), 2000);
    }

    #[test]
    fn bank_fee_collection_burns_half_execution_fees() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000, // Initial capitalization
            Rent::default(),
            Inflation::default(),
        );

        bank.add_execution_fee(1000);
        bank.add_priority_fee(500);

        let leader = Pubkey::new_unique();
        let (total, burned, distributed) = bank.collect_fees(leader).unwrap();

        // Total collected: 1000 + 500 = 1500
        assert_eq!(total, 1500);
        // Burned: 1000 / 2 = 500
        assert_eq!(burned, 500);
        // Distributed: 500 + (1000 - 500) = 500 + 500 = 1000
        assert_eq!(distributed, 1000);

        // Capitalization reduced by burned amount
        assert_eq!(bank.capitalization(), 1_000_000_000 - 500);

        // Fees reset to 0
        assert_eq!(bank.execution_fees(), 0);
        assert_eq!(bank.priority_fees(), 0);
    }

    #[test]
    fn bank_fee_collection_rejects_when_frozen() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        let leader = Pubkey::new_unique();
        let result = bank.collect_fees(leader);

        assert_eq!(result, Err(BankFeeError::BankFrozen));
    }

    #[test]
    fn bank_inherits_economic_config_from_parent() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let rent = Rent {
            lamports_per_byte_year: 5000,
            exemption_threshold: 2.5,
            burn_percent: 75,
        };
        let inflation = Inflation {
            initial_rate: 0.1,
            terminal_rate: 0.02,
            tapering_rate: 0.2,
            foundation_portion: 0.06,
            foundation_duration_years: 8.0,
        };

        let mut parent = Bank::new_genesis_with_config(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule.clone(),
            1_000_000_000,
            rent,
            inflation,
        );

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        let child_leader_schedule = create_test_leader_schedule(0);
        let child = Bank::new_from_parent(&parent, 1, child_leader_schedule);

        assert_eq!(child.capitalization(), parent.capitalization());
        assert_eq!(child.rent().lamports_per_byte_year, 5000);
        assert_eq!(child.rent().exemption_threshold, 2.5);
        assert_eq!(child.inflation().initial_rate, 0.1);
        assert_eq!(child.inflation().terminal_rate, 0.02);
    }

    #[test]
    fn bank_calculates_inflation_rewards() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000_000, // 1 trillion lamports
            Rent::default(),
            Inflation::default(),
        );

        let slots_per_year = 365.0 * 24.0 * 60.0 * 60.0 / 0.4; // Assuming 400ms slots
        let (validator_rewards, validator_rate, foundation_rate) =
            bank.calculate_epoch_inflation_rewards(slots_per_year);

        assert!(validator_rewards > 0);
        assert!(validator_rate > 0.0);
        assert!(foundation_rate >= 0.0);
    }

    #[test]
    fn bank_rent_configuration() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let rent = bank.rent();
        assert!(rent.minimum_balance(100) > 0);
        assert!(rent.is_exempt(1_000_000, 100));
    }

    // New tests for is_epoch_boundary and distribute_fees

    #[test]
    fn bank_genesis_is_not_epoch_boundary() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert!(!bank.is_epoch_boundary());
    }

    #[test]
    fn bank_mid_epoch_is_not_epoch_boundary() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule.clone());

        // Slot 1 is still in epoch 0
        let child = Bank::new_from_parent(&parent, 1, leader_schedule);
        assert!(!child.is_epoch_boundary());
    }

    #[test]
    fn bank_first_slot_of_new_epoch_is_epoch_boundary() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule.clone());

        // First slot of epoch 1
        let epoch_1_start = SLOTS_PER_EPOCH;
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, epoch_1_start, child_schedule);

        assert!(child.is_epoch_boundary());
        assert_eq!(child.epoch(), 1);
    }

    #[test]
    fn bank_distribute_fees_splits_correctly() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        bank.add_execution_fee(6000);
        bank.add_priority_fee(4000);

        let (leader, burned) = bank.distribute_fees().unwrap();

        // Total = 10000, burn 50% = 5000
        assert_eq!(burned, 5000);
        assert_eq!(leader, 5000);

        // Capitalization reduced
        assert_eq!(bank.capitalization(), 1_000_000_000 - 5000);

        // Fees cleared
        assert_eq!(bank.execution_fees(), 0);
        assert_eq!(bank.priority_fees(), 0);
    }

    #[test]
    fn bank_distribute_fees_with_zero() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000,
            Rent::default(),
            Inflation::default(),
        );

        let (leader, burned) = bank.distribute_fees().unwrap();
        assert_eq!(leader, 0);
        assert_eq!(burned, 0);
        assert_eq!(bank.capitalization(), 1_000_000);
    }

    #[test]
    fn bank_distribute_fees_rejects_when_frozen() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.freeze().unwrap();

        assert_eq!(bank.distribute_fees(), Err(BankFeeError::BankFrozen));
    }
}
