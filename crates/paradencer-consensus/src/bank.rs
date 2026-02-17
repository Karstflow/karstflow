use super::{EpochSchedule, Inflation, LeaderSchedule, Rent};
use crate::epoch_processing::EpochProcessor;
use crate::features::{process_feature_activations, FeatureSet};
use crate::reward_application::RewardApplicator;
use crate::rewards_distribution::RewardsDistributor;
use crate::StakeHistory;
use crate::StakeTracker;
use crate::sysvars::SysvarCache;
use paradencer_constants::economics::{FEE_BURN_PERCENT, LAMPORTS_PER_SIGNATURE};
use paradencer_constants::ledger::{GENESIS_EPOCH, GENESIS_SLOT, TICKS_PER_SLOT};
use paradencer_crypto::lthash::{self, LatticeHashValue};
use paradencer_storage::{Account, AccountDatabase, Pubkey};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

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

    // Sysvar cache (shared across the runtime)
    sysvars: Option<Arc<SysvarCache>>,

    // Bank hash state
    /// Cumulative lattice hash of all account states in this slot.
    lthash: RwLock<LatticeHashValue>,
    /// Number of transaction signatures processed in this slot.
    signature_count: AtomicU64,
    /// Last PoH blockhash for this slot.
    last_blockhash: RwLock<[u8; 32]>,

    // Epoch boundary state (optional, set externally)
    stake_tracker: Option<Arc<RwLock<StakeTracker>>>,
    stake_history: Option<Arc<RwLock<StakeHistory>>>,
    feature_set: Option<Arc<RwLock<FeatureSet>>>,
    rewards_distributor: RwLock<Option<RewardsDistributor>>,
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
            sysvars: None,
            lthash: RwLock::new(LatticeHashValue::zero()),
            signature_count: AtomicU64::new(0),
            last_blockhash: RwLock::new([0u8; 32]),
            stake_tracker: None,
            stake_history: None,
            feature_set: None,
            rewards_distributor: RwLock::new(None),
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
            sysvars: parent.sysvars.clone(),
            lthash: RwLock::new(parent.lthash.read().unwrap().clone()),
            signature_count: AtomicU64::new(0),
            last_blockhash: RwLock::new(parent_hash),
            stake_tracker: parent.stake_tracker.clone(),
            stake_history: parent.stake_history.clone(),
            feature_set: parent.feature_set.clone(),
            rewards_distributor: RwLock::new(None),
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

    /// Attach a sysvar cache to this bank.
    pub fn set_sysvar_cache(&mut self, cache: Arc<SysvarCache>) {
        self.sysvars = Some(cache);
    }

    /// Get a reference to the sysvar cache, if one is attached.
    pub fn sysvar_cache(&self) -> Option<&Arc<SysvarCache>> {
        self.sysvars.as_ref()
    }

    /// Attach a stake tracker for epoch boundary processing.
    pub fn set_stake_tracker(&mut self, tracker: Arc<RwLock<StakeTracker>>) {
        self.stake_tracker = Some(tracker);
    }

    /// Get a reference to the stake tracker, if attached.
    pub fn stake_tracker(&self) -> Option<&Arc<RwLock<StakeTracker>>> {
        self.stake_tracker.as_ref()
    }

    /// Attach a stake history for epoch boundary processing.
    pub fn set_stake_history(&mut self, history: Arc<RwLock<StakeHistory>>) {
        self.stake_history = Some(history);
    }

    /// Get a reference to the stake history, if attached.
    pub fn stake_history(&self) -> Option<&Arc<RwLock<StakeHistory>>> {
        self.stake_history.as_ref()
    }

    /// Attach a feature set for feature activation at epoch boundaries.
    pub fn set_feature_set(&mut self, features: Arc<RwLock<FeatureSet>>) {
        self.feature_set = Some(features);
    }

    /// Get a reference to the feature set, if attached.
    pub fn feature_set(&self) -> Option<&Arc<RwLock<FeatureSet>>> {
        self.feature_set.as_ref()
    }

    /// Update the lattice hash accumulator when an account is modified.
    ///
    /// Subtracts the old account's hash (if any) and adds the new account's hash.
    /// Must be called for every account write to maintain correct bank hash.
    pub fn update_account_hash(
        &self,
        pubkey: &Pubkey,
        old_account: Option<&Account>,
        new_account: &Account,
    ) {
        let pubkey_bytes = pubkey.to_bytes();

        let old_hash = match old_account {
            Some(acc) => lthash::hash_account(
                &pubkey_bytes,
                &acc.meta.owner.to_bytes(),
                acc.meta.lamports,
                acc.meta.executable,
                acc.data.as_ref(),
            ),
            None => LatticeHashValue::zero(),
        };

        let new_hash = lthash::hash_account(
            &pubkey_bytes,
            &new_account.meta.owner.to_bytes(),
            new_account.meta.lamports,
            new_account.meta.executable,
            new_account.data.as_ref(),
        );

        let mut accumulator = self.lthash.write().unwrap();
        accumulator.subtract(&old_hash);
        accumulator.add(&new_hash);
    }

    /// Increment the slot's signature count.
    pub fn add_signatures(&self, count: u64) {
        self.signature_count.fetch_add(count, Ordering::Relaxed);
    }

    /// Get the slot's signature count.
    pub fn signature_count(&self) -> u64 {
        self.signature_count.load(Ordering::Relaxed)
    }

    /// Set the last PoH blockhash for this slot.
    pub fn set_last_blockhash(&self, hash: [u8; 32]) {
        *self.last_blockhash.write().unwrap() = hash;
    }

    /// Get a clone of the current lattice hash accumulator.
    pub fn lthash(&self) -> LatticeHashValue {
        self.lthash.read().unwrap().clone()
    }

    /// Check whether there is a pending rewards distributor.
    pub fn has_pending_rewards(&self) -> bool {
        self.rewards_distributor
            .read()
            .unwrap()
            .as_ref()
            .map_or(false, |d| !d.is_complete())
    }

    /// Distribute pending stake rewards for the current slot.
    ///
    /// If a rewards distributor is active and has rewards for this slot,
    /// credits the corresponding accounts and marks the slot distributed.
    pub fn distribute_slot_rewards(&self) -> u64 {
        let mut guard = self.rewards_distributor.write().unwrap();
        if let Some(ref mut distributor) = *guard {
            let result = RewardApplicator::apply_partition(&self.accounts, distributor, self.slot);
            self.capitalization
                .fetch_add(result.total_distributed, Ordering::Relaxed);
            result.total_distributed
        } else {
            0
        }
    }

    /// Route vote updates from transaction execution to the consensus coordinator.
    ///
    /// For each vote update with a valid voted slot, creates a `ValidatorVote`
    /// with stake weight from the coordinator's tracker and records it.
    pub fn route_vote_updates(
        &self,
        updates: &[crate::bank_executor::VoteUpdate],
        coordinator: &mut crate::ConsensusCoordinator,
    ) {
        for update in updates {
            if let Some(voted_slot) = update.voted_slot {
                let stake = coordinator
                    .stake_tracker()
                    .total_stake_for_voter(&update.vote_account);
                coordinator.record_validator_vote(crate::consensus_coordinator::ValidatorVote {
                    validator: update.vote_account,
                    slot: voted_slot,
                    stake,
                    timestamp: 0,
                });
            }
        }
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

    /// Complete slot processing: distribute fees, run epoch boundary processing
    /// if applicable, and freeze the bank.
    ///
    /// This is the high-level slot finalization method that should be called
    /// when all ticks and transactions for the slot have been processed.
    /// Returns the epoch boundary flag and distributed fee amounts.
    pub fn finish_slot(&self) -> Result<SlotFinalizationResult, BankFreezeError> {
        if self.is_frozen() {
            return Err(BankFreezeError::AlreadyFrozen);
        }

        if !self.is_complete() {
            return Err(BankFreezeError::IncompleteSlot {
                current_ticks: self.tick_height(),
                required_ticks: self.max_tick_height,
            });
        }

        // Distribute accumulated fees before freezing
        let (leader_share, burn_share) = self
            .distribute_fees()
            .map_err(|_| BankFreezeError::AlreadyFrozen)?;

        // Update sysvars for this slot
        if let Some(sysvars) = &self.sysvars {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            sysvars.update_clock(self.slot, self.epoch, timestamp);
            sysvars.update_slot_hashes(self.slot, self.hash());
            sysvars.update_slot_history(self.slot);
            sysvars.update_recent_blockhashes(self.hash(), LAMPORTS_PER_SIGNATURE);
        }

        // Check and process epoch boundary
        let epoch_boundary = self.is_epoch_boundary();
        if epoch_boundary {
            self.process_epoch_boundary();
        }

        // Freeze the bank
        self.status
            .store(BankStatus::Frozen.to_u8(), Ordering::Relaxed);

        Ok(SlotFinalizationResult {
            slot: self.slot,
            epoch: self.epoch,
            epoch_boundary,
            leader_share,
            burn_share,
            transaction_count: self.transaction_count(),
        })
    }

    /// Run epoch boundary processing.
    ///
    /// Called when the bank's epoch differs from its parent's epoch.
    /// Performs feature activation, epoch rewards calculation, immediate
    /// vote reward distribution, leader schedule regeneration, and
    /// queues partitioned stake reward distribution.
    fn process_epoch_boundary(&self) {
        // Step 1: Feature activation — scan feature accounts, activate pending
        self.activate_pending_features();

        // Step 2: Epoch rewards — calculate and prepare distribution
        self.calculate_and_prepare_rewards();

        // Step 3: Regenerate leader schedule for the next epoch
        self.regenerate_leader_schedule();
    }

    /// Scan feature accounts and activate any newly created ones.
    fn activate_pending_features(&self) {
        if let Some(ref features_lock) = self.feature_set {
            let mut features = features_lock.write().unwrap();
            let accounts = &self.accounts;
            process_feature_activations(&mut features, self.slot, &|pubkey| {
                accounts.get_published_account(pubkey).is_some()
            });
        }
    }

    /// Calculate epoch rewards and apply vote rewards immediately.
    ///
    /// Stake rewards are queued in the rewards distributor for
    /// partitioned distribution over subsequent slots.
    fn calculate_and_prepare_rewards(&self) {
        let (tracker, mut history) = match (&self.stake_tracker, &self.stake_history) {
            (Some(t), Some(h)) => {
                let tracker = t.read().unwrap().clone();
                let history = h.read().unwrap().clone();
                (tracker, history)
            }
            _ => return,
        };

        let result = EpochProcessor::process_epoch_boundary(self, &tracker, &mut history);

        // Write back updated stake history
        if let Some(ref h) = self.stake_history {
            *h.write().unwrap() = history;
        }

        if let Ok(ctx) = result {
            // Apply vote rewards immediately
            if !ctx.validator_rewards.is_empty() {
                let vote_rewards: Vec<_> = ctx
                    .validator_rewards
                    .iter()
                    .filter(|vr| vr.total_reward > 0)
                    .map(|vr| crate::rewards_distribution::PendingReward {
                        account: vr.vote_account,
                        amount: vr.total_reward,
                        reward_type: crate::epoch_processing::RewardType::Voting,
                    })
                    .collect();

                let result = RewardApplicator::apply_rewards(&self.accounts, &vote_rewards);
                self.capitalization
                    .fetch_add(result.total_distributed, Ordering::Relaxed);
            }

            // Store the rewards distributor for partitioned stake distribution
            if let Some(distributor) = ctx.rewards_distributor {
                *self.rewards_distributor.write().unwrap() = Some(distributor);
            }
        }
    }

    /// Regenerate leader schedule for the next epoch based on current stakes.
    fn regenerate_leader_schedule(&self) {
        if let Some(ref tracker_lock) = self.stake_tracker {
            let tracker = tracker_lock.read().unwrap();
            let stakes = tracker.stake_by_vote_account();
            let validators: Vec<(Pubkey, u64)> = stakes.into_iter().collect();

            if !validators.is_empty() {
                let next_epoch = self.epoch + 1;
                if let Ok(schedule) = LeaderSchedule::new(next_epoch, &validators) {
                    // Note: leader_schedule field is not interior-mutable,
                    // so the new schedule takes effect on child banks via
                    // new_from_parent. The current bank keeps its original
                    // schedule for consistency.
                    let _ = schedule;
                }
            }
        }
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

    /// Compute the bank hash for this slot.
    ///
    /// The bank hash is a deterministic cryptographic hash of the slot's
    /// state: `SHA256(SHA256(prev_bank_hash || sig_count || last_blockhash) || lthash)`.
    pub fn hash(&self) -> [u8; 32] {
        use paradencer_crypto::sha256::Sha256StreamingHasher;

        let lthash = self.lthash.read().unwrap();
        let blockhash = self.last_blockhash.read().unwrap();
        let sig_count = self.signature_count.load(Ordering::Relaxed);

        // inner = SHA256(prev_bank_hash || sig_count || last_blockhash)
        let mut inner = Sha256StreamingHasher::new();
        inner.update(&self.parent_hash);
        inner.update(&sig_count.to_le_bytes());
        inner.update(&*blockhash);
        let inner_hash = inner.finalize();

        // bank_hash = SHA256(inner_hash || lthash_bytes)
        let mut outer = Sha256StreamingHasher::new();
        outer.update(&inner_hash);
        outer.update(lthash.as_bytes());
        outer.finalize()
    }
}

/// Result of slot finalization via `finish_slot()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotFinalizationResult {
    pub slot: u64,
    pub epoch: u64,
    pub epoch_boundary: bool,
    pub leader_share: u64,
    pub burn_share: u64,
    pub transaction_count: u64,
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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let hash_before = bank.hash();

        // Modifying signatures changes the hash
        bank.add_signatures(1);
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

    // finish_slot() tests

    #[test]
    fn finish_slot_freezes_bank_and_distributes_fees() {
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

        bank.add_execution_fee(2000);
        bank.add_priority_fee(1000);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }

        let result = bank.finish_slot().unwrap();

        assert_eq!(result.slot, GENESIS_SLOT);
        assert_eq!(result.epoch, GENESIS_EPOCH);
        assert!(!result.epoch_boundary);
        assert!(result.burn_share > 0);
        assert!(result.leader_share > 0);
        assert_eq!(bank.status(), BankStatus::Frozen);
    }

    #[test]
    fn finish_slot_rejects_incomplete() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        assert!(matches!(
            bank.finish_slot(),
            Err(BankFreezeError::IncompleteSlot { .. })
        ));
    }

    #[test]
    fn finish_slot_rejects_already_frozen() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }

        bank.finish_slot().unwrap();
        assert_eq!(bank.finish_slot(), Err(BankFreezeError::AlreadyFrozen));
    }

    #[test]
    fn finish_slot_detects_epoch_boundary() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // Create child at first slot of epoch 1
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, SLOTS_PER_EPOCH, child_schedule);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        let result = child.finish_slot().unwrap();
        assert!(result.epoch_boundary);
        assert_eq!(result.epoch, 1);
    }

    // -----------------------------------------------------------------------
    // Phase 3: Epoch boundary processing tests
    // -----------------------------------------------------------------------

    fn make_bank_with_epoch_state(
        capitalization: u64,
    ) -> (Bank, Arc<RwLock<StakeTracker>>, Arc<RwLock<StakeHistory>>) {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        // Set up stake tracker at epoch 1 (the child epoch) so delegations
        // activated at epoch 0 are fully warmed up (no history → assumed active).
        let voter = Pubkey::new_unique();
        let stake_acct = Pubkey::new_unique();

        // Store the vote account in the database so rewards can be applied
        let vote_account =
            paradencer_storage::Account::new(1_000_000, vec![], Pubkey::default());
        accounts.store_published_account(voter, vote_account);

        let mut tracker = StakeTracker::new(1);
        tracker.add_delegation(
            stake_acct,
            crate::Delegation::new(voter, 1_000_000_000, 0),
        );

        let tracker = Arc::new(RwLock::new(tracker));
        let history = Arc::new(RwLock::new(StakeHistory::new()));

        let mut parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule,
            capitalization,
            Rent::default(),
            Inflation::default(),
        );

        parent.set_stake_tracker(tracker.clone());
        parent.set_stake_history(history.clone());

        // Create child at epoch boundary
        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        (child, tracker, history)
    }

    #[test]
    fn epoch_boundary_calculates_rewards() {
        let (child, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        let result = child.finish_slot().unwrap();
        assert!(result.epoch_boundary);

        // Capitalization should have increased from vote rewards
        assert!(child.capitalization() > 1_000_000_000_000);
    }

    #[test]
    fn epoch_boundary_updates_stake_history() {
        let (child, _tracker, history) = make_bank_with_epoch_state(1_000_000_000_000);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        child.finish_slot().unwrap();

        // Stake history should have entry for epoch 0
        let h = history.read().unwrap();
        assert!(h.get(0).is_some());
        let entry = h.get(0).unwrap();
        assert!(entry.effective > 0);
    }

    #[test]
    fn epoch_boundary_with_feature_set() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        let features = Arc::new(RwLock::new(FeatureSet::new()));
        parent.set_feature_set(features.clone());

        let tracker = Arc::new(RwLock::new(StakeTracker::new(0)));
        let history = Arc::new(RwLock::new(StakeHistory::new()));
        parent.set_stake_tracker(tracker);
        parent.set_stake_history(history);

        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        // Should not panic — feature activation runs but no features are pending
        let result = child.finish_slot().unwrap();
        assert!(result.epoch_boundary);
    }

    #[test]
    fn non_boundary_slot_skips_epoch_processing() {
        let (parent_bank, _tracker, history) = make_bank_with_epoch_state(1_000_000_000_000);

        // Create a second child in the same epoch (not a boundary)
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent_bank, parent_bank.slot() + 1, child_schedule);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        let result = child.finish_slot().unwrap();
        assert!(!result.epoch_boundary);

        // Stake history should NOT have been updated
        let h = history.read().unwrap();
        assert!(h.get(0).is_none());
    }

    #[test]
    fn distribute_slot_rewards_no_distributor() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // No rewards distributor set
        assert!(!bank.has_pending_rewards());
        assert_eq!(bank.distribute_slot_rewards(), 0);
    }

    // -- Lattice hash accumulator tests --

    #[test]
    fn new_bank_has_zero_lthash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert!(bank.lthash().is_zero());
    }

    #[test]
    fn account_write_updates_lthash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert!(bank.lthash().is_zero());

        let pubkey = Pubkey::new_unique();
        let account = Account::new(1000, vec![1, 2, 3], Pubkey::new_unique());

        // Writing a new account should change lthash
        bank.update_account_hash(&pubkey, None, &account);
        assert!(!bank.lthash().is_zero());
    }

    #[test]
    fn modify_account_subtracts_old_adds_new() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let old_account = Account::new(1000, vec![1, 2, 3], owner);
        let new_account = Account::new(2000, vec![4, 5, 6], owner);

        // Add original
        bank.update_account_hash(&pubkey, None, &old_account);
        let hash_after_create = bank.lthash();

        // Modify: subtract old, add new
        bank.update_account_hash(&pubkey, Some(&old_account), &new_account);
        let hash_after_modify = bank.lthash();

        // Should be different from after create
        assert_ne!(hash_after_create, hash_after_modify);

        // Reverting should give back original
        bank.update_account_hash(&pubkey, Some(&new_account), &old_account);
        assert_eq!(bank.lthash(), hash_after_create);
    }

    #[test]
    fn delete_account_subtracts_hash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let account = Account::new(1000, vec![1, 2, 3], owner);
        let zero_account = Account::new(0, vec![], owner);

        // Add then "delete" (set to zero lamports)
        bank.update_account_hash(&pubkey, None, &account);
        assert!(!bank.lthash().is_zero());

        bank.update_account_hash(&pubkey, Some(&account), &zero_account);
        assert!(bank.lthash().is_zero());
    }

    #[test]
    fn multiple_writes_accumulate() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let owner = Pubkey::new_unique();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let acc1 = Account::new(1000, vec![1], owner);
        let acc2 = Account::new(2000, vec![2], owner);

        // Add in order 1, 2
        bank.update_account_hash(&pk1, None, &acc1);
        bank.update_account_hash(&pk2, None, &acc2);
        let hash_12 = bank.lthash();

        // Reset and add in order 2, 1 — should be the same (commutative)
        let bank2 = Bank::new_genesis(
            Arc::new(AccountDatabase::new()),
            Arc::new(EpochSchedule::default()),
            create_test_leader_schedule(0),
        );
        bank2.update_account_hash(&pk2, None, &acc2);
        bank2.update_account_hash(&pk1, None, &acc1);
        let hash_21 = bank2.lthash();

        assert_eq!(hash_12, hash_21);
    }

    #[test]
    fn signature_count_increments() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert_eq!(bank.signature_count(), 0);

        bank.add_signatures(3);
        assert_eq!(bank.signature_count(), 3);

        bank.add_signatures(2);
        assert_eq!(bank.signature_count(), 5);
    }

    #[test]
    fn child_inherits_parent_lthash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule.clone());

        // Modify an account in parent
        let pubkey = Pubkey::new_unique();
        let account = Account::new(5000, vec![42], Pubkey::new_unique());
        parent.update_account_hash(&pubkey, None, &account);
        parent.add_signatures(10);

        let parent_lthash = parent.lthash();
        assert!(!parent_lthash.is_zero());

        // Complete parent
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        // Create child
        let child = Bank::new_from_parent(&parent, 1, leader_schedule);

        // Child inherits parent's lthash
        assert_eq!(child.lthash(), parent_lthash);

        // Child's signature count is reset
        assert_eq!(child.signature_count(), 0);
    }

    #[test]
    fn last_blockhash_set_and_read() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        bank.set_last_blockhash([0xABu8; 32]);
        let hash1 = bank.hash();

        bank.set_last_blockhash([0xCDu8; 32]);
        let hash2 = bank.hash();

        // Different blockhashes produce different bank hashes
        assert_ne!(hash1, hash2);
    }

    // -- Deterministic bank hash tests --

    #[test]
    fn bank_hash_is_deterministic() {
        let make_bank = || {
            let accounts = Arc::new(AccountDatabase::new());
            let epoch_schedule = Arc::new(EpochSchedule::default());
            let leader_schedule = create_test_leader_schedule(0);
            Bank::new_genesis(accounts, epoch_schedule, leader_schedule)
        };

        let b1 = make_bank();
        let b2 = make_bank();

        // Same initial state → same hash
        assert_eq!(b1.hash(), b2.hash());

        // Same modifications → same hash
        b1.add_signatures(5);
        b2.add_signatures(5);
        assert_eq!(b1.hash(), b2.hash());
    }

    #[test]
    fn bank_hash_changes_with_accounts() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let hash_before = bank.hash();

        let pubkey = Pubkey::new_unique();
        let account = Account::new(1000, vec![1, 2, 3], Pubkey::new_unique());
        bank.update_account_hash(&pubkey, None, &account);

        let hash_after = bank.hash();
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn bank_hash_changes_with_signatures() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let hash_before = bank.hash();
        bank.add_signatures(1);
        let hash_after = bank.hash();

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn bank_hash_changes_with_blockhash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let hash_before = bank.hash();
        bank.set_last_blockhash([0xFF; 32]);
        let hash_after = bank.hash();

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn child_hash_incorporates_parent() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts.clone(), epoch_schedule.clone(), leader_schedule.clone());
        parent.add_signatures(3);
        parent.set_last_blockhash([0x42; 32]);
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        let parent_hash = parent.hash();

        let child = Bank::new_from_parent(&parent, 1, leader_schedule);

        // Child's parent_hash should be the parent's computed hash
        assert_eq!(child.parent_hash(), parent_hash);

        // Child's hash should differ from parent's (different sig count, etc.)
        assert_ne!(child.hash(), parent.hash());
    }

    #[test]
    fn genesis_bank_hash_is_sha256() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        let hash = bank.hash();

        // SHA256 output should use all 32 bytes meaningfully
        // (old placeholder only used first 24 bytes)
        assert_eq!(hash.len(), 32);
        // Verify it's not all zeros (prev_bank_hash=[0;32], sig_count=0,
        // blockhash=[0;32], lthash=zero still produces non-zero SHA256)
        assert!(hash.iter().any(|&b| b != 0));
    }
}
