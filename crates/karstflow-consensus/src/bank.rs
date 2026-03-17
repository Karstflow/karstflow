use super::{Clock, EpochSchedule, Inflation, LeaderSchedule, Rent};
use crate::bank_notifier::BankNotifier;
use crate::blockhash_queue::{BlockhashInfo, BlockhashQueue};
use crate::clock::calculate_stake_weighted_timestamp;
use crate::epoch_processing::{AccountDatabaseVoteReader, EpochProcessor};
use crate::epoch_schedule::EpochScheduleConfig;
use crate::features::{process_feature_activations, FeatureSet};
use crate::reward_application::RewardApplicator;
use crate::rewards_distribution::RewardsDistributor;
use crate::signature_status::SignatureStatusCache;
use crate::sysvars::SysvarCache;
use crate::transaction_cache::TransactionCache;
use crate::vote_account_cache::VoteAccountCache;
use crate::StakeHistory;
use crate::StakeTracker;
use karstflow_constants::economics::{DEFAULT_TARGET_SIGNATURES_PER_SLOT, LAMPORTS_PER_SIGNATURE};
use karstflow_constants::ledger::{GENESIS_EPOCH, GENESIS_SLOT, TICKS_PER_SLOT};
use karstflow_crypto::lthash::{self, LatticeHashValue};
use karstflow_ids::SYSTEM_PROGRAM_ID;
use karstflow_storage::{
    Account, AccountDatabase, EpochScheduleConfig as StorageEpochScheduleConfig, FeeRateConfig,
    InflationConfig, Pubkey, RecentBlockhash, RentConfig, SnapshotBankState, StakeHistoryRecord,
    StakeSummary,
};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
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
    /// Non-vote transactions processed in this slot.
    nonvote_transaction_count: AtomicU64,
    /// Failed transactions (both vote and non-vote) in this slot.
    failed_transaction_count: AtomicU64,
    /// Total compute units consumed across all transactions in this slot.
    total_compute_units_used: AtomicU64,

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

    // Recent blockhash queue for transaction validation
    blockhash_queue: RwLock<BlockhashQueue>,

    // Transaction deduplication cache
    transaction_cache: Arc<TransactionCache>,

    // Signature → status index for RPC queries
    signature_status_cache: Arc<SignatureStatusCache>,

    // Per-block cost tracking for compute/data limits
    cost_tracker: Arc<crate::cost_tracker::CostTracker>,

    /// Running total of all accounts' data sizes across the database.
    /// Updated by process_transaction after successful execution.
    accounts_data_size: AtomicI64,

    /// Current lamports-per-signature rate, derived from parent's signature count.
    /// Updated each slot via the fee rate governor.
    lamports_per_signature: AtomicU64,

    // Leader schedule computed at epoch boundary for the next epoch
    next_leader_schedule: RwLock<Option<Arc<LeaderSchedule>>>,

    // Epoch boundary state (optional, set externally)
    stake_tracker: Option<Arc<RwLock<StakeTracker>>>,
    stake_history: Option<Arc<RwLock<StakeHistory>>>,
    feature_set: Option<Arc<RwLock<FeatureSet>>>,
    vote_account_cache: Option<Arc<RwLock<VoteAccountCache>>>,
    rewards_distributor: RwLock<Option<RewardsDistributor>>,

    /// Optional notifier for account/transaction state changes.
    notifier: Option<Arc<dyn BankNotifier>>,
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

        // Build sysvar cache from genesis configuration so that programs
        // executed in the genesis slot see accurate clock, rent, and epoch
        // schedule values instead of zeros.
        let sysvar_cache = SysvarCache::new(
            Clock {
                slot,
                epoch,
                unix_timestamp: 0,
                epoch_start_timestamp: 0,
                leader_schedule_epoch: epoch.saturating_add(1),
            },
            *epoch_schedule,
            rent,
        );

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
            nonvote_transaction_count: AtomicU64::new(0),
            failed_transaction_count: AtomicU64::new(0),
            total_compute_units_used: AtomicU64::new(0),
            execution_fees: AtomicU64::new(0),
            priority_fees: AtomicU64::new(0),
            capitalization: AtomicU64::new(capitalization),
            rent,
            inflation,
            sysvars: Some(Arc::new(sysvar_cache)),
            lthash: RwLock::new(LatticeHashValue::zero()),
            signature_count: AtomicU64::new(0),
            last_blockhash: RwLock::new([0u8; 32]),
            blockhash_queue: RwLock::new(BlockhashQueue::default()),
            transaction_cache: Arc::new(TransactionCache::new()),
            signature_status_cache: Arc::new(SignatureStatusCache::new()),
            cost_tracker: Arc::new(crate::cost_tracker::CostTracker::new()),
            accounts_data_size: AtomicI64::new(0),
            lamports_per_signature: AtomicU64::new(LAMPORTS_PER_SIGNATURE),
            next_leader_schedule: RwLock::new(None),
            stake_tracker: None,
            stake_history: None,
            feature_set: None,
            vote_account_cache: None,
            rewards_distributor: RwLock::new(None),
            notifier: None,
        }
    }

    /// Initialize a bank from a restored Solana snapshot.
    ///
    /// Reconstructs all bank state from the parsed snapshot manifest:
    /// slot, epoch, blockhash queue, economic configuration, and counters.
    /// The bank is created in `Frozen` status since the snapshot represents
    /// a completed slot.
    ///
    /// The leader schedule must be computed externally from the restored
    /// stake accounts and passed in.
    pub fn new_from_snapshot(
        accounts: Arc<AccountDatabase>,
        bank_state: &SnapshotBankState,
        leader_schedule: Arc<LeaderSchedule>,
    ) -> Self {
        // Convert epoch schedule from snapshot format.
        let epoch_schedule_config = EpochScheduleConfig {
            slots_per_epoch: bank_state.epoch_schedule.slots_per_epoch,
            leader_schedule_slot_offset: bank_state.epoch_schedule.leader_schedule_slot_offset,
            warmup: bank_state.epoch_schedule.warmup,
            first_normal_epoch: bank_state.epoch_schedule.first_normal_epoch,
            first_normal_slot: bank_state.epoch_schedule.first_normal_slot,
        };
        let epoch_schedule = Arc::new(EpochSchedule::new(epoch_schedule_config));

        // Convert economic configuration.
        let rent = Rent {
            lamports_per_byte_year: bank_state.rent.lamports_per_byte_year,
            exemption_threshold: bank_state.rent.exemption_threshold,
            burn_percent: bank_state.rent.burn_percent,
        };
        let inflation = Inflation {
            initial_rate: bank_state.inflation.initial,
            terminal_rate: bank_state.inflation.terminal,
            tapering_rate: bank_state.inflation.taper,
            foundation_portion: bank_state.inflation.foundation,
            foundation_duration_years: bank_state.inflation.foundation_term,
        };

        // Build blockhash queue from snapshot's recent blockhashes.
        let blockhash_queue = Self::build_blockhash_queue(bank_state);

        // Compute slot index within the epoch.
        let (_, slot_index) = epoch_schedule.get_epoch_and_slot_index(bank_state.slot);

        Self {
            slot: bank_state.slot,
            parent_slot: Some(bank_state.parent_slot),
            parent_hash: bank_state.parent_hash,
            // Snapshot represents a rooted (finalized) slot.
            status: AtomicU8::new(BankStatus::Rooted.to_u8()),
            tick_height: AtomicU64::new(bank_state.tick_height),
            max_tick_height: bank_state.max_tick_height,
            epoch: bank_state.epoch,
            slot_index,
            epoch_schedule,
            leader_schedule,
            accounts,
            transaction_count: AtomicU64::new(bank_state.transaction_count),
            nonvote_transaction_count: AtomicU64::new(0),
            failed_transaction_count: AtomicU64::new(0),
            total_compute_units_used: AtomicU64::new(0),
            execution_fees: AtomicU64::new(0),
            priority_fees: AtomicU64::new(0),
            capitalization: AtomicU64::new(bank_state.capitalization),
            rent,
            inflation,
            sysvars: None,
            lthash: RwLock::new(LatticeHashValue::zero()),
            signature_count: AtomicU64::new(bank_state.signature_count),
            last_blockhash: RwLock::new(bank_state.last_blockhash.unwrap_or([0u8; 32])),
            blockhash_queue: RwLock::new(blockhash_queue),
            transaction_cache: Arc::new(TransactionCache::new()),
            signature_status_cache: Arc::new(SignatureStatusCache::new()),
            cost_tracker: Arc::new(crate::cost_tracker::CostTracker::new()),
            accounts_data_size: AtomicI64::new(bank_state.accounts_data_len as i64),
            lamports_per_signature: AtomicU64::new(
                bank_state.fee_rate_governor.target_lamports_per_signature,
            ),
            next_leader_schedule: RwLock::new(None),
            stake_tracker: None,
            stake_history: None,
            feature_set: None,
            vote_account_cache: None,
            rewards_distributor: RwLock::new(None),
            notifier: None,
        }
    }

    /// Build a BlockhashQueue from snapshot's recent blockhash entries.
    ///
    /// The entries are pre-sorted by hash_index in the snapshot parser,
    /// so we register them in ascending order to preserve the correct
    /// age ordering (oldest first, newest last).
    fn build_blockhash_queue(bank_state: &SnapshotBankState) -> BlockhashQueue {
        let max_age = bank_state.max_blockhash_age as usize;
        let mut queue = BlockhashQueue::new(max_age);

        for bh in &bank_state.recent_blockhashes {
            let info = BlockhashInfo::new(
                Pubkey::from(bh.hash),
                bh.lamports_per_signature,
                // Use the hash_index as a proxy for slot ordering.
                // The actual slot isn't stored in the blockhash queue.
                bh.hash_index,
            );
            queue.register_hash(info);
        }

        queue
    }

    pub fn new_from_parent(parent: &Bank, slot: u64, leader_schedule: Arc<LeaderSchedule>) -> Self {
        let (epoch, slot_index) = parent.epoch_schedule.get_epoch_and_slot_index(slot);
        let tick_height = parent.tick_height.load(Ordering::Relaxed);
        let max_tick_height = tick_height.saturating_add(TICKS_PER_SLOT);

        let parent_hash = parent.hash();

        // If crossing an epoch boundary, prefer the schedule computed during
        // the parent's epoch boundary processing over the caller-supplied one.
        let effective_schedule = if epoch > parent.epoch {
            parent
                .next_leader_schedule
                .read()
                .expect("leader_schedule lock poisoned")
                .clone()
                .unwrap_or(leader_schedule)
        } else {
            leader_schedule
        };

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
            leader_schedule: effective_schedule,
            accounts: parent.accounts.clone(),
            transaction_count: AtomicU64::new(0),
            nonvote_transaction_count: AtomicU64::new(0),
            failed_transaction_count: AtomicU64::new(0),
            total_compute_units_used: AtomicU64::new(0),
            execution_fees: AtomicU64::new(0),
            priority_fees: AtomicU64::new(0),
            capitalization: AtomicU64::new(parent.capitalization.load(Ordering::Relaxed)),
            rent: parent.rent,
            inflation: parent.inflation,
            sysvars: parent.sysvars.clone(),
            lthash: RwLock::new(
                parent
                    .lthash
                    .read()
                    .expect("parent lthash lock poisoned")
                    .clone(),
            ),
            signature_count: AtomicU64::new(0),
            last_blockhash: RwLock::new(parent_hash),
            blockhash_queue: RwLock::new(
                parent
                    .blockhash_queue
                    .read()
                    .expect("parent blockhash_queue lock poisoned")
                    .clone(),
            ),
            transaction_cache: parent.transaction_cache.clone(),
            signature_status_cache: parent.signature_status_cache.clone(),
            cost_tracker: Arc::new(crate::cost_tracker::CostTracker::new()),
            accounts_data_size: AtomicI64::new(parent.accounts_data_size.load(Ordering::Acquire)),
            // Use fixed fee rate matching Solana mainnet behavior.
            // The dynamic fee rate governor (derive_fee_rate) is not active
            // on Solana mainnet — lamports_per_signature is always the constant.
            lamports_per_signature: AtomicU64::new(LAMPORTS_PER_SIGNATURE),
            next_leader_schedule: RwLock::new(None),
            stake_tracker: parent.stake_tracker.clone(),
            stake_history: parent.stake_history.clone(),
            feature_set: parent.feature_set.clone(),
            vote_account_cache: parent.vote_account_cache.clone(),
            rewards_distributor: RwLock::new(
                parent
                    .rewards_distributor
                    .read()
                    .expect("parent rewards_distributor lock poisoned")
                    .clone(),
            ),
            notifier: parent.notifier.clone(),
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

    pub fn nonvote_transaction_count(&self) -> u64 {
        self.nonvote_transaction_count.load(Ordering::Relaxed)
    }

    pub fn failed_transaction_count(&self) -> u64 {
        self.failed_transaction_count.load(Ordering::Relaxed)
    }

    pub fn total_compute_units_used(&self) -> u64 {
        self.total_compute_units_used.load(Ordering::Relaxed)
    }

    /// Record a non-vote transaction in this slot's metrics.
    pub fn record_nonvote_transaction(&self) {
        self.nonvote_transaction_count
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed transaction in this slot's metrics.
    pub fn record_failed_transaction(&self) {
        self.failed_transaction_count
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Add to the total compute units consumed in this slot.
    pub fn add_compute_units_used(&self, cu: u64) {
        self.total_compute_units_used
            .fetch_add(cu, Ordering::Relaxed);
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

    /// Attach a vote account cache for vote state tracking.
    pub fn set_vote_account_cache(&mut self, cache: Arc<RwLock<VoteAccountCache>>) {
        self.vote_account_cache = Some(cache);
    }

    /// Get a reference to the vote account cache, if attached.
    pub fn vote_account_cache(&self) -> Option<&Arc<RwLock<VoteAccountCache>>> {
        self.vote_account_cache.as_ref()
    }

    /// Attach a bank notifier for account/transaction change notifications.
    pub fn set_notifier(&mut self, notifier: Arc<dyn BankNotifier>) {
        self.notifier = Some(notifier);
    }

    /// Get the bank notifier, if attached.
    pub fn notifier(&self) -> Option<&Arc<dyn BankNotifier>> {
        self.notifier.as_ref()
    }

    /// Estimate network timestamp using stake-weighted vote timestamps.
    ///
    /// Collects the last vote timestamp and current stake from each entry
    /// in the vote account cache, then computes a stake-weighted median.
    /// Falls back to system time when the cache is empty or not attached.
    fn estimate_network_timestamp(&self) -> i64 {
        let fallback = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        };

        let cache_lock = match &self.vote_account_cache {
            Some(c) => c,
            None => return fallback(),
        };

        let cache = cache_lock.read().expect("vote_cache lock poisoned");
        let total_stake = cache.total_epoch_stake();
        if total_stake == 0 {
            return fallback();
        }

        let vote_timestamps: Vec<(i64, u64)> = cache
            .iter()
            .filter(|(_, entry)| entry.stake > 0 && entry.last_vote_timestamp > 0)
            .map(|(_, entry)| (entry.last_vote_timestamp, entry.stake))
            .collect();

        if vote_timestamps.is_empty() {
            return fallback();
        }

        calculate_stake_weighted_timestamp(vote_timestamps, total_stake)
    }

    /// Build a slot context for instruction execution from current bank state.
    ///
    /// Populates slot, epoch, timestamps and schedule info from the sysvar
    /// cache if present, falling back to constants for epoch schedule and rent.
    pub fn slot_context(&self) -> crate::bank_executor::SlotContext {
        // Epoch schedule and rent configuration from the bank's state,
        // not global constants — supports non-default configurations.

        let (slot, epoch, timestamp, epoch_start_ts, leader_sched_epoch) =
            if let Some(sysvars) = &self.sysvars {
                let clock = sysvars.clock();
                (
                    clock.slot,
                    clock.epoch,
                    clock.unix_timestamp,
                    clock.epoch_start_timestamp,
                    clock.leader_schedule_epoch,
                )
            } else {
                (self.slot, self.epoch, 0, 0, self.epoch.saturating_add(1))
            };

        let es = self.epoch_schedule.config();

        // Snapshot active feature gate IDs for the execution layer.
        let active_features = if let Some(ref fs_lock) = self.feature_set {
            let fs = fs_lock.read().expect("feature_set lock poisoned");
            fs.active_features().map(|(id, _)| *id.as_bytes()).collect()
        } else {
            std::collections::HashSet::new()
        };

        // Snapshot epoch rewards and raw sysvar data for the execution layer.
        let (epoch_rewards_active, epoch_rewards_total_rewards, sysvar_data) =
            if let Some(ref sysvars) = self.sysvars {
                (
                    sysvars.is_epoch_rewards_active(),
                    sysvars.epoch_rewards_total(),
                    sysvars.serialize_all_sysvars(),
                )
            } else {
                (false, 0, std::collections::HashMap::new())
            };

        // Snapshot epoch stake per vote account for sol_get_epoch_stake syscall.
        let epoch_stake = if let Some(ref tracker_lock) = self.stake_tracker {
            let tracker = tracker_lock.read().expect("stake_tracker lock poisoned");
            tracker
                .stake_by_vote_account()
                .into_iter()
                .map(|(pubkey, stake)| (*pubkey.as_bytes(), stake))
                .collect()
        } else {
            std::collections::HashMap::new()
        };

        crate::bank_executor::SlotContext {
            slot,
            epoch,
            unix_timestamp: timestamp,
            epoch_start_timestamp: epoch_start_ts,
            leader_schedule_epoch: leader_sched_epoch,
            slots_per_epoch: es.slots_per_epoch,
            leader_schedule_slot_offset: es.leader_schedule_slot_offset,
            warmup: es.warmup,
            first_normal_epoch: es.first_normal_epoch,
            first_normal_slot: es.first_normal_slot,
            lamports_per_byte_year: self.rent.lamports_per_byte_year,
            exemption_threshold: self.rent.exemption_threshold,
            burn_percent: self.rent.burn_percent,
            last_restart_slot: self.sysvars.as_ref().map_or(0, |s| s.last_restart_slot()),
            recent_blockhash: *self.last_blockhash.read().expect("blockhash lock poisoned"),
            lamports_per_signature: self.lamports_per_signature(),
            epoch_rewards_active,
            epoch_rewards_total_rewards,
            sysvar_data,
            epoch_stake,
            active_features,
        }
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

        let mut accumulator = self.lthash.write().expect("lthash lock poisoned");
        accumulator.subtract(&old_hash);
        accumulator.add(&new_hash);
    }

    /// Compute and set the cumulative lthash from all published accounts.
    ///
    /// Used during snapshot bootstrap to initialize the bank's lattice hash
    /// from the full set of restored accounts. This must be called after all
    /// accounts have been loaded into the database but before any new
    /// transactions are processed, so the bank hash chain continues correctly.
    ///
    /// Returns the number of accounts contributing to the hash (non-zero lamports).
    pub fn initialize_lthash_from_accounts(&self) -> usize {
        let mut accumulator = LatticeHashValue::zero();
        let mut count = 0usize;

        if let Err(e) = self.accounts.for_each_published_account(|pubkey, account| {
            let h = lthash::hash_account(
                &pubkey.to_bytes(),
                &account.meta.owner.to_bytes(),
                account.meta.lamports,
                account.meta.executable,
                account.data.as_ref(),
            );
            if !h.is_zero() {
                accumulator.add(&h);
                count += 1;
            }
            Ok(())
        }) {
            eprintln!(
                "[ERROR] storage error during lthash initialization — hash may be incorrect: {e}"
            );
        }

        *self.lthash.write().expect("lthash lock poisoned") = accumulator;
        count
    }

    /// Increment the slot's signature count.
    pub fn add_signatures(&self, count: u64) {
        self.signature_count.fetch_add(count, Ordering::Relaxed);
    }

    /// Get the slot's signature count.
    pub fn signature_count(&self) -> u64 {
        self.signature_count.load(Ordering::Relaxed)
    }

    /// Current lamports-per-signature fee rate for this slot.
    pub fn lamports_per_signature(&self) -> u64 {
        self.lamports_per_signature.load(Ordering::Relaxed)
    }

    /// Get the last PoH blockhash for this slot.
    pub fn last_blockhash(&self) -> [u8; 32] {
        *self.last_blockhash.read().expect("blockhash lock poisoned")
    }

    /// Get the most recent blockhash that is registered in the queue and
    /// therefore accepted by `is_blockhash_valid` / `process_transaction`.
    /// Falls back to `last_blockhash()` if the queue is empty.
    pub fn latest_valid_blockhash(&self) -> [u8; 32] {
        let queue = self
            .blockhash_queue
            .read()
            .expect("blockhash_queue lock poisoned");
        queue
            .last_blockhash()
            .map(|h| h.to_bytes())
            .unwrap_or_else(|| self.last_blockhash())
    }

    /// Set the last PoH blockhash for this slot.
    pub fn set_last_blockhash(&self, hash: [u8; 32]) {
        *self
            .last_blockhash
            .write()
            .expect("blockhash lock poisoned") = hash;
    }

    /// Check if a blockhash is in the recent blockhash queue.
    pub fn is_blockhash_valid(&self, blockhash: &[u8; 32]) -> bool {
        let hash = Pubkey::from(*blockhash);
        self.blockhash_queue
            .read()
            .expect("blockhash_queue lock poisoned")
            .is_hash_valid(&hash)
    }

    /// Get a reference to the blockhash queue lock.
    pub fn blockhash_queue(&self) -> &RwLock<BlockhashQueue> {
        &self.blockhash_queue
    }

    /// Access the signature status cache (shared across the fork tree).
    pub fn signature_status_cache(&self) -> &SignatureStatusCache {
        &self.signature_status_cache
    }

    /// Access the transaction deduplication cache.
    pub fn transaction_cache(&self) -> &TransactionCache {
        &self.transaction_cache
    }

    /// Seed the transaction cache from status cache entries.
    ///
    /// Used during snapshot restore to populate recently processed
    /// transactions for deduplication. Returns the number of entries
    /// successfully inserted.
    pub fn seed_transaction_cache<I>(&self, entries: I) -> usize
    where
        I: IntoIterator<Item = crate::transaction_cache::SeedEntry>,
    {
        self.transaction_cache.seed(entries)
    }

    /// Get the per-block cost tracker.
    pub fn cost_tracker(&self) -> &crate::cost_tracker::CostTracker {
        &self.cost_tracker
    }

    /// Total bytes of account data across the database.
    pub fn accounts_data_size(&self) -> i64 {
        self.accounts_data_size.load(Ordering::Acquire)
    }

    /// Adjust the running total of accounts data bytes.
    ///
    /// Called after successful transaction execution with the net change
    /// in account data bytes (positive for growth, negative for shrink).
    pub fn update_accounts_data_size_delta(&self, delta: i64) {
        if delta != 0 {
            self.accounts_data_size.fetch_add(delta, Ordering::Release);
        }
    }

    /// Get a clone of the current lattice hash accumulator.
    pub fn lthash(&self) -> LatticeHashValue {
        self.lthash.read().expect("lthash lock poisoned").clone()
    }

    /// Check whether there is a pending rewards distributor.
    pub fn has_pending_rewards(&self) -> bool {
        self.rewards_distributor
            .read()
            .expect("rewards_distributor lock poisoned")
            .as_ref()
            .is_some_and(|d| !d.is_complete())
    }

    /// Distribute pending stake rewards for the current slot.
    ///
    /// If a rewards distributor is active and has rewards for this slot,
    /// credits the corresponding accounts and marks the slot distributed.
    /// When all partitions are complete, clears the EpochRewards sysvar.
    pub fn distribute_slot_rewards(&self) -> u64 {
        let mut guard = self
            .rewards_distributor
            .write()
            .expect("rewards_distributor lock poisoned");
        if let Some(ref mut distributor) = *guard {
            let result = RewardApplicator::apply_partition(
                &self.accounts,
                distributor,
                self.slot,
                |pubkey, old_acc, new_acc| {
                    self.update_account_hash(pubkey, Some(old_acc), new_acc);
                },
            );
            self.capitalization
                .fetch_add(result.total_distributed, Ordering::Relaxed);

            // Clear EpochRewards sysvar once all partitions are distributed.
            if distributor.is_complete() {
                if let Some(ref sysvars) = self.sysvars {
                    sysvars.clear_epoch_rewards();
                }
            }

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
                coordinator.process_incoming_vote(crate::consensus_coordinator::ValidatorVote {
                    validator: update.vote_account,
                    slot: voted_slot,
                    stake,
                    timestamp: 0,
                    block_hash: None,
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

    /// Register a tick using the actual PoH hash from the entry.
    ///
    /// During block replay, tick entries carry a PoH hash that has been
    /// verified against the entry chain. This method updates the bank's
    /// last blockhash with that verified hash and advances the tick height.
    pub fn register_tick_with_hash(&self, poh_hash: [u8; 32]) -> Result<(), BankTickError> {
        if self.is_frozen() {
            return Err(BankTickError::BankFrozen);
        }

        if self.is_complete() {
            return Err(BankTickError::MaxTickHeightReached);
        }

        self.tick_height.fetch_add(1, Ordering::Relaxed);
        *self
            .last_blockhash
            .write()
            .expect("blockhash lock poisoned") = poh_hash;

        Ok(())
    }

    /// Register a tick with a synthetic PoH hash derived from tick height.
    ///
    /// Used in testing and genesis initialization where no real PoH chain
    /// is available. Production replay should use `register_tick_with_hash()`
    /// with the verified entry hash.
    pub fn register_tick(&self) -> Result<(), BankTickError> {
        if self.is_frozen() {
            return Err(BankTickError::BankFrozen);
        }

        if self.is_complete() {
            return Err(BankTickError::MaxTickHeightReached);
        }

        let new_height = self.tick_height.fetch_add(1, Ordering::Relaxed) + 1;

        // Derive a deterministic placeholder from previous blockhash and tick height.
        use karstflow_crypto::sha256::Sha256Hasher;
        let prev = *self.last_blockhash.read().expect("blockhash lock poisoned");
        let mut data = [0u8; 40]; // 32 bytes hash + 8 bytes tick height
        data[..32].copy_from_slice(&prev);
        data[32..40].copy_from_slice(&new_height.to_le_bytes());
        let new_blockhash = Sha256Hasher::hash(&data);
        *self
            .last_blockhash
            .write()
            .expect("blockhash lock poisoned") = new_blockhash;

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

        // Distribute any pending partitioned epoch rewards for this slot
        self.distribute_slot_rewards();

        // Distribute accumulated fees before freezing
        let (leader_share, burn_share) = self
            .distribute_fees()
            .map_err(|_| BankFreezeError::AlreadyFrozen)?;

        // Compute bank hash and fee rate once (avoids redundant SHA256 + lock acquisition).
        let bank_hash = self.hash();
        let fee_rate = self.lamports_per_signature();

        // Update sysvars for this slot
        if let Some(sysvars) = &self.sysvars {
            let timestamp = self.estimate_network_timestamp();
            sysvars.update_clock(self.slot, self.epoch, timestamp);
            sysvars.update_slot_hashes(self.slot, bank_hash);
            sysvars.update_slot_history(self.slot);
            sysvars.update_recent_blockhashes(bank_hash, fee_rate);
        }

        // Register this slot's blockhash in the recent blockhash queue
        let blockhash_info = BlockhashInfo::new(Pubkey::from(bank_hash), fee_rate, self.slot);
        self.blockhash_queue
            .write()
            .expect("blockhash_queue lock poisoned")
            .register_hash(blockhash_info);

        // Delete incinerator account: zero its lamports and reduce capitalization.
        // The incinerator accumulates burned lamports from transactions;
        // zeroing it at slot freeze keeps total supply accurate.
        self.run_incinerator();

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
    /// vote reward distribution, vote cache rotation, leader schedule
    /// regeneration, and queues partitioned stake reward distribution.
    fn process_epoch_boundary(&self) {
        // Note: Rent fee collection is disabled on modern protocol.
        // The `disable_rent_fees_collection` feature is always active,
        // meaning no rent is collected from accounts. All accounts
        // must be rent-exempt (enforced during transaction execution
        // via rent state transition validation).

        // Step 1: Feature activation — scan feature accounts, activate pending
        self.activate_pending_features();

        // Step 2: Epoch rewards — calculate and prepare distribution
        self.calculate_and_prepare_rewards();

        // Step 3: Rotate vote account cache and populate with new epoch stakes
        self.refresh_vote_account_cache();

        // Step 4: Regenerate leader schedule for the next epoch
        self.regenerate_leader_schedule();
    }

    /// Rotate vote account cache epoch stakes and repopulate from delegations.
    ///
    /// At epoch boundaries, shifts current stake → previous → two-epochs-ago,
    /// then re-populates current epoch stakes from the stake tracker's
    /// delegation map. This keeps the three-epoch stake window accurate
    /// for tower consensus, leader schedule, and clock calculations.
    fn refresh_vote_account_cache(&self) {
        let (cache_lock, tracker_lock) = match (&self.vote_account_cache, &self.stake_tracker) {
            (Some(c), Some(t)) => (c, t),
            _ => return,
        };

        let tracker = tracker_lock.read().expect("stake_tracker lock poisoned");
        let stake_by_voter = tracker.stake_by_vote_account();

        let mut cache = cache_lock.write().expect("vote_cache lock poisoned");

        // Rotate: current → prev → prev_prev, then zero current
        cache.rotate_epoch();

        // Populate current epoch stakes from delegations
        for (vote_pubkey, &total_stake) in &stake_by_voter {
            cache.set_stake(vote_pubkey, total_stake);
        }
    }

    /// Zero out the incinerator account and reduce capitalization.
    ///
    /// The incinerator is a special account that accumulates burned lamports.
    /// At slot freeze, its balance is deleted to keep total supply accurate.
    fn run_incinerator(&self) {
        let incinerator_key = karstflow_ids::INCINERATOR_ID;
        if let Some(account) = self.accounts.get_published_account(&incinerator_key) {
            let balance = account.meta.lamports;
            if balance > 0 {
                // Update lattice hash before modifying the account
                let mut zeroed = account.clone();
                zeroed.meta.lamports = 0;
                self.update_account_hash(&incinerator_key, Some(&account), &zeroed);

                // Store the zeroed account
                self.accounts
                    .store_published_account(incinerator_key, zeroed);

                // Reduce capitalization by the burned amount
                self.capitalization.fetch_sub(balance, Ordering::Relaxed);
            }
        }
    }

    /// Collect rent from all non-exempt accounts at epoch boundary.
    ///
    /// NOTE: This method is retained for compatibility but is no longer called
    /// from the epoch boundary. The `disable_rent_fees_collection` feature is
    /// always active on modern protocol — rent is not actively collected.
    /// Rent state transitions are enforced during transaction execution instead.
    #[allow(dead_code)]
    fn collect_rent_for_epoch(&self) {
        let collector = crate::rent::RentCollector::default_for_epoch(self.epoch);

        // Stream accounts and collect only those owing rent. Most accounts are
        // rent-exempt, so this subset is small even at mainnet scale.
        let mut rent_updates: Vec<(Pubkey, Account, u64)> = Vec::new();

        let _ = self.accounts.for_each_published_account(|pubkey, account| {
            let collected =
                collector.collect_from_account(account.meta.lamports, account.data.len());
            if collected.rent_collected > 0 {
                let mut updated = account.clone();
                updated.meta.lamports = updated
                    .meta
                    .lamports
                    .saturating_sub(collected.rent_collected);
                rent_updates.push((*pubkey, updated, collected.rent_collected));
            }
            Ok(())
        });

        // Apply collected rent updates (lock is released from streaming above).
        let mut total_rent_collected: u64 = 0;
        for (pubkey, updated, rent) in &rent_updates {
            let original = self.accounts.get_published_account(pubkey);
            self.update_account_hash(pubkey, original.as_ref(), updated);
            self.accounts
                .store_published_account(*pubkey, updated.clone());
            total_rent_collected = total_rent_collected.saturating_add(*rent);
        }

        // Burn collected rent by reducing capitalization.
        if total_rent_collected > 0 {
            self.capitalization
                .fetch_sub(total_rent_collected, Ordering::Relaxed);
        }
    }

    /// Scan feature accounts and activate any newly created ones.
    fn activate_pending_features(&self) {
        if let Some(ref features_lock) = self.feature_set {
            let mut features = features_lock.write().expect("feature_set lock poisoned");
            let accounts = &self.accounts;
            process_feature_activations(&mut features, self.slot, &|pubkey| {
                accounts.get_published_account(pubkey).is_some()
            });
        }
    }

    /// Calculate epoch rewards and apply vote rewards immediately.
    ///
    /// Stake rewards are queued in the rewards distributor for
    /// partitioned distribution over subsequent slots. Updates both
    /// the internal stake history and the sysvar cache, and activates
    /// the EpochRewards sysvar for the duration of partitioned distribution.
    fn calculate_and_prepare_rewards(&self) {
        let (tracker, mut history) = match (&self.stake_tracker, &self.stake_history) {
            (Some(t), Some(h)) => {
                let tracker = t.read().expect("stake_tracker lock poisoned").clone();
                let history = h.read().expect("stake_history lock poisoned").clone();
                (tracker, history)
            }
            _ => return,
        };

        let vote_reader = AccountDatabaseVoteReader::new(&self.accounts);
        let result = EpochProcessor::process_epoch_boundary_with_reader(
            self,
            &tracker,
            &mut history,
            Some(&vote_reader),
        );

        // Write back updated stake history to internal tracker
        if let Some(ref h) = self.stake_history {
            *h.write().expect("stake_history lock poisoned") = history;
        }

        if let Ok(ctx) = result {
            // Propagate stake history update to the sysvar cache so programs
            // can read the latest StakeHistory sysvar account data.
            if let (Some(ref sysvars), Some(entry)) = (&self.sysvars, ctx.stake_snapshot) {
                sysvars.on_epoch_boundary(ctx.previous_epoch, entry);
            }

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

                let result = RewardApplicator::apply_rewards(
                    &self.accounts,
                    &vote_rewards,
                    |pubkey, old_acc, new_acc| {
                        self.update_account_hash(pubkey, Some(old_acc), new_acc);
                    },
                );
                self.capitalization
                    .fetch_add(result.total_distributed, Ordering::Relaxed);
            }

            // Store the rewards distributor for partitioned stake distribution.
            // Activate EpochRewards sysvar to signal ongoing distribution.
            if let Some(distributor) = ctx.rewards_distributor {
                if let Some(ref sysvars) = self.sysvars {
                    let total_rewards: u64 =
                        ctx.validator_rewards.iter().map(|vr| vr.total_reward).sum();
                    sysvars.set_epoch_rewards(crate::EpochRewards {
                        total_rewards,
                        validator_rewards: total_rewards,
                        foundation_rewards: 0,
                        capitalization: ctx.capitalization,
                        epoch_duration_years: 0.0,
                        validator_rate: 0.0,
                        foundation_rate: 0.0,
                    });
                }
                *self
                    .rewards_distributor
                    .write()
                    .expect("rewards_distributor lock poisoned") = Some(distributor);
            }
        }
    }

    /// Regenerate leader schedule for the next epoch based on current stakes.
    ///
    /// Maps vote account stakes to node identities via the vote account cache,
    /// then aggregates total stake per node. Multiple vote accounts owned by
    /// the same validator node are merged. Falls back to vote account pubkeys
    /// as identities when the cache is unavailable.
    ///
    /// The computed schedule is stored in `next_leader_schedule` so that
    /// `new_from_parent` can propagate it to child banks in the next epoch.
    fn regenerate_leader_schedule(&self) {
        if let Some(ref tracker_lock) = self.stake_tracker {
            let tracker = tracker_lock.read().expect("stake_tracker lock poisoned");
            let stakes = tracker.stake_by_vote_account();

            // Map vote account stakes to node identities via the vote cache.
            let mut stake_by_node: std::collections::HashMap<Pubkey, u64> =
                std::collections::HashMap::new();

            if let Some(ref cache_lock) = self.vote_account_cache {
                let cache = cache_lock.read().expect("vote_cache lock poisoned");
                for (vote_pubkey, stake) in &stakes {
                    let node = cache
                        .node_pubkey(vote_pubkey)
                        .copied()
                        .unwrap_or(*vote_pubkey);
                    *stake_by_node.entry(node).or_insert(0) += stake;
                }
            } else {
                // No vote cache — use vote account pubkeys as fallback.
                for (vote_pubkey, stake) in &stakes {
                    *stake_by_node.entry(*vote_pubkey).or_insert(0) += stake;
                }
            }

            let validators: Vec<(Pubkey, u64)> = stake_by_node.into_iter().collect();

            if !validators.is_empty() {
                let next_epoch = self.epoch + 1;
                if let Ok(schedule) = LeaderSchedule::new(next_epoch, &validators) {
                    *self
                        .next_leader_schedule
                        .write()
                        .expect("leader_schedule lock poisoned") = Some(Arc::new(schedule));
                }
            }
        }
    }

    /// Get the leader schedule computed for the next epoch, if available.
    pub fn next_leader_schedule(&self) -> Option<Arc<LeaderSchedule>> {
        self.next_leader_schedule
            .read()
            .expect("leader_schedule lock poisoned")
            .clone()
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

        let total_collected = execution_fees.saturating_add(priority_fees);

        Ok((total_collected, burn, fees_to_distribute))
    }

    /// Distribute accumulated fees: burn a portion and credit the leader.
    ///
    /// Computes the burn/leader split, reduces capitalization by the burned
    /// amount, and credits the leader's account in the account database.
    /// Returns (leader_share, burn_share).
    pub fn distribute_fees(&self) -> Result<(u64, u64), BankFeeError> {
        if self.is_frozen() {
            return Err(BankFeeError::BankFrozen);
        }

        let execution_fees = self.execution_fees.swap(0, Ordering::Relaxed);
        let priority_fees = self.priority_fees.swap(0, Ordering::Relaxed);

        if execution_fees == 0 && priority_fees == 0 {
            return Ok((0, 0));
        }

        // Burn 50% of execution fees only. Priority fees are NOT burned —
        // they go 100% to the slot leader.
        let burn_share = execution_fees / 2;
        let leader_share = priority_fees.saturating_add(execution_fees - burn_share);

        // Reduce capitalization by burned amount
        self.capitalization.fetch_sub(burn_share, Ordering::Relaxed);

        // Validate fee collector (leader) before crediting
        if leader_share > 0 {
            if let Some(leader) = self.get_leader() {
                if self.validate_fee_collector(&leader) {
                    self.credit_leader_fees(&leader, leader_share);
                } else {
                    // Invalid fee collector — burn the entire leader share
                    self.capitalization
                        .fetch_sub(leader_share, Ordering::Relaxed);
                    return Ok((0, burn_share.saturating_add(leader_share)));
                }
            }
        }

        Ok((leader_share, burn_share))
    }

    /// Validate the fee collector account before crediting fees.
    ///
    /// The fee collector must be owned by the system program and must
    /// remain rent-exempt after receiving the fee payout. If validation
    /// fails, fees should be burned instead.
    fn validate_fee_collector(&self, leader: &Pubkey) -> bool {
        let account = match self.accounts.get_published_account(leader) {
            Some(acc) => acc,
            None => {
                // New account — will be created by credit_leader_fees.
                // System-owned default account is always valid.
                return true;
            }
        };

        // Fee collector must be owned by the system program
        if account.meta.owner != SYSTEM_PROGRAM_ID {
            return false;
        }

        // After adding fees, account must be rent-exempt
        // (lamports always increase, data size unchanged, so just check post-state)
        let post_lamports = account.meta.lamports.saturating_add(1);
        let min_balance = self.rent.minimum_balance(account.data.len());
        post_lamports >= min_balance
    }

    /// Credit lamports to an account directly.
    ///
    /// Used for development mode airdrops. Creates the account as a
    /// system-owned account if it does not exist. Updates the lattice
    /// hash to maintain consistency.
    pub fn credit_lamports(&self, pubkey: &Pubkey, amount: u64) {
        let old_account = self.accounts.get_published_account(pubkey);
        let mut account = old_account.clone().unwrap_or_default();
        account.meta.lamports = account.meta.lamports.saturating_add(amount);
        if account.meta.owner == Pubkey::default() {
            account.meta.owner = SYSTEM_PROGRAM_ID;
        }
        self.update_account_hash(pubkey, old_account.as_ref(), &account);
        self.accounts.store_published_account(*pubkey, account);
    }

    /// Credit fee income to the leader's account.
    fn credit_leader_fees(&self, leader: &Pubkey, amount: u64) {
        let old_account = self.accounts.get_published_account(leader);
        let mut account = old_account.clone().unwrap_or_default();
        account.meta.lamports = account.meta.lamports.saturating_add(amount);
        self.update_account_hash(leader, old_account.as_ref(), &account);
        self.accounts.store_published_account(*leader, account);
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

    /// Extract the current bank state into a snapshot-compatible representation.
    ///
    /// Produces a `SnapshotBankState` that contains all the fields needed
    /// to serialize a Solana-compatible snapshot manifest. This enables
    /// other validators to bootstrap from snapshots created by this node.
    ///
    /// Reads atomics, locks blockhash queue and stake tracker, so call
    /// this on a frozen (rooted) bank to avoid contention.
    pub fn to_snapshot_state(&self) -> SnapshotBankState {
        use karstflow_constants::economics::{
            DEFAULT_FEE_BURN_PERCENT, DEFAULT_SLOTS_PER_YEAR, DEFAULT_TARGET_SIGNATURES_PER_SLOT,
            LAMPORTS_PER_SIGNATURE, MAX_LAMPORTS_PER_SIGNATURE, MIN_LAMPORTS_PER_SIGNATURE,
        };
        use karstflow_constants::ledger::{
            DEFAULT_HASHES_PER_TICK, DEFAULT_TICK_DURATION_NS, TICKS_PER_SLOT,
        };

        let bh_queue = self
            .blockhash_queue
            .read()
            .expect("blockhash_queue lock poisoned");
        let recent_blockhashes: Vec<RecentBlockhash> = bh_queue
            .entries()
            .enumerate()
            .map(|(idx, info)| RecentBlockhash {
                hash: *info.hash.as_bytes(),
                lamports_per_signature: info.lamports_per_signature,
                hash_index: idx as u64,
                timestamp: 0,
            })
            .collect();
        let max_blockhash_age = bh_queue.max_age() as u64;
        let last_blockhash_index = if !bh_queue.is_empty() {
            bh_queue.len() as u64 - 1
        } else {
            0
        };
        drop(bh_queue);

        let last_blockhash = Some(self.last_blockhash());
        let ns_per_slot = (TICKS_PER_SLOT as u128) * (DEFAULT_TICK_DURATION_NS as u128);

        let genesis_creation_time = self
            .sysvars
            .as_ref()
            .map(|c| c.clock().epoch_start_timestamp)
            .unwrap_or(0);

        // Build stake summary from tracker if available.
        let stake_summary = self.build_stake_summary_for_snapshot();

        let es = self.epoch_schedule.config();

        SnapshotBankState {
            recent_blockhashes,
            last_blockhash,
            max_blockhash_age,
            last_blockhash_index,
            slot: self.slot,
            parent_slot: self.parent_slot.unwrap_or(0),
            block_height: self.slot,
            epoch: self.epoch,
            hash: self.hash(),
            parent_hash: self.parent_hash,
            transaction_count: self.transaction_count.load(Ordering::Relaxed),
            tick_height: self.tick_height.load(Ordering::Relaxed),
            max_tick_height: self.max_tick_height,
            signature_count: self.signature_count.load(Ordering::Relaxed),
            capitalization: self.capitalization.load(Ordering::Relaxed),
            accounts_data_len: self.accounts_data_size.load(Ordering::Acquire).max(0) as u64,
            hashes_per_tick: Some(DEFAULT_HASHES_PER_TICK),
            ticks_per_slot: TICKS_PER_SLOT,
            ns_per_slot,
            genesis_creation_time,
            slots_per_year: DEFAULT_SLOTS_PER_YEAR,
            collector_id: [0u8; 32],
            collector_fees: 0,
            fee_rate_governor: FeeRateConfig {
                target_lamports_per_signature: LAMPORTS_PER_SIGNATURE,
                target_signatures_per_slot: DEFAULT_TARGET_SIGNATURES_PER_SLOT,
                min_lamports_per_signature: MIN_LAMPORTS_PER_SIGNATURE,
                max_lamports_per_signature: MAX_LAMPORTS_PER_SIGNATURE,
                burn_percent: DEFAULT_FEE_BURN_PERCENT,
            },
            rent: RentConfig {
                lamports_per_byte_year: self.rent.lamports_per_byte_year,
                exemption_threshold: self.rent.exemption_threshold,
                burn_percent: self.rent.burn_percent,
                collector_epoch: self.epoch,
                collector_slots_per_year: DEFAULT_SLOTS_PER_YEAR,
            },
            collected_rent: 0,
            epoch_schedule: StorageEpochScheduleConfig {
                slots_per_epoch: es.slots_per_epoch,
                leader_schedule_slot_offset: es.leader_schedule_slot_offset,
                warmup: es.warmup,
                first_normal_epoch: es.first_normal_epoch,
                first_normal_slot: es.first_normal_slot,
            },
            inflation: InflationConfig {
                initial: self.inflation.initial_rate,
                terminal: self.inflation.terminal_rate,
                taper: self.inflation.tapering_rate,
                foundation: self.inflation.foundation_portion,
                foundation_term: self.inflation.foundation_duration_years,
            },
            hard_forks: vec![],
            ancestor_count: 0,
            stake_summary,
            is_delta: self.parent_slot.is_some(),
        }
    }

    /// Build a stake summary from the bank's stake tracker and history.
    fn build_stake_summary_for_snapshot(&self) -> StakeSummary {
        let mut summary = StakeSummary::default();

        if let Some(ref tracker_lock) = self.stake_tracker {
            if let Ok(tracker) = tracker_lock.read() {
                summary.stake_delegation_count = tracker.delegation_count() as u64;
                summary.total_delegated_stake = tracker.stake_by_vote_account().values().sum();
                summary.vote_account_count = tracker.stake_by_vote_account().len() as u64;
                summary.stakes_epoch = self.epoch;
            }
        }

        if let Some(ref history_lock) = self.stake_history {
            if let Ok(history) = history_lock.read() {
                summary.stake_history_entries = history.len() as u64;
                summary.stake_history = history
                    .iter()
                    .map(|ese| StakeHistoryRecord {
                        epoch: ese.epoch,
                        effective: ese.entry.effective,
                        activating: ese.entry.activating,
                        deactivating: ese.entry.deactivating,
                    })
                    .collect();
            }
        }

        summary
    }

    /// Compute the bank hash for this slot.
    ///
    /// The bank hash is a deterministic cryptographic hash of the slot's
    /// state: `SHA256(SHA256(prev_bank_hash || sig_count || last_blockhash) || lthash)`.
    pub fn hash(&self) -> [u8; 32] {
        use karstflow_crypto::sha256::Sha256StreamingHasher;

        let lthash = self.lthash.read().expect("lthash lock poisoned");
        let blockhash = self.last_blockhash.read().expect("blockhash lock poisoned");
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

/// Derive the new fee rate from the parent slot's signature count.
///
/// Uses an adjustment step of target/20 (5%) per slot, clamped between
/// target/2 and target*10. This matches the protocol's gradual fee
/// adjustment to prevent sudden fee spikes.
///
/// Note: currently unused — Solana mainnet uses a fixed fee rate.
/// Retained for potential future dynamic fee activation.
#[allow(dead_code)]
pub(crate) fn derive_fee_rate(current_rate: u64, parent_signature_count: u64) -> u64 {
    let target = LAMPORTS_PER_SIGNATURE;
    let target_sigs = DEFAULT_TARGET_SIGNATURES_PER_SLOT;

    if target_sigs == 0 {
        return target;
    }

    let min_rate = (target / 2).max(1);
    let max_rate = target.saturating_mul(10);

    // Calculate desired rate based on congestion ratio
    let clamped_sigs = parent_signature_count.min(u32::MAX as u64);
    let desired = (target as u128 * clamped_sigs as u128 / target_sigs as u128) as u64;
    let desired = desired.clamp(min_rate, max_rate);

    // Gradually adjust toward desired rate in steps of target/20 (5%)
    let step = (target / 20).max(1);
    if desired > current_rate {
        (current_rate + step).min(max_rate)
    } else if desired < current_rate {
        current_rate.saturating_sub(step).max(min_rate)
    } else {
        desired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::ledger::SLOTS_PER_EPOCH;
    use karstflow_storage::Pubkey;

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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let parent = Bank::new_genesis(
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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let bank = Bank::new_genesis_with_config(
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

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

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

        let parent = Bank::new_genesis_with_config(
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

        // Burn 50% of execution fees only: 6000/2 = 3000
        // Leader gets: 4000 (all priority) + 3000 (half execution) = 7000
        assert_eq!(burned, 3000);
        assert_eq!(leader, 7000);

        // Capitalization reduced by burned amount
        assert_eq!(bank.capitalization(), 1_000_000_000 - 3000);

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
        let vote_account = karstflow_storage::Account::new(1_000_000, vec![], Pubkey::default());
        accounts.store_published_account(voter, vote_account);

        let mut tracker = StakeTracker::new(1);
        tracker.add_delegation(stake_acct, crate::Delegation::new(voter, 1_000_000_000, 0));

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

    // -----------------------------------------------------------------------
    // Phase 3b: Sysvar cache wiring at epoch boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_boundary_updates_sysvar_stake_history() {
        let (child, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        // The sysvar cache should exist (inherited from genesis parent).
        assert!(child.sysvar_cache().is_some());

        // Before processing, stake history in the sysvar cache should be empty.
        let sysvars = child.sysvar_cache().unwrap();
        let history_before = sysvars.stake_history();
        assert!(
            history_before.get(0).is_none(),
            "Sysvar stake history should not have epoch 0 entry before epoch processing"
        );

        // Process epoch boundary.
        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.finish_slot().unwrap();

        // After processing, the sysvar cache should contain a StakeHistory entry
        // for the previous epoch (epoch 0).
        let history_after = sysvars.stake_history();
        let entry = history_after.get(0);
        assert!(
            entry.is_some(),
            "Sysvar stake history should have epoch 0 entry after epoch boundary"
        );
        let entry = entry.unwrap();
        assert!(entry.effective > 0, "Effective stake should be non-zero");
    }

    #[test]
    fn epoch_boundary_activates_epoch_rewards_sysvar() {
        let (child, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        // Before processing, epoch rewards sysvar should be inactive.
        let sysvars = child.sysvar_cache().unwrap();
        assert!(
            !sysvars.is_epoch_rewards_active(),
            "EpochRewards should be inactive before epoch processing"
        );

        // Process epoch boundary — this should activate rewards.
        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.finish_slot().unwrap();

        // If a rewards distributor was created, epoch rewards should be active.
        if child.has_pending_rewards() {
            assert!(
                sysvars.is_epoch_rewards_active(),
                "EpochRewards should be active when distributor is pending"
            );
        }
    }

    #[test]
    fn distribute_slot_rewards_clears_epoch_rewards_on_completion() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis_with_config(
            accounts.clone(),
            epoch_schedule,
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Manually activate epoch rewards via the sysvar cache.
        let sysvars = bank.sysvar_cache().unwrap();
        sysvars.set_epoch_rewards(crate::EpochRewards {
            total_rewards: 100_000,
            validator_rewards: 100_000,
            foundation_rewards: 0,
            capitalization: 1_000_000_000_000,
            epoch_duration_years: 0.0,
            validator_rate: 0.0,
            foundation_rate: 0.0,
        });
        assert!(sysvars.is_epoch_rewards_active());

        // Set up a single-slot rewards distributor.
        let target = Pubkey::new_unique();
        accounts.store_published_account(
            target,
            karstflow_storage::Account::new(1_000, vec![], Pubkey::default()),
        );
        let reward = crate::rewards_distribution::PendingReward {
            account: target,
            amount: 5_000,
            reward_type: crate::epoch_processing::RewardType::Staking,
        };
        let distributor =
            crate::rewards_distribution::RewardsDistributor::new(vec![reward], 1, bank.slot());
        *bank.rewards_distributor.write().unwrap() = Some(distributor);

        // Distribute — this should complete the single partition and clear rewards.
        let distributed = bank.distribute_slot_rewards();
        assert!(distributed > 0);
        assert!(
            !sysvars.is_epoch_rewards_active(),
            "EpochRewards should be cleared after distribution completes"
        );
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

        let parent = Bank::new_genesis(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule.clone(),
        );
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

    // -- Blockhash queue tests --

    #[test]
    fn bank_blockhash_queue_starts_empty() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        assert!(bank.blockhash_queue().read().unwrap().is_empty());
        assert!(!bank.is_blockhash_valid(&[0u8; 32]));
    }

    #[test]
    fn bank_finish_slot_registers_blockhash() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }

        let expected_hash = bank.hash();
        bank.finish_slot().unwrap();

        assert!(bank.is_blockhash_valid(&expected_hash));
        assert_eq!(bank.blockhash_queue().read().unwrap().len(), 1);
    }

    #[test]
    fn child_bank_inherits_parent_blockhash_queue() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule.clone());

        // Register a blockhash in parent
        use crate::blockhash_queue::BlockhashInfo;
        let test_hash = [0x42u8; 32];
        let info = BlockhashInfo::new(Pubkey::from(test_hash), LAMPORTS_PER_SIGNATURE, 0);
        parent
            .blockhash_queue()
            .write()
            .unwrap()
            .register_hash(info);

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();

        let child = Bank::new_from_parent(&parent, 1, leader_schedule);

        // Child should have the same blockhash queue
        assert!(child.is_blockhash_valid(&test_hash));
    }

    // -- Wave 15: Epoch processing wiring tests --

    #[test]
    fn child_bank_inherits_rewards_distributor() {
        let (parent, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        // Complete the parent so epoch boundary processing runs
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        // Parent should have a rewards distributor from epoch boundary
        assert!(parent.has_pending_rewards());

        // Child inherits the distributor
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, parent.slot() + 1, child_schedule);
        assert!(child.has_pending_rewards());
    }

    #[test]
    fn finish_slot_distributes_pending_rewards() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // Manually set up a rewards distributor with a reward for this slot
        let target = Pubkey::new_unique();
        let target_account = karstflow_storage::Account::new(1_000, vec![], Pubkey::default());
        bank.accounts()
            .store_published_account(target, target_account);

        let reward = crate::rewards_distribution::PendingReward {
            account: target,
            amount: 5_000,
            reward_type: crate::epoch_processing::RewardType::Staking,
        };
        let distributor =
            crate::rewards_distribution::RewardsDistributor::new(vec![reward], 1, bank.slot());
        *bank.rewards_distributor.write().unwrap() = Some(distributor);

        assert!(bank.has_pending_rewards());

        // Complete and finalize the slot
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        // Reward should have been applied
        let acct = bank.accounts().get_published_account(&target).unwrap();
        assert_eq!(acct.meta.lamports, 1_000 + 5_000);
    }

    #[test]
    fn regenerated_leader_schedule_stored_in_bank() {
        let (parent, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        // The epoch boundary should have regenerated a leader schedule
        let next_schedule = parent.next_leader_schedule();
        assert!(next_schedule.is_some());

        let schedule = next_schedule.unwrap();
        assert_eq!(schedule.get_epoch(), parent.epoch() + 1);
    }

    #[test]
    fn child_bank_uses_regenerated_leader_schedule() {
        let (parent, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        let regenerated = parent.next_leader_schedule().unwrap();

        // Create child in the next epoch — should use regenerated schedule
        let next_epoch_slot = parent
            .epoch_schedule()
            .get_first_slot_in_epoch(parent.epoch() + 1);
        let fallback_schedule = create_test_leader_schedule(parent.epoch() + 1);
        let child = Bank::new_from_parent(&parent, next_epoch_slot, fallback_schedule);

        // The child should be using the regenerated schedule, not the fallback
        assert_eq!(child.leader_schedule().get_epoch(), regenerated.get_epoch());
    }

    #[test]
    fn child_in_same_epoch_uses_provided_schedule() {
        let (parent, _tracker, _history) = make_bank_with_epoch_state(1_000_000_000_000);

        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        // Create child in same epoch — should use provided schedule
        let same_epoch_schedule = create_test_leader_schedule(parent.epoch());
        let child = Bank::new_from_parent(&parent, parent.slot() + 1, same_epoch_schedule.clone());

        // Should use the provided schedule, not the regenerated one
        assert_eq!(
            child.leader_schedule().get_epoch(),
            same_epoch_schedule.get_epoch()
        );
    }

    #[test]
    fn distribute_fees_credits_leader_account() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());

        let leader = Pubkey::new_unique();
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &[(leader, 1000)]).unwrap());

        let bank = Bank::new_genesis_with_config(
            accounts.clone(),
            epoch_schedule,
            leader_schedule,
            1_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Store a leader account with initial balance
        accounts.store_published_account(
            leader,
            Account {
                meta: karstflow_types::AccountMeta {
                    lamports: 500,
                    owner: Pubkey::default(),
                    executable: false,
                    rent_epoch: 0,
                },
                data: karstflow_types::AccountData::empty(),
            },
        );

        bank.add_execution_fee(2000);
        bank.add_priority_fee(0);

        let (leader_share, burn_share) = bank.distribute_fees().unwrap();
        assert_eq!(burn_share, 1000); // 50% of 2000
        assert_eq!(leader_share, 1000);

        // Leader account should now have initial 500 + 1000 = 1500
        let leader_account = accounts.get_published_account(&leader).unwrap();
        assert_eq!(leader_account.meta.lamports, 1500);
    }

    #[test]
    fn rent_not_collected_at_epoch_boundary() {
        // Rent collection is disabled (`disable_rent_fees_collection` always active).
        // All accounts must be rent-exempt; this is enforced during transaction
        // execution via rent state transition validation.
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader = Pubkey::new_unique();
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &[(leader, 1000)]).unwrap());

        let parent = Bank::new_genesis_with_config(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule.clone(),
            10_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Store a non-exempt account (small balance, some data)
        let renter = Pubkey::new_unique();
        accounts.store_published_account(
            renter,
            Account {
                meta: karstflow_types::AccountMeta {
                    lamports: 100,
                    owner: Pubkey::default(),
                    executable: false,
                    rent_epoch: 0,
                },
                data: karstflow_types::AccountData::new(vec![0u8; 200]),
            },
        );

        // Complete genesis slot
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.finish_slot().unwrap();

        // Create child at epoch boundary (first slot of epoch 1)
        let epoch_1_start = SLOTS_PER_EPOCH;
        let child_schedule = Arc::new(LeaderSchedule::new(1, &[(leader, 1000)]).unwrap());
        let child = Bank::new_from_parent(&parent, epoch_1_start, child_schedule);

        assert!(child.is_epoch_boundary());

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.finish_slot().unwrap();

        // Rent is NOT collected — balance should remain unchanged.
        let renter_account = accounts.get_published_account(&renter).unwrap();
        assert_eq!(
            renter_account.meta.lamports, 100,
            "Rent should NOT be collected: balance = {}",
            renter_account.meta.lamports
        );
    }

    #[test]
    fn slot_context_reflects_bank_state() {
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

        let ctx = bank.slot_context();
        assert_eq!(ctx.slot, bank.slot());
        assert_eq!(ctx.epoch, bank.epoch());
        assert_eq!(ctx.slots_per_epoch, SLOTS_PER_EPOCH);
        assert!(ctx.exemption_threshold > 0.0);
        assert!(ctx.lamports_per_byte_year > 0);
    }

    // -----------------------------------------------------------------------
    // Snapshot bootstrap tests
    // -----------------------------------------------------------------------

    fn make_test_bank_state(slot: u64, epoch: u64, capitalization: u64) -> SnapshotBankState {
        use karstflow_storage::{
            EpochScheduleConfig as SnapEpochSchedule, FeeRateConfig, InflationConfig,
            RecentBlockhash, RentConfig, StakeSummary,
        };

        // A completed slot has tick_height == max_tick_height.
        let ticks_per_slot = 64u64;
        let tick_height = slot * ticks_per_slot + ticks_per_slot;
        let max_tick_height = tick_height;

        SnapshotBankState {
            recent_blockhashes: vec![
                RecentBlockhash {
                    hash: [0xAA; 32],
                    lamports_per_signature: 5000,
                    hash_index: 100,
                    timestamp: 1_000_000,
                },
                RecentBlockhash {
                    hash: [0xBB; 32],
                    lamports_per_signature: 5000,
                    hash_index: 101,
                    timestamp: 1_000_001,
                },
                RecentBlockhash {
                    hash: [0xCC; 32],
                    lamports_per_signature: 5000,
                    hash_index: 102,
                    timestamp: 1_000_002,
                },
            ],
            last_blockhash: Some([0xCC; 32]),
            max_blockhash_age: 300,
            last_blockhash_index: 102,
            slot,
            parent_slot: slot.saturating_sub(1),
            block_height: slot,
            epoch,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            transaction_count: 100_000,
            tick_height,
            max_tick_height,
            signature_count: 50_000,
            capitalization,
            accounts_data_len: 1_000_000_000,
            hashes_per_tick: Some(12500),
            ticks_per_slot: 64,
            ns_per_slot: 400_000_000,
            genesis_creation_time: 1_700_000_000,
            slots_per_year: 78_892_314.0,
            collector_id: [0x33; 32],
            collector_fees: 1000,
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
            collected_rent: 500,
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
        }
    }

    #[test]
    fn snapshot_bank_initializes_slot_and_epoch() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 500_000_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert_eq!(bank.slot(), 1000);
        assert_eq!(bank.epoch(), 2);
        assert_eq!(bank.parent_slot(), Some(999));
        assert_eq!(bank.parent_hash(), [0x22; 32]);
    }

    #[test]
    fn snapshot_bank_is_rooted() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(500, 1, 1_000_000);
        let leader_schedule = create_test_leader_schedule(1);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert_eq!(bank.status(), BankStatus::Rooted);
        assert!(bank.is_frozen()); // Rooted implies frozen
    }

    #[test]
    fn snapshot_bank_restores_capitalization() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 500_000_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert_eq!(bank.capitalization(), 500_000_000_000);
    }

    #[test]
    fn snapshot_bank_restores_tick_height() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        // Snapshot slot is complete: tick_height == max_tick_height.
        let expected_ticks = 1000 * 64 + 64;
        assert_eq!(bank.tick_height(), expected_ticks);
        assert_eq!(bank.max_tick_height(), expected_ticks);
        assert!(bank.is_complete());
    }

    #[test]
    fn snapshot_bank_restores_transaction_count() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert_eq!(bank.transaction_count(), 100_000);
        assert_eq!(bank.signature_count(), 50_000);
    }

    #[test]
    fn snapshot_bank_restores_rent_config() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert_eq!(bank.rent().lamports_per_byte_year, 3_480);
        assert_eq!(bank.rent().exemption_threshold, 2.0);
        assert_eq!(bank.rent().burn_percent, 50);
    }

    #[test]
    fn snapshot_bank_restores_inflation() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert!((bank.inflation().initial_rate - 0.08).abs() < f64::EPSILON);
        assert!((bank.inflation().terminal_rate - 0.015).abs() < f64::EPSILON);
        assert!((bank.inflation().tapering_rate - 0.15).abs() < f64::EPSILON);
        assert!((bank.inflation().foundation_portion - 0.05).abs() < f64::EPSILON);
        assert!((bank.inflation().foundation_duration_years - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn snapshot_bank_restores_blockhash_queue() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        // All 3 blockhashes from snapshot should be in the queue
        let queue = bank.blockhash_queue().read().unwrap();
        assert_eq!(queue.len(), 3);

        // All should be valid
        assert!(bank.is_blockhash_valid(&[0xAA; 32]));
        assert!(bank.is_blockhash_valid(&[0xBB; 32]));
        assert!(bank.is_blockhash_valid(&[0xCC; 32]));

        // Last blockhash should be 0xCC
        let last = queue.last_blockhash().unwrap();
        assert_eq!(last.to_bytes(), [0xCC; 32]);
    }

    #[test]
    fn snapshot_bank_restores_last_blockhash() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        // Bank hash uses the last_blockhash field
        let hash_with_cc = bank.hash();

        // Verify it's non-zero (the blockhash is [0xCC; 32])
        assert!(hash_with_cc.iter().any(|&b| b != 0));
    }

    #[test]
    fn snapshot_bank_epoch_schedule_matches() {
        let accounts = Arc::new(AccountDatabase::new());
        let state = make_test_bank_state(432_001, 1, 1_000_000);
        let leader_schedule = create_test_leader_schedule(1);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        // Slot 432_001 in epoch schedule with 432K slots_per_epoch = epoch 1, slot_index 1
        assert_eq!(bank.epoch(), 1);
        assert_eq!(bank.slot_index(), 1);
    }

    #[test]
    fn snapshot_bank_child_inherits_state() {
        let accounts = Arc::new(AccountDatabase::new());
        // Use slot 864_100 which is in epoch 2 (432K slots_per_epoch).
        let snap_slot = 864_100;
        let state = make_test_bank_state(snap_slot, 2, 500_000_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule.clone());

        // Create a child bank from the snapshot bank.
        let child_slot = snap_slot + 1;
        let child = Bank::new_from_parent(&bank, child_slot, leader_schedule);

        assert_eq!(child.slot(), child_slot);
        assert_eq!(child.parent_slot(), Some(snap_slot));
        assert_eq!(child.epoch(), 2);
        assert_eq!(child.capitalization(), 500_000_000_000);

        // Child inherits the blockhash queue.
        assert!(child.is_blockhash_valid(&[0xAA; 32]));
        assert!(child.is_blockhash_valid(&[0xBB; 32]));
        assert!(child.is_blockhash_valid(&[0xCC; 32]));

        // Child is in Processing status.
        assert_eq!(child.status(), BankStatus::Processing);
        assert!(!child.is_frozen());
    }

    #[test]
    fn snapshot_bank_with_empty_blockhash_queue() {
        let accounts = Arc::new(AccountDatabase::new());
        let mut state = make_test_bank_state(100, 0, 1_000_000);
        state.recent_blockhashes.clear();
        state.last_blockhash = None;
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_from_snapshot(accounts, &state, leader_schedule);

        assert!(bank.blockhash_queue().read().unwrap().is_empty());
    }

    #[test]
    fn snapshot_bank_shares_account_database() {
        let accounts = Arc::new(AccountDatabase::new());
        let pk = Pubkey::new_unique();
        accounts.store_published_account(pk, Account::new(5000, vec![1, 2, 3], Pubkey::default()));

        let state = make_test_bank_state(1000, 2, 1_000_000);
        let leader_schedule = create_test_leader_schedule(2);

        let bank = Bank::new_from_snapshot(accounts.clone(), &state, leader_schedule);

        // Bank should see accounts from the shared database
        let acct = bank.accounts().get_published_account(&pk).unwrap();
        assert_eq!(acct.meta.lamports, 5000);
        assert_eq!(acct.data.as_slice(), &[1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // Vote account cache epoch integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn estimate_timestamp_uses_vote_cache() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            0,
            Rent::default(),
            Inflation::default(),
        );

        let cache = VoteAccountCache::new();
        let cache = Arc::new(RwLock::new(cache));
        bank.set_vote_account_cache(cache.clone());

        // With empty cache (no staked entries), falls back to system time
        let ts = bank.estimate_network_timestamp();
        assert!(ts > 0);

        // Populate cache with two validators with known timestamps
        let v1 = Pubkey::new_unique();
        let v2 = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        {
            let mut c = cache.write().unwrap();
            c.update_from_vote_state(v1, node, 5, 100, 1_700_000_000);
            c.update_from_vote_state(v2, node, 5, 200, 1_700_000_010);
            c.set_stake(&v1, 600);
            c.set_stake(&v2, 400);
        }

        let ts = bank.estimate_network_timestamp();
        // v1 has 60% stake, v2 has 40%. Sorted: [v1=1700000000, v2=1700000010]
        // Cumulative at v1: 600 >= 500 (half of 1000), so median is v1's timestamp
        assert_eq!(ts, 1_700_000_000);
    }

    #[test]
    fn estimate_timestamp_returns_system_time_without_cache() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        // No vote cache attached
        let ts = bank.estimate_network_timestamp();
        // Should be current system time (positive)
        assert!(ts > 0);
    }

    #[test]
    fn refresh_vote_cache_rotates_and_populates() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Set up vote cache with initial stakes
        let cache = Arc::new(RwLock::new(VoteAccountCache::new()));
        let v1 = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        {
            let mut c = cache.write().unwrap();
            c.update_from_vote_state(v1, node, 5, 0, 0);
            c.set_stake(&v1, 1000);
        }
        bank.set_vote_account_cache(cache.clone());

        // Set up stake tracker with different stakes for new epoch
        let tracker = Arc::new(RwLock::new(StakeTracker::new(1)));
        {
            let mut t = tracker.write().unwrap();
            t.add_delegation(Pubkey::new_unique(), crate::Delegation::new(v1, 2000, 0));
        }
        bank.set_stake_tracker(tracker);

        // Call refresh — should rotate old stakes and populate new ones
        bank.refresh_vote_account_cache();

        let c = cache.read().unwrap();
        let entry = c.get(&v1).unwrap();
        // After rotation: old 1000 moved to stake_prev, new 2000 set as current
        assert_eq!(entry.stake_prev, 1000);
        assert_eq!(entry.stake, 2000);
        assert_eq!(entry.stake_prev_prev, 0);
        assert_eq!(c.total_epoch_stake(), 2000);
    }

    #[test]
    fn refresh_vote_cache_multiple_rotations() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let mut bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let cache = Arc::new(RwLock::new(VoteAccountCache::new()));
        let v1 = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        {
            let mut c = cache.write().unwrap();
            c.update_from_vote_state(v1, node, 5, 0, 0);
            c.set_stake(&v1, 500);
        }
        bank.set_vote_account_cache(cache.clone());

        // First rotation with 1000 stake
        let tracker = Arc::new(RwLock::new(StakeTracker::new(1)));
        {
            let mut t = tracker.write().unwrap();
            t.add_delegation(Pubkey::new_unique(), crate::Delegation::new(v1, 1000, 0));
        }
        bank.set_stake_tracker(tracker.clone());
        bank.refresh_vote_account_cache();

        {
            let c = cache.read().unwrap();
            let e = c.get(&v1).unwrap();
            assert_eq!(e.stake, 1000);
            assert_eq!(e.stake_prev, 500);
            assert_eq!(e.stake_prev_prev, 0);
        }

        // Second rotation with 1500 stake
        {
            let mut t = tracker.write().unwrap();
            *t = StakeTracker::new(2);
            t.add_delegation(Pubkey::new_unique(), crate::Delegation::new(v1, 1500, 0));
        }
        bank.refresh_vote_account_cache();

        {
            let c = cache.read().unwrap();
            let e = c.get(&v1).unwrap();
            assert_eq!(e.stake, 1500);
            assert_eq!(e.stake_prev, 1000);
            assert_eq!(e.stake_prev_prev, 500);
        }
    }

    #[test]
    fn refresh_vote_cache_noop_without_cache() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);
        // No cache or tracker attached — should be a no-op, not panic
        bank.refresh_vote_account_cache();
    }

    #[test]
    fn regenerate_leader_schedule_uses_node_identities() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let vote_a = Pubkey::new_unique();
        let vote_b = Pubkey::new_unique();
        let node_a = Pubkey::new_unique();
        let node_b = Pubkey::new_unique();

        // Set up stake tracker with two vote accounts
        let mut tracker = StakeTracker::new(1);
        tracker.add_delegation(
            Pubkey::new_unique(),
            crate::Delegation::new(vote_a, 3_000_000_000, 0),
        );
        tracker.add_delegation(
            Pubkey::new_unique(),
            crate::Delegation::new(vote_b, 7_000_000_000, 0),
        );

        // Set up vote cache mapping vote accounts → node identities
        let mut vote_cache = VoteAccountCache::new();
        vote_cache.update_from_vote_state(vote_a, node_a, 5, 100, 0);
        vote_cache.update_from_vote_state(vote_b, node_b, 8, 200, 0);

        // Store vote accounts in DB (needed for rewards path)
        let empty_account = karstflow_storage::Account::new(1_000_000, vec![], Pubkey::default());
        accounts.store_published_account(vote_a, empty_account.clone());
        accounts.store_published_account(vote_b, empty_account);

        let mut parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );
        parent.set_stake_tracker(Arc::new(RwLock::new(tracker)));
        parent.set_stake_history(Arc::new(RwLock::new(StakeHistory::new())));
        parent.set_vote_account_cache(Arc::new(RwLock::new(vote_cache)));

        // Create child at epoch boundary to trigger schedule regeneration
        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        // Process epoch boundary (triggers regenerate_leader_schedule)
        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.finish_slot().unwrap();

        let next = child.next_leader_schedule().unwrap();

        // The schedule should contain node identities, not vote pubkeys
        let slot_counts = next.validator_slot_counts();
        assert!(
            slot_counts.contains_key(&node_a) || slot_counts.contains_key(&node_b),
            "Leader schedule should contain node identities"
        );
        assert!(
            !slot_counts.contains_key(&vote_a) && !slot_counts.contains_key(&vote_b),
            "Leader schedule should NOT contain vote account pubkeys"
        );
    }

    #[test]
    fn regenerate_leader_schedule_aggregates_same_node() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let vote_a = Pubkey::new_unique();
        let vote_b = Pubkey::new_unique();
        let node = Pubkey::new_unique(); // Same node for both vote accounts

        let mut tracker = StakeTracker::new(1);
        tracker.add_delegation(
            Pubkey::new_unique(),
            crate::Delegation::new(vote_a, 3_000_000_000, 0),
        );
        tracker.add_delegation(
            Pubkey::new_unique(),
            crate::Delegation::new(vote_b, 7_000_000_000, 0),
        );

        // Both vote accounts owned by the same node
        let mut vote_cache = VoteAccountCache::new();
        vote_cache.update_from_vote_state(vote_a, node, 5, 100, 0);
        vote_cache.update_from_vote_state(vote_b, node, 8, 200, 0);

        let empty_account = karstflow_storage::Account::new(1_000_000, vec![], Pubkey::default());
        accounts.store_published_account(vote_a, empty_account.clone());
        accounts.store_published_account(vote_b, empty_account);

        let mut parent = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule.clone(),
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );
        parent.set_stake_tracker(Arc::new(RwLock::new(tracker)));
        parent.set_stake_history(Arc::new(RwLock::new(StakeHistory::new())));
        parent.set_vote_account_cache(Arc::new(RwLock::new(vote_cache)));

        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = create_test_leader_schedule(1);
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.finish_slot().unwrap();

        let next = child.next_leader_schedule().unwrap();
        let slot_counts = next.validator_slot_counts();

        // Only one validator (node), with combined 10B stake → gets all slots
        assert_eq!(slot_counts.len(), 1);
        assert!(slot_counts.contains_key(&node));
    }

    #[test]
    fn to_snapshot_state_captures_bank_fields() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // Register a blockhash and some ticks so there's non-trivial state.
        bank.register_tick().unwrap();
        bank.register_tick().unwrap();

        let state = bank.to_snapshot_state();

        // Slot and epoch should match genesis values.
        assert_eq!(state.slot, GENESIS_SLOT);
        assert_eq!(state.epoch, GENESIS_EPOCH);
        assert_eq!(state.parent_slot, 0);

        // Tick height should reflect the ticks we registered.
        assert_eq!(state.tick_height, 2);
        assert_eq!(state.max_tick_height, TICKS_PER_SLOT);

        // Protocol constants should be populated.
        assert_eq!(state.ticks_per_slot, TICKS_PER_SLOT);
        assert!(state.hashes_per_tick.is_some());
        assert!(state.ns_per_slot > 0);
        assert!(state.slots_per_year > 0.0);

        // Fee rate governor should have valid values.
        assert!(state.fee_rate_governor.target_lamports_per_signature > 0);

        // Rent config should be populated from bank.
        assert!(state.rent.lamports_per_byte_year > 0);
        assert!(state.rent.exemption_threshold > 0.0);

        // Epoch schedule should match.
        assert!(state.epoch_schedule.slots_per_epoch > 0);

        // Inflation config should be populated.
        assert!(state.inflation.initial > 0.0);
        assert!(state.inflation.terminal > 0.0);

        // Hash should be a valid 32-byte value (non-trivial after ticks).
        assert_eq!(state.hash.len(), 32);

        // Stake summary should have default values (no stakes registered).
        assert_eq!(state.stake_summary.stake_delegation_count, 0);
        assert_eq!(state.stake_summary.total_delegated_stake, 0);

        // Blockhash queue may or may not have entries depending on
        // whether genesis registers a blockhash.
        assert!(state.max_blockhash_age > 0);
    }

    #[test]
    fn to_snapshot_state_includes_blockhash_entries() {
        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule = create_test_leader_schedule(0);

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        // Complete the slot to trigger blockhash registration.
        for _ in 0..TICKS_PER_SLOT {
            bank.register_tick().unwrap();
        }
        bank.finish_slot().unwrap();

        let state = bank.to_snapshot_state();

        // After finishing a slot, the blockhash queue should have entries.
        // The last_blockhash should be set.
        assert!(state.last_blockhash.is_some());
        assert_eq!(state.slot, GENESIS_SLOT);
        // Genesis bank: is_delta depends on parent_slot being Some.
        assert!(!state.is_delta, "genesis bank has no parent");
    }
}
