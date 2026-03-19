//! Bootstrap pipelines for validator initialization.
//!
//! Provides two bootstrap paths:
//! - **Snapshot bootstrap**: Restores from a Solana snapshot archive (for joining
//!   an existing network). Combines the snapshot restore result with Bank
//!   initialization, transaction cache seeding, and BankForks creation.
//! - **Genesis bootstrap**: Creates the initial state from a genesis configuration
//!   (for starting a new network or local development cluster).

use crate::bank::Bank;
use crate::bank_forks::{BankForks, BankForksError};
use crate::clock::Clock;
use crate::epoch_schedule::EpochScheduleConfig;
use crate::features::known_features;
use crate::features::FeatureSet;
use crate::inflation::Inflation;
use crate::rent::Rent;
use crate::stake::{deserialize_stake_state, Delegation, StakeState};
use crate::stake_history::{StakeHistory, StakeHistoryEntry};
use crate::sysvars::SysvarCache;
use crate::transaction_cache::SeedEntry;
use crate::vote_account_cache::VoteAccountCache;
use crate::{EpochSchedule, LeaderSchedule, StakeTracker};
use karstflow_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES;
use karstflow_ids::{FEATURE_PROGRAM_ID, STAKE_PROGRAM_ID, VOTE_PROGRAM_ID};
use karstflow_storage::{
    AccountDatabase, ClusterType, GenesisConfig, RestoreResult, SnapshotBankState, StatusCacheEntry,
};
use karstflow_types::Pubkey;
use std::sync::{Arc, RwLock};

/// Result of a successful snapshot bootstrap.
#[derive(Debug)]
pub struct BootstrapResult {
    /// Initialized BankForks with the snapshot bank as root.
    pub bank_forks: BankForks,
    /// Number of accounts loaded from the snapshot.
    pub accounts_loaded: u64,
    /// Total lamports across all loaded accounts.
    pub total_lamports: u64,
    /// Number of transaction cache entries seeded from status cache.
    pub transactions_seeded: usize,
    /// Stake initialization statistics.
    pub stake_init: StakeInitStats,
    /// Vote account cache initialization statistics.
    pub vote_init: VoteInitStats,
    /// Number of accounts included in the lattice hash computation.
    pub lthash_accounts: usize,
    /// Number of stake history epochs loaded.
    pub stake_history_entries: usize,
    /// Feature set initialization statistics.
    pub feature_init: FeatureInitStats,
    /// Snapshot slot number.
    pub slot: u64,
    /// Bank hash computed after initialization.
    pub computed_bank_hash: [u8; 32],
    /// Expected bank hash from the snapshot manifest.
    pub expected_bank_hash: [u8; 32],
    /// Whether the computed bank hash matches the snapshot manifest.
    pub bank_hash_verified: bool,
}

/// Statistics from initializing features after snapshot restore.
#[derive(Debug, Clone, Default)]
pub struct FeatureInitStats {
    /// Total feature-program-owned accounts found in the database.
    pub feature_accounts_scanned: usize,
    /// Number of features that matched a known feature ID and were activated.
    pub features_activated: usize,
    /// Number of feature accounts that were not recognized as known features.
    pub unknown_features: usize,
    /// Number of feature accounts with data too short or missing activation slot.
    pub not_yet_activated: usize,
}

/// Statistics from initializing stake state after snapshot restore.
#[derive(Debug, Clone, Default)]
pub struct StakeInitStats {
    /// Total stake accounts scanned (owned by stake program).
    pub stake_accounts_scanned: usize,
    /// Number of delegated stake accounts loaded into the tracker.
    pub delegations_loaded: usize,
    /// Number of accounts that failed deserialization (skipped).
    pub deserialization_errors: usize,
    /// Total lamports delegated across all active delegations.
    pub total_delegated_lamports: u64,
    /// Number of unique vote accounts receiving delegation.
    pub vote_accounts_with_stake: usize,
}

/// Statistics from initializing vote accounts after snapshot restore.
#[derive(Debug, Clone, Default)]
pub struct VoteInitStats {
    /// Total vote accounts scanned (owned by vote program).
    pub vote_accounts_scanned: usize,
    /// Number of vote accounts successfully loaded into the cache.
    pub vote_accounts_loaded: usize,
    /// Number of accounts that failed metadata parsing (skipped).
    pub parse_errors: usize,
}

/// Errors that can occur during snapshot bootstrap.
#[derive(Debug)]
pub enum BootstrapError {
    /// Snapshot restore result is missing bank state metadata.
    MissingBankState,
    /// BankForks initialization failed.
    BankForks(BankForksError),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBankState => write!(f, "snapshot restore result missing bank state"),
            Self::BankForks(e) => write!(f, "bank forks initialization failed: {:?}", e),
        }
    }
}

impl std::error::Error for BootstrapError {}

impl From<BankForksError> for BootstrapError {
    fn from(e: BankForksError) -> Self {
        Self::BankForks(e)
    }
}

/// Bootstrap a validator from a snapshot restore result.
///
/// Collect (validator_identity, total_stake) pairs from snapshot accounts.
///
/// Scans stake and vote accounts to build a mapping from each validator's
/// node identity to their total delegated stake. This is used to construct
/// the leader schedule before full bootstrap, since `bootstrap_from_snapshot`
/// requires a leader schedule parameter.
///
/// Returns a sorted (descending by stake) vector. Returns an empty vector
/// if no delegated stake accounts are found.
pub fn collect_validator_stakes(accounts: &AccountDatabase) -> Vec<(Pubkey, u64)> {
    use std::collections::HashMap;

    // Step 1: Build vote_pubkey → node_identity map from vote accounts.
    let vote_accounts = accounts.get_accounts_by_owner(&VOTE_PROGRAM_ID);
    let mut vote_to_node: HashMap<Pubkey, Pubkey> = HashMap::with_capacity(vote_accounts.len());
    for (vote_pubkey, account) in &vote_accounts {
        if let Some((node_pubkey, _commission, _last_vote)) =
            parse_vote_metadata(account.data.as_ref())
        {
            vote_to_node.insert(*vote_pubkey, node_pubkey);
        }
    }

    // Step 2: Aggregate stake per node identity via stake delegations.
    let stake_accounts = accounts.get_accounts_by_owner(&STAKE_PROGRAM_ID);
    let mut node_stakes: HashMap<Pubkey, u64> = HashMap::new();
    for (_pubkey, account) in &stake_accounts {
        if let Ok(StakeState::Delegated(_meta, stake, _flags)) =
            deserialize_stake_state(account.data.as_ref())
        {
            if let Some(&node) = vote_to_node.get(&stake.delegation.voter_pubkey) {
                *node_stakes.entry(node).or_insert(0) += stake.delegation.stake_amount;
            }
        }
    }

    // Sort descending by stake for deterministic schedule generation.
    let mut result: Vec<(Pubkey, u64)> = node_stakes.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

/// This function performs the complete initialization sequence:
/// 1. Constructs a `Bank` from the snapshot bank state
/// 2. Computes the cumulative lattice hash from all restored accounts
/// 3. Initializes stake tracker from restored accounts
/// 4. Loads stake history from the snapshot for warmup/cooldown
/// 5. Initializes the sysvar cache (clock, epoch schedule, rent)
/// 6. Initializes feature set from on-chain feature gate accounts
/// 7. Seeds the transaction cache from the status cache
/// 8. Verifies the computed bank hash against the snapshot manifest
/// 9. Wraps in `BankForks` as the root bank
///
/// The caller is responsible for running the `SnapshotRestorer` first
/// to populate the `AccountDatabase` and produce the `RestoreResult`.
pub fn bootstrap_from_snapshot(
    accounts: Arc<AccountDatabase>,
    restore_result: &RestoreResult,
    leader_schedule: Arc<LeaderSchedule>,
) -> Result<BootstrapResult, BootstrapError> {
    let bank_state = restore_result
        .bank_state
        .as_ref()
        .ok_or(BootstrapError::MissingBankState)?;

    // Step 1: Create Bank from snapshot state.
    let mut bank = Bank::new_from_snapshot(accounts.clone(), bank_state, leader_schedule);

    // Step 2: Compute cumulative lattice hash from all restored accounts.
    let lthash_accounts = bank.initialize_lthash_from_accounts();

    // Step 3: Initialize stake tracker from restored stake accounts.
    let (tracker, stake_init) = initialize_stakes(&accounts, bank_state.epoch);
    bank.set_stake_tracker(Arc::new(RwLock::new(tracker)));

    // Step 3b: Initialize vote account cache from restored vote accounts.
    let (vote_cache, vote_init) = initialize_vote_accounts(&accounts);
    bank.set_vote_account_cache(Arc::new(RwLock::new(vote_cache)));

    // Step 4: Initialize stake history from snapshot.
    let stake_history = initialize_stake_history(&bank_state.stake_summary);
    let stake_history_entries = stake_history.len();
    bank.set_stake_history(Arc::new(RwLock::new(stake_history)));

    // Step 5: Initialize sysvar cache from snapshot state.
    let sysvar_cache = initialize_sysvar_cache(bank_state);
    bank.set_sysvar_cache(Arc::new(sysvar_cache));

    // Step 6: Initialize feature set from feature-program-owned accounts.
    let (feature_set, feature_init) = initialize_features(&accounts);
    bank.set_feature_set(Arc::new(RwLock::new(feature_set)));

    // Step 7: Seed transaction cache from status cache.
    let transactions_seeded = if let Some(status_cache) = &restore_result.status_cache {
        let seed_entries = status_cache.entries.iter().map(convert_status_cache_entry);
        bank.seed_transaction_cache(seed_entries)
    } else {
        0
    };

    // Step 8: Verify bank hash against snapshot manifest.
    let computed_bank_hash = bank.hash();
    let expected_bank_hash = bank_state.hash;
    let bank_hash_verified = computed_bank_hash == expected_bank_hash;

    // Step 9: Wrap in BankForks.
    let bank_forks = BankForks::new_from_snapshot(bank)?;

    Ok(BootstrapResult {
        bank_forks,
        accounts_loaded: restore_result.accounts_loaded,
        total_lamports: restore_result.total_lamports,
        transactions_seeded,
        stake_init,
        vote_init,
        lthash_accounts,
        stake_history_entries,
        feature_init,
        slot: restore_result.slot,
        computed_bank_hash,
        expected_bank_hash,
        bank_hash_verified,
    })
}

/// Result of a successful genesis bootstrap.
#[derive(Debug)]
pub struct GenesisBootstrapResult {
    /// Initialized BankForks with the genesis bank as root.
    pub bank_forks: BankForks,
    /// Number of accounts loaded from the genesis configuration.
    pub accounts_loaded: usize,
    /// Total lamports across all genesis accounts.
    pub total_lamports: u64,
    /// Stake initialization statistics.
    pub stake_init: StakeInitStats,
    /// Vote account cache initialization statistics.
    pub vote_init: VoteInitStats,
    /// Number of accounts included in the lattice hash computation.
    pub lthash_accounts: usize,
    /// Feature set initialization statistics.
    pub feature_init: FeatureInitStats,
}

/// Bootstrap a validator from a genesis configuration.
///
/// This function performs the complete initialization sequence for a new network:
/// 1. Loads all genesis accounts into the account database
/// 2. Constructs a `Bank` at slot 0 with genesis economic parameters
/// 3. Computes the cumulative lattice hash from all loaded accounts
/// 4. Initializes stake tracker from any delegated stake accounts
/// 5. Initializes empty stake history (genesis has no prior epochs)
/// 6. Initializes the sysvar cache (clock at slot 0, epoch schedule, rent)
/// 7. Initializes feature set from on-chain feature gate accounts
/// 8. Wraps in `BankForks` as the root bank
pub fn bootstrap_from_genesis(
    genesis: &GenesisConfig,
    leader_schedule: Arc<LeaderSchedule>,
) -> GenesisBootstrapResult {
    let accounts = Arc::new(AccountDatabase::new());

    // Step 1: Load all genesis accounts into the database.
    let runtime_accounts = genesis.to_accounts();
    let mut total_lamports: u64 = 0;
    for (pubkey, account) in &runtime_accounts {
        total_lamports = total_lamports.saturating_add(account.meta.lamports);
        accounts.store_published_account(*pubkey, account.clone());
    }
    let accounts_loaded = runtime_accounts.len();

    // Step 2: Create Bank at slot 0 with genesis economic configuration.
    let epoch_schedule_config = EpochScheduleConfig {
        slots_per_epoch: genesis.epoch_schedule.slots_per_epoch,
        leader_schedule_slot_offset: genesis.epoch_schedule.leader_schedule_slot_offset,
        warmup: genesis.epoch_schedule.warmup,
        first_normal_epoch: genesis.epoch_schedule.first_normal_epoch,
        first_normal_slot: genesis.epoch_schedule.first_normal_slot,
    };
    let epoch_schedule = Arc::new(EpochSchedule::new(epoch_schedule_config));

    let rent = Rent {
        lamports_per_byte_year: genesis.rent.lamports_per_byte_year,
        exemption_threshold: genesis.rent.exemption_threshold,
        burn_percent: genesis.rent.burn_percent,
    };
    let inflation = Inflation {
        initial_rate: genesis.inflation.initial_rate,
        terminal_rate: genesis.inflation.terminal_rate,
        tapering_rate: genesis.inflation.tapering_rate,
        foundation_portion: genesis.inflation.foundation_portion,
        foundation_duration_years: genesis.inflation.foundation_duration_years,
    };

    let mut bank = Bank::new_genesis_with_config(
        accounts.clone(),
        epoch_schedule,
        leader_schedule,
        total_lamports,
        rent,
        inflation,
    );

    // Step 3: Compute cumulative lattice hash from all loaded accounts.
    let lthash_accounts = bank.initialize_lthash_from_accounts();

    // Step 4: Initialize stake tracker.
    // Primary: scan for Solana-compatible stake program accounts (production genesis).
    // Fallback: if no delegated stakes found but genesis carries `initial_validators`,
    //           seed the tracker directly from that list (dev cluster genesis).
    let (mut tracker, stake_init) = initialize_stakes(&accounts, 0);
    if tracker.total_stake() == 0 && !genesis.initial_validators.is_empty() {
        for (node_identity, stake_lamports) in &genesis.initial_validators {
            // In dev cluster genesis there are no separate vote accounts, so we use
            // the node identity as a synthetic voter pubkey.  This gives correct
            // total_stake() and total_stake_for_voter() semantics for fork choice.
            // Use activation_epoch=MAX so the stake is immediately effective
            // (bootstrap delegation, no warmup period required).
            let delegation = Delegation::new(*node_identity, *stake_lamports, u64::MAX);
            tracker.add_delegation(*node_identity, delegation);
        }
    }
    bank.set_stake_tracker(Arc::new(RwLock::new(tracker)));

    // Step 4b: Initialize vote account cache from genesis vote accounts.
    let (vote_cache, vote_init) = initialize_vote_accounts(&accounts);
    bank.set_vote_account_cache(Arc::new(RwLock::new(vote_cache)));

    // Step 5: Initialize empty stake history (no prior epochs at genesis).
    bank.set_stake_history(Arc::new(RwLock::new(StakeHistory::new())));

    // Step 6: Initialize sysvar cache with genesis parameters.
    let clock = Clock {
        slot: 0,
        epoch_start_timestamp: genesis.creation_time,
        epoch: 0,
        leader_schedule_epoch: 1,
        unix_timestamp: genesis.creation_time,
    };
    let sysvar_epoch_schedule = EpochSchedule::new(EpochScheduleConfig {
        slots_per_epoch: genesis.epoch_schedule.slots_per_epoch,
        leader_schedule_slot_offset: genesis.epoch_schedule.leader_schedule_slot_offset,
        warmup: genesis.epoch_schedule.warmup,
        first_normal_epoch: genesis.epoch_schedule.first_normal_epoch,
        first_normal_slot: genesis.epoch_schedule.first_normal_slot,
    });
    let sysvar_cache = SysvarCache::new(clock, sysvar_epoch_schedule, rent);
    bank.set_sysvar_cache(Arc::new(sysvar_cache));

    // Step 7: Initialize feature set.
    // In development mode, activate all known features at slot 0 (matching Solana
    // test-validator behavior). On other cluster types, scan on-chain feature accounts.
    let (feature_set, feature_init) = if genesis.cluster_type == ClusterType::Development {
        let fs = FeatureSet::all_active();
        let stats = FeatureInitStats {
            feature_accounts_scanned: 0,
            features_activated: fs.active_count(),
            not_yet_activated: 0,
            unknown_features: 0,
        };
        (fs, stats)
    } else {
        initialize_features(&accounts)
    };
    bank.set_feature_set(Arc::new(RwLock::new(feature_set)));

    // Step 8: Wrap in BankForks (genesis bank is Processing, use standard constructor).
    let bank_forks = BankForks::new(bank);

    GenesisBootstrapResult {
        bank_forks,
        accounts_loaded,
        total_lamports,
        stake_init,
        vote_init,
        lthash_accounts,
        feature_init,
    }
}

/// Scan the account database for stake program accounts and build a StakeTracker.
///
/// Iterates all accounts owned by the stake program, deserializes their state,
/// and loads delegated stakes into a tracker for consensus weight calculation.
fn initialize_stakes(accounts: &AccountDatabase, epoch: u64) -> (StakeTracker, StakeInitStats) {
    let stake_accounts = accounts.get_accounts_by_owner(&STAKE_PROGRAM_ID);
    let mut tracker = StakeTracker::new(epoch);
    let mut stats = StakeInitStats {
        stake_accounts_scanned: stake_accounts.len(),
        ..Default::default()
    };

    for (pubkey, account) in &stake_accounts {
        match deserialize_stake_state(account.data.as_ref()) {
            Ok(StakeState::Delegated(_meta, stake, _flags)) => {
                stats.delegations_loaded += 1;
                stats.total_delegated_lamports += stake.delegation.stake_amount;
                tracker.add_delegation(*pubkey, stake.delegation);
            }
            Ok(_) => {
                // Initialized, Uninitialized, or RewardsPool — not a delegation.
            }
            Err(_) => {
                stats.deserialization_errors += 1;
            }
        }
    }

    stats.vote_accounts_with_stake = tracker.stake_by_vote_account().len();
    (tracker, stats)
}

/// Scan the account database for vote program accounts and build a VoteAccountCache.
///
/// Iterates all accounts owned by the vote program, extracts metadata
/// (node identity, commission, last vote slot), and populates a cache
/// for stake-weighted clock, leader schedule, and epoch processing.
fn initialize_vote_accounts(accounts: &AccountDatabase) -> (VoteAccountCache, VoteInitStats) {
    let vote_accounts = accounts.get_accounts_by_owner(&VOTE_PROGRAM_ID);
    let mut cache = VoteAccountCache::with_capacity(vote_accounts.len());
    let mut stats = VoteInitStats {
        vote_accounts_scanned: vote_accounts.len(),
        ..Default::default()
    };

    for (pubkey, account) in &vote_accounts {
        match parse_vote_metadata(account.data.as_ref()) {
            Some((node_pubkey, commission, last_vote_slot)) => {
                cache.update_from_vote_state(
                    *pubkey,
                    node_pubkey,
                    commission,
                    last_vote_slot,
                    0, // Timestamp not stored in binary format; updated at runtime.
                );
                stats.vote_accounts_loaded += 1;
            }
            None => {
                stats.parse_errors += 1;
            }
        }
    }

    (cache, stats)
}

/// Extract node identity, commission, and last vote slot from vote account data.
///
/// Binary layout (matching the vote program serialization):
/// - `[0..32]`   node_pubkey
/// - `[32..64]`  authorized_voter
/// - `[64..96]`  authorized_withdrawer
/// - `[96]`      commission (1 byte)
/// - `[97..101]` vote_count (u32 LE)
/// - votes:      vote_count * 12 bytes (slot:u64 + confirmation:u32)
///
/// Returns `(node_pubkey, commission, last_vote_slot)` or `None` on parse failure.
fn parse_vote_metadata(data: &[u8]) -> Option<(Pubkey, u8, u64)> {
    // Minimum: 3 pubkeys (96) + commission (1) + vote_count (4) = 101
    if data.len() < 101 {
        return None;
    }

    let node_pubkey = Pubkey::new(data[0..32].try_into().ok()?);
    let commission = data[96];

    let vote_count = u32::from_le_bytes(data[97..101].try_into().ok()?) as usize;

    // Extract the last vote slot from the votes array.
    let last_vote_slot = if vote_count > 0 {
        // Each vote entry is 12 bytes (slot:u64 + conf:u32).
        // The last vote is at offset 101 + (vote_count - 1) * 12.
        let last_vote_offset = 101 + (vote_count - 1) * 12;
        if data.len() < last_vote_offset + 8 {
            return None;
        }
        u64::from_le_bytes(
            data[last_vote_offset..last_vote_offset + 8]
                .try_into()
                .ok()?,
        )
    } else {
        0
    };

    Some((node_pubkey, commission, last_vote_slot))
}

/// Initialize the sysvar cache from snapshot bank state.
///
/// Creates a SysvarCache populated with clock, epoch schedule, and rent
/// values derived from the snapshot manifest.
fn initialize_sysvar_cache(bank_state: &SnapshotBankState) -> SysvarCache {
    let epoch_schedule = EpochSchedule::new(EpochScheduleConfig {
        slots_per_epoch: bank_state.epoch_schedule.slots_per_epoch,
        leader_schedule_slot_offset: bank_state.epoch_schedule.leader_schedule_slot_offset,
        warmup: bank_state.epoch_schedule.warmup,
        first_normal_epoch: bank_state.epoch_schedule.first_normal_epoch,
        first_normal_slot: bank_state.epoch_schedule.first_normal_slot,
    });

    // Derive leader_schedule_epoch from the epoch schedule rather than
    // assuming current_epoch + 1. This is correct during warmup and at
    // epoch boundaries where the offset isn't exactly one epoch.
    let leader_schedule_epoch = epoch_schedule.get_leader_schedule_epoch(bank_state.slot);

    let clock = Clock {
        slot: bank_state.slot,
        epoch_start_timestamp: bank_state.genesis_creation_time,
        epoch: bank_state.epoch,
        leader_schedule_epoch,
        unix_timestamp: bank_state.genesis_creation_time,
    };

    let rent = Rent {
        lamports_per_byte_year: bank_state.rent.lamports_per_byte_year,
        exemption_threshold: bank_state.rent.exemption_threshold,
        burn_percent: bank_state.rent.burn_percent,
    };

    SysvarCache::new(clock, epoch_schedule, rent)
}

/// Initialize the feature set from on-chain feature gate accounts.
///
/// Scans all accounts owned by the Feature program, checks if each one matches
/// a known feature ID, and reads the activation slot from the account data.
/// The Solana feature account data format is `Option<Slot>` serialized with
/// bincode: `[0]` for not-yet-activated, `[1, slot_le_bytes]` for activated.
fn initialize_features(accounts: &AccountDatabase) -> (FeatureSet, FeatureInitStats) {
    let feature_accounts = accounts.get_accounts_by_owner(&FEATURE_PROGRAM_ID);
    let known = known_features::all_known_features();
    let known_set: std::collections::HashSet<karstflow_types::Pubkey> =
        known.iter().map(|f| f.feature_id).collect();

    let mut feature_set = FeatureSet::with_known_features();
    let mut stats = FeatureInitStats {
        feature_accounts_scanned: feature_accounts.len(),
        ..Default::default()
    };

    for (pubkey, account) in &feature_accounts {
        if !known_set.contains(pubkey) {
            stats.unknown_features += 1;
            continue;
        }

        // Parse feature account data: Option<Slot> in bincode.
        // Activated: [1, slot_u64_le] (9 bytes)
        // Not activated: [0] (1 byte) or empty data
        let data = account.data.as_ref();
        if data.len() >= 9 && data[0] == 1 {
            let slot = u64::from_le_bytes(data[1..9].try_into().unwrap_or_else(|_| unreachable!()));
            feature_set.activate(*pubkey, slot);
            stats.features_activated += 1;
        } else {
            stats.not_yet_activated += 1;
        }
    }

    (feature_set, stats)
}

/// Build stake history from snapshot's parsed stake summary.
///
/// Converts the raw stake history records from the snapshot manifest into
/// the consensus-layer StakeHistory used for warmup/cooldown calculations.
fn initialize_stake_history(summary: &karstflow_storage::StakeSummary) -> StakeHistory {
    let mut history = StakeHistory::new();
    for record in &summary.stake_history {
        history.add(
            record.epoch,
            StakeHistoryEntry::new(record.effective, record.activating, record.deactivating),
        );
    }
    history
}

/// Convert a storage-layer status cache entry to a consensus-layer seed entry.
fn convert_status_cache_entry(entry: &StatusCacheEntry) -> SeedEntry {
    let mut message_hash = [0u8; MESSAGE_HASH_PREFIX_BYTES];
    message_hash.copy_from_slice(&entry.message_hash);
    SeedEntry {
        slot: entry.slot,
        blockhash: entry.blockhash,
        message_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake::{serialize_stake_state, Authorized, Delegation, Lockup, Meta, StakeAccount};
    use karstflow_storage::{
        Account, EpochScheduleConfig, FeeRateConfig, InflationConfig, Pubkey, RentConfig,
        SnapshotBankState, StakeSummary, StatusCacheParseResult,
    };

    fn make_bank_state(slot: u64) -> SnapshotBankState {
        let ticks_per_slot = 64u64;
        let tick_height = slot * ticks_per_slot + ticks_per_slot;

        SnapshotBankState {
            recent_blockhashes: vec![],
            last_blockhash: Some([1u8; 32]),
            max_blockhash_age: 300,
            last_blockhash_index: 0,
            slot,
            parent_slot: slot.saturating_sub(1),
            block_height: slot,
            epoch: 0,
            hash: [0x11; 32],
            parent_hash: [0x22; 32],
            transaction_count: 1000,
            tick_height,
            max_tick_height: tick_height,
            signature_count: 500,
            capitalization: 500_000_000_000,
            accounts_data_len: 1_000_000_000,
            hashes_per_tick: Some(12500),
            ticks_per_slot: 64,
            ns_per_slot: 400_000_000,
            genesis_creation_time: 1_700_000_000,
            slots_per_year: 78_892_314.0,
            collector_id: [0u8; 32],
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
                collector_epoch: 0,
                collector_slots_per_year: 78_892_314.0,
            },
            collected_rent: 0,
            epoch_schedule: EpochScheduleConfig {
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

    fn make_leader_schedule() -> Arc<LeaderSchedule> {
        let validator = Pubkey::new_unique();
        Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap())
    }

    fn make_restore_result(slot: u64) -> RestoreResult {
        RestoreResult {
            slot,
            version: "1.18.0".to_string(),
            accounts_loaded: 50_000,
            total_lamports: 500_000_000_000,
            append_vecs_processed: 100,
            validation_errors: 0,
            bank_state: Some(make_bank_state(slot)),
            status_cache: None,
            expected_accounts_hash: [0u8; 32],
        }
    }

    /// Create a serialized delegated stake account.
    fn make_delegated_stake_data(voter: &Pubkey, stake_amount: u64) -> Vec<u8> {
        let meta = Meta::new(
            2_282_880, // rent-exempt reserve
            Authorized::new(Pubkey::new_unique(), Pubkey::new_unique()),
            Lockup::default(),
        );
        let delegation = Delegation::new(*voter, stake_amount, 0);
        let stake = StakeAccount::new(delegation, 0);
        let state = StakeState::Delegated(meta, stake, Default::default());
        serialize_stake_state(&state)
    }

    /// Insert a stake account into the database.
    fn insert_stake_account(db: &AccountDatabase, voter: &Pubkey, stake_amount: u64) -> Pubkey {
        let pubkey = Pubkey::new_unique();
        let data = make_delegated_stake_data(voter, stake_amount);
        let account = Account {
            data: data.into(),
            meta: karstflow_storage::AccountMeta {
                lamports: stake_amount + 2_282_880,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey, account);
        pubkey
    }

    // ── existing bootstrap tests ───────────────────────────────────────

    #[test]
    fn bootstrap_creates_bank_forks() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.slot, 1000);
        assert_eq!(bootstrap.accounts_loaded, 50_000);
        assert_eq!(bootstrap.total_lamports, 500_000_000_000);
        assert_eq!(bootstrap.transactions_seeded, 0);
        assert_eq!(bootstrap.stake_init.delegations_loaded, 0);
        assert_eq!(bootstrap.bank_forks.root_slot(), 1000);
    }

    #[test]
    fn bootstrap_fails_without_bank_state() {
        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(1000);
        result.bank_state = None;
        let leader_schedule = make_leader_schedule();

        let err = bootstrap_from_snapshot(db, &result, leader_schedule);
        assert!(matches!(err, Err(BootstrapError::MissingBankState)));
    }

    #[test]
    fn bootstrap_seeds_transaction_cache() {
        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(1000);

        let blockhash_a = [0xAA; 32];
        let blockhash_b = [0xBB; 32];

        result.status_cache = Some(StatusCacheParseResult {
            entries: vec![
                StatusCacheEntry {
                    slot: 998,
                    blockhash: blockhash_a,
                    message_hash: [0x11; 20],
                    succeeded: true,
                },
                StatusCacheEntry {
                    slot: 999,
                    blockhash: blockhash_a,
                    message_hash: [0x22; 20],
                    succeeded: true,
                },
                StatusCacheEntry {
                    slot: 1000,
                    blockhash: blockhash_b,
                    message_hash: [0x33; 20],
                    succeeded: false,
                },
            ],
            slot_deltas_processed: 3,
            parse_errors: 0,
        });

        let leader_schedule = make_leader_schedule();
        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.transactions_seeded, 3);

        // Verify the cache contains the seeded entries.
        let bank = bootstrap.bank_forks.working_bank();
        let cache = bank.transaction_cache();
        assert_eq!(cache.entry_count(), 3);
        assert!(cache.contains(&blockhash_a, &[0x11; 20], 998));
        assert!(cache.contains(&blockhash_a, &[0x22; 20], 999));
        assert!(cache.contains(&blockhash_b, &[0x33; 20], 1000));
    }

    #[test]
    fn bootstrap_with_empty_status_cache() {
        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(500);

        result.status_cache = Some(StatusCacheParseResult {
            entries: vec![],
            slot_deltas_processed: 0,
            parse_errors: 0,
        });

        let leader_schedule = make_leader_schedule();
        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.transactions_seeded, 0);
        assert_eq!(
            bootstrap
                .bank_forks
                .working_bank()
                .transaction_cache()
                .entry_count(),
            0
        );
    }

    #[test]
    fn bootstrap_bank_slot_matches_restore() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(42_000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        let bank = bootstrap.bank_forks.working_bank();
        assert_eq!(bank.slot(), 42_000);
        assert_eq!(bank.transaction_count(), 1000);
        assert_eq!(bank.capitalization(), 500_000_000_000);
    }

    #[test]
    fn bootstrap_result_propagates_restore_stats() {
        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(100);
        result.accounts_loaded = 123_456;
        result.total_lamports = 999_999_999;
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.accounts_loaded, 123_456);
        assert_eq!(bootstrap.total_lamports, 999_999_999);
    }

    #[test]
    fn bootstrap_bank_is_rooted() {
        use crate::BankStatus;

        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(5000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(
            bootstrap.bank_forks.working_bank().status(),
            BankStatus::Rooted
        );
    }

    #[test]
    fn bootstrap_allows_child_creation() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule.clone()).unwrap();
        let root_bank = bootstrap.bank_forks.working_bank();

        // Create a child bank from the root.
        let child = Bank::new_from_parent(&root_bank, 1001, leader_schedule);
        assert_eq!(child.slot(), 1001);
        assert_eq!(child.parent_slot(), Some(1000));
    }

    // ── stake initialization tests ─────────────────────────────────────

    #[test]
    fn bootstrap_initializes_stake_tracker_empty() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_init.stake_accounts_scanned, 0);
        assert_eq!(bootstrap.stake_init.delegations_loaded, 0);
        assert_eq!(bootstrap.stake_init.deserialization_errors, 0);
        assert_eq!(bootstrap.stake_init.total_delegated_lamports, 0);
        assert_eq!(bootstrap.stake_init.vote_accounts_with_stake, 0);

        // Stake tracker should be attached to the bank.
        let bank = bootstrap.bank_forks.working_bank();
        assert!(bank.stake_tracker().is_some());
    }

    #[test]
    fn bootstrap_loads_delegated_stakes() {
        let db = Arc::new(AccountDatabase::new());
        let vote_a = Pubkey::new_unique();
        let vote_b = Pubkey::new_unique();

        insert_stake_account(&db, &vote_a, 1_000_000);
        insert_stake_account(&db, &vote_a, 2_000_000);
        insert_stake_account(&db, &vote_b, 500_000);

        // Use epoch > 0 so delegations activated at epoch 0 are fully effective.
        let mut result = make_restore_result(1000);
        result.bank_state.as_mut().unwrap().epoch = 10;
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_init.stake_accounts_scanned, 3);
        assert_eq!(bootstrap.stake_init.delegations_loaded, 3);
        assert_eq!(bootstrap.stake_init.deserialization_errors, 0);
        assert_eq!(bootstrap.stake_init.total_delegated_lamports, 3_500_000);
        assert_eq!(bootstrap.stake_init.vote_accounts_with_stake, 2);

        // Verify tracker is populated on the bank.
        let bank = bootstrap.bank_forks.working_bank();
        let tracker_lock = bank.stake_tracker().unwrap();
        let tracker = tracker_lock.read().unwrap();
        assert_eq!(tracker.delegation_count(), 3);
        assert_eq!(tracker.total_stake_for_voter(&vote_a), 3_000_000);
        assert_eq!(tracker.total_stake_for_voter(&vote_b), 500_000);
    }

    #[test]
    fn bootstrap_skips_initialized_stake_accounts() {
        let db = Arc::new(AccountDatabase::new());

        // Insert an Initialized (not Delegated) stake account.
        let meta = Meta::new(
            2_282_880,
            Authorized::new(Pubkey::new_unique(), Pubkey::new_unique()),
            Lockup::default(),
        );
        let data = serialize_stake_state(&StakeState::Initialized(meta));
        let pubkey = Pubkey::new_unique();
        let account = Account {
            data: data.into(),
            meta: karstflow_storage::AccountMeta {
                lamports: 5_000_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey, account);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_init.stake_accounts_scanned, 1);
        assert_eq!(bootstrap.stake_init.delegations_loaded, 0);
        assert_eq!(bootstrap.stake_init.total_delegated_lamports, 0);
    }

    #[test]
    fn bootstrap_counts_deserialization_errors() {
        let db = Arc::new(AccountDatabase::new());

        // Insert a stake-program-owned account with invalid data.
        let pubkey = Pubkey::new_unique();
        let account = Account {
            data: vec![0xFF, 0xFF].into(), // too short, invalid discriminant
            meta: karstflow_storage::AccountMeta {
                lamports: 1_000_000,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey, account);

        // Also insert a valid delegated stake.
        let voter = Pubkey::new_unique();
        insert_stake_account(&db, &voter, 1_000_000);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_init.stake_accounts_scanned, 2);
        assert_eq!(bootstrap.stake_init.delegations_loaded, 1);
        assert_eq!(bootstrap.stake_init.deserialization_errors, 1);
        assert_eq!(bootstrap.stake_init.total_delegated_lamports, 1_000_000);
    }

    #[test]
    fn bootstrap_stake_tracker_inherits_to_child() {
        let db = Arc::new(AccountDatabase::new());
        let voter = Pubkey::new_unique();
        insert_stake_account(&db, &voter, 5_000_000);

        let mut result = make_restore_result(1000);
        result.bank_state.as_mut().unwrap().epoch = 10;
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule.clone()).unwrap();
        let root_bank = bootstrap.bank_forks.working_bank();

        // Child bank should inherit the stake tracker.
        let child = Bank::new_from_parent(&root_bank, 1001, leader_schedule);
        let child_tracker = child.stake_tracker().unwrap();
        let tracker = child_tracker.read().unwrap();
        assert_eq!(tracker.total_stake_for_voter(&voter), 5_000_000);
    }

    // ── lattice hash initialization tests ──────────────────────────────

    #[test]
    fn bootstrap_lthash_zero_with_no_accounts() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.lthash_accounts, 0);

        // Bank hash should still be computable (though based on zero lthash).
        let bank = bootstrap.bank_forks.working_bank();
        let hash = bank.hash();
        assert_ne!(hash, [0u8; 32]); // Non-zero due to parent_hash and blockhash.
    }

    #[test]
    fn bootstrap_lthash_includes_restored_accounts() {
        let db = Arc::new(AccountDatabase::new());

        // Insert some non-stake accounts.
        let system_program = Pubkey::new([0u8; 32]);
        for i in 0u8..5 {
            let pubkey = Pubkey::new_unique();
            let account = Account {
                data: vec![i; 100].into(),
                meta: karstflow_storage::AccountMeta {
                    lamports: 1_000_000 + i as u64,
                    owner: system_program,
                    executable: false,
                    rent_epoch: 0,
                },
            };
            db.store_published_account(pubkey, account);
        }

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.lthash_accounts, 5);
    }

    #[test]
    fn bootstrap_lthash_deterministic() {
        // Same accounts in same DB should produce same bank hash.
        let make_db = || {
            let db = Arc::new(AccountDatabase::new());
            let pubkey = Pubkey::new([0x42; 32]);
            let account = Account {
                data: vec![1, 2, 3].into(),
                meta: karstflow_storage::AccountMeta {
                    lamports: 5_000_000,
                    owner: Pubkey::new([0x11; 32]),
                    executable: false,
                    rent_epoch: 0,
                },
            };
            db.store_published_account(pubkey, account);
            db
        };

        let result = make_restore_result(1000);
        let ls1 = make_leader_schedule();
        let ls2 = make_leader_schedule();

        let b1 = bootstrap_from_snapshot(make_db(), &result, ls1).unwrap();
        let b2 = bootstrap_from_snapshot(make_db(), &result, ls2).unwrap();

        let hash1 = b1.bank_forks.working_bank().hash();
        let hash2 = b2.bank_forks.working_bank().hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn bootstrap_lthash_different_accounts_different_hash() {
        let result = make_restore_result(1000);

        // DB with one account.
        let db1 = Arc::new(AccountDatabase::new());
        let pubkey = Pubkey::new([0x42; 32]);
        db1.store_published_account(
            pubkey,
            Account {
                data: vec![1].into(),
                meta: karstflow_storage::AccountMeta {
                    lamports: 1_000,
                    owner: Pubkey::new([0x11; 32]),
                    executable: false,
                    rent_epoch: 0,
                },
            },
        );

        // DB with different account data.
        let db2 = Arc::new(AccountDatabase::new());
        db2.store_published_account(
            pubkey,
            Account {
                data: vec![2].into(),
                meta: karstflow_storage::AccountMeta {
                    lamports: 1_000,
                    owner: Pubkey::new([0x11; 32]),
                    executable: false,
                    rent_epoch: 0,
                },
            },
        );

        let ls1 = make_leader_schedule();
        let ls2 = make_leader_schedule();

        let b1 = bootstrap_from_snapshot(db1, &result, ls1).unwrap();
        let b2 = bootstrap_from_snapshot(db2, &result, ls2).unwrap();

        let hash1 = b1.bank_forks.working_bank().hash();
        let hash2 = b2.bank_forks.working_bank().hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn bootstrap_lthash_skips_zero_lamport_accounts() {
        let db = Arc::new(AccountDatabase::new());

        // Zero-lamport account should not contribute to lthash.
        let pubkey = Pubkey::new_unique();
        let account = Account {
            data: vec![1, 2, 3].into(),
            meta: karstflow_storage::AccountMeta {
                lamports: 0,
                owner: Pubkey::new([0x11; 32]),
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey, account);

        // Non-zero account.
        let pubkey2 = Pubkey::new_unique();
        let account2 = Account {
            data: vec![4, 5, 6].into(),
            meta: karstflow_storage::AccountMeta {
                lamports: 1_000,
                owner: Pubkey::new([0x11; 32]),
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey2, account2);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.lthash_accounts, 1); // Only non-zero lamport counts.
    }

    // ── stake history initialization tests ─────────────────────────────

    #[test]
    fn bootstrap_loads_empty_stake_history() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_history_entries, 0);

        // Stake history should be attached to the bank.
        let bank = bootstrap.bank_forks.working_bank();
        assert!(bank.stake_history().is_some());
    }

    #[test]
    fn bootstrap_loads_stake_history_from_snapshot() {
        use karstflow_storage::StakeHistoryRecord;

        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(1000);

        // Populate stake history in the snapshot.
        result
            .bank_state
            .as_mut()
            .unwrap()
            .stake_summary
            .stake_history = vec![
            StakeHistoryRecord {
                epoch: 5,
                effective: 100_000_000,
                activating: 10_000_000,
                deactivating: 5_000_000,
            },
            StakeHistoryRecord {
                epoch: 6,
                effective: 110_000_000,
                activating: 5_000_000,
                deactivating: 3_000_000,
            },
            StakeHistoryRecord {
                epoch: 7,
                effective: 112_000_000,
                activating: 2_000_000,
                deactivating: 1_000_000,
            },
        ];
        result
            .bank_state
            .as_mut()
            .unwrap()
            .stake_summary
            .stake_history_entries = 3;

        let leader_schedule = make_leader_schedule();
        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.stake_history_entries, 3);

        // Verify the history is accessible from the bank.
        let bank = bootstrap.bank_forks.working_bank();
        let history_lock = bank.stake_history().unwrap();
        let history = history_lock.read().unwrap();
        assert_eq!(history.len(), 3);

        let entry5 = history.get(5).unwrap();
        assert_eq!(entry5.effective, 100_000_000);
        assert_eq!(entry5.activating, 10_000_000);
        assert_eq!(entry5.deactivating, 5_000_000);

        let entry7 = history.get(7).unwrap();
        assert_eq!(entry7.effective, 112_000_000);
    }

    #[test]
    fn bootstrap_stake_history_inherits_to_child() {
        use karstflow_storage::StakeHistoryRecord;

        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(1000);
        result
            .bank_state
            .as_mut()
            .unwrap()
            .stake_summary
            .stake_history = vec![StakeHistoryRecord {
            epoch: 10,
            effective: 500_000_000,
            activating: 0,
            deactivating: 0,
        }];
        result
            .bank_state
            .as_mut()
            .unwrap()
            .stake_summary
            .stake_history_entries = 1;

        let leader_schedule = make_leader_schedule();
        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule.clone()).unwrap();
        let root_bank = bootstrap.bank_forks.working_bank();

        // Child bank should inherit the stake history.
        let child = Bank::new_from_parent(&root_bank, 1001, leader_schedule);
        let child_history = child.stake_history().unwrap();
        let history = child_history.read().unwrap();
        assert_eq!(history.len(), 1);
        assert!(history.get(10).is_some());
    }

    // ── sysvar cache initialization tests ──────────────────────────────

    #[test]
    fn bootstrap_initializes_sysvar_cache() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        let bank = bootstrap.bank_forks.working_bank();

        // Sysvar cache should be attached.
        assert!(bank.sysvar_cache().is_some());

        let cache = bank.sysvar_cache().unwrap();
        let clock = cache.clock();
        assert_eq!(clock.slot, 1000);
        assert_eq!(clock.epoch, 0);
    }

    #[test]
    fn bootstrap_sysvar_cache_has_correct_epoch_schedule() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        let bank = bootstrap.bank_forks.working_bank();
        let cache = bank.sysvar_cache().unwrap();

        let epoch_schedule = cache.epoch_schedule();
        assert_eq!(epoch_schedule.config().slots_per_epoch, 432_000);
    }

    #[test]
    fn bootstrap_sysvar_cache_has_correct_rent() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        let bank = bootstrap.bank_forks.working_bank();
        let cache = bank.sysvar_cache().unwrap();

        let rent = cache.rent();
        assert_eq!(rent.lamports_per_byte_year, 3_480);
        assert!((rent.exemption_threshold - 2.0).abs() < f64::EPSILON);
    }

    // ── feature set initialization tests ──────────────────────────────

    /// Create feature account data for an activated feature.
    fn make_activated_feature_data(activation_slot: u64) -> Vec<u8> {
        let mut data = vec![1u8]; // Some tag
        data.extend_from_slice(&activation_slot.to_le_bytes());
        data
    }

    /// Create feature account data for a not-yet-activated feature.
    fn make_pending_feature_data() -> Vec<u8> {
        vec![0u8] // None tag
    }

    /// Insert a feature account into the database.
    fn insert_feature_account(db: &AccountDatabase, pubkey: Pubkey, data: Vec<u8>) {
        let account = Account {
            data: data.into(),
            meta: karstflow_storage::AccountMeta {
                lamports: 1,
                owner: FEATURE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(pubkey, account);
    }

    #[test]
    fn bootstrap_initializes_feature_set_empty() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.feature_init.feature_accounts_scanned, 0);
        assert_eq!(bootstrap.feature_init.features_activated, 0);
        assert_eq!(bootstrap.feature_init.unknown_features, 0);
        assert_eq!(bootstrap.feature_init.not_yet_activated, 0);

        // Feature set should be attached to the bank.
        let bank = bootstrap.bank_forks.working_bank();
        assert!(bank.feature_set().is_some());
    }

    #[test]
    fn bootstrap_activates_known_features() {
        use crate::features::known_features;

        let db = Arc::new(AccountDatabase::new());

        // Pick two known features and insert them as activated.
        let known = known_features::all_known_features();
        assert!(known.len() >= 2, "need at least 2 known features for test");

        let feat_a = known[0].feature_id;
        let feat_b = known[1].feature_id;

        insert_feature_account(&db, feat_a, make_activated_feature_data(100));
        insert_feature_account(&db, feat_b, make_activated_feature_data(200));

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.feature_init.feature_accounts_scanned, 2);
        assert_eq!(bootstrap.feature_init.features_activated, 2);
        assert_eq!(bootstrap.feature_init.unknown_features, 0);
        assert_eq!(bootstrap.feature_init.not_yet_activated, 0);

        // Verify features are active on the bank.
        let bank = bootstrap.bank_forks.working_bank();
        let fs_lock = bank.feature_set().unwrap();
        let fs = fs_lock.read().unwrap();
        assert!(fs.is_active(&feat_a));
        assert_eq!(fs.activated_slot(&feat_a), Some(100));
        assert!(fs.is_active(&feat_b));
        assert_eq!(fs.activated_slot(&feat_b), Some(200));
    }

    #[test]
    fn bootstrap_tracks_pending_features() {
        use crate::features::known_features;

        let db = Arc::new(AccountDatabase::new());

        let known = known_features::all_known_features();
        let feat = known[0].feature_id;

        // Insert a known feature that is NOT yet activated.
        insert_feature_account(&db, feat, make_pending_feature_data());

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.feature_init.feature_accounts_scanned, 1);
        assert_eq!(bootstrap.feature_init.features_activated, 0);
        assert_eq!(bootstrap.feature_init.not_yet_activated, 1);

        // Feature should NOT be active.
        let bank = bootstrap.bank_forks.working_bank();
        let fs_lock = bank.feature_set().unwrap();
        let fs = fs_lock.read().unwrap();
        assert!(!fs.is_active(&feat));
    }

    #[test]
    fn bootstrap_counts_unknown_features() {
        let db = Arc::new(AccountDatabase::new());

        // Insert a feature account with a pubkey that doesn't match any known feature.
        let unknown_pubkey = Pubkey::new_unique();
        insert_feature_account(&db, unknown_pubkey, make_activated_feature_data(50));

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.feature_init.feature_accounts_scanned, 1);
        assert_eq!(bootstrap.feature_init.features_activated, 0);
        assert_eq!(bootstrap.feature_init.unknown_features, 1);
    }

    #[test]
    fn bootstrap_feature_set_inherits_to_child() {
        use crate::features::known_features;

        let db = Arc::new(AccountDatabase::new());

        let known = known_features::all_known_features();
        let feat = known[0].feature_id;
        insert_feature_account(&db, feat, make_activated_feature_data(42));

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule.clone()).unwrap();
        let root_bank = bootstrap.bank_forks.working_bank();

        // Child bank should inherit the feature set.
        let child = Bank::new_from_parent(&root_bank, 1001, leader_schedule);
        let child_fs = child.feature_set().unwrap();
        let fs = child_fs.read().unwrap();
        assert!(fs.is_active(&feat));
        assert_eq!(fs.activated_slot(&feat), Some(42));
    }

    // ── bank hash verification tests ─────────────────────────────────

    #[test]
    fn bootstrap_returns_bank_hash_fields() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        // Expected hash from our test fixture is [0x11; 32].
        assert_eq!(bootstrap.expected_bank_hash, [0x11; 32]);
        // Computed hash will differ since our lthash is computed from empty DB.
        assert_ne!(bootstrap.computed_bank_hash, [0u8; 32]);
    }

    #[test]
    fn bootstrap_bank_hash_mismatch_reported() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        // With an empty DB and a non-matching fixture hash, verification should fail.
        assert!(!bootstrap.bank_hash_verified);
        assert_ne!(bootstrap.computed_bank_hash, bootstrap.expected_bank_hash);
    }

    #[test]
    fn bootstrap_bank_hash_matches_when_expected_matches_computed() {
        let db = Arc::new(AccountDatabase::new());
        let mut result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        // First bootstrap to get the actual computed hash.
        let first = bootstrap_from_snapshot(db.clone(), &result, leader_schedule.clone()).unwrap();
        let computed = first.computed_bank_hash;

        // Set the expected hash to match the computed one.
        result.bank_state.as_mut().unwrap().hash = computed;

        let second =
            bootstrap_from_snapshot(Arc::new(AccountDatabase::new()), &result, leader_schedule)
                .unwrap();
        assert!(second.bank_hash_verified);
        assert_eq!(second.computed_bank_hash, second.expected_bank_hash);
    }

    #[test]
    fn bootstrap_bank_hash_deterministic_across_runs() {
        let result = make_restore_result(1000);

        let db1 = Arc::new(AccountDatabase::new());
        let db2 = Arc::new(AccountDatabase::new());
        let ls1 = make_leader_schedule();
        let ls2 = make_leader_schedule();

        let b1 = bootstrap_from_snapshot(db1, &result, ls1).unwrap();
        let b2 = bootstrap_from_snapshot(db2, &result, ls2).unwrap();
        assert_eq!(b1.computed_bank_hash, b2.computed_bank_hash);
    }

    #[test]
    fn bootstrap_bank_hash_changes_with_different_accounts() {
        let result = make_restore_result(1000);

        let db1 = Arc::new(AccountDatabase::new());
        let db2 = Arc::new(AccountDatabase::new());

        // Add an account to db2 but not db1.
        let pubkey = Pubkey::new_unique();
        db2.store_published_account(
            pubkey,
            Account {
                data: vec![1, 2, 3].into(),
                meta: karstflow_storage::AccountMeta {
                    lamports: 1_000,
                    owner: Pubkey::new([0x11; 32]),
                    executable: false,
                    rent_epoch: 0,
                },
            },
        );

        let ls1 = make_leader_schedule();
        let ls2 = make_leader_schedule();

        let b1 = bootstrap_from_snapshot(db1, &result, ls1).unwrap();
        let b2 = bootstrap_from_snapshot(db2, &result, ls2).unwrap();
        assert_ne!(b1.computed_bank_hash, b2.computed_bank_hash);
    }

    // ── genesis bootstrap tests ───────────────────────────────────────

    fn make_genesis_config() -> GenesisConfig {
        GenesisConfig::default_development()
    }

    fn make_genesis_account(pubkey: Pubkey, lamports: u64) -> (Pubkey, GenesisAccount) {
        (
            pubkey,
            GenesisAccount {
                lamports,
                data: vec![],
                owner: Pubkey::new([0u8; 32]),
                executable: false,
                rent_epoch: 0,
            },
        )
    }

    use karstflow_storage::GenesisAccount;

    #[test]
    fn genesis_bootstrap_creates_bank_forks() {
        let genesis = make_genesis_config();
        let leader_schedule = make_leader_schedule();

        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.accounts_loaded, 0);
        assert_eq!(result.total_lamports, 0);
        assert_eq!(result.bank_forks.root_slot(), 0);
    }

    #[test]
    fn genesis_bootstrap_loads_accounts() {
        let mut genesis = make_genesis_config();
        genesis.accounts = vec![
            make_genesis_account(Pubkey::new_unique(), 1_000_000),
            make_genesis_account(Pubkey::new_unique(), 2_000_000),
            make_genesis_account(Pubkey::new_unique(), 3_000_000),
        ];

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.accounts_loaded, 3);
        assert_eq!(result.total_lamports, 6_000_000);
    }

    #[test]
    fn genesis_bootstrap_bank_at_slot_zero() {
        let genesis = make_genesis_config();
        let leader_schedule = make_leader_schedule();

        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        let bank = result.bank_forks.working_bank();
        assert_eq!(bank.slot(), 0);
        assert_eq!(bank.epoch(), 0);
        assert!(bank.parent_slot().is_none());
    }

    #[test]
    fn genesis_bootstrap_sets_capitalization() {
        let mut genesis = make_genesis_config();
        genesis.accounts = vec![
            make_genesis_account(Pubkey::new_unique(), 500_000_000),
            make_genesis_account(Pubkey::new_unique(), 500_000_000),
        ];

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        let bank = result.bank_forks.working_bank();
        assert_eq!(bank.capitalization(), 1_000_000_000);
    }

    #[test]
    fn genesis_bootstrap_computes_lthash() {
        let mut genesis = make_genesis_config();
        genesis.accounts = vec![
            make_genesis_account(Pubkey::new_unique(), 1_000_000),
            make_genesis_account(Pubkey::new_unique(), 2_000_000),
        ];

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.lthash_accounts, 2);

        // Bank hash should be non-zero (lthash contributes).
        let bank = result.bank_forks.working_bank();
        let hash = bank.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn genesis_bootstrap_lthash_deterministic() {
        let mut genesis = make_genesis_config();
        let pk = Pubkey::new([0x42; 32]);
        genesis.accounts = vec![(
            pk,
            GenesisAccount {
                lamports: 5_000_000,
                data: vec![1, 2, 3],
                owner: Pubkey::new([0x11; 32]),
                executable: false,
                rent_epoch: 0,
            },
        )];

        let ls1 = make_leader_schedule();
        let ls2 = make_leader_schedule();

        let r1 = bootstrap_from_genesis(&genesis, ls1);
        let r2 = bootstrap_from_genesis(&genesis, ls2);

        let hash1 = r1.bank_forks.working_bank().hash();
        let hash2 = r2.bank_forks.working_bank().hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn genesis_bootstrap_initializes_sysvar_cache() {
        let mut genesis = make_genesis_config();
        genesis.creation_time = 1_700_000_000;

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        let bank = result.bank_forks.working_bank();

        let cache = bank.sysvar_cache().unwrap();
        let clock = cache.clock();
        assert_eq!(clock.slot, 0);
        assert_eq!(clock.epoch, 0);
        assert_eq!(clock.unix_timestamp, 1_700_000_000);
        assert_eq!(clock.leader_schedule_epoch, 1);
    }

    #[test]
    fn genesis_bootstrap_initializes_stake_tracker_empty() {
        let genesis = make_genesis_config();
        let leader_schedule = make_leader_schedule();

        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.stake_init.delegations_loaded, 0);

        let bank = result.bank_forks.working_bank();
        assert!(bank.stake_tracker().is_some());
        assert!(bank.stake_history().is_some());

        // Stake history should be empty at genesis.
        let history = bank.stake_history().unwrap();
        assert_eq!(history.read().unwrap().len(), 0);
    }

    #[test]
    fn genesis_bootstrap_with_stake_accounts() {
        let mut genesis = make_genesis_config();
        let voter = Pubkey::new_unique();

        // Create a delegated stake account in genesis.
        let meta = Meta::new(
            2_282_880,
            Authorized::new(Pubkey::new_unique(), Pubkey::new_unique()),
            Lockup::default(),
        );
        let delegation = Delegation::new(voter, 5_000_000, 0);
        let stake = StakeAccount::new(delegation, 0);
        let state = StakeState::Delegated(meta, stake, Default::default());
        let stake_data = serialize_stake_state(&state);
        let stake_pubkey = Pubkey::new_unique();

        genesis.accounts.push((
            stake_pubkey,
            GenesisAccount {
                lamports: 5_000_000 + 2_282_880,
                data: stake_data,
                owner: STAKE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        ));

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.stake_init.stake_accounts_scanned, 1);
        assert_eq!(result.stake_init.delegations_loaded, 1);
        assert_eq!(result.stake_init.total_delegated_lamports, 5_000_000);
    }

    #[test]
    fn genesis_bootstrap_with_feature_accounts() {
        use crate::features::known_features;

        let mut genesis = make_genesis_config();
        let known = known_features::all_known_features();
        let feat = known[0].feature_id;

        // Add an activated feature account to genesis.
        genesis.accounts.push((
            feat,
            GenesisAccount {
                lamports: 1,
                data: make_activated_feature_data(0),
                owner: FEATURE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        ));

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        // Development genesis activates all known features at slot 0
        assert!(result.feature_init.features_activated >= 1);

        let bank = result.bank_forks.working_bank();
        let fs_lock = bank.feature_set().unwrap();
        let fs = fs_lock.read().unwrap();
        assert!(fs.is_active(&feat));
    }

    #[test]
    fn genesis_bootstrap_allows_child_creation() {
        let mut genesis = make_genesis_config();
        genesis.accounts = vec![make_genesis_account(Pubkey::new_unique(), 1_000_000)];

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule.clone());
        let root_bank = result.bank_forks.working_bank();

        let child = Bank::new_from_parent(&root_bank, 1, leader_schedule);
        assert_eq!(child.slot(), 1);
        assert_eq!(child.parent_slot(), Some(0));
    }

    #[test]
    fn genesis_bootstrap_uses_economic_config() {
        let mut genesis = make_genesis_config();
        genesis.rent.lamports_per_byte_year = 9999;
        genesis.rent.exemption_threshold = 3.5;

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        let bank = result.bank_forks.working_bank();

        let cache = bank.sysvar_cache().unwrap();
        let rent = cache.rent();
        assert_eq!(rent.lamports_per_byte_year, 9999);
        assert!((rent.exemption_threshold - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn genesis_bootstrap_includes_rewards_pool() {
        let mut genesis = make_genesis_config();
        genesis.accounts = vec![make_genesis_account(Pubkey::new_unique(), 1_000_000)];
        genesis.rewards_pool_accounts = vec![make_genesis_account(Pubkey::new_unique(), 500_000)];

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.accounts_loaded, 2);
        assert_eq!(result.total_lamports, 1_500_000);
    }

    // ── vote account cache initialization tests ─────────────────────────

    /// Build minimal serialized vote account data for bootstrap.
    fn make_vote_account_data(node_pubkey: &Pubkey, commission: u8, vote_slots: &[u64]) -> Vec<u8> {
        let mut data = Vec::new();
        // node_pubkey (32 bytes)
        data.extend_from_slice(node_pubkey.as_bytes());
        // authorized_voter (32 bytes)
        data.extend_from_slice(&[1u8; 32]);
        // authorized_withdrawer (32 bytes)
        data.extend_from_slice(&[2u8; 32]);
        // commission (1 byte)
        data.push(commission);
        // votes: count (u32 LE) + entries (slot:u64 + conf:u32 each)
        data.extend_from_slice(&(vote_slots.len() as u32).to_le_bytes());
        for (i, &slot) in vote_slots.iter().enumerate() {
            data.extend_from_slice(&slot.to_le_bytes());
            let conf = (vote_slots.len() - i) as u32;
            data.extend_from_slice(&conf.to_le_bytes());
        }
        // root_slot: None
        data.push(0);
        // epoch credits: count=0
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    /// Insert a vote account into the database.
    fn insert_vote_account(
        db: &AccountDatabase,
        vote_pubkey: &Pubkey,
        node_pubkey: &Pubkey,
        commission: u8,
        vote_slots: &[u64],
    ) {
        let data = make_vote_account_data(node_pubkey, commission, vote_slots);
        let account = Account {
            data: data.into(),
            meta: karstflow_storage::AccountMeta {
                lamports: 1_000_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(*vote_pubkey, account);
    }

    #[test]
    fn parse_vote_metadata_extracts_fields() {
        let node = Pubkey::new([0xAA; 32]);
        let data = make_vote_account_data(&node, 10, &[100, 200, 300]);
        let result = parse_vote_metadata(&data);
        assert!(result.is_some());
        let (parsed_node, commission, last_vote_slot) = result.unwrap();
        assert_eq!(parsed_node, node);
        assert_eq!(commission, 10);
        assert_eq!(last_vote_slot, 300);
    }

    #[test]
    fn parse_vote_metadata_zero_votes() {
        let node = Pubkey::new([0xBB; 32]);
        let data = make_vote_account_data(&node, 5, &[]);
        let result = parse_vote_metadata(&data);
        assert!(result.is_some());
        let (parsed_node, commission, last_vote_slot) = result.unwrap();
        assert_eq!(parsed_node, node);
        assert_eq!(commission, 5);
        assert_eq!(last_vote_slot, 0);
    }

    #[test]
    fn parse_vote_metadata_rejects_short_data() {
        let data = vec![0u8; 50]; // Too short
        assert!(parse_vote_metadata(&data).is_none());
    }

    #[test]
    fn bootstrap_initializes_vote_cache_empty() {
        let db = Arc::new(AccountDatabase::new());
        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.vote_init.vote_accounts_scanned, 0);
        assert_eq!(bootstrap.vote_init.vote_accounts_loaded, 0);
        assert_eq!(bootstrap.vote_init.parse_errors, 0);

        // Vote account cache should be attached to the bank.
        let bank = bootstrap.bank_forks.working_bank();
        assert!(bank.vote_account_cache().is_some());
        let cache_lock = bank.vote_account_cache().unwrap();
        let cache = cache_lock.read().unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn bootstrap_loads_vote_accounts_into_cache() {
        let db = Arc::new(AccountDatabase::new());
        let vote_a = Pubkey::new_unique();
        let vote_b = Pubkey::new_unique();
        let node_a = Pubkey::new_unique();
        let node_b = Pubkey::new_unique();

        insert_vote_account(&db, &vote_a, &node_a, 8, &[100, 200, 300]);
        insert_vote_account(&db, &vote_b, &node_b, 10, &[150, 250]);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.vote_init.vote_accounts_scanned, 2);
        assert_eq!(bootstrap.vote_init.vote_accounts_loaded, 2);
        assert_eq!(bootstrap.vote_init.parse_errors, 0);

        // Verify cache contents.
        let bank = bootstrap.bank_forks.working_bank();
        let cache_lock = bank.vote_account_cache().unwrap();
        let cache = cache_lock.read().unwrap();
        assert_eq!(cache.len(), 2);

        let entry_a = cache.get(&vote_a).unwrap();
        assert_eq!(entry_a.node_pubkey, node_a);
        assert_eq!(entry_a.commission, 8);
        assert_eq!(entry_a.last_vote_slot, 300);

        let entry_b = cache.get(&vote_b).unwrap();
        assert_eq!(entry_b.node_pubkey, node_b);
        assert_eq!(entry_b.commission, 10);
        assert_eq!(entry_b.last_vote_slot, 250);
    }

    #[test]
    fn bootstrap_counts_vote_parse_errors() {
        let db = Arc::new(AccountDatabase::new());

        // Insert a valid vote account.
        let vote_ok = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        insert_vote_account(&db, &vote_ok, &node, 5, &[100]);

        // Insert an invalid vote-program-owned account.
        let vote_bad = Pubkey::new_unique();
        let account = Account {
            data: vec![0xFF; 50].into(), // Too short to be valid
            meta: karstflow_storage::AccountMeta {
                lamports: 1_000_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        };
        db.store_published_account(vote_bad, account);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule).unwrap();
        assert_eq!(bootstrap.vote_init.vote_accounts_scanned, 2);
        assert_eq!(bootstrap.vote_init.vote_accounts_loaded, 1);
        assert_eq!(bootstrap.vote_init.parse_errors, 1);
    }

    #[test]
    fn bootstrap_vote_cache_inherits_to_child() {
        let db = Arc::new(AccountDatabase::new());
        let vote = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        insert_vote_account(&db, &vote, &node, 7, &[500]);

        let result = make_restore_result(1000);
        let leader_schedule = make_leader_schedule();

        let bootstrap = bootstrap_from_snapshot(db, &result, leader_schedule.clone()).unwrap();
        let root_bank = bootstrap.bank_forks.working_bank();

        // Child bank should inherit the vote account cache.
        let child = Bank::new_from_parent(&root_bank, 1001, leader_schedule);
        let child_cache = child.vote_account_cache().unwrap();
        let cache = child_cache.read().unwrap();
        assert_eq!(cache.len(), 1);
        let entry = cache.get(&vote).unwrap();
        assert_eq!(entry.node_pubkey, node);
        assert_eq!(entry.commission, 7);
    }

    #[test]
    fn genesis_bootstrap_initializes_vote_cache_empty() {
        let genesis = make_genesis_config();
        let leader_schedule = make_leader_schedule();

        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.vote_init.vote_accounts_scanned, 0);
        assert_eq!(result.vote_init.vote_accounts_loaded, 0);

        let bank = result.bank_forks.working_bank();
        assert!(bank.vote_account_cache().is_some());
    }

    #[test]
    fn genesis_bootstrap_with_vote_accounts() {
        let mut genesis = make_genesis_config();
        let vote_pubkey = Pubkey::new_unique();
        let node_pubkey = Pubkey::new_unique();
        let vote_data = make_vote_account_data(&node_pubkey, 12, &[0]);

        genesis.accounts.push((
            vote_pubkey,
            GenesisAccount {
                lamports: 1_000_000,
                data: vote_data,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        ));

        let leader_schedule = make_leader_schedule();
        let result = bootstrap_from_genesis(&genesis, leader_schedule);
        assert_eq!(result.vote_init.vote_accounts_scanned, 1);
        assert_eq!(result.vote_init.vote_accounts_loaded, 1);

        let bank = result.bank_forks.working_bank();
        let cache_lock = bank.vote_account_cache().unwrap();
        let cache = cache_lock.read().unwrap();
        assert_eq!(cache.len(), 1);
        let entry = cache.get(&vote_pubkey).unwrap();
        assert_eq!(entry.node_pubkey, node_pubkey);
        assert_eq!(entry.commission, 12);
        assert_eq!(entry.last_vote_slot, 0);
    }

    #[test]
    fn collect_validator_stakes_from_accounts() {
        let accounts = AccountDatabase::new();
        let node_a = Pubkey::new_unique();
        let node_b = Pubkey::new_unique();
        let vote_a = Pubkey::new_unique();
        let vote_b = Pubkey::new_unique();

        // Create two vote accounts (node_a at vote_a, node_b at vote_b).
        fn make_vote_data(node: &Pubkey, commission: u8) -> Vec<u8> {
            let mut data = vec![0u8; 101];
            data[..32].copy_from_slice(node.as_ref());
            data[96] = commission;
            // zero votes (u32 at 97..101 already zeroed)
            data
        }
        accounts.store_published_account(
            vote_a,
            Account::new(1_000_000, make_vote_data(&node_a, 10), VOTE_PROGRAM_ID),
        );
        accounts.store_published_account(
            vote_b,
            Account::new(1_000_000, make_vote_data(&node_b, 5), VOTE_PROGRAM_ID),
        );

        // Create stake delegations: 3M to vote_a, 7M to vote_b.
        let meta = Meta::new(
            2_282_880,
            Authorized::new(Pubkey::new_unique(), Pubkey::new_unique()),
            Lockup::default(),
        );
        let stake_a = StakeAccount::new(Delegation::new(vote_a, 3_000_000, 0), 0);
        let data_a = serialize_stake_state(&StakeState::Delegated(
            meta.clone(),
            stake_a,
            Default::default(),
        ));
        accounts.store_published_account(
            Pubkey::new_unique(),
            Account::new(3_000_000 + 2_282_880, data_a, STAKE_PROGRAM_ID),
        );

        let stake_b = StakeAccount::new(Delegation::new(vote_b, 7_000_000, 0), 0);
        let data_b =
            serialize_stake_state(&StakeState::Delegated(meta, stake_b, Default::default()));
        accounts.store_published_account(
            Pubkey::new_unique(),
            Account::new(7_000_000 + 2_282_880, data_b, STAKE_PROGRAM_ID),
        );

        let stakes = collect_validator_stakes(&accounts);
        assert_eq!(stakes.len(), 2);
        // Sorted descending by stake.
        assert_eq!(stakes[0], (node_b, 7_000_000));
        assert_eq!(stakes[1], (node_a, 3_000_000));
    }

    #[test]
    fn collect_validator_stakes_empty_when_no_delegations() {
        let accounts = AccountDatabase::new();
        let stakes = collect_validator_stakes(&accounts);
        assert!(stakes.is_empty());
    }
}
