//! End-to-end snapshot bootstrap pipeline.
//!
//! Combines the snapshot restore result with Bank initialization,
//! transaction cache seeding, and BankForks creation into a single
//! orchestrated flow.

use crate::bank::Bank;
use crate::bank_forks::{BankForks, BankForksError};
use crate::clock::Clock;
use crate::epoch_schedule::EpochScheduleConfig;
use crate::rent::Rent;
use crate::stake::{deserialize_stake_state, StakeState};
use crate::stake_history::{StakeHistory, StakeHistoryEntry};
use crate::sysvars::SysvarCache;
use crate::transaction_cache::SeedEntry;
use crate::{EpochSchedule, LeaderSchedule, StakeTracker};
use paradencer_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES;
use paradencer_ids::STAKE_PROGRAM_ID;
use paradencer_storage::{AccountDatabase, RestoreResult, SnapshotBankState, StatusCacheEntry};
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
    /// Number of accounts included in the lattice hash computation.
    pub lthash_accounts: usize,
    /// Number of stake history epochs loaded.
    pub stake_history_entries: usize,
    /// Snapshot slot number.
    pub slot: u64,
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
/// This function performs the complete initialization sequence:
/// 1. Constructs a `Bank` from the snapshot bank state
/// 2. Computes the cumulative lattice hash from all restored accounts
/// 3. Initializes stake tracker from restored accounts
/// 4. Loads stake history from the snapshot for warmup/cooldown
/// 5. Initializes the sysvar cache (clock, epoch schedule, rent)
/// 6. Seeds the transaction cache from the status cache
/// 7. Wraps in `BankForks` as the root bank
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

    // Step 4: Initialize stake history from snapshot.
    let stake_history = initialize_stake_history(&bank_state.stake_summary);
    let stake_history_entries = stake_history.len();
    bank.set_stake_history(Arc::new(RwLock::new(stake_history)));

    // Step 5: Initialize sysvar cache from snapshot state.
    let sysvar_cache = initialize_sysvar_cache(bank_state);
    bank.set_sysvar_cache(Arc::new(sysvar_cache));

    // Step 6: Seed transaction cache from status cache.
    let transactions_seeded = if let Some(status_cache) = &restore_result.status_cache {
        let seed_entries = status_cache.entries.iter().map(convert_status_cache_entry);
        bank.seed_transaction_cache(seed_entries)
    } else {
        0
    };

    // Step 7: Wrap in BankForks.
    let bank_forks = BankForks::new_from_snapshot(bank)?;

    Ok(BootstrapResult {
        bank_forks,
        accounts_loaded: restore_result.accounts_loaded,
        total_lamports: restore_result.total_lamports,
        transactions_seeded,
        stake_init,
        lthash_accounts,
        stake_history_entries,
        slot: restore_result.slot,
    })
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

/// Initialize the sysvar cache from snapshot bank state.
///
/// Creates a SysvarCache populated with clock, epoch schedule, and rent
/// values derived from the snapshot manifest.
fn initialize_sysvar_cache(bank_state: &SnapshotBankState) -> SysvarCache {
    let clock = Clock {
        slot: bank_state.slot,
        epoch_start_timestamp: bank_state.genesis_creation_time,
        epoch: bank_state.epoch,
        leader_schedule_epoch: bank_state.epoch.saturating_add(1),
        unix_timestamp: bank_state.genesis_creation_time,
    };

    let epoch_schedule = EpochSchedule::new(EpochScheduleConfig {
        slots_per_epoch: bank_state.epoch_schedule.slots_per_epoch,
        leader_schedule_slot_offset: bank_state.epoch_schedule.leader_schedule_slot_offset,
        warmup: bank_state.epoch_schedule.warmup,
        first_normal_epoch: bank_state.epoch_schedule.first_normal_epoch,
        first_normal_slot: bank_state.epoch_schedule.first_normal_slot,
    });

    let rent = Rent {
        lamports_per_byte_year: bank_state.rent.lamports_per_byte_year,
        exemption_threshold: bank_state.rent.exemption_threshold,
        burn_percent: bank_state.rent.burn_percent,
    };

    SysvarCache::new(clock, epoch_schedule, rent)
}

/// Build stake history from snapshot's parsed stake summary.
///
/// Converts the raw stake history records from the snapshot manifest into
/// the consensus-layer StakeHistory used for warmup/cooldown calculations.
fn initialize_stake_history(summary: &paradencer_storage::StakeSummary) -> StakeHistory {
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
    use paradencer_storage::{
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
            meta: paradencer_storage::AccountMeta {
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
            meta: paradencer_storage::AccountMeta {
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
            meta: paradencer_storage::AccountMeta {
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
                meta: paradencer_storage::AccountMeta {
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
                meta: paradencer_storage::AccountMeta {
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
                meta: paradencer_storage::AccountMeta {
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
                meta: paradencer_storage::AccountMeta {
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
            meta: paradencer_storage::AccountMeta {
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
            meta: paradencer_storage::AccountMeta {
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
        use paradencer_storage::StakeHistoryRecord;

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
        use paradencer_storage::StakeHistoryRecord;

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
}
