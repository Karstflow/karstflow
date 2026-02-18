//! End-to-end snapshot bootstrap pipeline.
//!
//! Combines the snapshot restore result with Bank initialization,
//! transaction cache seeding, and BankForks creation into a single
//! orchestrated flow.

use crate::bank::Bank;
use crate::bank_forks::{BankForks, BankForksError};
use crate::transaction_cache::SeedEntry;
use crate::LeaderSchedule;
use paradencer_constants::block_limits::MESSAGE_HASH_PREFIX_BYTES;
use paradencer_storage::{AccountDatabase, RestoreResult, StatusCacheEntry};
use std::sync::Arc;

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
    /// Snapshot slot number.
    pub slot: u64,
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
/// 2. Seeds the transaction cache from the status cache
/// 3. Wraps in `BankForks` as the root bank
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
    let bank = Bank::new_from_snapshot(accounts, bank_state, leader_schedule);

    // Step 2: Seed transaction cache from status cache.
    let transactions_seeded = if let Some(status_cache) = &restore_result.status_cache {
        let seed_entries = status_cache.entries.iter().map(convert_status_cache_entry);
        bank.seed_transaction_cache(seed_entries)
    } else {
        0
    };

    // Step 3: Wrap in BankForks.
    let bank_forks = BankForks::new_from_snapshot(bank)?;

    Ok(BootstrapResult {
        bank_forks,
        accounts_loaded: restore_result.accounts_loaded,
        total_lamports: restore_result.total_lamports,
        transactions_seeded,
        slot: restore_result.slot,
    })
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
    use paradencer_storage::{
        EpochScheduleConfig, FeeRateConfig, InflationConfig, Pubkey, RentConfig, SnapshotBankState,
        StakeSummary, StatusCacheParseResult,
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
}
