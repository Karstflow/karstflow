use crate::bootstrap::{
    build_consensus_infrastructure, resolve_validator_identity, save_tower_to_disk,
    start_gossip_service,
};
use karstflow_config::NodeConfig;
use std::sync::{Arc, Mutex};

/// Guard for tests that modify process-global environment variables.
/// `std::env::set_var` is not thread-safe, so tests touching env vars
/// must hold this lock to avoid contaminating parallel tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn build_consensus_infrastructure_creates_all_components() {
    let consensus = build_consensus_infrastructure(1_000_000, None, None).unwrap();
    let forks = consensus.bank_forks.read().unwrap();
    assert_eq!(forks.root_slot(), 0);
    assert!(consensus.storage_engine.is_none());
}

#[test]
fn build_consensus_with_storage_engine() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let consensus = build_consensus_infrastructure(1_000_000, Some(dir.path()), None).unwrap();
    assert!(consensus.storage_engine.is_some());

    let forks = consensus.bank_forks.read().unwrap();
    assert_eq!(forks.root_slot(), 0);
}

#[test]
fn build_consensus_from_bank_forks_uses_real_stake() {
    use crate::bootstrap::build_consensus_from_bank_forks;
    use karstflow_consensus::{
        Bank, BankForks, Delegation, EpochSchedule, LeaderSchedule, StakeTracker,
    };
    use karstflow_storage::{AccountDatabase, Pubkey};
    use std::sync::RwLock;

    let voter_a = Pubkey::new_unique();
    let voter_b = Pubkey::new_unique();

    let db = Arc::new(AccountDatabase::new());
    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = Pubkey::new_unique();
    let ls = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
    let mut bank = Bank::new_genesis(db, epoch_schedule, ls);

    let mut tracker = StakeTracker::new(10);
    let stake_a = Pubkey::new_unique();
    let stake_b = Pubkey::new_unique();
    tracker.add_delegation(stake_a, Delegation::new(voter_a, 5_000_000, 0));
    tracker.add_delegation(stake_b, Delegation::new(voter_b, 3_000_000, 0));
    assert_eq!(tracker.total_stake(), 8_000_000);

    bank.set_stake_tracker(Arc::new(RwLock::new(tracker)));
    let bank_forks = BankForks::new(bank);

    let consensus = build_consensus_from_bank_forks(bank_forks, None, None, None, None);

    let fork_choice = consensus.fork_choice.lock().unwrap();
    assert_eq!(fork_choice.stats().total_stake, 8_000_000);
    drop(fork_choice);

    let vp = consensus.vote_processor.lock().unwrap();
    assert_eq!(vp.total_stake(), 8_000_000);
}

#[test]
fn build_consensus_from_bank_forks_handles_empty_stake() {
    use crate::bootstrap::build_consensus_from_bank_forks;
    use karstflow_consensus::{Bank, BankForks, EpochSchedule, LeaderSchedule};
    use karstflow_storage::{AccountDatabase, Pubkey};

    let db = Arc::new(AccountDatabase::new());
    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = Pubkey::new_unique();
    let ls = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
    let bank = Bank::new_genesis(db, epoch_schedule, ls);
    let bank_forks = BankForks::new(bank);

    let consensus = build_consensus_from_bank_forks(bank_forks, None, None, None, None);
    let fork_choice = consensus.fork_choice.lock().unwrap();
    assert_eq!(fork_choice.stats().total_stake, 1);
}

#[test]
fn tower_loaded_from_disk_on_startup() {
    use karstflow_consensus::{SavedTower, Tower};
    use karstflow_storage::Pubkey;

    let dir = tempfile::tempdir().expect("tmpdir");
    let identity = Pubkey::new_unique();

    let mut tower = Tower::new();
    tower.push_vote(10);
    tower.push_vote(11);
    tower.push_vote(12);
    let saved = SavedTower::from_tower(&tower, identity);
    saved.save_to_directory(dir.path()).unwrap();

    let consensus =
        build_consensus_infrastructure(1_000_000, Some(dir.path()), Some(identity.as_bytes()))
            .unwrap();

    let loaded = consensus.tower.read().unwrap();
    assert_eq!(loaded.last_vote_slot(), Some(12));
    assert_eq!(loaded.votes().len(), 3);
}

#[test]
fn tower_starts_fresh_without_data_dir() {
    let consensus = build_consensus_infrastructure(1_000_000, None, None).unwrap();
    let tower = consensus.tower.read().unwrap();
    assert_eq!(tower.last_vote_slot(), None);
    assert!(tower.votes().is_empty());
}

#[test]
fn save_tower_to_disk_roundtrip() {
    use karstflow_consensus::{SavedTower, Tower};
    use karstflow_storage::Pubkey;

    let dir = tempfile::tempdir().expect("tmpdir");
    let identity = Pubkey::new_unique();

    let mut tower = Tower::new();
    tower.push_vote(100);
    tower.push_vote(101);

    save_tower_to_disk(&tower, dir.path(), &identity).unwrap();

    let saved = SavedTower::load_and_verify(dir.path(), &identity).unwrap();
    let restored = saved.to_tower();
    assert_eq!(restored.last_vote_slot(), Some(101));
    assert_eq!(restored.votes().len(), 2);
}

#[test]
fn start_gossip_service_creates_handle_with_cluster_info() {
    let _guard = ENV_LOCK.lock().unwrap();
    // Use port 0 so the OS assigns a free ephemeral port — avoids conflicts under parallel tests.
    std::env::set_var("KARSTFLOW_GOSSIP_BIND_ADDR", "127.0.0.1:0");
    let node_config = NodeConfig::from_profile(None).unwrap();
    std::env::remove_var("KARSTFLOW_GOSSIP_BIND_ADDR");
    let identity = resolve_validator_identity(&node_config).unwrap();
    let handle = start_gossip_service(&node_config, &identity).unwrap();
    assert_eq!(handle.cluster_info.size(), 0);
    drop(handle);
}

#[test]
fn gossip_node_id_matches_identity_pubkey() {
    let _guard = ENV_LOCK.lock().unwrap();
    // Use port 0 so the OS assigns a free ephemeral port — avoids conflicts under parallel tests.
    std::env::set_var("KARSTFLOW_GOSSIP_BIND_ADDR", "127.0.0.1:0");
    let node_config = NodeConfig::from_profile(None).unwrap();
    std::env::remove_var("KARSTFLOW_GOSSIP_BIND_ADDR");
    let identity = resolve_validator_identity(&node_config).unwrap();
    let handle = start_gossip_service(&node_config, &identity).unwrap();
    assert_eq!(&handle.node_id.0, identity.pubkey());
    drop(handle);
}

#[test]
fn restore_from_snapshot_archive_returns_error_for_missing_file() {
    use crate::bootstrap::restore_from_snapshot_archive;
    use crate::errors::ControlPlaneError;
    use std::path::Path;

    let result = restore_from_snapshot_archive(
        Path::new("/nonexistent/snapshot-123456.tar.zst"),
        None,
        None,
        None,
    );
    match result {
        Err(ControlPlaneError::Bootstrap { message }) => {
            assert!(
                message.contains("failed to open snapshot archive"),
                "unexpected error: {message}"
            );
        }
        Err(e) => panic!("expected Bootstrap error, got: {e:?}"),
        Ok(_) => panic!("expected error for missing file, got Ok"),
    }
}

#[test]
fn bootstrap_from_genesis_file_multi_validator_builds_leader_schedule() {
    use crate::bootstrap::bootstrap_from_genesis_file;
    use karstflow_crypto::ed25519_batch::generate_keypair;
    use karstflow_ids::SYSTEM_PROGRAM_ID;
    use karstflow_storage::{
        genesis::{serialize_genesis, GenesisAccount, GenesisConfig},
        Pubkey,
    };

    let dir = tempfile::tempdir().expect("tmpdir");
    let genesis_path = dir.path().join("genesis.bin");

    // Create a 3-validator genesis.
    let mut genesis = GenesisConfig::default_development();
    let mut pubkeys = Vec::new();
    for _ in 0..3 {
        let (_, pubkey_bytes) = generate_keypair();
        let pk = Pubkey::new(pubkey_bytes);
        pubkeys.push(pk);
        genesis.accounts.push((
            pk,
            GenesisAccount {
                lamports: 500_000_000_000,
                data: Vec::new(),
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: u64::MAX,
            },
        ));
    }
    genesis.initial_validators = pubkeys.iter().map(|pk| (*pk, 1_000_000_000)).collect();

    let bytes = serialize_genesis(&genesis).expect("serialize");
    std::fs::write(&genesis_path, &bytes).expect("write");

    // Each node bootstraps with its own identity but should see all 3 validators.
    let bundle = bootstrap_from_genesis_file(&genesis_path, None, Some(&pubkeys[0])).unwrap();
    let forks = bundle.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    // Stake tracker should have all 3 validators.
    if let Some(tracker_arc) = bank.stake_tracker() {
        let tracker = tracker_arc.read().unwrap();
        assert_eq!(tracker.delegation_count(), 3, "should have 3 stake entries");
        assert_eq!(
            tracker.total_stake(),
            3 * 1_000_000_000,
            "total stake should be 3B lamports"
        );
    } else {
        panic!("stake tracker not set after multi-validator genesis bootstrap");
    }
}

#[test]
fn build_consensus_from_bank_forks_seeds_vote_accounts() {
    use crate::bootstrap::build_consensus_from_bank_forks;
    use karstflow_consensus::{Bank, BankForks, EpochSchedule, LeaderSchedule, VoteAccountCache};
    use karstflow_storage::{AccountDatabase, Pubkey};
    use std::sync::RwLock;

    let node_a = Pubkey::new_unique();
    let node_b = Pubkey::new_unique();
    let vote_a = Pubkey::new_unique();
    let vote_b = Pubkey::new_unique();

    let db = Arc::new(AccountDatabase::new());
    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = Pubkey::new_unique();
    let ls = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
    let mut bank = Bank::new_genesis(db, epoch_schedule, ls);

    // Populate the vote account cache on the bank.
    let mut cache = VoteAccountCache::new();
    cache.update_from_vote_state(vote_a, node_a, 5, 0, 0);
    cache.update_from_vote_state(vote_b, node_b, 10, 0, 0);
    bank.set_vote_account_cache(Arc::new(RwLock::new(cache)));

    let bank_forks = BankForks::new(bank);
    let consensus = build_consensus_from_bank_forks(bank_forks, None, None, None, None);

    let vp = consensus.vote_processor.lock().unwrap();

    // Vote accounts should be registered.
    assert!(
        vp.get_vote_state(&vote_a).is_some(),
        "vote_a not registered"
    );
    assert!(
        vp.get_vote_state(&vote_b).is_some(),
        "vote_b not registered"
    );

    // Reverse lookup: node identity → vote account should work.
    assert_eq!(
        vp.vote_account_for_node_identity(&node_a),
        Some(vote_a),
        "node_a → vote_a mapping missing",
    );
    assert_eq!(
        vp.vote_account_for_node_identity(&node_b),
        Some(vote_b),
        "node_b → vote_b mapping missing",
    );

    // Commission should be preserved.
    assert_eq!(vp.get_vote_state(&vote_a).unwrap().commission, 5);
    assert_eq!(vp.get_vote_state(&vote_b).unwrap().commission, 10);
}

#[test]
fn build_consensus_from_bank_forks_no_cache_still_works() {
    use crate::bootstrap::build_consensus_from_bank_forks;
    use karstflow_consensus::{Bank, BankForks, EpochSchedule, LeaderSchedule};
    use karstflow_storage::{AccountDatabase, Pubkey};

    let db = Arc::new(AccountDatabase::new());
    let epoch_schedule = Arc::new(EpochSchedule::default());
    let validator = Pubkey::new_unique();
    let ls = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
    let bank = Bank::new_genesis(db, epoch_schedule, ls);
    let bank_forks = BankForks::new(bank);

    // No vote account cache set — should still build without panic.
    let consensus = build_consensus_from_bank_forks(bank_forks, None, None, None, None);
    let vp = consensus.vote_processor.lock().unwrap();
    assert_eq!(
        vp.vote_account_for_node_identity(&Pubkey::new_unique()),
        None
    );
}

#[test]
fn build_replay_service_with_consensus_creates_service() {
    use crate::bootstrap::build_replay_service_with_consensus;
    use karstflow_mesh::{bounded_link, DualReceiver};
    use karstflow_stages::ReplayServiceConfig;

    let consensus = build_consensus_infrastructure(1_000_000, None, None).unwrap();
    let (_tx, rx) = bounded_link::<karstflow_stages::AssembledBlock>(16);

    let bundle = build_replay_service_with_consensus(
        ReplayServiceConfig::default(),
        DualReceiver::Channel(rx),
        consensus,
        None,
    );
    assert_eq!(bundle.service.name(), "replay-service");
}

#[test]
fn development_genesis_installs_core_programs_as_two_accounts() {
    // The unit tests on `genesis_program_accounts` prove the pair is built
    // correctly. This proves it survives installation: the bank must hold both
    // accounts, and following the pointer from the one the runtime dispatches
    // must reach the account holding the bytecode.
    use crate::bootstrap::bootstrap_from_development_genesis;
    use crate::program_binaries::programdata_address;
    use karstflow_sbpf::UpgradeableLoaderState;

    let bundle = bootstrap_from_development_genesis(None, None).unwrap();
    let forks = bundle.bank_forks.read().unwrap();
    let bank = forks.working_bank();

    for program_id in [
        karstflow_ids::ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
        karstflow_ids::CONFIG_PROGRAM_ID,
        karstflow_ids::FEATURE_PROGRAM_ID,
    ] {
        let program = bank
            .accounts()
            .get_published_account(&program_id)
            .unwrap_or_else(|| panic!("program account {program_id} missing from genesis"));

        let state = UpgradeableLoaderState::deserialize(program.data.as_slice())
            .unwrap_or_else(|e| panic!("program {program_id} is not a Program state: {e}"));
        let UpgradeableLoaderState::Program {
            programdata_address: pointer,
        } = state
        else {
            panic!("program {program_id} holds {state:?}, not a pointer");
        };
        assert_eq!(pointer, programdata_address(&program_id));

        let programdata = bank
            .accounts()
            .get_published_account(&pointer)
            .unwrap_or_else(|| panic!("programdata account for {program_id} missing"));
        assert!(
            programdata.data.as_slice().len()
                > karstflow_constants::bpf_loader_program::SIZE_OF_PROGRAMDATA_METADATA,
            "programdata for {program_id} carries no bytecode"
        );
    }
}
