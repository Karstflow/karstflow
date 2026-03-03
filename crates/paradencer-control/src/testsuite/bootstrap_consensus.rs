use crate::bootstrap::{
    build_consensus_infrastructure, resolve_validator_identity, save_tower_to_disk,
    start_gossip_service,
};
use paradencer_config::NodeConfig;
use std::sync::Arc;

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
    use paradencer_consensus::{
        Bank, BankForks, Delegation, EpochSchedule, LeaderSchedule, StakeTracker,
    };
    use paradencer_storage::{AccountDatabase, Pubkey};
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
    use paradencer_consensus::{Bank, BankForks, EpochSchedule, LeaderSchedule};
    use paradencer_storage::{AccountDatabase, Pubkey};

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
    use paradencer_consensus::{SavedTower, Tower};
    use paradencer_storage::Pubkey;

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
    use paradencer_consensus::{SavedTower, Tower};
    use paradencer_storage::Pubkey;

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
    // Use port 0 so the OS assigns a free ephemeral port — avoids conflicts under parallel tests.
    std::env::set_var("PARADENCER_GOSSIP_BIND_ADDR", "127.0.0.1:0");
    let node_config = NodeConfig::from_profile(None).unwrap();
    std::env::remove_var("PARADENCER_GOSSIP_BIND_ADDR");
    let identity = resolve_validator_identity(&node_config).unwrap();
    let handle = start_gossip_service(&node_config, &identity).unwrap();
    assert_eq!(handle.cluster_info.size(), 0);
    drop(handle);
}

#[test]
fn gossip_node_id_matches_identity_pubkey() {
    // Use port 0 so the OS assigns a free ephemeral port — avoids conflicts under parallel tests.
    std::env::set_var("PARADENCER_GOSSIP_BIND_ADDR", "127.0.0.1:0");
    let node_config = NodeConfig::from_profile(None).unwrap();
    std::env::remove_var("PARADENCER_GOSSIP_BIND_ADDR");
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
fn build_replay_service_with_consensus_creates_service() {
    use crate::bootstrap::build_replay_service_with_consensus;
    use paradencer_mesh::{bounded_link, DualReceiver};
    use paradencer_stages::ReplayServiceConfig;

    let consensus = build_consensus_infrastructure(1_000_000, None, None).unwrap();
    let (_tx, rx) = bounded_link::<paradencer_stages::AssembledBlock>(16);

    let bundle = build_replay_service_with_consensus(
        ReplayServiceConfig::default(),
        DualReceiver::Channel(rx),
        consensus,
        None,
    );
    assert_eq!(bundle.service.name(), "replay-service");
}
