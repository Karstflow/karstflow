use crate::accounts::database::AccountDatabase;
use crate::accounts::primitives::{Account, AccountData, AccountMeta, Pubkey};
use crate::catalog::SnapshotCatalog;
use crate::snapshot::{
    CompressionType, SnapshotConfig, SnapshotCreator, SnapshotLoader, SnapshotMetadata,
};
use std::collections::HashMap;

fn create_test_account(lamports: u64, data_size: usize) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(vec![0u8; data_size]),
    }
}

fn setup_test_database(account_count: usize) -> AccountDatabase {
    let db = AccountDatabase::with_capacity(account_count);
    let mut accounts = HashMap::new();

    for i in 0..account_count {
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        let account = create_test_account(1000 * (i as u64 + 1), 100 + i * 10);
        accounts.insert(pubkey, account);
    }

    db.bulk_insert_published_accounts(accounts).unwrap();
    db
}

#[test]
fn test_snapshot_metadata_creation() {
    let metadata = SnapshotMetadata::new(
        100,
        1000,
        5000000,
        None,
        CompressionType::Zstd,
        10000,
    );

    assert_eq!(metadata.slot, 100);
    assert_eq!(metadata.total_accounts, 1000);
    assert_eq!(metadata.total_lamports, 5000000);
    assert!(metadata.is_full());
    assert!(!metadata.is_incremental());
    assert_eq!(metadata.compression, CompressionType::Zstd);
}

#[test]
fn test_incremental_metadata() {
    let metadata = SnapshotMetadata::new(
        200,
        500,
        2500000,
        Some(100),
        CompressionType::Zstd,
        5000,
    );

    assert_eq!(metadata.slot, 200);
    assert_eq!(metadata.incremental_base, Some(100));
    assert!(metadata.is_incremental());
    assert!(!metadata.is_full());
}

#[test]
fn test_snapshot_config_builder() {
    let config = SnapshotConfig::new()
        .with_full_interval(5000)
        .with_incremental_interval(500)
        .with_max_full_snapshots(5)
        .with_compression_level(5);

    assert_eq!(config.full_snapshot_interval, 5000);
    assert_eq!(config.incremental_snapshot_interval, 500);
    assert_eq!(config.max_full_snapshots, 5);
    assert_eq!(config.compression_level, 5);
}

#[test]
fn test_full_snapshot_creation_and_restoration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(100);
    let original_accounts = db.get_all_published_accounts();
    let original_lamports = db.get_total_lamports();

    let config = SnapshotConfig::new();
    let creator = SnapshotCreator::new(config);

    let manifest = creator.create_full_snapshot(&db, 100, snapshot_dir).unwrap();

    assert_eq!(manifest.metadata.slot, 100);
    assert_eq!(manifest.metadata.total_accounts, 100);
    assert!(manifest.metadata.is_full());
    assert_eq!(manifest.chunk_count, 1);

    let new_db = AccountDatabase::new();
    let loader = SnapshotLoader::new();

    let snapshot_path = snapshot_dir.join("full-100.snapshot");
    let manifest_path = snapshot_dir.join("full-100.snapshot.manifest");

    let (loaded_accounts, metadata) = loader
        .load_snapshot_to_map(&snapshot_path, &manifest_path)
        .unwrap();

    new_db.bulk_insert_published_accounts(loaded_accounts).unwrap();

    let restored_accounts = new_db.get_all_published_accounts();
    let restored_lamports = new_db.get_total_lamports();

    assert_eq!(original_accounts.len(), restored_accounts.len());
    assert_eq!(original_lamports, restored_lamports);
    assert_eq!(metadata.slot, 100);
}

#[test]
fn test_incremental_snapshot() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(100);

    let config = SnapshotConfig::new();
    let creator = SnapshotCreator::new(config);

    let full_manifest = creator.create_full_snapshot(&db, 100, snapshot_dir).unwrap();
    assert!(full_manifest.metadata.is_full());

    let mut base_accounts = db.get_all_published_accounts();

    let mut modified_pubkey_bytes = [0u8; 32];
    modified_pubkey_bytes[0..8].copy_from_slice(&50u64.to_le_bytes());
    let modified_pubkey = Pubkey::from_bytes(modified_pubkey_bytes);
    let modified_account = create_test_account(999999, 200);
    base_accounts.insert(modified_pubkey, modified_account.clone());

    db.bulk_insert_published_accounts(base_accounts.clone()).unwrap();

    let snapshot_path = snapshot_dir.join("full-100.snapshot");
    let manifest_path = snapshot_dir.join("full-100.snapshot.manifest");

    let loader = SnapshotLoader::new();
    let (original_base_accounts, _) = loader
        .load_snapshot_to_map(&snapshot_path, &manifest_path)
        .unwrap();

    let inc_manifest = creator
        .create_incremental_snapshot(&db, 200, 100, &original_base_accounts, snapshot_dir)
        .unwrap();

    assert!(inc_manifest.metadata.is_incremental());
    assert_eq!(inc_manifest.metadata.incremental_base, Some(100));
}

#[test]
fn test_snapshot_verification() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(50);

    let config = SnapshotConfig::new();
    let creator = SnapshotCreator::new(config);

    creator.create_full_snapshot(&db, 100, snapshot_dir).unwrap();

    let mut catalog = SnapshotCatalog::new().with_config(SnapshotConfig::new());

    let snapshot_path = snapshot_dir.join("full-100.snapshot");
    let manifest_path = snapshot_dir.join("full-100.snapshot.manifest");

    catalog.register_full_snapshot(100, snapshot_path);

    let is_valid = catalog.verify_snapshot(100, snapshot_dir, false).unwrap();
    assert!(is_valid);
}

#[test]
fn test_snapshot_catalog_integration() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(100);

    let config = SnapshotConfig::new()
        .with_full_interval(1000)
        .with_incremental_interval(100);

    let mut catalog = SnapshotCatalog::new().with_config(config);

    assert!(catalog.should_create_full_snapshot(1000));
    assert!(!catalog.should_create_full_snapshot(100));
    assert!(catalog.should_create_incremental_snapshot(100));
    assert!(!catalog.should_create_incremental_snapshot(1000));

    catalog.create_full_snapshot(&db, 1000, snapshot_dir).unwrap();

    let snapshots = catalog.list_full_snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0], 1000);

    let new_db = AccountDatabase::new();
    catalog
        .restore_from_full_snapshot(&new_db, 1000, snapshot_dir)
        .unwrap();

    let original_count = db.get_account_count();
    let restored_count = new_db.get_account_count();
    assert_eq!(original_count, restored_count);
}

#[test]
fn test_snapshot_retention_policy() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(50);

    let config = SnapshotConfig::new()
        .with_max_full_snapshots(3)
        .with_max_incremental_snapshots(5);

    let mut catalog = SnapshotCatalog::new().with_config(config);

    for i in 1..=5 {
        let slot = i * 1000;
        catalog.create_full_snapshot(&db, slot, snapshot_dir).unwrap();
    }

    let snapshots = catalog.list_full_snapshots();
    assert_eq!(snapshots.len(), 3);
    assert_eq!(snapshots[0], 3000);
    assert_eq!(snapshots[1], 4000);
    assert_eq!(snapshots[2], 5000);
}

#[test]
fn test_large_account_database_snapshot() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(1000);

    let config = SnapshotConfig::new();
    let creator = SnapshotCreator::new(config);

    let start = std::time::Instant::now();
    let manifest = creator.create_full_snapshot(&db, 100, snapshot_dir).unwrap();
    let creation_time = start.elapsed();

    println!("Created snapshot of 1000 accounts in {:?}", creation_time);

    assert_eq!(manifest.metadata.total_accounts, 1000);

    let loader = SnapshotLoader::new();
    let snapshot_path = snapshot_dir.join("full-100.snapshot");
    let manifest_path = snapshot_dir.join("full-100.snapshot.manifest");

    let start = std::time::Instant::now();
    let (accounts, _) = loader
        .load_snapshot_to_map(&snapshot_path, &manifest_path)
        .unwrap();
    let load_time = start.elapsed();

    println!("Loaded snapshot of 1000 accounts in {:?}", load_time);

    assert_eq!(accounts.len(), 1000);
}

#[test]
fn test_snapshot_progress_tracking() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(500);

    let config = SnapshotConfig::new();
    let creator = SnapshotCreator::new(config);

    creator.create_full_snapshot(&db, 100, snapshot_dir).unwrap();

    let progress = creator.get_progress();
    assert_eq!(progress.total_accounts, 500);
    assert_eq!(progress.processed_accounts, 500);
    assert_eq!(progress.percentage(), 100.0);
}

#[test]
fn test_account_database_cache() {
    let db = AccountDatabase::with_capacity(100);

    let pubkey = Pubkey::zeroed();
    let account = create_test_account(1000, 100);

    let mut accounts = HashMap::new();
    accounts.insert(pubkey, account.clone());
    db.bulk_insert_published_accounts(accounts).unwrap();

    assert_eq!(db.cache_size(), 1);

    let retrieved = db.get_published_account(&pubkey).unwrap();
    assert_eq!(retrieved.meta.lamports, 1000);

    db.invalidate_cache();
    assert_eq!(db.cache_size(), 0);
}

#[test]
fn test_account_database_state_hash() {
    let db1 = setup_test_database(100);
    let db2 = setup_test_database(100);

    let hash1 = db1.compute_state_hash();
    let hash2 = db2.compute_state_hash();

    assert_eq!(hash1, hash2);

    let db3 = setup_test_database(50);
    let hash3 = db3.compute_state_hash();

    assert_ne!(hash1, hash3);
}

#[test]
fn test_compression_types() {
    let metadata_none = SnapshotMetadata::new(
        100,
        1000,
        5000000,
        None,
        CompressionType::None,
        10000,
    );

    let metadata_zstd = SnapshotMetadata::new(
        100,
        1000,
        5000000,
        None,
        CompressionType::Zstd,
        10000,
    );

    assert_eq!(metadata_none.compression.as_str(), "none");
    assert_eq!(metadata_zstd.compression.as_str(), "zstd");
}

#[test]
fn test_restore_with_incrementals() {
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    let db = setup_test_database(100);
    let config = SnapshotConfig::new();
    let mut catalog = SnapshotCatalog::new().with_config(config.clone());

    catalog.create_full_snapshot(&db, 1000, snapshot_dir).unwrap();

    let mut modified_accounts = db.get_all_published_accounts();
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes[0] = 1;
    let pubkey = Pubkey::from_bytes(pubkey_bytes);
    modified_accounts.insert(pubkey, create_test_account(99999, 200));
    db.bulk_insert_published_accounts(modified_accounts).unwrap();

    let snapshot_path = snapshot_dir.join("full-1000.snapshot");
    let manifest_path = snapshot_dir.join("full-1000.snapshot.manifest");
    let loader = SnapshotLoader::new();
    let (base_accounts, _) = loader
        .load_snapshot_to_map(&snapshot_path, &manifest_path)
        .unwrap();

    let creator = SnapshotCreator::new(config);
    creator
        .create_incremental_snapshot(&db, 1100, 1000, &base_accounts, snapshot_dir)
        .unwrap();

    catalog.register_incremental_snapshot(
        1100,
        snapshot_dir.join("incremental-1100.snapshot"),
    );
    catalog.register_full_snapshot(1000, snapshot_path);

    let new_db = AccountDatabase::new();
    catalog
        .restore_with_incrementals(&new_db, 1000, &[1100], snapshot_dir)
        .unwrap();

    let restored_accounts = new_db.get_all_published_accounts();
    let current_accounts = db.get_all_published_accounts();
    assert_eq!(restored_accounts.len(), current_accounts.len());
}
