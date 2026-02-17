/// Demonstration of snapshot functionality
/// Run with: cargo run --example snapshot_demo --release
use paradencer_storage::{
    Account, AccountData, AccountDatabase, AccountMeta, Pubkey, SnapshotCatalog, SnapshotConfig,
    SnapshotCreator, SnapshotLoader,
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

fn setup_database_with_accounts(count: usize) -> AccountDatabase {
    let db = AccountDatabase::with_capacity(count);
    let mut accounts = HashMap::new();

    println!("Creating {} accounts...", count);
    for i in 0..count {
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        let account = create_test_account(1000 * (i as u64 + 1), 100 + i * 10);
        accounts.insert(pubkey, account);
    }

    db.bulk_insert_published_accounts(accounts).unwrap();
    println!("Database created with {} accounts", db.get_account_count());
    println!("Total lamports: {}", db.get_total_lamports());

    db
}

fn main() {
    println!("=== Paradencer Storage Snapshot Demo ===\n");

    // Create a temporary directory for snapshots
    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();
    println!("Snapshot directory: {:?}\n", snapshot_dir);

    // Setup configuration
    let config = SnapshotConfig::new()
        .with_full_interval(1000)
        .with_incremental_interval(100)
        .with_max_full_snapshots(3)
        .with_compression_level(3);

    println!("Snapshot Configuration:");
    println!(
        "  Full snapshot interval: {}",
        config.full_snapshot_interval
    );
    println!(
        "  Incremental interval: {}",
        config.incremental_snapshot_interval
    );
    println!("  Max full snapshots: {}", config.max_full_snapshots);
    println!("  Compression level: {}\n", config.compression_level);

    // Create database with 1000 accounts
    println!("--- Step 1: Create Initial Database ---");
    let db = setup_database_with_accounts(1000);
    let initial_hash = db.compute_state_hash();
    println!("Initial state hash: {:016x}\n", initial_hash);

    // Create full snapshot
    println!("--- Step 2: Create Full Snapshot ---");
    let creator = SnapshotCreator::new(config.clone());
    let start = std::time::Instant::now();
    let manifest = creator
        .create_full_snapshot(&db, 1000, snapshot_dir)
        .unwrap();
    let duration = start.elapsed();

    println!("Full snapshot created in {:?}", duration);
    println!("Snapshot metadata:");
    println!("  Slot: {}", manifest.metadata.slot);
    println!("  Total accounts: {}", manifest.metadata.total_accounts);
    println!("  Total lamports: {}", manifest.metadata.total_lamports);
    println!(
        "  Account data size: {} bytes",
        manifest.metadata.account_data_size
    );
    println!("  Compression: {:?}", manifest.metadata.compression);
    println!("  Chunk count: {}", manifest.chunk_count);

    let progress = creator.get_progress();
    println!("Creation progress:");
    println!(
        "  Processed accounts: {}/{}",
        progress.processed_accounts, progress.total_accounts
    );
    println!(
        "  Processed bytes: {}/{}",
        progress.processed_bytes, progress.total_bytes
    );
    println!("  Completion: {:.1}%\n", progress.percentage());

    // Verify snapshot
    println!("--- Step 3: Verify Snapshot ---");
    let mut catalog = SnapshotCatalog::new().with_config(config.clone());
    catalog.register_full_snapshot(1000, snapshot_dir.join("full-1000.snapshot"));

    let is_valid = catalog.verify_snapshot(1000, snapshot_dir, false).unwrap();
    println!(
        "Snapshot verification: {}\n",
        if is_valid { "PASSED" } else { "FAILED" }
    );

    // Load snapshot into new database
    println!("--- Step 4: Load Snapshot ---");
    let loader = SnapshotLoader::new();
    let snapshot_path = snapshot_dir.join("full-1000.snapshot");
    let manifest_path = snapshot_dir.join("full-1000.snapshot.manifest");

    let start = std::time::Instant::now();
    let (loaded_accounts, _metadata) = loader
        .load_snapshot_to_map(&snapshot_path, &manifest_path)
        .unwrap();
    let duration = start.elapsed();

    println!("Snapshot loaded in {:?}", duration);
    println!("Loaded {} accounts", loaded_accounts.len());

    let load_progress = loader.get_progress();
    println!("Load progress:");
    println!(
        "  Loaded accounts: {}/{}",
        load_progress.loaded_accounts, load_progress.total_accounts
    );
    println!(
        "  Loaded bytes: {}/{}",
        load_progress.loaded_bytes, load_progress.total_bytes
    );
    println!("  Completion: {:.1}%", load_progress.percentage());
    println!("  Validation errors: {}\n", load_progress.validation_errors);

    // Restore to new database
    let new_db = AccountDatabase::new();
    new_db
        .bulk_insert_published_accounts(loaded_accounts)
        .unwrap();

    let restored_hash = new_db.compute_state_hash();
    println!("Restored state hash: {:016x}", restored_hash);
    println!("State match: {}\n", initial_hash == restored_hash);

    // Create incremental snapshot with modifications
    println!("--- Step 5: Create Incremental Snapshot ---");
    let mut modified_accounts = db.get_all_published_accounts();

    // Modify 10% of accounts
    let modify_count = 100;
    println!("Modifying {} accounts...", modify_count);
    for i in 0..modify_count {
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        modified_accounts.insert(pubkey, create_test_account(99999, 200));
    }

    db.bulk_insert_published_accounts(modified_accounts)
        .unwrap();

    let base_accounts_map = new_db.get_all_published_accounts();
    let start = std::time::Instant::now();
    let inc_manifest = creator
        .create_incremental_snapshot(&db, 1100, 1000, &base_accounts_map, snapshot_dir)
        .unwrap();
    let duration = start.elapsed();

    println!("Incremental snapshot created in {:?}", duration);
    println!("Incremental metadata:");
    println!("  Slot: {}", inc_manifest.metadata.slot);
    println!("  Base slot: {:?}", inc_manifest.metadata.incremental_base);
    println!("  Delta accounts: {}", inc_manifest.metadata.total_accounts);
    println!(
        "  Is incremental: {}\n",
        inc_manifest.metadata.is_incremental()
    );

    // Apply incremental snapshot
    println!("--- Step 6: Apply Incremental Snapshot ---");
    let mut base_accounts = new_db.get_all_published_accounts();
    let inc_snapshot_path = snapshot_dir.join("incremental-1100.snapshot");
    let inc_manifest_path = snapshot_dir.join("incremental-1100.snapshot.manifest");

    let loaded_snapshot = loader
        .apply_incremental_snapshot(&mut base_accounts, &inc_snapshot_path, &inc_manifest_path)
        .unwrap();

    println!("Incremental snapshot applied");
    println!("  Final account count: {}", loaded_snapshot.total_accounts);
    println!("  Final lamports: {}", loaded_snapshot.total_lamports);

    let final_db = AccountDatabase::new();
    final_db
        .bulk_insert_published_accounts(base_accounts)
        .unwrap();

    let final_hash = final_db.compute_state_hash();
    let current_hash = db.compute_state_hash();
    println!("  Final state hash: {:016x}", final_hash);
    println!("  Current state hash: {:016x}", current_hash);
    println!("  State match: {}\n", final_hash == current_hash);

    // Performance summary
    println!("--- Performance Summary ---");
    println!("Database operations:");
    println!("  Account lookups: O(1) with cache");
    println!("  Bulk inserts: {} accounts", db.get_account_count());
    println!("  State hash computation: O(n log n)");
    println!("\nSnapshot operations:");
    println!(
        "  Full snapshot: ~{} ms for 1000 accounts",
        duration.as_millis()
    );
    println!(
        "  Incremental: ~{} ms for {} modified accounts",
        duration.as_millis(),
        modify_count
    );
    println!("  Compression: zstd level {}", config.compression_level);
    println!("  Parallel workers: {}", config.parallel_workers);

    println!("\n=== Demo Complete ===");
}
