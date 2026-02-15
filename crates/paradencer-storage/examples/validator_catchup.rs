/// Example: Validator Catchup Using Snapshots
///
/// This example demonstrates how a validator can use snapshots to catch up
/// to the current network state after being offline or falling behind.
///
/// Run with: cargo run --example validator_catchup --release

use paradencer_storage::{
    Account, AccountData, AccountDatabase, AccountMeta, Pubkey, SnapshotCatalog, SnapshotConfig,
    SnapshotCreator, SnapshotLoader,
};
use std::collections::HashMap;

fn create_account(lamports: u64, data: Vec<u8>) -> Account {
    Account {
        meta: AccountMeta {
            lamports,
            owner: Pubkey::zeroed(),
            executable: false,
            rent_epoch: 0,
        },
        data: AccountData::new(data),
    }
}

fn simulate_network_state(slot: u64, base_accounts: usize, modifications: usize) -> AccountDatabase {
    let db = AccountDatabase::with_capacity(base_accounts + modifications);
    let mut accounts = HashMap::new();

    // Create base accounts
    for i in 0..base_accounts {
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        let lamports = 1000 * (i as u64 + 1);
        let data_size = 100 + (i % 10) * 10;
        accounts.insert(pubkey, create_account(lamports, vec![0u8; data_size]));
    }

    // Add modifications based on slot
    for i in 0..modifications {
        let idx = (slot as usize * 7 + i * 13) % base_accounts;
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(idx as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        let lamports = 1000 * (slot + i as u64);
        let data_size = 150 + (i % 5) * 20;
        accounts.insert(pubkey, create_account(lamports, vec![1u8; data_size]));
    }

    db.bulk_insert_published_accounts(accounts).unwrap();
    db
}

fn main() {
    println!("=== Validator Catchup Simulation ===\n");

    let temp_dir = tempfile::tempdir().unwrap();
    let snapshot_dir = temp_dir.path();

    // Configuration
    let config = SnapshotConfig::new()
        .with_full_interval(1000)
        .with_incremental_interval(100)
        .with_max_full_snapshots(5)
        .with_max_incremental_snapshots(20)
        .with_compression_level(3);

    println!("Configuration:");
    println!("  Full snapshots every {} slots", config.full_snapshot_interval);
    println!("  Incremental snapshots every {} slots", config.incremental_snapshot_interval);
    println!("  Keep {} full + {} incremental snapshots\n",
             config.max_full_snapshots, config.max_incremental_snapshots);

    // Simulate validator creating snapshots as it processes blocks
    println!("--- Phase 1: Validator Processing (Creating Snapshots) ---\n");

    let mut catalog = SnapshotCatalog::new().with_config(config.clone());
    let creator = SnapshotCreator::new(config.clone());

    let slots = vec![1000, 1100, 1200, 1300, 1400, 2000, 2100, 2200, 2300, 3000];

    for &slot in &slots {
        let db = simulate_network_state(slot, 500, 50);

        if catalog.should_create_full_snapshot(slot) {
            println!("Slot {}: Creating FULL snapshot", slot);
            let start = std::time::Instant::now();
            let manifest = creator.create_full_snapshot(&db, slot, snapshot_dir).unwrap();
            println!("  - Created in {:?}", start.elapsed());
            println!("  - {} accounts, {} lamports",
                     manifest.metadata.total_accounts,
                     manifest.metadata.total_lamports);
            println!("  - Size: {} bytes (compressed)\n",
                     std::fs::metadata(snapshot_dir.join(format!("full-{}.snapshot", slot)))
                         .unwrap().len());

            catalog.register_full_snapshot(slot, snapshot_dir.join(format!("full-{}.snapshot", slot)));
        }
        else if catalog.should_create_incremental_snapshot(slot) {
            println!("Slot {}: Creating INCREMENTAL snapshot", slot);

            // Find base snapshot
            let base_slot = catalog.get_latest_full_snapshot_slot().unwrap();
            let base_path = snapshot_dir.join(format!("full-{}.snapshot", base_slot));
            let base_manifest_path = snapshot_dir.join(format!("full-{}.snapshot.manifest", base_slot));

            let loader = SnapshotLoader::new();
            let (base_accounts, _) = loader.load_snapshot_to_map(&base_path, &base_manifest_path).unwrap();

            let start = std::time::Instant::now();
            let manifest = creator.create_incremental_snapshot(
                &db, slot, base_slot, &base_accounts, snapshot_dir
            ).unwrap();
            println!("  - Created in {:?}", start.elapsed());
            println!("  - {} modified accounts (from base slot {})",
                     manifest.metadata.total_accounts, base_slot);
            println!("  - Size: {} bytes (compressed)\n",
                     std::fs::metadata(snapshot_dir.join(format!("incremental-{}.snapshot", slot)))
                         .unwrap().len());

            catalog.register_incremental_snapshot(
                slot,
                snapshot_dir.join(format!("incremental-{}.snapshot", slot))
            );
        }
    }

    println!("Snapshot Summary:");
    println!("  Full snapshots: {:?}", catalog.list_full_snapshots());
    println!("  Incremental snapshots: {:?}\n", catalog.list_incremental_snapshots());

    // Simulate validator catching up from snapshots
    println!("--- Phase 2: Validator Catchup (Loading Snapshots) ---\n");

    // Find the latest full snapshot
    let latest_full = catalog.get_latest_full_snapshot_slot().unwrap();
    println!("Latest full snapshot: slot {}", latest_full);

    // Find all incremental snapshots after the full snapshot
    let incremental_slots = catalog.get_incremental_snapshots_after(latest_full);
    println!("Incremental snapshots to apply: {:?}\n", incremental_slots);

    // Method 1: Manual restoration
    println!("Method 1: Manual Restoration");
    {
        let catchup_db = AccountDatabase::new();
        let loader = SnapshotLoader::new();

        // Load full snapshot
        println!("  Loading full snapshot from slot {}...", latest_full);
        let full_path = snapshot_dir.join(format!("full-{}.snapshot", latest_full));
        let full_manifest = snapshot_dir.join(format!("full-{}.snapshot.manifest", latest_full));

        let start = std::time::Instant::now();
        let (mut accounts, metadata) = loader.load_snapshot_to_map(&full_path, &full_manifest).unwrap();
        println!("  Loaded {} accounts in {:?}", accounts.len(), start.elapsed());
        println!("  Total lamports: {}", metadata.total_lamports);

        // Apply incremental snapshots
        for &inc_slot in &incremental_slots {
            println!("  Applying incremental snapshot from slot {}...", inc_slot);
            let inc_path = snapshot_dir.join(format!("incremental-{}.snapshot", inc_slot));
            let inc_manifest = snapshot_dir.join(format!("incremental-{}.snapshot.manifest", inc_slot));

            let start = std::time::Instant::now();
            let result = loader.apply_incremental_snapshot(&mut accounts, &inc_path, &inc_manifest).unwrap();
            println!("    Applied {} changes in {:?}", result.metadata.total_accounts, start.elapsed());
        }

        // Insert into database
        println!("  Inserting accounts into database...");
        let start = std::time::Instant::now();
        catchup_db.bulk_insert_published_accounts(accounts).unwrap();
        println!("  Inserted in {:?}", start.elapsed());

        println!("  Final state:");
        println!("    Account count: {}", catchup_db.get_account_count());
        println!("    Total lamports: {}", catchup_db.get_total_lamports());
        println!("    State hash: {:016x}\n", catchup_db.compute_state_hash());
    }

    // Method 2: Using catalog convenience method
    println!("Method 2: Using Catalog");
    {
        let catchup_db = AccountDatabase::new();

        let start = std::time::Instant::now();
        catalog.restore_with_incrementals(
            &catchup_db,
            latest_full,
            &incremental_slots,
            snapshot_dir
        ).unwrap();
        let duration = start.elapsed();

        println!("  Restored complete state in {:?}", duration);
        println!("  Account count: {}", catchup_db.get_account_count());
        println!("  Total lamports: {}", catchup_db.get_total_lamports());
        println!("  State hash: {:016x}\n", catchup_db.compute_state_hash());
    }

    // Verification
    println!("--- Phase 3: Verification ---\n");

    // Verify snapshot integrity
    for &slot in catalog.list_full_snapshots().iter() {
        let is_valid = catalog.verify_snapshot(slot, snapshot_dir, false).unwrap();
        println!("Full snapshot at slot {}: {}",
                 slot, if is_valid { "VALID ✓" } else { "INVALID ✗" });
    }

    for &slot in catalog.list_incremental_snapshots().iter() {
        let is_valid = catalog.verify_snapshot(slot, snapshot_dir, true).unwrap();
        println!("Incremental snapshot at slot {}: {}",
                 slot, if is_valid { "VALID ✓" } else { "INVALID ✗" });
    }

    // Compare states
    println!("\n--- Phase 4: State Comparison ---\n");

    let current_state = simulate_network_state(*slots.last().unwrap(), 500, 50);
    let catchup_state = AccountDatabase::new();

    catalog.restore_with_incrementals(
        &catchup_state,
        latest_full,
        &incremental_slots,
        snapshot_dir
    ).unwrap();

    let current_hash = current_state.compute_state_hash();
    let catchup_hash = catchup_state.compute_state_hash();

    println!("Current network state hash:  {:016x}", current_hash);
    println!("Caught-up validator hash:    {:016x}", catchup_hash);
    println!("States match: {}", if current_hash == catchup_hash { "YES ✓" } else { "NO ✗" });

    // Performance summary
    println!("\n--- Performance Summary ---\n");

    let full_count = catalog.list_full_snapshots().len();
    let inc_count = catalog.list_incremental_snapshots().len();
    let total_snapshots = full_count + inc_count;

    println!("Snapshots created: {}", total_snapshots);
    println!("  Full: {}", full_count);
    println!("  Incremental: {}", inc_count);

    let total_size: u64 = catalog.list_full_snapshots().iter()
        .chain(catalog.list_incremental_snapshots().iter())
        .map(|&slot| {
            let is_full = catalog.list_full_snapshots().contains(&slot);
            let filename = if is_full {
                format!("full-{}.snapshot", slot)
            } else {
                format!("incremental-{}.snapshot", slot)
            };
            std::fs::metadata(snapshot_dir.join(filename))
                .map(|m| m.len())
                .unwrap_or(0)
        })
        .sum();

    println!("Total snapshot size: {} bytes ({:.2} MB)",
             total_size, total_size as f64 / 1_000_000.0);
    println!("Average snapshot size: {} bytes", total_size / total_snapshots as u64);

    println!("\nCatchup Benefits:");
    println!("  - No need to replay all transactions");
    println!("  - Fast state restoration from latest snapshot");
    println!("  - Incremental updates reduce bandwidth");
    println!("  - Cryptographic verification ensures integrity");

    println!("\n=== Catchup Complete ===");
}
