/*!
# Snapshot System

The snapshot system provides comprehensive state capture and restoration capabilities
for the Karstflow storage layer.

## Features

- **Full Snapshots**: Complete account database state at a specific slot
- **Incremental Snapshots**: Delta-based snapshots from a base snapshot
- **Compression**: Zstd compression for reduced storage footprint
- **Parallel Processing**: Multi-threaded serialization and deserialization
- **Verification**: SHA-256 checksums for integrity validation
- **Progress Tracking**: Real-time progress monitoring for long operations

## Quick Start

### Creating a Full Snapshot

```rust,no_run
use karstflow_storage::{AccountDatabase, SnapshotConfig, SnapshotCreator};

let db = AccountDatabase::new();
// ... populate database with accounts ...

let config = SnapshotConfig::new()
    .with_full_interval(10000)
    .with_compression_level(3);

let creator = SnapshotCreator::new(config);
let manifest = creator.create_full_snapshot(
    &db,
    100,  // slot
    std::path::Path::new("./snapshots")
)?;

println!("Created snapshot with {} accounts", manifest.metadata.total_accounts);
# Ok::<(), karstflow_storage::StorageError>(())
```

### Loading a Snapshot

```rust,no_run
use karstflow_storage::{AccountDatabase, SnapshotLoader};

let loader = SnapshotLoader::new();
let (accounts, metadata) = loader.load_snapshot_to_map(
    std::path::Path::new("./snapshots/full-100.snapshot"),
    std::path::Path::new("./snapshots/full-100.snapshot.manifest")
)?;

let db = AccountDatabase::new();
db.bulk_insert_published_accounts(accounts)?;

println!("Restored {} accounts at slot {}",
    db.get_account_count(), metadata.slot);
# Ok::<(), karstflow_storage::StorageError>(())
```

### Creating an Incremental Snapshot

```rust,no_run
use karstflow_storage::{AccountDatabase, SnapshotConfig, SnapshotCreator, SnapshotLoader};

// Load base snapshot
let loader = SnapshotLoader::new();
let (base_accounts, _) = loader.load_snapshot_to_map(
    std::path::Path::new("./snapshots/full-100.snapshot"),
    std::path::Path::new("./snapshots/full-100.snapshot.manifest")
)?;

// Create incremental from modified state
let db = AccountDatabase::new();
// ... make changes to accounts ...

let config = SnapshotConfig::new();
let creator = SnapshotCreator::new(config);
let manifest = creator.create_incremental_snapshot(
    &db,
    200,  // current slot
    100,  // base slot
    &base_accounts,
    std::path::Path::new("./snapshots")
)?;

println!("Created incremental snapshot with {} changed accounts",
    manifest.metadata.total_accounts);
# Ok::<(), karstflow_storage::StorageError>(())
```

### Using SnapshotCatalog for Management

```rust,no_run
use karstflow_storage::{SnapshotCatalog, SnapshotConfig, AccountDatabase};

let config = SnapshotConfig::new()
    .with_full_interval(10000)
    .with_incremental_interval(1000)
    .with_max_full_snapshots(3)
    .with_max_incremental_snapshots(10);

let mut catalog = SnapshotCatalog::new().with_config(config);

let db = AccountDatabase::new();
// ... populate database ...

// Create snapshots based on slot intervals
let snapshot_dir = std::path::Path::new("./snapshots");

if catalog.should_create_full_snapshot(10000) {
    catalog.create_full_snapshot(&db, 10000, snapshot_dir)?;
}

if catalog.should_create_incremental_snapshot(11000) {
    catalog.create_incremental_snapshot(&db, 11000, 10000, snapshot_dir)?;
}

// Restore from latest snapshot
if let Some(latest_slot) = catalog.get_latest_full_snapshot_slot() {
    let incremental_slots = catalog.get_incremental_snapshots_after(latest_slot);
    catalog.restore_with_incrementals(&db, latest_slot, &incremental_slots, snapshot_dir)?;
}
# Ok::<(), karstflow_storage::StorageError>(())
```

## Configuration

The snapshot system is highly configurable through `SnapshotConfig`:

```rust
use karstflow_storage::SnapshotConfig;

let config = SnapshotConfig::new()
    .with_full_interval(10000)           // Full snapshot every 10k slots
    .with_incremental_interval(1000)     // Incremental every 1k slots
    .with_max_full_snapshots(3)          // Keep last 3 full snapshots
    .with_max_incremental_snapshots(10)  // Keep last 10 incrementals
    .with_compression_level(3)           // Zstd level (0-22)
    .with_parallel_workers(8)            // Number of parallel workers
    .with_chunk_size(1024 * 1024);       // 1MB chunk size
```

## Performance

The snapshot system is optimized for performance:

- **Parallel serialization**: Utilizes multiple CPU cores via rayon
- **Efficient compression**: Zstd provides ~70% size reduction with minimal overhead
- **Account caching**: Hot account cache reduces lookup overhead
- **Bulk operations**: Optimized for large-scale account insertion/extraction

Typical performance on modern hardware:
- Full snapshot creation: 1-5ms per 1000 accounts
- Snapshot loading: 2-8ms per 1000 accounts
- Incremental snapshot: <1ms per 100 modified accounts

## Error Handling

All snapshot operations return `Result<T, StorageError>`:

```rust,no_run
use karstflow_storage::{SnapshotLoader, StorageError};

match SnapshotLoader::new().load_snapshot_to_map(
    std::path::Path::new("./snapshot"),
    std::path::Path::new("./manifest")
) {
    Ok((accounts, metadata)) => {
        println!("Loaded {} accounts", accounts.len());
    }
    Err(StorageError::SnapshotChecksumMismatch { .. }) => {
        eprintln!("Snapshot corruption detected!");
    }
    Err(e) => {
        eprintln!("Failed to load snapshot: {}", e);
    }
}
# Ok::<(), StorageError>(())
```

## Thread Safety

All snapshot components are thread-safe and can be used concurrently:

- `SnapshotCreator`: Immutable, safe to share across threads
- `SnapshotLoader`: Immutable, safe to share across threads
- `AccountDatabase`: Uses `Arc<DashMap>` for concurrent access
- `SnapshotCatalog`: Mutable operations require external synchronization

## Compression

The system uses zstd compression with configurable levels:

- **Level 0**: No compression (fastest)
- **Level 1-3**: Fast compression, good ratio (default: 3)
- **Level 4-9**: Balanced compression
- **Level 10-22**: Maximum compression, slower

For most use cases, level 3 provides the best speed/size tradeoff.

## Verification

All snapshots include cryptographic verification:

1. **Per-chunk hashing**: SHA-256 hash of each snapshot chunk
2. **Manifest verification**: Checksums stored in manifest file
3. **Load-time validation**: Checksums verified during snapshot loading
4. **State hash**: Deterministic hash of complete account state

## Best Practices

1. **Regular Full Snapshots**: Create full snapshots at regular intervals (e.g., every 10k slots)
2. **Incremental Between**: Use incrementals between full snapshots for efficiency
3. **Retention Policy**: Keep multiple full snapshots for redundancy
4. **Verification**: Periodically verify snapshot integrity
5. **Cleanup**: Use catalog retention policies to manage disk space
6. **Monitoring**: Track snapshot creation time and size metrics

## Examples

See the `examples/` directory for complete working examples:

- `snapshot_demo.rs`: Comprehensive demonstration of snapshot functionality

Run with: `cargo run --example snapshot_demo --release`

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                 SnapshotCatalog                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  Snapshot Lifecycle Management               │  │
│  │  - Creation scheduling                        │  │
│  │  - Retention policies                         │  │
│  │  - Verification                               │  │
│  └──────────────────────────────────────────────┘  │
└──────────────┬──────────────────┬───────────────────┘
               │                  │
       ┌───────▼──────┐   ┌──────▼────────┐
       │   Creator    │   │    Loader     │
       │              │   │               │
       │ Serialize    │   │ Deserialize   │
       │ Compress     │   │ Decompress    │
       │ Hash         │   │ Verify        │
       └──────┬───────┘   └──────┬────────┘
              │                  │
              └─────────┬────────┘
                        │
              ┌─────────▼─────────┐
              │  AccountDatabase  │
              │                   │
              │  - MVCC storage   │
              │  - Account cache  │
              │  - Bulk ops       │
              └───────────────────┘
```

## License

See the main Karstflow license file.
*/
