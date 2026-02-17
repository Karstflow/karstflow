use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use paradencer_storage::{
    Account, AccountData, AccountDatabase, AccountMeta, Pubkey, SnapshotConfig, SnapshotCreator,
    SnapshotLoader,
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

fn setup_database(account_count: usize, data_size: usize) -> AccountDatabase {
    let db = AccountDatabase::with_capacity(account_count);
    let mut accounts = HashMap::new();

    for i in 0..account_count {
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let pubkey = Pubkey::new(pubkey_bytes);
        let account = create_test_account(1000 * (i as u64 + 1), data_size);
        accounts.insert(pubkey, account);
    }

    db.bulk_insert_published_accounts(accounts).unwrap();
    db
}

fn bench_snapshot_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_creation");

    for account_count in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*account_count as u64));

        group.bench_with_input(
            BenchmarkId::new("accounts", account_count),
            account_count,
            |b, &size| {
                let db = setup_database(size, 100);
                let temp_dir = tempfile::tempdir().unwrap();
                let config = SnapshotConfig::new();
                let creator = SnapshotCreator::new(config);

                b.iter(|| {
                    black_box(
                        creator
                            .create_full_snapshot(&db, 100, temp_dir.path())
                            .unwrap(),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_snapshot_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_loading");

    for account_count in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*account_count as u64));

        group.bench_with_input(
            BenchmarkId::new("accounts", account_count),
            account_count,
            |b, &size| {
                let db = setup_database(size, 100);
                let temp_dir = tempfile::tempdir().unwrap();
                let snapshot_dir = temp_dir.path();
                let config = SnapshotConfig::new();
                let creator = SnapshotCreator::new(config);

                creator
                    .create_full_snapshot(&db, 100, snapshot_dir)
                    .unwrap();

                let snapshot_path = snapshot_dir.join("full-100.snapshot");
                let manifest_path = snapshot_dir.join("full-100.snapshot.manifest");
                let loader = SnapshotLoader::new();

                b.iter(|| {
                    black_box(
                        loader
                            .load_snapshot_to_map(&snapshot_path, &manifest_path)
                            .unwrap(),
                    );
                });
            },
        );
    }

    group.finish();
}

fn bench_account_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_lookup");

    for account_count in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*account_count as u64));

        group.bench_with_input(
            BenchmarkId::new("cached", account_count),
            account_count,
            |b, &size| {
                let db = setup_database(size, 100);

                let mut pubkey_bytes = [0u8; 32];
                pubkey_bytes[0] = 1;
                let pubkey = Pubkey::new(pubkey_bytes);

                db.get_published_account(&pubkey);

                b.iter(|| {
                    black_box(db.get_published_account(&pubkey));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("uncached", account_count),
            account_count,
            |b, &size| {
                let db = setup_database(size, 100);

                let mut pubkey_bytes = [0u8; 32];
                pubkey_bytes[0] = 1;
                let pubkey = Pubkey::new(pubkey_bytes);

                b.iter(|| {
                    db.invalidate_cache();
                    black_box(db.get_published_account(&pubkey));
                });
            },
        );
    }

    group.finish();
}

fn bench_bulk_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_insert");

    for account_count in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*account_count as u64));

        group.bench_with_input(
            BenchmarkId::new("accounts", account_count),
            account_count,
            |b, &size| {
                let mut accounts = HashMap::new();

                for i in 0..size {
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    let pubkey = Pubkey::new(pubkey_bytes);
                    let account = create_test_account(1000 * (i as u64 + 1), 100);
                    accounts.insert(pubkey, account);
                }

                b.iter(|| {
                    let db = AccountDatabase::with_capacity(size);
                    db.bulk_insert_published_accounts(accounts.clone()).unwrap();
                    black_box(&db);
                });
            },
        );
    }

    group.finish();
}

fn bench_state_hash_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_hash");

    for account_count in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*account_count as u64));

        group.bench_with_input(
            BenchmarkId::new("accounts", account_count),
            account_count,
            |b, &size| {
                let db = setup_database(size, 100);

                b.iter(|| {
                    black_box(db.compute_state_hash());
                });
            },
        );
    }

    group.finish();
}

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");

    for data_size in [1024, 10240, 102400, 1024000].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));

        group.bench_with_input(
            BenchmarkId::new("compress", data_size),
            data_size,
            |b, &size| {
                let data = vec![0u8; size];

                b.iter(|| {
                    black_box(zstd::encode_all(&data[..], 3).unwrap());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decompress", data_size),
            data_size,
            |b, &size| {
                let data = vec![0u8; size];
                let compressed = zstd::encode_all(&data[..], 3).unwrap();

                b.iter(|| {
                    black_box(zstd::decode_all(&compressed[..]).unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_incremental_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_snapshot");

    for delta_percent in [5, 10, 25, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("delta_percent", delta_percent),
            delta_percent,
            |b, &percent| {
                let total_accounts = 1000;
                let db = setup_database(total_accounts, 100);
                let base_accounts = db.get_all_published_accounts();

                let delta_count = (total_accounts * percent) / 100;
                let mut modified_accounts = base_accounts.clone();

                for i in 0..delta_count {
                    let mut pubkey_bytes = [0u8; 32];
                    pubkey_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    let pubkey = Pubkey::new(pubkey_bytes);
                    let account = create_test_account(99999, 200);
                    modified_accounts.insert(pubkey, account);
                }

                db.bulk_insert_published_accounts(modified_accounts)
                    .unwrap();

                let temp_dir = tempfile::tempdir().unwrap();
                let config = SnapshotConfig::new();
                let creator = SnapshotCreator::new(config);

                b.iter(|| {
                    black_box(
                        creator
                            .create_incremental_snapshot(
                                &db,
                                200,
                                100,
                                &base_accounts,
                                temp_dir.path(),
                            )
                            .unwrap(),
                    );
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_snapshot_creation,
    bench_snapshot_loading,
    bench_account_lookup,
    bench_bulk_insert,
    bench_state_hash_computation,
    bench_compression,
    bench_incremental_snapshot
);

criterion_main!(benches);
