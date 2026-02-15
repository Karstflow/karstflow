use crate::tests::unique_temp_file;
use crate::{CommittedFragmentRecord, HotStateStore, SnapshotCatalog, SnapshotImage, StorageError};
use std::fs;

#[test]
fn snapshot_catalog_writes_and_restores_latest_snapshot() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();
    let record = CommittedFragmentRecord {
        fragment_id: 10,
        transaction_count: 1,
        total_cost_units: 1,
    };

    store.apply_committed_fragment(&record).unwrap();
    let wrote_snapshot = catalog.maybe_write_snapshot(&record, &store, 5).unwrap();
    assert!(wrote_snapshot);

    let latest = catalog.restore_latest_snapshot().unwrap();
    assert_eq!(latest.fragment_id, 10);
    assert_eq!(latest.committed_fragments, 1);
    assert_eq!(latest.committed_transactions, 1);
}

#[test]
fn snapshot_catalog_restores_named_snapshot() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();
    let record = CommittedFragmentRecord {
        fragment_id: 12,
        transaction_count: 2,
        total_cost_units: 99,
    };
    store.apply_committed_fragment(&record).unwrap();
    catalog.write_snapshot(12, &store).unwrap();

    let restored = catalog.restore_snapshot(12).unwrap();
    assert_eq!(restored, SnapshotImage::new(12, 1, 2));
}

#[test]
fn snapshot_catalog_rejects_regressive_snapshot_write() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();
    let first = CommittedFragmentRecord {
        fragment_id: 20,
        transaction_count: 1,
        total_cost_units: 1,
    };
    let second = CommittedFragmentRecord {
        fragment_id: 19,
        transaction_count: 1,
        total_cost_units: 1,
    };

    store.apply_committed_fragment(&first).unwrap();
    catalog.write_snapshot(20, &store).unwrap();

    store.last_fragment_id = 19;
    store.committed_fragments = 2;
    store.committed_transactions = 2;
    let error = catalog
        .write_snapshot(second.fragment_id, &store)
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::SnapshotRegression {
            last_snapshot_fragment_id: 20,
            new_snapshot_fragment_id: 19
        }
    );
}

#[test]
fn snapshot_catalog_roundtrip_persist_and_load_restores_latest() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();
    let file_path = unique_temp_file("paradencer-snapshot-catalog", "json");

    for fragment_id in [8_u64, 16, 24] {
        let record = CommittedFragmentRecord {
            fragment_id,
            transaction_count: 3,
            total_cost_units: 42,
        };
        store.apply_committed_fragment(&record).unwrap();
        catalog.write_snapshot(fragment_id, &store).unwrap();
    }

    catalog.persist_to_file(&file_path).unwrap();
    let restored_catalog = SnapshotCatalog::load_from_file(&file_path).unwrap();
    fs::remove_file(&file_path).unwrap();

    let latest_snapshot = restored_catalog.restore_latest_snapshot().unwrap();
    assert_eq!(latest_snapshot.fragment_id, 24);
    assert_eq!(latest_snapshot.committed_fragments, 3);
    assert_eq!(latest_snapshot.committed_transactions, 9);
}

#[test]
fn snapshot_catalog_load_if_exists_returns_none_for_missing_file() {
    let file_path = unique_temp_file("paradencer-no-catalog", "json");
    let loaded = SnapshotCatalog::load_from_file_if_exists(&file_path).unwrap();
    assert!(loaded.is_none());
}

#[test]
fn snapshot_catalog_rejects_unknown_schema_version() {
    let file_path = unique_temp_file("paradencer-invalid-catalog", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":99,"last_snapshot_fragment_id":0,"snapshots_written":0,"snapshots":[]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();

    assert_eq!(
        error,
        StorageError::UnsupportedCatalogSchema {
            found: 99,
            expected: 2
        }
    );
}

#[test]
fn snapshot_catalog_migrates_legacy_v0_without_schema_field() {
    let file_path = unique_temp_file("paradencer-legacy-catalog", "json");
    fs::write(
        &file_path,
        r#"{"last_snapshot_fragment_id":12,"snapshots_written":1,"snapshots":[{"fragment_id":12,"committed_fragments":1,"committed_transactions":5}]}"#,
    )
    .unwrap();

    let catalog = SnapshotCatalog::load_from_file(&file_path).unwrap();
    fs::remove_file(&file_path).unwrap();
    let snapshot = catalog.restore_latest_snapshot().unwrap();
    assert_eq!(snapshot.fragment_id, 12);
    assert_eq!(snapshot.committed_transactions, 5);
}

#[test]
fn snapshot_catalog_migrates_legacy_v0_with_explicit_schema_zero() {
    let file_path = unique_temp_file("paradencer-legacy-catalog-v0", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":0,"last_snapshot_fragment_id":14,"snapshots_written":1,"snapshots":[{"fragment_id":14,"committed_fragments":2,"committed_transactions":9}]}"#,
    )
    .unwrap();

    let catalog = SnapshotCatalog::load_from_file(&file_path).unwrap();
    fs::remove_file(&file_path).unwrap();
    let snapshot = catalog.restore_latest_snapshot().unwrap();
    assert_eq!(snapshot.fragment_id, 14);
    assert_eq!(snapshot.committed_fragments, 2);
}

#[test]
fn snapshot_catalog_enforce_retention_keeps_latest_snapshots_only() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();

    for fragment_id in [10_u64, 20, 30] {
        let record = CommittedFragmentRecord {
            fragment_id,
            transaction_count: 1,
            total_cost_units: 1,
        };
        store.apply_committed_fragment(&record).unwrap();
        catalog.write_snapshot(fragment_id, &store).unwrap();
    }

    catalog.enforce_retention(2);

    assert!(catalog.restore_snapshot(10).is_err());
    assert_eq!(catalog.restore_snapshot(20).unwrap().fragment_id, 20);
    assert_eq!(catalog.restore_snapshot(30).unwrap().fragment_id, 30);
    assert_eq!(catalog.last_snapshot_fragment_id, 30);
}

#[test]
fn snapshot_catalog_rejects_non_monotonic_snapshot_fragment_sequence() {
    let file_path = unique_temp_file("paradencer-invalid-order-catalog", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":12,"snapshots_written":2,"snapshots":[{"fragment_id":12,"committed_fragments":2,"committed_transactions":8},{"fragment_id":10,"committed_fragments":3,"committed_transactions":12}]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();
    assert!(matches!(
        error,
        StorageError::CatalogInvariantViolation { .. }
    ));
}

#[test]
fn snapshot_catalog_rejects_non_monotonic_snapshot_counters() {
    let file_path = unique_temp_file("paradencer-invalid-counters-catalog", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":14,"snapshots_written":2,"snapshots":[{"fragment_id":12,"committed_fragments":2,"committed_transactions":8},{"fragment_id":14,"committed_fragments":3,"committed_transactions":7}]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();
    assert!(matches!(
        error,
        StorageError::CatalogInvariantViolation { .. }
    ));
}

#[test]
fn snapshot_catalog_migrates_legacy_v1_without_checksum_field() {
    let file_path = unique_temp_file("paradencer-legacy-catalog-v1", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":18,"snapshots_written":1,"snapshots":[{"fragment_id":18,"committed_fragments":3,"committed_transactions":11}]}"#,
    )
    .unwrap();

    let catalog = SnapshotCatalog::load_from_file(&file_path).unwrap();
    fs::remove_file(&file_path).unwrap();
    let snapshot = catalog.restore_latest_snapshot().unwrap();
    assert_eq!(snapshot, SnapshotImage::new(18, 3, 11));
}

#[test]
fn snapshot_catalog_rejects_checksum_mismatch() {
    let file_path = unique_temp_file("paradencer-invalid-checksum-catalog", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":2,"last_snapshot_fragment_id":20,"snapshots_written":1,"snapshots":[{"fragment_id":20,"committed_fragments":4,"committed_transactions":12,"state_checksum":1}]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();
    assert!(matches!(
        error,
        StorageError::SnapshotChecksumMismatch { .. }
    ));
}

#[test]
fn snapshot_catalog_rejects_header_last_fragment_id_mismatch() {
    let file_path = unique_temp_file("paradencer-invalid-header-last-fragment", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":30,"snapshots_written":2,"snapshots":[{"fragment_id":10,"committed_fragments":1,"committed_transactions":3},{"fragment_id":20,"committed_fragments":2,"committed_transactions":7}]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();
    assert!(matches!(
        error,
        StorageError::CatalogInvariantViolation { .. }
    ));
}

#[test]
fn snapshot_catalog_rejects_header_written_count_smaller_than_entries() {
    let file_path = unique_temp_file("paradencer-invalid-header-written-count", "json");
    fs::write(
        &file_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":20,"snapshots_written":1,"snapshots":[{"fragment_id":10,"committed_fragments":1,"committed_transactions":3},{"fragment_id":20,"committed_fragments":2,"committed_transactions":7}]}"#,
    )
    .unwrap();

    let error = SnapshotCatalog::load_from_file(&file_path).unwrap_err();
    fs::remove_file(&file_path).unwrap();
    assert!(matches!(
        error,
        StorageError::CatalogInvariantViolation { .. }
    ));
}

#[test]
fn snapshot_catalog_rewind_prunes_newer_snapshots() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();

    for fragment_id in [10_u64, 20, 30] {
        let record = CommittedFragmentRecord {
            fragment_id,
            transaction_count: 1,
            total_cost_units: 1,
        };
        store.apply_committed_fragment(&record).unwrap();
        catalog.write_snapshot(fragment_id, &store).unwrap();
    }

    let removed = catalog.rewind_to_fragment(20);
    assert_eq!(removed, 1);
    assert!(catalog.restore_snapshot(30).is_err());
    assert_eq!(catalog.restore_snapshot(20).unwrap().fragment_id, 20);
    assert_eq!(catalog.last_snapshot_fragment_id, 20);
    assert_eq!(catalog.snapshots_written, 3);
}

#[test]
fn snapshot_catalog_rewind_to_zero_clears_all_snapshots() {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();

    for fragment_id in [1_u64, 2, 3] {
        let record = CommittedFragmentRecord {
            fragment_id,
            transaction_count: 1,
            total_cost_units: 1,
        };
        store.apply_committed_fragment(&record).unwrap();
        catalog.write_snapshot(fragment_id, &store).unwrap();
    }

    let removed = catalog.rewind_to_fragment(0);
    assert_eq!(removed, 3);
    assert!(catalog.restore_latest_snapshot().is_none());
    assert_eq!(catalog.last_snapshot_fragment_id, 0);
    assert_eq!(catalog.snapshots_written, 3);
}
