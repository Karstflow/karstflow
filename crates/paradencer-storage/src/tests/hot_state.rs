use crate::{CommittedFragmentRecord, HotStateStore, SnapshotImage, StorageError};

#[test]
fn hot_state_store_applies_committed_fragment() {
    let mut store = HotStateStore::new();
    let record = CommittedFragmentRecord {
        fragment_id: 5,
        transaction_count: 64,
        total_cost_units: 512_000,
    };

    store.apply_committed_fragment(&record).unwrap();
    assert_eq!(store.last_fragment_id, 5);
    assert_eq!(store.committed_fragments, 1);
    assert_eq!(store.committed_transactions, 64);
}

#[test]
fn hot_state_store_rejects_fragment_regression() {
    let mut store = HotStateStore::new();
    let first = CommittedFragmentRecord {
        fragment_id: 8,
        transaction_count: 16,
        total_cost_units: 128_000,
    };
    let second = CommittedFragmentRecord {
        fragment_id: 7,
        transaction_count: 16,
        total_cost_units: 128_000,
    };

    store.apply_committed_fragment(&first).unwrap();
    let error = store.apply_committed_fragment(&second).unwrap_err();
    assert_eq!(
        error,
        StorageError::FragmentRegression {
            last_fragment_id: 8,
            new_fragment_id: 7
        }
    );
}

#[test]
fn hot_state_can_restore_from_snapshot_image() {
    let snapshot = SnapshotImage::new(33, 7, 512);
    let mut store = HotStateStore::new();
    store.restore_from_snapshot(&snapshot);

    assert_eq!(store.last_fragment_id, 33);
    assert_eq!(store.committed_fragments, 7);
    assert_eq!(store.committed_transactions, 512);
}

#[test]
fn hot_state_store_rejects_counter_overflow_on_committed_fragments() {
    let mut store = HotStateStore::new();
    store.restore_from_snapshot(&SnapshotImage::new(99, u64::MAX, 0));
    let error = store
        .apply_committed_fragment(&CommittedFragmentRecord {
            fragment_id: 100,
            transaction_count: 1,
            total_cost_units: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::StateCounterOverflow {
            field: "committed_fragments",
            current: u64::MAX,
            delta: 1,
        }
    );
    assert_eq!(store.last_fragment_id, 99);
    assert_eq!(store.committed_fragments, u64::MAX);
    assert_eq!(store.committed_transactions, 0);
}
