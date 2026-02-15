use crate::{RuntimeStateApplyReceipt, RuntimeStateApplyRequest, RuntimeStateStore, StorageError};

#[test]
fn runtime_state_store_applies_effects() {
    let mut store = RuntimeStateStore::new();
    let receipt = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 11,
            account_writes: 32,
            account_data_bytes: 16_384,
            rent_epoch_updates: 4,
            program_loads: 7,
            program_evictions: 2,
            program_invalidations: 1,
        })
        .unwrap();

    assert_eq!(receipt.fragment_id, 11);
    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 11);
    assert_eq!(snapshot.total_account_writes, 32);
    assert_eq!(snapshot.total_account_data_bytes, 16_384);
    assert_eq!(snapshot.total_rent_epoch_updates, 4);
    assert_eq!(snapshot.total_program_loads, 7);
    assert_eq!(snapshot.total_program_evictions, 2);
    assert_eq!(snapshot.total_program_invalidations, 1);
}

#[test]
fn runtime_state_store_rolls_back_effects() {
    let mut store = RuntimeStateStore::new();
    let receipt = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 19,
            account_writes: 10,
            account_data_bytes: 4_096,
            rent_epoch_updates: 2,
            program_loads: 5,
            program_evictions: 1,
            program_invalidations: 1,
        })
        .unwrap();
    store.rollback_effects(receipt).unwrap();

    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 0);
    assert_eq!(snapshot.total_account_writes, 0);
    assert_eq!(snapshot.total_account_data_bytes, 0);
    assert_eq!(snapshot.total_rent_epoch_updates, 0);
    assert_eq!(snapshot.total_program_loads, 0);
    assert_eq!(snapshot.total_program_evictions, 0);
    assert_eq!(snapshot.total_program_invalidations, 0);
}

#[test]
fn runtime_state_store_rejects_fragment_regression() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 23,
            account_writes: 4,
            account_data_bytes: 1_024,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    let error = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 22,
            account_writes: 4,
            account_data_bytes: 1_024,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::FragmentRegression {
            last_fragment_id: 23,
            new_fragment_id: 22
        }
    );
}

#[test]
fn runtime_state_store_rejects_duplicate_fragment_id() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 31,
            account_writes: 8,
            account_data_bytes: 2_048,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    let error = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 31,
            account_writes: 8,
            account_data_bytes: 2_048,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::FragmentRegression {
            last_fragment_id: 31,
            new_fragment_id: 31
        }
    );
}

#[test]
fn runtime_state_store_rejects_out_of_order_rollback() {
    let mut store = RuntimeStateStore::new();
    let receipt_41 = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 41,
            account_writes: 12,
            account_data_bytes: 3_072,
            rent_epoch_updates: 1,
            program_loads: 3,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    let _receipt_42 = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 42,
            account_writes: 10,
            account_data_bytes: 2_560,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 1,
            program_invalidations: 0,
        })
        .unwrap();
    let error = store.rollback_effects(receipt_41).unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateRollbackOrderViolation {
            expected_last_fragment_id: 42,
            receipt_fragment_id: 41
        }
    );
}

#[test]
fn runtime_state_store_rejects_invalid_receipt_previous_fragment_invariant() {
    let mut store = RuntimeStateStore::new();
    let _ = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 60,
            account_writes: 1,
            account_data_bytes: 1,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    let error = store
        .rollback_effects(crate::RuntimeStateApplyReceipt {
            fragment_id: 60,
            previous_last_fragment_id: 60,
            account_writes: 1,
            account_data_bytes: 1,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateReceiptInvariantViolation {
            receipt_fragment_id: 60,
            previous_last_fragment_id: 60
        }
    );
}

#[test]
fn runtime_state_store_rejects_underflow_during_rollback() {
    let mut store = RuntimeStateStore::new();
    let error = store
        .rollback_effects(crate::RuntimeStateApplyReceipt {
            fragment_id: 1,
            previous_last_fragment_id: 0,
            account_writes: 1,
            account_data_bytes: 0,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateRollbackOrderViolation {
            expected_last_fragment_id: 0,
            receipt_fragment_id: 1
        }
    );
}

#[test]
fn runtime_state_store_rejects_counter_overflow_during_apply() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 50,
            account_writes: 1,
            account_data_bytes: u64::MAX,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    let error = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 51,
            account_writes: 0,
            account_data_bytes: 1,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::StateCounterOverflow {
            field: "total_account_data_bytes",
            current: u64::MAX,
            delta: 1,
        }
    );
    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 50);
    assert_eq!(snapshot.total_account_data_bytes, u64::MAX);
}

#[test]
fn runtime_state_store_rewind_to_fragment_rolls_back_multiple_steps() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 101,
            account_writes: 3,
            account_data_bytes: 300,
            rent_epoch_updates: 1,
            program_loads: 2,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 102,
            account_writes: 5,
            account_data_bytes: 500,
            rent_epoch_updates: 1,
            program_loads: 3,
            program_evictions: 1,
            program_invalidations: 0,
        })
        .unwrap();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 103,
            account_writes: 7,
            account_data_bytes: 700,
            rent_epoch_updates: 2,
            program_loads: 4,
            program_evictions: 1,
            program_invalidations: 1,
        })
        .unwrap();

    let rolled_back = store.rewind_to_fragment(101).unwrap();
    assert_eq!(rolled_back, 2);

    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 101);
    assert_eq!(snapshot.total_account_writes, 3);
    assert_eq!(snapshot.total_account_data_bytes, 300);
    assert_eq!(snapshot.total_rent_epoch_updates, 1);
    assert_eq!(snapshot.total_program_loads, 2);
    assert_eq!(snapshot.total_program_evictions, 0);
    assert_eq!(snapshot.total_program_invalidations, 0);
}

#[test]
fn runtime_state_store_rewind_to_zero_clears_all_applied_effects() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 201,
            account_writes: 4,
            account_data_bytes: 256,
            rent_epoch_updates: 1,
            program_loads: 1,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 202,
            account_writes: 6,
            account_data_bytes: 512,
            rent_epoch_updates: 2,
            program_loads: 2,
            program_evictions: 1,
            program_invalidations: 1,
        })
        .unwrap();

    let rolled_back = store.rewind_to_fragment(0).unwrap();
    assert_eq!(rolled_back, 2);

    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 0);
    assert_eq!(snapshot.total_account_writes, 0);
    assert_eq!(snapshot.total_account_data_bytes, 0);
    assert_eq!(snapshot.total_rent_epoch_updates, 0);
    assert_eq!(snapshot.total_program_loads, 0);
    assert_eq!(snapshot.total_program_evictions, 0);
    assert_eq!(snapshot.total_program_invalidations, 0);
}

#[test]
fn runtime_state_store_rewind_rejects_target_ahead_of_current() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 301,
            account_writes: 1,
            account_data_bytes: 64,
            rent_epoch_updates: 0,
            program_loads: 0,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();

    let error = store.rewind_to_fragment(302).unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateRewindTargetAhead {
            current_last_fragment_id: 301,
            target_fragment_id: 302
        }
    );
}

#[test]
fn runtime_state_store_rejects_mismatched_rollback_receipt_payload() {
    let mut store = RuntimeStateStore::new();
    let _receipt = store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 401,
            account_writes: 2,
            account_data_bytes: 128,
            rent_epoch_updates: 0,
            program_loads: 1,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();

    let error = store
        .rollback_effects(crate::RuntimeStateApplyReceipt {
            fragment_id: 401,
            previous_last_fragment_id: 0,
            account_writes: 3,
            account_data_bytes: 128,
            rent_epoch_updates: 0,
            program_loads: 1,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateReceiptMismatch {
            expected_fragment_id: 401,
            provided_fragment_id: 401
        }
    );
}

#[test]
fn runtime_state_store_seed_checkpoint_sets_rewind_floor() {
    let mut store = RuntimeStateStore::new();
    store.seed_checkpoint(700);

    let rolled_back = store.rewind_to_fragment(700).unwrap();
    assert_eq!(rolled_back, 0);
    assert_eq!(store.snapshot().last_fragment_id, 700);

    let error = store.rewind_to_fragment(699).unwrap_err();
    assert_eq!(
        error,
        StorageError::RuntimeStateRewindTargetBelowFloor {
            rewind_floor_fragment_id: 700,
            target_fragment_id: 699
        }
    );
}

#[test]
fn runtime_state_store_seed_checkpoint_keeps_floor_on_rewind() {
    let mut store = RuntimeStateStore::new();
    store.seed_checkpoint(800);
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 801,
            account_writes: 2,
            account_data_bytes: 128,
            rent_epoch_updates: 1,
            program_loads: 1,
            program_evictions: 0,
            program_invalidations: 0,
        })
        .unwrap();

    let rolled_back = store.rewind_to_fragment(800).unwrap();
    assert_eq!(rolled_back, 1);
    assert_eq!(store.snapshot().last_fragment_id, 800);
}

#[test]
fn runtime_state_store_seed_checkpoint_resets_accumulated_totals() {
    let mut store = RuntimeStateStore::new();
    store
        .apply_effects(RuntimeStateApplyRequest {
            fragment_id: 100,
            account_writes: 9,
            account_data_bytes: 999,
            rent_epoch_updates: 4,
            program_loads: 3,
            program_evictions: 2,
            program_invalidations: 1,
        })
        .unwrap();

    store.seed_checkpoint(500);
    let snapshot = store.snapshot();
    assert_eq!(snapshot.last_fragment_id, 500);
    assert_eq!(snapshot.total_account_writes, 0);
    assert_eq!(snapshot.total_account_data_bytes, 0);
    assert_eq!(snapshot.total_rent_epoch_updates, 0);
    assert_eq!(snapshot.total_program_loads, 0);
    assert_eq!(snapshot.total_program_evictions, 0);
    assert_eq!(snapshot.total_program_invalidations, 0);

    let error = store.rollback_effects(RuntimeStateApplyReceipt {
        fragment_id: 100,
        previous_last_fragment_id: 99,
        account_writes: 9,
        account_data_bytes: 999,
        rent_epoch_updates: 4,
        program_loads: 3,
        program_evictions: 2,
        program_invalidations: 1,
    });
    assert!(matches!(
        error.unwrap_err(),
        StorageError::RuntimeStateRollbackOrderViolation { .. }
    ));
}
