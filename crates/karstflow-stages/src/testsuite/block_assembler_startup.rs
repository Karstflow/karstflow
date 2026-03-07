use super::*;
use karstflow_mesh::DualReceiver;

#[test]
fn block_assembler_persists_snapshot_catalog_when_path_is_configured() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound.clone()),
        StorageRuntimePolicy {
            snapshot_interval: 1,
            startup_policy: StorageStartupPolicy::SkipRestore,
            snapshot_catalog_path: Some(unique_temp_file("karstflow-catalog", "json")),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());
    let catalog_path = block_assembler
        .storage_runtime_policy
        .snapshot_catalog_path
        .clone()
        .unwrap();

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    let persisted_catalog = SnapshotCatalog::load_from_file(&catalog_path).unwrap();
    fs::remove_file(&catalog_path).unwrap();
    let latest_snapshot = persisted_catalog.restore_latest_snapshot().unwrap();
    assert_eq!(latest_snapshot.fragment_id, 1);
}

#[test]
fn block_assembler_prunes_old_catalog_snapshots_when_retention_is_enabled() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(256);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound.clone()),
        StorageRuntimePolicy {
            snapshot_interval: 1,
            snapshot_retention_policy: SnapshotRetentionPolicy {
                max_catalog_snapshots: 2,
            },
            startup_policy: StorageStartupPolicy::SkipRestore,
            snapshot_catalog_path: Some(unique_temp_file("karstflow-catalog-retain", "json")),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());
    let catalog_path = block_assembler
        .storage_runtime_policy
        .snapshot_catalog_path
        .clone()
        .unwrap();

    for transaction_id in 1..=192_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    let persisted_catalog = SnapshotCatalog::load_from_file(&catalog_path).unwrap();
    fs::remove_file(&catalog_path).unwrap();

    assert!(persisted_catalog.restore_snapshot(1).is_err());
    assert_eq!(
        persisted_catalog.restore_snapshot(2).unwrap().fragment_id,
        2
    );
    assert_eq!(
        persisted_catalog.restore_snapshot(3).unwrap().fragment_id,
        3
    );
}

#[test]
fn block_assembler_restore_latest_initializes_runtime_state_from_catalog() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-restore-latest", "json");
    write_catalog_with_fragments(&catalog_path, &[3, 7]);

    let block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_interval: 256,
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.fragment_counter, 7);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 7);
    assert_eq!(
        block_assembler
            .replay_boundary_state
            .last_applied_fragment_id,
        7
    );
    assert_eq!(block_assembler.replay_window_checkpoint_depth(), 1);
}

#[test]
fn block_assembler_restore_specific_initializes_runtime_state_from_catalog() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-restore-specific", "json");
    write_catalog_with_fragments(&catalog_path, &[4, 9]);

    let block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_interval: 256,
            startup_policy: StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id: 4 },
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.fragment_counter, 4);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 4);
    assert_eq!(
        block_assembler
            .replay_boundary_state
            .last_applied_fragment_id,
        4
    );
    assert_eq!(block_assembler.replay_window_checkpoint_depth(), 1);
}

#[test]
fn block_assembler_restore_latest_seeds_slot_and_leader_positions_from_checkpoint() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-restore-slot-leader", "json");
    write_catalog_with_fragments(&catalog_path, &[3, 7]);

    let block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.slot_pipeline_slot(), 7);
    assert_eq!(block_assembler.next_leader_slot(), 7);
}

#[test]
fn block_assembler_restore_respects_higher_configured_initial_slot_floor() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-restore-slot-floor", "json");
    write_catalog_with_fragments(&catalog_path, &[2, 4]);

    let block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            leader_schedule_policy: LeaderSchedulePolicy {
                enabled: true,
                slot_cycle_length: 4,
                leader_slots_per_cycle: 2,
                hold_retry_delay_millis: 10,
                initial_slot: 11,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.slot_pipeline_slot(), 11);
    assert_eq!(block_assembler.next_leader_slot(), 11);
}

#[test]
fn block_assembler_runtime_like_restore_latest_commits_next_fragment_without_drift() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let catalog_path = unique_temp_file("karstflow-runtime-like-restore-latest", "json");
    write_catalog_with_fragments(&catalog_path, &[3, 7]);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            execution_engine_policy: ExecutionEnginePolicy::RuntimeLike,
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    assert_eq!(block_assembler.fragment_counter, 7);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 7);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 2);
    assert_eq!(block_assembler.hot_state_store.committed_transactions, 10);

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.fragment_counter, 8);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 8);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 3);
    assert_eq!(block_assembler.hot_state_store.committed_transactions, 74);
    assert_eq!(
        block_assembler
            .replay_boundary_state
            .last_applied_fragment_id,
        8
    );
}

#[test]
fn block_assembler_strict_restore_latest_fails_when_snapshot_missing() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let startup = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            startup_strict_restore_policy: crate::StorageStartupStrictRestorePolicy {
                restore_latest_requires_snapshot: true,
                restore_specific_requires_snapshot: false,
            },
            ..test_storage_runtime_policy()
        },
    );

    let error = match startup {
        Ok(_) => panic!("strict restore_latest without catalog path must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires snapshot catalog path"));
}

#[test]
fn block_assembler_strict_restore_specific_without_catalog_path_fails_preflight() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let startup = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id: 4 },
            startup_strict_restore_policy: crate::StorageStartupStrictRestorePolicy {
                restore_latest_requires_snapshot: false,
                restore_specific_requires_snapshot: true,
            },
            ..test_storage_runtime_policy()
        },
    );

    let error = match startup {
        Ok(_) => panic!("strict restore_specific without catalog path must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires snapshot catalog path"));
}

#[test]
fn block_assembler_strict_restore_specific_fails_when_snapshot_missing() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-strict-restore-specific", "json");
    write_catalog_with_fragments(&catalog_path, &[9]);

    let startup = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id: 4 },
            startup_strict_restore_policy: crate::StorageStartupStrictRestorePolicy {
                restore_latest_requires_snapshot: false,
                restore_specific_requires_snapshot: true,
            },
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    );

    fs::remove_file(&catalog_path).unwrap();
    let error = match startup {
        Ok(_) => panic!("strict restore_specific missing snapshot must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("snapshot 4 is unavailable"));
}

#[test]
fn block_assembler_rejects_malformed_snapshot_catalog_on_startup() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-malformed-catalog", "json");
    fs::write(&catalog_path, "{invalid-json").unwrap();

    let error = match BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    ) {
        Ok(_) => panic!("malformed catalog must fail startup"),
        Err(error) => error,
    };

    fs::remove_file(&catalog_path).unwrap();
    assert!(error
        .to_string()
        .contains("failed to load snapshot catalog"));
}

#[test]
fn block_assembler_rejects_truncated_snapshot_catalog_on_startup() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-truncated-catalog", "json");
    fs::write(&catalog_path, r#"{"schema_version":1,"snapshots":["#).unwrap();

    let error = match BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    ) {
        Ok(_) => panic!("truncated catalog must fail startup"),
        Err(error) => error,
    };

    fs::remove_file(&catalog_path).unwrap();
    assert!(error
        .to_string()
        .contains("failed to load snapshot catalog"));
}

#[test]
fn block_assembler_rejects_unknown_catalog_schema_on_startup() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-unknown-schema-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":99,"snapshots":[],"latest_snapshot_fragment_id":null}"#,
    )
    .unwrap();

    let error = match BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    ) {
        Ok(_) => panic!("unknown schema catalog must fail startup"),
        Err(error) => error,
    };

    fs::remove_file(&catalog_path).unwrap();
    assert!(error
        .to_string()
        .contains("failed to load snapshot catalog"));
}

#[test]
fn block_assembler_rejects_catalog_with_invalid_field_shape_on_startup() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-invalid-shape-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":1,"snapshots":"broken","latest_snapshot_fragment_id":null}"#,
    )
    .unwrap();

    let error = match BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    ) {
        Ok(_) => panic!("invalid-shape catalog must fail startup"),
        Err(error) => error,
    };

    fs::remove_file(&catalog_path).unwrap();
    assert!(error
        .to_string()
        .contains("failed to load snapshot catalog"));
}

#[test]
fn block_assembler_restores_after_catalog_is_rewritten_from_corrupt_to_valid() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(8);
    let catalog_path = unique_temp_file("karstflow-recovery-catalog", "json");
    fs::write(&catalog_path, r#"{"schema_version":1,"snapshots":["#).unwrap();

    let failed_startup = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound.clone()),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    );
    assert!(failed_startup.is_err());

    write_catalog_with_fragments(&catalog_path, &[5, 12]);
    let restored = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
            snapshot_catalog_path: Some(catalog_path.clone()),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(restored.fragment_counter, 12);
    assert_eq!(restored.hot_state_store.last_fragment_id, 12);
    assert_eq!(restored.replay_boundary_state.last_applied_fragment_id, 12);
}

#[test]
fn block_assembler_returns_runtime_error_when_catalog_parent_is_missing() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let missing_parent = unique_temp_file("karstflow-missing-catalog-parent", "dir");
    let catalog_path = missing_parent.join("catalog.json");
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_interval: 1,
            snapshot_catalog_path: Some(catalog_path),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());
    let mut failure = None;

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        if let Err(error) = block_assembler.tick(&context) {
            failure = Some(error);
            break;
        }
    }

    let error = failure.expect("catalog persist failure expected");
    assert!(error
        .to_string()
        .contains("failed to persist snapshot catalog"));
}

#[cfg(unix)]
#[test]
fn block_assembler_returns_runtime_error_when_catalog_parent_is_not_writable() {
    use std::os::unix::fs::PermissionsExt;

    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let restricted_parent = unique_temp_file("karstflow-catalog-no-write", "dir");
    fs::create_dir_all(&restricted_parent).unwrap();
    let mut permissions = fs::metadata(&restricted_parent).unwrap().permissions();
    permissions.set_mode(0o500);
    fs::set_permissions(&restricted_parent, permissions).unwrap();

    let catalog_path = restricted_parent.join("catalog.json");
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            snapshot_interval: 1,
            snapshot_catalog_path: Some(catalog_path),
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());
    let mut failure = None;

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        if let Err(error) = block_assembler.tick(&context) {
            failure = Some(error);
            break;
        }
    }

    let mut cleanup_permissions = fs::metadata(&restricted_parent).unwrap().permissions();
    cleanup_permissions.set_mode(0o700);
    fs::set_permissions(&restricted_parent, cleanup_permissions).unwrap();
    fs::remove_dir_all(&restricted_parent).unwrap();

    let error = failure.expect("catalog persist failure expected");
    assert!(error
        .to_string()
        .contains("failed to persist snapshot catalog"));
}
