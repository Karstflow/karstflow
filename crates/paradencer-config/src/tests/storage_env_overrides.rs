use crate::parts::{
    build_storage_runtime_policy_with_overrides, parse_node_profile_toml, StorageEnvOverrides,
};
use paradencer_execution::{AccountStateApplyPolicy, ProgramCacheApplyPolicy};
use paradencer_stages::{ExecutionEnginePolicy, ExecutionErrorHandlingPolicy};
#[test]
fn storage_runtime_policy_env_overrides_take_precedence_over_profile_retry_controls() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
max_retry_attempts = 4
retry_backoff_cap_millis = 700
"#,
    )
    .unwrap();
    let env_overrides = StorageEnvOverrides {
        startup_strict_restore_latest_requires_snapshot: Some(true),
        startup_strict_restore_specific_requires_snapshot: Some(true),
        snapshot_max_catalog_entries: Some(77),
        assembly_max_fragment_transactions: Some(33),
        assembly_max_fragment_cost_units: Some(96_000),
        assembly_max_fragment_wait_ticks: Some(5),
        max_retry_attempts: Some(9),
        retry_backoff_cap_millis: Some(120),
        execution_transient_base_delay_millis: Some(77),
        execution_max_replay_conflict_attempts: Some(6),
        execution_max_transient_attempts: Some(5),
        execution_max_resource_attempts: Some(2),
        execution_max_fallback_attempts: Some(4),
        leader_schedule_enabled: Some(true),
        leader_slot_cycle_length: Some(16),
        leader_slots_per_cycle: Some(4),
        leader_initial_slot: Some(7),
        leader_hold_retry_delay_millis: Some(11),
        scheduler_enabled: Some(true),
        scheduler_slot_duration_millis: Some(70),
        scheduler_priority_penalty_class_2_millis: Some(90),
        scheduler_priority_penalty_class_3_millis: Some(180),
        fork_choice_enabled: Some(true),
        fork_choice_reorg_retry_delay_millis: Some(160),
        fork_choice_max_reorg_retry_attempts: Some(6),
        fork_choice_hold_requires_confirmed_candidate: Some(true),
        fork_choice_quarantine_enabled: Some(true),
        fork_choice_quarantine_consecutive_reorg_threshold: Some(5),
        fork_choice_quarantine_ticks: Some(17),
        execution_health_enabled: Some(true),
        execution_health_transient_failure_threshold: Some(5),
        execution_health_cooldown_ticks: Some(21),
        replay_safety_enabled: Some(true),
        replay_safety_conflict_threshold: Some(4),
        replay_safety_hold_ticks: Some(15),
        replay_controller_candidate_confirmation_threshold: Some(5),
        replay_controller_candidate_confirmation_max_failed_ratio_bps: Some(7777),
        replay_controller_max_candidates: Some(21),
        replay_controller_reorg_signal_weight: Some(333),
        replay_controller_fragment_recency_weight: Some(9),
        replay_controller_failed_transaction_ratio_penalty_weight: Some(44),
        replay_controller_candidate_stale_fragment_lag: Some(256),
        replay_controller_candidate_switch_min_score_delta: Some(512),
        replay_window_max_checkpoints: Some(96),
        replay_window_rewind_on_confirmed_reorg: Some(true),
        ..StorageEnvOverrides::default()
    };

    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert!(
        built
            .startup_strict_restore_policy
            .restore_latest_requires_snapshot
    );
    assert!(
        built
            .startup_strict_restore_policy
            .restore_specific_requires_snapshot
    );
    assert_eq!(built.snapshot_retention_policy.max_catalog_snapshots, 77);
    assert_eq!(built.assembly_policy.max_fragment_transactions, 33);
    assert_eq!(built.assembly_policy.max_fragment_cost_units, 96_000);
    assert_eq!(built.assembly_policy.max_fragment_wait_ticks, 5);
    assert_eq!(built.max_retry_attempts, 9);
    assert_eq!(built.retry_backoff_cap_millis, 120);
    assert_eq!(built.execution_retry_policy.transient_base_delay_millis, 77);
    assert_eq!(built.execution_retry_policy.max_retries_replay_conflict, 6);
    assert_eq!(
        built.execution_retry_policy.max_retries_transient_pressure,
        5
    );
    assert_eq!(
        built.execution_retry_policy.max_retries_resource_exhaustion,
        2
    );
    assert_eq!(built.execution_retry_policy.max_retries_fallback, 4);
    assert!(built.leader_schedule_policy.enabled);
    assert_eq!(built.leader_schedule_policy.slot_cycle_length, 16);
    assert_eq!(built.leader_schedule_policy.leader_slots_per_cycle, 4);
    assert_eq!(built.leader_schedule_policy.initial_slot, 7);
    assert_eq!(built.leader_schedule_policy.hold_retry_delay_millis, 11);
    assert!(built.scheduler_runtime_policy.enabled);
    assert_eq!(built.scheduler_runtime_policy.slot_duration_millis, 70);
    assert_eq!(
        built
            .scheduler_runtime_policy
            .priority_penalty_class_2_millis,
        90
    );
    assert_eq!(
        built
            .scheduler_runtime_policy
            .priority_penalty_class_3_millis,
        180
    );
    assert!(built.fork_choice_runtime_policy.enabled);
    assert_eq!(
        built.fork_choice_runtime_policy.reorg_retry_delay_millis,
        160
    );
    assert_eq!(built.fork_choice_runtime_policy.max_reorg_retry_attempts, 6);
    assert!(
        built
            .fork_choice_runtime_policy
            .hold_requires_confirmed_candidate
    );
    assert!(built.fork_choice_quarantine_policy.enabled);
    assert_eq!(
        built
            .fork_choice_quarantine_policy
            .consecutive_reorg_threshold,
        5
    );
    assert_eq!(built.fork_choice_quarantine_policy.quarantine_ticks, 17);
    assert!(built.execution_health_policy.enabled);
    assert_eq!(built.execution_health_policy.transient_failure_threshold, 5);
    assert_eq!(built.execution_health_policy.cooldown_ticks, 21);
    assert!(built.replay_safety_policy.enabled);
    assert_eq!(built.replay_safety_policy.replay_conflict_threshold, 4);
    assert_eq!(built.replay_safety_policy.hold_ticks, 15);
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_confirmation_threshold,
        5
    );
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_confirmation_max_failed_ratio_bps,
        7_777
    );
    assert_eq!(built.replay_controller_policy.max_candidates, 21);
    assert_eq!(built.replay_controller_policy.reorg_signal_weight, 333);
    assert_eq!(built.replay_controller_policy.fragment_recency_weight, 9);
    assert_eq!(
        built
            .replay_controller_policy
            .failed_transaction_ratio_penalty_weight,
        44
    );
    assert_eq!(
        built.replay_controller_policy.candidate_stale_fragment_lag,
        256
    );
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_switch_min_score_delta,
        512
    );
    assert_eq!(built.replay_window_policy.max_checkpoints, 96);
    assert!(built.replay_window_policy.rewind_on_confirmed_reorg);
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_retry_attempts() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        max_retry_attempts: Some(0),
        ..StorageEnvOverrides::default()
    };

    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        execution_max_replay_conflict_attempts: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_apply_execution_engine_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_engine_policy: Some("heuristic".to_string()),
        ..StorageEnvOverrides::default()
    };
    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert_eq!(
        built.execution_engine_policy,
        ExecutionEnginePolicy::Heuristic
    );
}

#[test]
fn storage_runtime_policy_env_overrides_reject_unknown_execution_engine_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_engine_policy: Some("unknown".to_string()),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_apply_runtime_like_execution_engine_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_engine_policy: Some("runtime_like".to_string()),
        ..StorageEnvOverrides::default()
    };
    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert_eq!(
        built.execution_engine_policy,
        ExecutionEnginePolicy::RuntimeLike
    );
}

#[test]
fn storage_runtime_policy_env_overrides_apply_execution_error_handling_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_error_handling_policy: Some("fail_fast".to_string()),
        ..StorageEnvOverrides::default()
    };
    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert_eq!(
        built.execution_error_handling_policy,
        ExecutionErrorHandlingPolicy::FailFast
    );
}

#[test]
fn storage_runtime_policy_env_overrides_reject_unknown_execution_error_handling_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_error_handling_policy: Some("oops".to_string()),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_apply_fail_open_max_consecutive_execution_errors() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_error_fail_open_max_consecutive: Some(9),
        ..StorageEnvOverrides::default()
    };
    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert_eq!(built.execution_error_fail_open_max_consecutive, 9);
}

#[test]
fn storage_runtime_policy_env_overrides_apply_runtime_like_channel_policies() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        runtime_like_account_state_apply_policy: Some("lenient".to_string()),
        runtime_like_program_cache_apply_policy: Some("lenient".to_string()),
        ..StorageEnvOverrides::default()
    };
    let built =
        build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).unwrap();
    assert_eq!(
        built.runtime_like_account_state_apply_policy,
        AccountStateApplyPolicy::Lenient
    );
    assert_eq!(
        built.runtime_like_program_cache_apply_policy,
        ProgramCacheApplyPolicy::Lenient
    );
}

#[test]
fn storage_runtime_policy_env_overrides_reject_unknown_runtime_like_channel_policy() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        runtime_like_program_cache_apply_policy: Some("nope".to_string()),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_rejects_strict_restore_without_catalog_path_in_env_overrides() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        startup_policy: Some("restore_latest_if_available".to_string()),
        startup_strict_restore_latest_requires_snapshot: Some(true),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_execution_health_values() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        execution_health_transient_failure_threshold: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        execution_health_cooldown_ticks: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_fork_choice_quarantine_values() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        fork_choice_quarantine_consecutive_reorg_threshold: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        fork_choice_quarantine_ticks: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_replay_safety_values() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        replay_safety_conflict_threshold: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_safety_hold_ticks: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_replay_controller_values() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        replay_controller_candidate_confirmation_threshold: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_candidate_confirmation_max_failed_ratio_bps: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_max_candidates: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_reorg_signal_weight: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_fragment_recency_weight: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_failed_transaction_ratio_penalty_weight: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_candidate_stale_fragment_lag: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());

    let env_overrides = StorageEnvOverrides {
        replay_controller_candidate_switch_min_score_delta: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_replay_window_values() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        replay_window_max_checkpoints: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}

#[test]
fn storage_runtime_policy_env_overrides_reject_zero_snapshot_max_catalog_entries() {
    let profile = parse_node_profile_toml("").unwrap();
    let env_overrides = StorageEnvOverrides {
        snapshot_max_catalog_entries: Some(0),
        ..StorageEnvOverrides::default()
    };
    assert!(build_storage_runtime_policy_with_overrides(Some(&profile), &env_overrides).is_err());
}
