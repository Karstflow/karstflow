use crate::parts::{
    build_storage_runtime_policy, parse_node_profile_toml, parse_storage_startup_policy,
};
use karstflow_execution::{AccountStateApplyPolicy, ProgramCacheApplyPolicy};
use karstflow_stages::{ExecutionEnginePolicy, ExecutionErrorHandlingPolicy, StorageStartupPolicy};
#[test]
fn storage_startup_policy_parser_accepts_aliases() {
    assert_eq!(
        parse_storage_startup_policy("skip_restore", None).unwrap(),
        StorageStartupPolicy::SkipRestore
    );
    assert_eq!(
        parse_storage_startup_policy("restore_latest_if_available", None).unwrap(),
        StorageStartupPolicy::RestoreLatestIfAvailable
    );
    assert_eq!(
        parse_storage_startup_policy("restore_specific", Some(77)).unwrap(),
        StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id: 77 }
    );
}

#[test]
fn storage_startup_policy_parser_requires_fragment_id_for_specific_restore() {
    let parsed = parse_storage_startup_policy("restore_specific_if_available", None);
    assert!(parsed.is_err());
}

#[test]
fn storage_runtime_policy_rejects_strict_restore_without_catalog_path_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
startup_policy = "restore_latest_if_available"
startup_strict_restore_latest_requires_snapshot = true
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_builds_retry_controls_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
assembly_max_fragment_transactions = 21
assembly_max_fragment_cost_units = 64000
assembly_max_fragment_wait_ticks = 6
snapshot_max_catalog_entries = 99
startup_strict_restore_latest_requires_snapshot = true
startup_strict_restore_specific_requires_snapshot = true
max_retry_attempts = 7
retry_backoff_cap_millis = 900
execution_replay_conflict_delay_millis = 13
execution_resource_cap_millis = 3210
execution_max_replay_conflict_attempts = 6
execution_max_transient_attempts = 5
execution_max_resource_attempts = 2
execution_max_fallback_attempts = 4
execution_health_enabled = true
execution_health_transient_failure_threshold = 3
execution_health_cooldown_ticks = 12
replay_safety_enabled = true
replay_safety_conflict_threshold = 2
replay_safety_hold_ticks = 9
replay_controller_candidate_confirmation_threshold = 3
replay_controller_candidate_confirmation_max_failed_ratio_bps = 7777
replay_controller_max_candidates = 12
replay_controller_reorg_signal_weight = 200
replay_controller_fragment_recency_weight = 5
replay_controller_failed_transaction_ratio_penalty_weight = 77
replay_controller_candidate_stale_fragment_lag = 222
replay_controller_candidate_switch_min_score_delta = 333
replay_window_max_checkpoints = 64
replay_window_rewind_on_confirmed_reorg = true
leader_schedule_enabled = true
leader_slot_cycle_length = 8
leader_slots_per_cycle = 2
leader_initial_slot = 3
leader_hold_retry_delay_millis = 9
scheduler_enabled = true
scheduler_slot_duration_millis = 40
scheduler_priority_penalty_class_2_millis = 100
scheduler_priority_penalty_class_3_millis = 250
fork_choice_enabled = true
fork_choice_reorg_retry_delay_millis = 140
fork_choice_max_reorg_retry_attempts = 5
fork_choice_hold_requires_confirmed_candidate = true
fork_choice_quarantine_enabled = true
fork_choice_quarantine_consecutive_reorg_threshold = 3
fork_choice_quarantine_ticks = 14
"#,
    )
    .unwrap();

    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(built.assembly_policy.max_fragment_transactions, 21);
    assert_eq!(built.assembly_policy.max_fragment_cost_units, 64_000);
    assert_eq!(built.assembly_policy.max_fragment_wait_ticks, 6);
    assert_eq!(built.snapshot_retention_policy.max_catalog_snapshots, 99);
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
    assert_eq!(built.max_retry_attempts, 7);
    assert_eq!(built.retry_backoff_cap_millis, 900);
    assert_eq!(
        built.execution_retry_policy.replay_conflict_delay_millis,
        13
    );
    assert_eq!(built.execution_retry_policy.resource_cap_millis, 3210);
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
    assert!(built.execution_health_policy.enabled);
    assert_eq!(built.execution_health_policy.transient_failure_threshold, 3);
    assert_eq!(built.execution_health_policy.cooldown_ticks, 12);
    assert!(built.replay_safety_policy.enabled);
    assert_eq!(built.replay_safety_policy.replay_conflict_threshold, 2);
    assert_eq!(built.replay_safety_policy.hold_ticks, 9);
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_confirmation_threshold,
        3
    );
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_confirmation_max_failed_ratio_bps,
        7_777
    );
    assert_eq!(built.replay_controller_policy.max_candidates, 12);
    assert_eq!(built.replay_controller_policy.reorg_signal_weight, 200);
    assert_eq!(built.replay_controller_policy.fragment_recency_weight, 5);
    assert_eq!(
        built
            .replay_controller_policy
            .failed_transaction_ratio_penalty_weight,
        77
    );
    assert_eq!(
        built.replay_controller_policy.candidate_stale_fragment_lag,
        222
    );
    assert_eq!(
        built
            .replay_controller_policy
            .candidate_switch_min_score_delta,
        333
    );
    assert_eq!(built.replay_window_policy.max_checkpoints, 64);
    assert!(built.replay_window_policy.rewind_on_confirmed_reorg);
    assert!(built.leader_schedule_policy.enabled);
    assert_eq!(built.leader_schedule_policy.slot_cycle_length, 8);
    assert_eq!(built.leader_schedule_policy.leader_slots_per_cycle, 2);
    assert_eq!(built.leader_schedule_policy.initial_slot, 3);
    assert_eq!(built.leader_schedule_policy.hold_retry_delay_millis, 9);
    assert!(built.scheduler_runtime_policy.enabled);
    assert_eq!(built.scheduler_runtime_policy.slot_duration_millis, 40);
    assert_eq!(
        built
            .scheduler_runtime_policy
            .priority_penalty_class_2_millis,
        100
    );
    assert_eq!(
        built
            .scheduler_runtime_policy
            .priority_penalty_class_3_millis,
        250
    );
    assert!(built.fork_choice_runtime_policy.enabled);
    assert_eq!(
        built.fork_choice_runtime_policy.reorg_retry_delay_millis,
        140
    );
    assert_eq!(built.fork_choice_runtime_policy.max_reorg_retry_attempts, 5);
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
        3
    );
    assert_eq!(built.fork_choice_quarantine_policy.quarantine_ticks, 14);
}

#[test]
fn storage_runtime_policy_rejects_zero_retry_attempts() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
max_retry_attempts = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_assembly_limits_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
assembly_max_fragment_transactions = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
assembly_max_fragment_cost_units = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
assembly_max_fragment_wait_ticks = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_execution_retry_delay_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_replay_conflict_delay_millis = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_max_replay_conflict_attempts = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_parses_execution_engine_policy_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_engine_policy = "heuristic"
"#,
    )
    .unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(
        built.execution_engine_policy,
        ExecutionEnginePolicy::Heuristic
    );
}

#[test]
fn storage_runtime_policy_rejects_unknown_execution_engine_policy_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_engine_policy = "invalid-engine"
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_parses_runtime_like_execution_engine_policy_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_engine_policy = "runtime_like"
"#,
    )
    .unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(
        built.execution_engine_policy,
        ExecutionEnginePolicy::RuntimeLike
    );
}

#[test]
fn storage_runtime_policy_parses_execution_error_handling_policy_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_error_handling_policy = "fail_fast"
"#,
    )
    .unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(
        built.execution_error_handling_policy,
        ExecutionErrorHandlingPolicy::FailFast
    );
}

#[test]
fn storage_runtime_policy_rejects_unknown_execution_error_handling_policy_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_error_handling_policy = "halt"
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_parses_fail_open_max_consecutive_execution_errors_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_error_fail_open_max_consecutive = 7
"#,
    )
    .unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(built.execution_error_fail_open_max_consecutive, 7);
}

#[test]
fn storage_runtime_policy_parses_runtime_like_apply_policies_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
runtime_like_account_state_apply_policy = "lenient"
runtime_like_program_cache_apply_policy = "lenient"
"#,
    )
    .unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
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
fn storage_runtime_policy_rejects_unknown_runtime_like_apply_policy_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
runtime_like_account_state_apply_policy = "fast"
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_leader_cycle_length_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
leader_slot_cycle_length = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_scheduler_slot_duration_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
scheduler_slot_duration_millis = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_fork_choice_reorg_delay_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
fork_choice_reorg_retry_delay_millis = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_fork_choice_reorg_retries_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
fork_choice_max_reorg_retry_attempts = 0
"#,
    )
    .unwrap();

    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_fork_choice_quarantine_values_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
fork_choice_quarantine_consecutive_reorg_threshold = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
fork_choice_quarantine_ticks = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_execution_health_values_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_health_transient_failure_threshold = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_health_cooldown_ticks = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_replay_safety_values_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_safety_conflict_threshold = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_safety_hold_ticks = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_replay_controller_values_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_candidate_confirmation_threshold = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_candidate_confirmation_max_failed_ratio_bps = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_max_candidates = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_reorg_signal_weight = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_fragment_recency_weight = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_failed_transaction_ratio_penalty_weight = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_candidate_stale_fragment_lag = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_controller_candidate_switch_min_score_delta = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_replay_window_max_checkpoints_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
replay_window_max_checkpoints = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_rejects_zero_snapshot_max_catalog_entries_in_profile() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
snapshot_max_catalog_entries = 0
"#,
    )
    .unwrap();
    assert!(build_storage_runtime_policy(Some(&profile)).is_err());
}

#[test]
fn storage_runtime_policy_uses_default_retry_controls_when_profile_is_missing() {
    let profile = parse_node_profile_toml("").unwrap();
    let built = build_storage_runtime_policy(Some(&profile)).unwrap();
    assert_eq!(built.max_retry_attempts, 3);
    assert_eq!(built.retry_backoff_cap_millis, 2_000);
}
