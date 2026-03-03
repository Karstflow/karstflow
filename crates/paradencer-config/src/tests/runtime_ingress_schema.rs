use crate::parts::{
    build_topology_spec, is_routable_socket_addr, is_valid_genesis_hash,
    map_legacy_core_sharing_flag, migrate_ingress_policy_schema, migrate_node_profile_schema,
    parse_cluster_mode, parse_execution_mode, parse_ingress_policy_toml, parse_live_entrypoints,
    parse_metrics_output_format, parse_node_profile_toml, parse_pinned_core_policy,
    validate_identity_keypair_file, validate_live_runtime_spec, validate_metrics_target_preflight,
    validate_storage_startup_preflight,
};
use crate::{ClusterMode, NodeConfig};
use paradencer_core::{ExecutionMode, PinnedCorePolicy, RuntimeSpec};
use paradencer_stages::{
    ExecutionErrorHandlingPolicy, MetricsOutputFormat, MetricsOutputTarget, StorageRuntimePolicy,
    StorageStartupPolicy,
};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_file(prefix: &str, extension: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{suffix}.{extension}"))
}
#[test]
fn execution_mode_defaults_to_tokio() {
    let parsed = parse_execution_mode(None).unwrap();
    assert_eq!(parsed, ExecutionMode::Tokio);
}

#[test]
fn cluster_mode_defaults_to_dev() {
    let parsed = parse_cluster_mode(None).unwrap();
    assert_eq!(parsed, ClusterMode::Dev);
}

#[test]
fn cluster_mode_parser_accepts_live() {
    let parsed = parse_cluster_mode(Some("live".to_string())).unwrap();
    assert_eq!(parsed, ClusterMode::Live);
}

#[test]
fn cluster_mode_parser_rejects_invalid_value() {
    let parsed = parse_cluster_mode(Some("stage".to_string()));
    assert!(parsed.is_err());
}

#[test]
fn parse_live_entrypoints_accepts_comma_separated_addrs() {
    let parsed =
        parse_live_entrypoints(Some("192.0.2.10:8001,198.51.100.20:8002".to_string())).unwrap();
    assert_eq!(parsed.len(), 2);
}

#[test]
fn parse_live_entrypoints_rejects_invalid_addr() {
    // A string with no port and no resolvable hostname
    let parsed = parse_live_entrypoints(Some("not-a-valid-entrypoint-at-all".to_string()));
    assert!(parsed.is_err());
}

#[test]
fn parse_live_entrypoints_accepts_localhost_hostname() {
    // "localhost:8001" should resolve via DNS on any platform.
    let parsed = parse_live_entrypoints(Some("localhost:8001".to_string()));
    assert!(
        parsed.is_ok(),
        "localhost:8001 should resolve: {:?}",
        parsed
    );
    assert_eq!(parsed.unwrap().len(), 1);
}

#[test]
fn parse_live_entrypoints_accepts_mixed_ip_and_hostname() {
    // Mix of IP:port and hostname:port in one list.
    let parsed =
        parse_live_entrypoints(Some("192.0.2.10:8001,localhost:8002".to_string())).unwrap();
    assert_eq!(parsed.len(), 2);
}

#[test]
fn genesis_hash_validator_requires_64_lower_hex_chars() {
    assert!(is_valid_genesis_hash(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ));
    assert!(!is_valid_genesis_hash("ABCDEF"));
}

#[test]
fn routable_socket_validator_rejects_loopback_and_accepts_public_ip() {
    assert!(!is_routable_socket_addr(&"127.0.0.1:8001".parse().unwrap()));
    assert!(is_routable_socket_addr(&"192.0.2.50:8001".parse().unwrap()));
}

#[test]
fn identity_keypair_validator_accepts_64_byte_json_array() {
    let keypair_path = unique_temp_file("paradencer-keypair-valid", "json");
    let keypair_json = format!(
        "[{}]",
        (0_u8..64)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    fs::write(&keypair_path, keypair_json).unwrap();

    let result = validate_identity_keypair_file(&keypair_path);
    fs::remove_file(&keypair_path).unwrap();
    assert!(result.is_ok());
}

#[test]
fn identity_keypair_validator_rejects_short_json_array() {
    let keypair_path = unique_temp_file("paradencer-keypair-short", "json");
    fs::write(&keypair_path, "[1,2,3]").unwrap();

    let result = validate_identity_keypair_file(&keypair_path);
    fs::remove_file(&keypair_path).unwrap();
    assert!(result.is_err());
}

#[test]
fn identity_keypair_validator_rejects_invalid_json_shape() {
    let keypair_path = unique_temp_file("paradencer-keypair-invalid", "json");
    fs::write(&keypair_path, r#"{"secret":"not-an-array"}"#).unwrap();

    let result = validate_identity_keypair_file(&keypair_path);
    fs::remove_file(&keypair_path).unwrap();
    assert!(result.is_err());
}

#[test]
fn live_runtime_validator_rejects_run_for_seconds_knob() {
    let runtime_spec = RuntimeSpec {
        mode: ExecutionMode::Tokio,
        workers: 4,
        run_for_seconds: Some(30),
        pinned_allow_core_sharing: false,
        pinned_core_policy: PinnedCorePolicy::Strict,
        pinned_service_core_ids: None,
    };
    assert!(validate_live_runtime_spec(&runtime_spec).is_err());
}

#[test]
fn live_runtime_validator_accepts_unbounded_runtime() {
    let runtime_spec = RuntimeSpec {
        mode: ExecutionMode::Pinned,
        workers: 4,
        run_for_seconds: None,
        pinned_allow_core_sharing: false,
        pinned_core_policy: PinnedCorePolicy::Adaptive,
        pinned_service_core_ids: None,
    };
    assert!(validate_live_runtime_spec(&runtime_spec).is_ok());
}

#[test]
fn storage_preflight_rejects_missing_catalog_parent_directory() {
    let mut policy = StorageRuntimePolicy::default();
    let catalog_path = std::env::temp_dir()
        .join("paradencer-storage-missing-parent")
        .join("catalog.json");
    policy.snapshot_catalog_path = Some(catalog_path);
    let result = validate_storage_startup_preflight(&policy);
    assert!(result.is_err());
}

#[test]
fn storage_preflight_rejects_strict_restore_without_existing_catalog_file() {
    let policy = StorageRuntimePolicy {
        startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
        startup_strict_restore_policy: paradencer_stages::StorageStartupStrictRestorePolicy {
            restore_latest_requires_snapshot: true,
            restore_specific_requires_snapshot: false,
        },
        snapshot_catalog_path: Some(unique_temp_file("paradencer-missing-catalog", "json")),
        ..StorageRuntimePolicy::default()
    };
    let result = validate_storage_startup_preflight(&policy);
    assert!(result.is_err());
}

#[test]
fn storage_preflight_accepts_strict_restore_when_catalog_file_exists() {
    let catalog_path = unique_temp_file("paradencer-existing-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":0,"snapshots_written":0,"snapshots":[]}"#,
    )
    .unwrap();
    let policy = StorageRuntimePolicy {
        startup_policy: StorageStartupPolicy::RestoreLatestIfAvailable,
        startup_strict_restore_policy: paradencer_stages::StorageStartupStrictRestorePolicy {
            restore_latest_requires_snapshot: true,
            restore_specific_requires_snapshot: false,
        },
        snapshot_catalog_path: Some(catalog_path.clone()),
        ..StorageRuntimePolicy::default()
    };

    let result = validate_storage_startup_preflight(&policy);
    fs::remove_file(&catalog_path).unwrap();
    assert!(result.is_ok());
}

#[test]
fn storage_preflight_rejects_existing_catalog_with_invalid_checksum() {
    let catalog_path = unique_temp_file("paradencer-invalid-checksum-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":2,"last_snapshot_fragment_id":20,"snapshots_written":1,"snapshots":[{"fragment_id":20,"committed_fragments":4,"committed_transactions":12,"state_checksum":1}]}"#,
    )
    .unwrap();
    let policy = StorageRuntimePolicy {
        snapshot_catalog_path: Some(catalog_path.clone()),
        ..StorageRuntimePolicy::default()
    };

    let result = validate_storage_startup_preflight(&policy);
    fs::remove_file(&catalog_path).unwrap();
    assert!(result.is_err());
}

#[test]
fn storage_preflight_rejects_existing_catalog_with_header_last_fragment_mismatch() {
    let catalog_path = unique_temp_file("paradencer-invalid-header-last-fragment-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":30,"snapshots_written":2,"snapshots":[{"fragment_id":10,"committed_fragments":1,"committed_transactions":3},{"fragment_id":20,"committed_fragments":2,"committed_transactions":7}]}"#,
    )
    .unwrap();
    let policy = StorageRuntimePolicy {
        snapshot_catalog_path: Some(catalog_path.clone()),
        ..StorageRuntimePolicy::default()
    };

    let result = validate_storage_startup_preflight(&policy);
    fs::remove_file(&catalog_path).unwrap();
    assert!(result.is_err());
}

#[test]
fn storage_preflight_rejects_existing_catalog_with_header_written_count_mismatch() {
    let catalog_path = unique_temp_file("paradencer-invalid-header-written-count-catalog", "json");
    fs::write(
        &catalog_path,
        r#"{"schema_version":1,"last_snapshot_fragment_id":20,"snapshots_written":1,"snapshots":[{"fragment_id":10,"committed_fragments":1,"committed_transactions":3},{"fragment_id":20,"committed_fragments":2,"committed_transactions":7}]}"#,
    )
    .unwrap();
    let policy = StorageRuntimePolicy {
        snapshot_catalog_path: Some(catalog_path.clone()),
        ..StorageRuntimePolicy::default()
    };

    let result = validate_storage_startup_preflight(&policy);
    fs::remove_file(&catalog_path).unwrap();
    assert!(result.is_err());
}

#[test]
fn metrics_preflight_rejects_missing_file_parent_directory() {
    let target = MetricsOutputTarget::File(
        std::env::temp_dir()
            .join("paradencer-metrics-missing-parent")
            .join("metrics.jsonl"),
    );
    assert!(validate_metrics_target_preflight(&target).is_err());
}

#[test]
fn metrics_preflight_rejects_udp_target_with_zero_port() {
    let target = MetricsOutputTarget::Udp("192.0.2.10:0".parse().unwrap());
    assert!(validate_metrics_target_preflight(&target).is_err());
}

#[test]
fn metrics_preflight_accepts_well_formed_targets() {
    let file_target = MetricsOutputTarget::File(unique_temp_file("paradencer-metrics", "jsonl"));
    let udp_target = MetricsOutputTarget::Udp("192.0.2.10:8125".parse().unwrap());
    assert!(validate_metrics_target_preflight(&file_target).is_ok());
    assert!(validate_metrics_target_preflight(&udp_target).is_ok());
}

#[test]
fn execution_mode_rejects_invalid_value() {
    let parsed = parse_execution_mode(Some("invalid".to_string()));
    assert!(parsed.is_err());
}

#[test]
fn pinned_core_policy_parser_accepts_adaptive() {
    let parsed = parse_pinned_core_policy(Some("adaptive".to_string())).unwrap();
    assert_eq!(parsed, PinnedCorePolicy::Adaptive);
}

#[test]
fn legacy_core_sharing_map_is_backwards_compatible() {
    assert_eq!(map_legacy_core_sharing_flag(true), PinnedCorePolicy::Shared);
    assert_eq!(
        map_legacy_core_sharing_flag(false),
        PinnedCorePolicy::Strict
    );
}

#[test]
fn ingress_policy_toml_parser_reads_partial_profile() {
    let policy = parse_ingress_policy_toml(
        r#"
max_payload_bytes = 1100
allow_bundle_source = false
quic_min_gap_ticks = 3
quic_burst_capacity = 4
quic_cost_budget_per_window = 9000
egress_retry_buffer_capacity = 321
synthetic_batch_size_per_tick = 2
ingress_mode = "udp"
udp_bind_address = "127.0.0.1:9001"
udp_gossip_source_port = 8001
udp_max_packets_per_tick = 17
"#,
    )
    .unwrap();
    assert_eq!(policy.max_payload_bytes, Some(1100));
    assert_eq!(policy.allow_bundle_source, Some(false));
    assert_eq!(policy.quic_min_gap_ticks, Some(3));
    assert_eq!(policy.quic_burst_capacity, Some(4));
    assert_eq!(policy.quic_cost_budget_per_window, Some(9000));
    assert_eq!(policy.egress_retry_buffer_capacity, Some(321));
    assert_eq!(policy.synthetic_batch_size_per_tick, Some(2));
    assert_eq!(policy.ingress_mode, Some("udp".to_string()));
    assert_eq!(policy.udp_bind_address, Some("127.0.0.1:9001".to_string()));
    assert_eq!(policy.udp_gossip_source_port, Some(8001));
    assert_eq!(policy.udp_max_packets_per_tick, Some(17));
    assert_eq!(policy.allow_quic_source, None);
    migrate_ingress_policy_schema(policy).unwrap();
}

#[test]
fn ingress_schema_migration_accepts_legacy_schema_version() {
    let policy = parse_ingress_policy_toml(
        r#"
schema_version = 0
max_payload_bytes = 1200
"#,
    )
    .unwrap();
    assert!(migrate_ingress_policy_schema(policy).is_ok());
}

#[test]
fn ingress_schema_validation_rejects_unknown_schema_version() {
    let policy = parse_ingress_policy_toml("schema_version = 99").unwrap();
    assert!(migrate_ingress_policy_schema(policy).is_err());
}

#[test]
fn node_profile_parser_reads_nested_sections() {
    let profile = parse_node_profile_toml(
        r#"
[runtime]
mode = "pinned"
workers = 6
pinned_core_policy = "adaptive"
pinned_service_core_ids = [0, 2, 4]

[topology]
packet_link_capacity = 2048
shred_link_capacity = 1536
transaction_link_capacity = 1024
transaction_sanitizer_workers = 3
shred_sanitizer_workers = 2

[ingress_policy]
allow_rpc_source = false
bundle_min_gap_ticks = 2
bundle_burst_capacity = 5
bundle_cost_budget_window_ticks = 9
egress_retry_max_wait_ticks = 4
synthetic_source_weight_bundle = 7

[metrics]
output_format = "prometheus_text"
output_target = "stdout"

[rpc]
enabled = true
bind = "127.0.0.1:8899"
private = true
full_api = false

[storage]
startup_policy = "restore_specific"
restore_fragment_id = 42
snapshot_interval = 128
catalog_path = "/tmp/paradencer-snapshot-catalog.json"
max_retry_attempts = 5
retry_backoff_cap_millis = 750
execution_error_fail_open_max_consecutive = 6

[readiness]
min_runtime_workers = 16
min_live_entrypoints = 3
min_transaction_sanitizer_stages = 3
min_shred_sanitizer_stages = 2
min_packet_stream_capacity = 6000
min_shred_stream_capacity = 6000
min_transaction_stream_capacity = 12000
min_replay_candidate_confirmation_threshold = 3
min_replay_failed_ratio_penalty_weight = 90
require_pinned_runtime_mode = true
require_udp_ingress_mode = true
require_non_stdout_metrics_target = true
require_metrics_http_bind = true
require_fork_choice_runtime_enabled = true
require_fail_fast_execution_errors = true
require_fail_open_execution_error_circuit_breaker = true
"#,
    )
    .unwrap();
    let runtime = profile.runtime.unwrap();
    assert_eq!(runtime.mode, Some("pinned".to_string()));
    assert_eq!(runtime.pinned_service_core_ids, Some(vec![0, 2, 4]));
    let topology = profile.topology.unwrap();
    assert_eq!(topology.packet_link_capacity, Some(2048));
    assert_eq!(topology.shred_link_capacity, Some(1536));
    assert_eq!(topology.transaction_sanitizer_workers, Some(3));
    assert_eq!(topology.shred_sanitizer_workers, Some(2));
    let ingress = profile.ingress_policy.unwrap();
    assert_eq!(ingress.allow_rpc_source, Some(false));
    assert_eq!(ingress.bundle_min_gap_ticks, Some(2));
    assert_eq!(ingress.bundle_burst_capacity, Some(5));
    assert_eq!(ingress.bundle_cost_budget_window_ticks, Some(9));
    assert_eq!(ingress.egress_retry_max_wait_ticks, Some(4));
    assert_eq!(ingress.synthetic_source_weight_bundle, Some(7));
    assert_eq!(
        profile.metrics.unwrap().output_format,
        Some("prometheus_text".to_string())
    );
    let rpc = profile.rpc.unwrap();
    assert_eq!(rpc.enabled, Some(true));
    assert_eq!(rpc.bind, Some("127.0.0.1:8899".to_string()));
    assert_eq!(rpc.private, Some(true));
    assert_eq!(rpc.full_api, Some(false));
    let storage = profile.storage.unwrap();
    assert_eq!(storage.startup_policy, Some("restore_specific".to_string()));
    assert_eq!(storage.restore_fragment_id, Some(42));
    assert_eq!(storage.snapshot_interval, Some(128));
    assert_eq!(
        storage.catalog_path,
        Some("/tmp/paradencer-snapshot-catalog.json".to_string())
    );
    assert_eq!(storage.max_retry_attempts, Some(5));
    assert_eq!(storage.retry_backoff_cap_millis, Some(750));
    assert_eq!(storage.execution_error_fail_open_max_consecutive, Some(6));
    let readiness = profile.readiness.unwrap();
    assert_eq!(readiness.min_runtime_workers, Some(16));
    assert_eq!(readiness.min_live_entrypoints, Some(3));
    assert_eq!(readiness.min_transaction_sanitizer_stages, Some(3));
    assert_eq!(readiness.min_shred_sanitizer_stages, Some(2));
    assert_eq!(readiness.min_packet_stream_capacity, Some(6000));
    assert_eq!(readiness.min_shred_stream_capacity, Some(6000));
    assert_eq!(readiness.min_transaction_stream_capacity, Some(12000));
    assert_eq!(
        readiness.min_replay_candidate_confirmation_threshold,
        Some(3)
    );
    assert_eq!(readiness.min_replay_failed_ratio_penalty_weight, Some(90));
    assert_eq!(readiness.require_pinned_runtime_mode, Some(true));
    assert_eq!(readiness.require_udp_ingress_mode, Some(true));
    assert_eq!(readiness.require_non_stdout_metrics_target, Some(true));
    assert_eq!(readiness.require_metrics_http_bind, Some(true));
    assert_eq!(readiness.require_fork_choice_runtime_enabled, Some(true));
    assert_eq!(readiness.require_fail_fast_execution_errors, Some(true));
    assert_eq!(
        readiness.require_fail_open_execution_error_circuit_breaker,
        Some(true)
    );
}

#[test]
fn node_config_builds_mainnet_readiness_policy_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[readiness]
min_runtime_workers = 12
min_live_entrypoints = 2
min_transaction_sanitizer_stages = 4
min_shred_sanitizer_stages = 5
min_packet_stream_capacity = 9000
min_shred_stream_capacity = 10000
min_transaction_stream_capacity = 20000
min_replay_candidate_confirmation_threshold = 4
min_replay_failed_ratio_penalty_weight = 120
require_pinned_runtime_mode = false
require_udp_ingress_mode = false
require_non_stdout_metrics_target = false
require_metrics_http_bind = true
require_fork_choice_runtime_enabled = true
require_fail_fast_execution_errors = true
require_fail_open_execution_error_circuit_breaker = true
"#,
    )
    .unwrap();
    let node_config = NodeConfig::from_profile(Some(&profile)).unwrap();
    let policy = node_config.mainnet_readiness_policy;
    assert_eq!(policy.min_runtime_workers, 12);
    assert_eq!(policy.min_live_entrypoints, 2);
    assert_eq!(policy.min_transaction_sanitizer_stages, 4);
    assert_eq!(policy.min_shred_sanitizer_stages, 5);
    assert_eq!(policy.min_packet_stream_capacity, 9000);
    assert_eq!(policy.min_shred_stream_capacity, 10000);
    assert_eq!(policy.min_transaction_stream_capacity, 20000);
    assert_eq!(policy.min_replay_candidate_confirmation_threshold, 4);
    assert_eq!(policy.min_replay_failed_ratio_penalty_weight, 120);
    assert!(!policy.require_pinned_runtime_mode);
    assert!(!policy.require_udp_ingress_mode);
    assert!(!policy.require_non_stdout_metrics_target);
    assert!(policy.require_metrics_http_bind);
    assert!(policy.require_fork_choice_runtime_enabled);
    assert!(policy.require_fail_fast_execution_errors);
    assert!(policy.require_fail_open_execution_error_circuit_breaker);
}

#[test]
fn node_config_from_profile_builds_topology_from_inline_profile() {
    let profile = parse_node_profile_toml(
        r#"
[runtime]
pinned_service_core_ids = [1, 3, 5]

[topology]
transaction_sanitizer_workers = 3
shred_sanitizer_workers = 2
"#,
    )
    .unwrap();

    let config = NodeConfig::from_profile(Some(&profile)).unwrap();
    assert_eq!(config.topology_spec.stages.len(), 8);
    assert_eq!(
        config.runtime_spec.pinned_service_core_ids,
        Some(vec![1, 3, 5])
    );
}

#[test]
fn node_config_builds_rpc_config_from_profile() {
    let profile = parse_node_profile_toml(
        r#"
[rpc]
enabled = true
bind = "127.0.0.1:7799"
private = false
full_api = true
"#,
    )
    .unwrap();

    let config = NodeConfig::from_profile(Some(&profile)).unwrap();
    assert!(config.rpc_enabled);
    assert_eq!(config.rpc_bind, Some("127.0.0.1:7799".parse().unwrap()));
    assert!(!config.rpc_private);
    assert!(config.rpc_full_api);
}

#[test]
fn node_config_rejects_enabled_rpc_without_bind() {
    let profile = parse_node_profile_toml(
        r#"
[rpc]
enabled = true
"#,
    )
    .unwrap();

    let result = NodeConfig::from_profile(Some(&profile));
    assert!(result.is_err());
}

#[test]
fn node_config_from_file_loads_profile_and_builds_storage_policy() {
    let config_path = unique_temp_file("paradencer-node-config", "toml");
    fs::write(
        &config_path,
        r#"
[storage]
snapshot_interval = 77
"#,
    )
    .unwrap();

    let result = NodeConfig::from_file(&config_path);
    fs::remove_file(&config_path).unwrap();

    let config = result.unwrap();
    assert_eq!(config.storage_runtime_policy.snapshot_interval, 77);
}

#[test]
fn node_config_from_profile_builds_execution_error_handling_policy() {
    let profile = parse_node_profile_toml(
        r#"
[storage]
execution_error_handling_policy = "fail_fast"
execution_error_fail_open_max_consecutive = 4
"#,
    )
    .unwrap();
    let config = NodeConfig::from_profile(Some(&profile)).unwrap();
    assert_eq!(
        config
            .storage_runtime_policy
            .execution_error_handling_policy,
        ExecutionErrorHandlingPolicy::FailFast
    );
    assert_eq!(
        config
            .storage_runtime_policy
            .execution_error_fail_open_max_consecutive,
        4
    );
}

#[test]
fn topology_builder_expands_transaction_sanitizer_workers_in_default_plan() {
    let profile = parse_node_profile_toml(
        r#"
[topology]
transaction_sanitizer_workers = 4
shred_sanitizer_workers = 3
"#,
    )
    .unwrap();
    let topology = build_topology_spec(Some(&profile)).unwrap();
    assert_eq!(topology.stages.len(), 10);
    assert_eq!(topology.links.len(), 11);
}

#[test]
fn topology_builder_rejects_zero_sanitizer_worker_counts() {
    let profile = parse_node_profile_toml(
        r#"
[topology]
transaction_sanitizer_workers = 0
"#,
    )
    .unwrap();
    assert!(build_topology_spec(Some(&profile)).is_err());

    let profile = parse_node_profile_toml(
        r#"
[topology]
shred_sanitizer_workers = 0
"#,
    )
    .unwrap();
    assert!(build_topology_spec(Some(&profile)).is_err());
}

#[test]
fn metrics_output_parser_accepts_prometheus_text() {
    let parsed = parse_metrics_output_format(Some("prometheus_text".to_string())).unwrap();
    assert_eq!(parsed, MetricsOutputFormat::PrometheusText);
}

#[test]
fn schema_validation_rejects_unknown_node_schema_version() {
    let profile = parse_node_profile_toml("schema_version = 2").unwrap();
    assert!(migrate_node_profile_schema(profile).is_err());
}

#[test]
fn schema_migration_accepts_legacy_node_schema_version() {
    let profile = parse_node_profile_toml("schema_version = 0").unwrap();
    assert!(migrate_node_profile_schema(profile).is_ok());
}
