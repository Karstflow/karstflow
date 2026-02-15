use crate::errors::{ControlPlaneError, Result};
use paradencer_config::{validate_identity_keypair_file, NodeConfig};
use std::path::PathBuf;

pub fn render_config_summary(node_config: &NodeConfig) -> String {
    [
        format!(
            "cluster_mode={:?} topology='{}' services={} links={}",
            node_config.cluster_mode,
            node_config.topology_spec.topology_name,
            node_config.topology_spec.stages.len(),
            node_config.topology_spec.links.len()
        ),
        format!(
            "runtime mode={} workers={} pinned_policy={} pinned_service_core_ids={:?} run_for_seconds={:?}",
            node_config.runtime_spec.mode,
            node_config.runtime_spec.workers,
            node_config.runtime_spec.pinned_core_policy,
            node_config.runtime_spec.pinned_service_core_ids,
            node_config.runtime_spec.run_for_seconds
        ),
        format!(
            "ingress mode={:?} udp_bind={:?} dedup_window={} max_payload={}",
            node_config.ingress_policy.ingress_mode,
            node_config.ingress_policy.udp_bind_address,
            node_config.ingress_policy.dedup_window_capacity,
            node_config.ingress_policy.max_payload_bytes
        ),
        format!(
            "metrics format={:?} target={:?} http_bind={:?}",
            node_config.metrics_output_format,
            node_config.metrics_output_target,
            node_config.metrics_http_bind
        ),
        format!(
            "rpc enabled={} bind={:?} private={} full_api={}",
            node_config.rpc_enabled,
            node_config.rpc_bind,
            node_config.rpc_private,
            node_config.rpc_full_api
        ),
        format!(
            "storage snapshot_interval={} startup_policy={:?} catalog_path={:?} execution_engine_policy={:?} execution_error_handling_policy={:?} execution_error_fail_open_max_consecutive={} runtime_like_account_state_apply_policy={:?} runtime_like_program_cache_apply_policy={:?}",
            node_config.storage_runtime_policy.snapshot_interval,
            node_config.storage_runtime_policy.startup_policy,
            node_config.storage_runtime_policy.snapshot_catalog_path,
            node_config.storage_runtime_policy.execution_engine_policy,
            node_config
                .storage_runtime_policy
                .execution_error_handling_policy,
            node_config
                .storage_runtime_policy
                .execution_error_fail_open_max_consecutive,
            node_config
                .storage_runtime_policy
                .runtime_like_account_state_apply_policy,
            node_config
                .storage_runtime_policy
                .runtime_like_program_cache_apply_policy
        ),
        format!(
            "readiness min_runtime_workers={} min_live_entrypoints={} min_tx_sanitizers={} min_shred_sanitizers={} min_packet_capacity={} min_shred_capacity={} min_transaction_capacity={} min_replay_candidate_confirmation_threshold={} min_replay_failed_ratio_penalty_weight={} require_pinned_mode={} require_udp_ingress={} require_non_stdout_metrics={} require_metrics_http_bind={} require_fork_choice_runtime_enabled={} require_fail_fast_execution_errors={} require_fail_open_execution_error_circuit_breaker={}",
            node_config.mainnet_readiness_policy.min_runtime_workers,
            node_config.mainnet_readiness_policy.min_live_entrypoints,
            node_config.mainnet_readiness_policy.min_transaction_sanitizer_stages,
            node_config.mainnet_readiness_policy.min_shred_sanitizer_stages,
            node_config.mainnet_readiness_policy.min_packet_stream_capacity,
            node_config.mainnet_readiness_policy.min_shred_stream_capacity,
            node_config.mainnet_readiness_policy.min_transaction_stream_capacity,
            node_config
                .mainnet_readiness_policy
                .min_replay_candidate_confirmation_threshold,
            node_config
                .mainnet_readiness_policy
                .min_replay_failed_ratio_penalty_weight,
            node_config.mainnet_readiness_policy.require_pinned_runtime_mode,
            node_config.mainnet_readiness_policy.require_udp_ingress_mode,
            node_config.mainnet_readiness_policy.require_non_stdout_metrics_target,
            node_config.mainnet_readiness_policy.require_metrics_http_bind,
            node_config
                .mainnet_readiness_policy
                .require_fork_choice_runtime_enabled,
            node_config
                .mainnet_readiness_policy
                .require_fail_fast_execution_errors,
            node_config
                .mainnet_readiness_policy
                .require_fail_open_execution_error_circuit_breaker
        ),
    ]
    .join("\n")
}

pub fn validate_identity_keypair_from_env() -> Result<PathBuf> {
    let keypair_path = std::env::var("PARADENCER_IDENTITY_KEYPAIR_PATH")
        .ok()
        .ok_or(ControlPlaneError::KeysCommandRequiresIdentityPath)?;
    let keypair_path = PathBuf::from(keypair_path);
    validate_identity_keypair_file(&keypair_path)?;
    Ok(keypair_path)
}

#[cfg(test)]
mod tests {
    use super::{render_config_summary, validate_identity_keypair_from_env};
    use paradencer_config::NodeConfig;
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
    fn render_config_summary_contains_core_sections() {
        let node_config = NodeConfig::from_profile(None).unwrap();
        let summary = render_config_summary(&node_config);
        assert!(summary.contains("cluster_mode="));
        assert!(summary.contains("runtime mode="));
        assert!(summary.contains("ingress mode="));
        assert!(summary.contains("metrics format="));
        assert!(summary.contains("rpc enabled="));
        assert!(summary.contains("storage snapshot_interval="));
        assert!(summary.contains("execution_engine_policy="));
        assert!(summary.contains("execution_error_handling_policy="));
        assert!(summary.contains("execution_error_fail_open_max_consecutive="));
        assert!(summary.contains("runtime_like_account_state_apply_policy="));
        assert!(summary.contains("runtime_like_program_cache_apply_policy="));
        assert!(summary.contains("readiness min_runtime_workers="));
    }

    #[test]
    fn validate_identity_keypair_from_env_accepts_valid_keypair_file() {
        let keypair_path = unique_temp_file("paradencer-keypair", "json");
        let keypair_json = format!(
            "[{}]",
            (0_u8..64)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        fs::write(&keypair_path, keypair_json).unwrap();

        unsafe {
            std::env::set_var("PARADENCER_IDENTITY_KEYPAIR_PATH", &keypair_path);
        }
        let result = validate_identity_keypair_from_env();
        unsafe {
            std::env::remove_var("PARADENCER_IDENTITY_KEYPAIR_PATH");
        }
        fs::remove_file(&keypair_path).unwrap();

        assert!(result.is_ok());
    }
}
