use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct MainnetReadinessProfileToml {
    pub min_runtime_workers: Option<usize>,
    pub min_live_entrypoints: Option<usize>,
    pub min_transaction_sanitizer_stages: Option<usize>,
    pub min_shred_sanitizer_stages: Option<usize>,
    pub min_packet_stream_capacity: Option<usize>,
    pub min_shred_stream_capacity: Option<usize>,
    pub min_transaction_stream_capacity: Option<usize>,
    pub min_replay_candidate_confirmation_threshold: Option<u32>,
    pub min_replay_failed_ratio_penalty_weight: Option<u64>,
    pub require_pinned_runtime_mode: Option<bool>,
    pub require_udp_ingress_mode: Option<bool>,
    pub require_non_stdout_metrics_target: Option<bool>,
    pub require_metrics_http_bind: Option<bool>,
    pub require_fork_choice_runtime_enabled: Option<bool>,
    pub require_fail_fast_execution_errors: Option<bool>,
    pub require_fail_open_execution_error_circuit_breaker: Option<bool>,
}
