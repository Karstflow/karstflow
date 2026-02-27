use paradencer_execution::{AccountStateApplyPolicy, ProgramCacheApplyPolicy, RetryPolicy};
use paradencer_net::{InboundFrame, PreparedShred, PreparedTransaction};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsOutputFormat {
    JsonLines,
    PrometheusText,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsOutputTarget {
    Stdout,
    File(PathBuf),
    Udp(SocketAddr),
    /// Write Prometheus text to a shared buffer served by MetricsHttpServer.
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageStartupPolicy {
    SkipRestore,
    RestoreLatestIfAvailable,
    RestoreSpecificIfAvailable { fragment_id: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageStartupStrictRestorePolicy {
    pub restore_latest_requires_snapshot: bool,
    pub restore_specific_requires_snapshot: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionEnginePolicy {
    Heuristic,
    RuntimeLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionErrorHandlingPolicy {
    FailOpen,
    FailFast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRuntimePolicy {
    pub snapshot_interval: u64,
    pub snapshot_retention_policy: SnapshotRetentionPolicy,
    pub startup_policy: StorageStartupPolicy,
    pub startup_strict_restore_policy: StorageStartupStrictRestorePolicy,
    pub snapshot_catalog_path: Option<PathBuf>,
    pub assembly_policy: AssemblyPolicy,
    pub max_retry_attempts: u8,
    pub retry_backoff_cap_millis: u64,
    pub execution_engine_policy: ExecutionEnginePolicy,
    pub execution_error_handling_policy: ExecutionErrorHandlingPolicy,
    pub execution_error_fail_open_max_consecutive: u32,
    pub runtime_like_account_state_apply_policy: AccountStateApplyPolicy,
    pub runtime_like_program_cache_apply_policy: ProgramCacheApplyPolicy,
    pub execution_retry_policy: RetryPolicy,
    pub leader_schedule_policy: LeaderSchedulePolicy,
    pub scheduler_runtime_policy: SchedulerRuntimePolicy,
    pub fork_choice_runtime_policy: ForkChoiceRuntimePolicy,
    pub fork_choice_quarantine_policy: ForkChoiceQuarantinePolicy,
    pub execution_health_policy: ExecutionHealthPolicy,
    pub replay_safety_policy: ReplaySafetyPolicy,
    pub replay_controller_policy: ReplayControllerPolicy,
    pub replay_window_policy: ReplayWindowPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyPolicy {
    pub max_fragment_transactions: usize,
    pub max_fragment_cost_units: u64,
    pub max_fragment_wait_ticks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderSchedulePolicy {
    pub enabled: bool,
    pub slot_cycle_length: u64,
    pub leader_slots_per_cycle: u64,
    pub initial_slot: u64,
    pub hold_retry_delay_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerRuntimePolicy {
    pub enabled: bool,
    pub slot_duration_millis: u64,
    pub priority_penalty_class_2_millis: u64,
    pub priority_penalty_class_3_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkChoiceRuntimePolicy {
    pub enabled: bool,
    pub reorg_retry_delay_millis: u64,
    pub max_reorg_retry_attempts: u8,
    pub hold_requires_confirmed_candidate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkChoiceQuarantinePolicy {
    pub enabled: bool,
    pub consecutive_reorg_threshold: u32,
    pub quarantine_ticks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionHealthPolicy {
    pub enabled: bool,
    pub transient_failure_threshold: u32,
    pub cooldown_ticks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySafetyPolicy {
    pub enabled: bool,
    pub replay_conflict_threshold: u32,
    pub hold_ticks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayControllerPolicy {
    pub candidate_confirmation_threshold: u32,
    pub candidate_confirmation_max_failed_ratio_bps: u32,
    pub max_candidates: usize,
    pub reorg_signal_weight: u64,
    pub fragment_recency_weight: u64,
    pub failed_transaction_ratio_penalty_weight: u64,
    pub candidate_stale_fragment_lag: u64,
    pub candidate_switch_min_score_delta: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayWindowPolicy {
    pub max_checkpoints: usize,
    pub rewind_on_confirmed_reorg: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRetentionPolicy {
    pub max_catalog_snapshots: usize,
}

impl Default for StorageRuntimePolicy {
    fn default() -> Self {
        Self {
            snapshot_interval: 256,
            snapshot_retention_policy: SnapshotRetentionPolicy::default(),
            startup_policy: StorageStartupPolicy::SkipRestore,
            startup_strict_restore_policy: StorageStartupStrictRestorePolicy::default(),
            snapshot_catalog_path: None,
            assembly_policy: AssemblyPolicy::default(),
            max_retry_attempts: 3,
            retry_backoff_cap_millis: 2_000,
            execution_engine_policy: ExecutionEnginePolicy::Heuristic,
            execution_error_handling_policy: ExecutionErrorHandlingPolicy::FailOpen,
            execution_error_fail_open_max_consecutive: 0,
            runtime_like_account_state_apply_policy: AccountStateApplyPolicy::Strict,
            runtime_like_program_cache_apply_policy: ProgramCacheApplyPolicy::Strict,
            execution_retry_policy: RetryPolicy::default(),
            leader_schedule_policy: LeaderSchedulePolicy::default(),
            scheduler_runtime_policy: SchedulerRuntimePolicy::default(),
            fork_choice_runtime_policy: ForkChoiceRuntimePolicy::default(),
            fork_choice_quarantine_policy: ForkChoiceQuarantinePolicy::default(),
            execution_health_policy: ExecutionHealthPolicy::default(),
            replay_safety_policy: ReplaySafetyPolicy::default(),
            replay_controller_policy: ReplayControllerPolicy::default(),
            replay_window_policy: ReplayWindowPolicy::default(),
        }
    }
}

impl Default for AssemblyPolicy {
    fn default() -> Self {
        Self {
            max_fragment_transactions: 64,
            max_fragment_cost_units: 256_000,
            max_fragment_wait_ticks: 8,
        }
    }
}

impl Default for LeaderSchedulePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            slot_cycle_length: 4,
            leader_slots_per_cycle: 1,
            initial_slot: 0,
            hold_retry_delay_millis: 20,
        }
    }
}

impl Default for SchedulerRuntimePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            slot_duration_millis: 50,
            priority_penalty_class_2_millis: 25,
            priority_penalty_class_3_millis: 75,
        }
    }
}

impl Default for ForkChoiceRuntimePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            reorg_retry_delay_millis: 100,
            max_reorg_retry_attempts: 2,
            hold_requires_confirmed_candidate: false,
        }
    }
}

impl Default for ForkChoiceQuarantinePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            consecutive_reorg_threshold: 2,
            quarantine_ticks: 10,
        }
    }
}

impl Default for ExecutionHealthPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            transient_failure_threshold: 4,
            cooldown_ticks: 16,
        }
    }
}

impl Default for ReplaySafetyPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            replay_conflict_threshold: 3,
            hold_ticks: 12,
        }
    }
}

impl Default for ReplayControllerPolicy {
    fn default() -> Self {
        Self {
            candidate_confirmation_threshold: 2,
            candidate_confirmation_max_failed_ratio_bps: 9_000,
            max_candidates: 8,
            reorg_signal_weight: 1_000_000,
            fragment_recency_weight: 1,
            failed_transaction_ratio_penalty_weight: 50,
            candidate_stale_fragment_lag: 128,
            candidate_switch_min_score_delta: 25_000,
        }
    }
}

impl Default for ReplayWindowPolicy {
    fn default() -> Self {
        Self {
            max_checkpoints: 256,
            rewind_on_confirmed_reorg: false,
        }
    }
}

impl Default for SnapshotRetentionPolicy {
    fn default() -> Self {
        Self {
            max_catalog_snapshots: 4_096,
        }
    }
}

pub type InboundPacket = InboundFrame;
pub type SanitizedShred = PreparedShred;
pub type SanitizedTransaction = PreparedTransaction;

#[derive(Debug, Clone)]
pub struct AssembledBlockFragment {
    pub fragment_id: u64,
    pub transaction_count: usize,
}
