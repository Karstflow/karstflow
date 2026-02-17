#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    redundant_imports
)]
#![allow(
    clippy::useless_vec,
    clippy::manual_find,
    clippy::new_without_default,
    clippy::manual_clamp,
    clippy::too_many_arguments,
    clippy::let_and_return,
    clippy::manual_div_ceil,
    clippy::len_zero,
    clippy::single_component_path_imports
)]

mod block_assembler;
mod block_producer;
mod edge_intake;
mod errors;
mod execution_adapter;
#[cfg(test)]
mod integration_tests;
mod metrics_reporter;
mod replay_stage;
mod shred_assembler;
mod shred_filter;
mod stats;
#[cfg(test)]
mod testsuite;
mod tx_filter;
mod types;

pub use block_assembler::BlockAssembler;
pub use edge_intake::EdgeIntake;
pub use errors::StageError;
pub use execution_adapter::SbpfExecutionAdapter;
pub use metrics_reporter::{LinkTelemetryStats, MetricsReporter, StageTelemetryStats};
pub use replay_stage::{
    AggregateMetrics, AlertSeverity, AlertType, AncestryError, AncestryStats, AncestryVerifier,
    AnomalyType, BankTransition, BankTransitionError, BatchReplayResult, BlockOutcome,
    BlockProcessor, BlockProcessorError, ConfirmationInfo, ConfirmationStats, CoordinatorStats,
    ForkDetector, ForkPoint, ForkReplayCoordinator, MetricsTracker, OptimisticConfirmationTracker,
    PerformanceAlert, PerformanceAnomaly, PerformanceMonitor, PerformanceThresholds,
    ReplayBatchProcessor, ReplayConfig, ReplayOptimizer, ReplayStage, ReplayStats, SlotMetrics,
    SlotReplayInfo, TransactionResult, VoteIntegration, VoteIntegrationError,
};
pub use shred_assembler::{
    detect_block_boundary, group_shreds_by_slot, AssembledBlock, Entry, ShredAssembler,
    ShredAssemblyError, ShredAssemblyResult, ShredAssemblyStats,
};
pub use shred_filter::ShredFilter;
pub use stats::{BlockAssemblyStats, IngressFilterStats, ShredFilterStats};
pub use tx_filter::TxFilter;
pub use types::{
    AssembledBlockFragment, AssemblyPolicy, ExecutionEnginePolicy, ExecutionErrorHandlingPolicy,
    ExecutionHealthPolicy, ForkChoiceQuarantinePolicy, ForkChoiceRuntimePolicy, InboundPacket,
    LeaderSchedulePolicy, MetricsOutputFormat, MetricsOutputTarget, ReplayControllerPolicy,
    ReplaySafetyPolicy, ReplayWindowPolicy, SanitizedShred, SanitizedTransaction,
    SchedulerRuntimePolicy, SnapshotRetentionPolicy, StorageRuntimePolicy, StorageStartupPolicy,
    StorageStartupStrictRestorePolicy,
};

pub(crate) use stats::{BlockAssemblyMetrics, IngressFilterMetrics, ShredFilterMetrics};
