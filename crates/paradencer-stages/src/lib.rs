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
mod codec_impls;
mod dedup_stage;
mod edge_intake;
mod errors;
mod exec_stage;
mod execution_adapter;
mod fec_cache;
mod fec_resolver;
pub mod health;
#[cfg(test)]
mod integration_tests;
mod leader_pipeline;
pub mod metrics_aggregator;
pub mod metrics_http;
mod metrics_reporter;
pub mod pack_stage;
mod pipeline_service;
mod replay_service;
mod replay_stage;
mod resolv_service;
mod resolv_stage;
mod shred_assembler;
mod shred_collector;
mod shred_filter;
pub mod shred_link;
mod shred_network;
mod shred_store_service;
pub mod shred_verifier;
mod sign_service;
mod stats;
#[cfg(test)]
mod testsuite;
mod tile_metrics;
mod tile_pipeline;
mod tx_filter;
mod types;
mod verify_service;
mod verify_stage;

pub use block_assembler::BlockAssembler;
pub use dedup_stage::{DedupOutcome, DedupStage, DedupStats, TransactionCache};
pub use edge_intake::EdgeIntake;
pub use errors::StageError;
pub use execution_adapter::SbpfExecutionAdapter;
pub use health::{shared_health_status, SharedHealthStatus};
pub use metrics_aggregator::{
    AggregatedSnapshot, DedupSnapshot, FecCacheSnapshot, FecResolverSnapshot, GossipSnapshot,
    GossipStatsRef, MetricsAggregator, ReplaySnapshot,
};
pub use metrics_http::{
    shared_metrics_content, MetricsContent, MetricsHttpServer, MetricsHttpStats,
};
pub use metrics_reporter::{LinkTelemetryStats, MetricsReporter, StageTelemetryStats};
pub use replay_stage::{
    AggregateMetrics, AlertSeverity, AlertType, AncestryError, AncestryStats, AncestryVerifier,
    AnomalyType, BankTransition, BankTransitionError, BatchReplayResult, BecameLeaderInfo,
    BlockOutcome, BlockProcessor, BlockProcessorError, ConfirmationInfo, ConfirmationStats,
    CoordinatorStats, DependencyGraph, DispatchProgress, DispatchState, DispatcherStats,
    ForkDetector, ForkPoint, ForkReplayCoordinator, MetricsTracker, OptimisticConfirmationInfo,
    OptimisticConfirmationTracker, PerformanceAlert, PerformanceAnomaly, PerformanceMonitor,
    PerformanceThresholds, PohResetInfo, ReplayBatchProcessor, ReplayConfig, ReplayOptimizer,
    ReplaySignal, ReplayStage, ReplayStats, RootAdvancedInfo, SignalBus, SlotCompletedInfo,
    SlotDeadInfo, SlotDeadReason, SlotMetrics, SlotReplayInfo, TransactionDispatcher,
    TransactionResult, VoteIntegration, VoteIntegrationError,
};
pub use shred_assembler::{
    detect_block_boundary, group_shreds_by_slot, AssembledBlock, Entry, ShredAssembler,
    ShredAssemblyError, ShredAssemblyResult, ShredAssemblyStats,
};
pub use shred_collector::{
    ShredArrival, ShredCollector, ShredCollectorConfig, ShredCollectorStats,
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

pub use exec_stage::{
    ExecConfig, ExecStage, ExecStats, ExecStatsSnapshot, ExecutionEngine, MicroblockExecResult,
    MockExecutionEngine, TransactionExecResult,
};
pub use fec_cache::{CachedFecSet, FecCacheConfig, FecCacheStats, FecSetCache};
pub use fec_resolver::{
    AtomicFecResolverStats, EquivocationProof, FecBufferHandle, FecResolverPool, FecResolverStats,
    FecSetKey, FecSetView, FecSetViewMut, ResolverInsertResult, SpilledFecSet,
};
pub use leader_pipeline::{
    LeaderPipeline, LeaderPipelineStats, PipelineStepResult, SbpfExecutionEngine,
};
pub use pack_stage::{
    AccountLock, ConflictDetector, LockKind, Microblock, MicroblockRebate, PackConfig, PackLimits,
    PackOutcome, PackPacer, PackScheduler, PackStats, PackStatsSnapshot, PackedTransaction,
    TransactionQueue,
};
pub use pipeline_service::{
    PipelineHandle, PipelineService, PipelineServiceBuilder, PipelineServiceConfig,
    PipelineServiceStats, PipelineStageStats, RawTransaction,
};
pub use replay_service::{OrphanBuffer, ReplayService, ReplayServiceConfig};
pub use resolv_service::{ResolvService, ResolvServiceStats};
pub use resolv_stage::{
    Blockhash, ResolvConfig, ResolvOutcome, ResolvStage, ResolvStats, ResolvStatsSnapshot,
    ResolvedTransaction,
};
pub use shred_network::{
    CompletedFecSet, NetworkShred, RetransmitDecision, ShredInsertOutcome, ShredNetworkConfig,
    ShredNetworkService, ShredNetworkStage, ShredNetworkStats, ShredNetworkStatsSnapshot,
    ShredSource,
};
pub use shred_store_service::{ShredStoreConfig, ShredStoreService, ShredStoreStats};
pub use shred_verifier::{DeferredLeaderLookup, LeaderLookup, ShredVerifyResult};
pub use sign_service::{SignError, SignResult, SignService, SignServiceStats, SignType};
pub use tile_metrics::{SignalBusHealthTracker, TickTimer, TickTimerSnapshot};
pub use tile_pipeline::{
    DedupTile, PipelineConfig, ResolvTile, TransactionPipeline, ValidatorPipeline,
    ValidatorPipelineResult, VerifyTile,
};
pub use verify_service::{VerifyService, VerifyServiceStats};
pub use verify_stage::{
    TransactionSource, UnverifiedTransaction, VerifiedTransaction, VerifyConfig, VerifyOutcome,
    VerifyStage, VerifyStats, VerifyStatsSnapshot,
};

pub(crate) use stats::{BlockAssemblyMetrics, IngressFilterMetrics, ShredFilterMetrics};
