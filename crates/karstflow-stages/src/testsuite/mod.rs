use crate::{
    AssemblyPolicy, BlockAssembler, BlockAssemblyStats, EdgeIntake, ExecutionEnginePolicy,
    ExecutionErrorHandlingPolicy, ExecutionHealthPolicy, ForkChoiceQuarantinePolicy,
    ForkChoiceRuntimePolicy, InboundPacket, IngressFilterStats, LeaderSchedulePolicy,
    LinkTelemetryStats, MetricsOutputFormat, MetricsOutputTarget, MetricsReporter,
    ReplaySafetyPolicy, ReplayWindowPolicy, SanitizedTransaction, SchedulerRuntimePolicy,
    ShredFilterStats, SnapshotRetentionPolicy, StageTelemetryStats, StorageRuntimePolicy,
    StorageStartupPolicy, TxFilter,
};
use karstflow_execution::RetryPolicy;
use karstflow_mesh::bounded_link;
use karstflow_net::{IngressMode, IngressPolicy, IngressSource};
use karstflow_runtime::{Service, ServiceContext, ShutdownSwitch};
use karstflow_storage::{CommittedFragmentRecord, HotStateStore, SnapshotCatalog};
use std::fs;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_storage_runtime_policy() -> StorageRuntimePolicy {
    StorageRuntimePolicy {
        execution_engine_policy: ExecutionEnginePolicy::Heuristic,
        ..StorageRuntimePolicy::default()
    }
}

fn unique_temp_file(prefix: &str, extension: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{suffix}.{extension}"))
}

fn write_catalog_with_fragments(path: &std::path::Path, fragments: &[u64]) {
    let mut store = HotStateStore::new();
    let mut catalog = SnapshotCatalog::new();
    for fragment_id in fragments {
        let record = CommittedFragmentRecord {
            fragment_id: *fragment_id,
            transaction_count: 5,
            total_cost_units: 500,
        };
        store.apply_committed_fragment(&record).unwrap();
        catalog.write_snapshot(*fragment_id, &store).unwrap();
    }
    catalog.persist_to_file(path).unwrap();
}

mod block_assembler_runtime;
mod block_assembler_startup;
mod leader_pipeline_e2e;
mod metrics_reporter;
mod pipeline;
mod shred_collector;
mod shred_filter;
mod tx_filter;
