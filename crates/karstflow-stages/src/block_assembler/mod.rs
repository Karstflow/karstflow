mod bank_timeline;
mod fork_choice_engine;
mod publication_gate;
mod replay_controller;
mod retry;
mod service;
mod slot_pipeline;

use crate::errors::StageError;
use crate::{
    BlockAssemblyStats, ExecutionEnginePolicy, SanitizedTransaction, StorageRuntimePolicy,
    StorageStartupPolicy,
};
use bank_timeline::BankTimeline;
use karstflow_execution::{
    ExecutionBridge, ExecutionEngine, ExecutionStateController, HeuristicExecutionEngine,
    LeaderGateState, ReplayBoundaryState, RuntimeLikeExecutionEngine, StorageBackedRuntimeAdapter,
};
use karstflow_mesh::DualReceiver;
use karstflow_runtime::{RuntimeError, RuntimeResult, Service};
use karstflow_storage::{CommittedFragmentRecord, HotStateStore, SnapshotCatalog};
use publication_gate::PublicationGate;
use replay_controller::ReplayController;
use slot_pipeline::SlotPipelineStateMachine;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRetryFragment {
    fragment_id: u64,
    transaction_count: usize,
    total_cost_units: u64,
    retries_attempted: u8,
    wait_ticks_remaining: u32,
}

pub struct BlockAssembler {
    incoming_transactions: Vec<DualReceiver<SanitizedTransaction>>,
    next_incoming_transaction_index: usize,
    closed_incoming_transactions: Vec<bool>,
    closed_incoming_transaction_count: usize,
    pub(crate) fragment_counter: u64,
    buffered_transactions: usize,
    buffered_cost_units: u64,
    buffered_ticks: u32,
    pending_retry: Option<PendingRetryFragment>,
    pub(crate) dropped_fragments: u64,
    consecutive_execution_errors: u32,
    consecutive_transient_failures: u32,
    cooldown_ticks_remaining: u32,
    consecutive_replay_conflicts: u32,
    replay_safety_hold_ticks_remaining: u32,
    consecutive_reorg_directives: u32,
    fork_choice_quarantine_ticks_remaining: u32,
    execution_bridge: ExecutionBridge,
    pub(crate) replay_boundary_state: ReplayBoundaryState,
    leader_gate_state: LeaderGateState,
    pub(crate) hot_state_store: HotStateStore,
    snapshot_catalog: SnapshotCatalog,
    block_assembly_stats: Arc<BlockAssemblyStats>,
    pub(crate) storage_runtime_policy: StorageRuntimePolicy,
    slot_pipeline: SlotPipelineStateMachine,
    replay_controller: ReplayController,
    publication_gate: PublicationGate,
    bank_timeline: BankTimeline,
}

impl BlockAssembler {
    pub fn new(incoming_transactions: DualReceiver<SanitizedTransaction>) -> Self {
        Self::with_storage_policy(incoming_transactions, StorageRuntimePolicy::default())
            .unwrap_or_else(|error| panic!("default storage policy must be valid: {error}"))
    }

    pub fn with_storage_policy(
        incoming_transactions: DualReceiver<SanitizedTransaction>,
        storage_runtime_policy: StorageRuntimePolicy,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_inputs(vec![incoming_transactions], storage_runtime_policy)
    }

    pub fn with_storage_policy_inputs(
        incoming_transactions: Vec<DualReceiver<SanitizedTransaction>>,
        storage_runtime_policy: StorageRuntimePolicy,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_and_stats_and_inputs(
            incoming_transactions,
            storage_runtime_policy,
            Arc::new(BlockAssemblyStats::default()),
        )
    }

    pub fn with_storage_policy_and_input(
        incoming_transactions: DualReceiver<SanitizedTransaction>,
        storage_runtime_policy: StorageRuntimePolicy,
        block_assembly_stats: Arc<BlockAssemblyStats>,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_and_stats_and_inputs(
            vec![incoming_transactions],
            storage_runtime_policy,
            block_assembly_stats,
        )
    }

    pub fn with_storage_policy_and_stats(
        incoming_transactions: DualReceiver<SanitizedTransaction>,
        storage_runtime_policy: StorageRuntimePolicy,
        block_assembly_stats: Arc<BlockAssemblyStats>,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_and_stats_and_inputs(
            vec![incoming_transactions],
            storage_runtime_policy,
            block_assembly_stats,
        )
    }

    pub fn with_storage_policy_and_stats_and_inputs(
        incoming_transactions: Vec<DualReceiver<SanitizedTransaction>>,
        storage_runtime_policy: StorageRuntimePolicy,
        block_assembly_stats: Arc<BlockAssemblyStats>,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_and_stats_and_inputs_with_execution_bridge_override(
            incoming_transactions,
            storage_runtime_policy,
            block_assembly_stats,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_storage_policy_and_stats_and_execution_bridge(
        incoming_transactions: DualReceiver<SanitizedTransaction>,
        storage_runtime_policy: StorageRuntimePolicy,
        block_assembly_stats: Arc<BlockAssemblyStats>,
        execution_bridge: ExecutionBridge,
    ) -> std::result::Result<Self, StageError> {
        Self::with_storage_policy_and_stats_and_inputs_with_execution_bridge_override(
            vec![incoming_transactions],
            storage_runtime_policy,
            block_assembly_stats,
            Some(execution_bridge),
        )
    }

    fn with_storage_policy_and_stats_and_inputs_with_execution_bridge_override(
        incoming_transactions: Vec<DualReceiver<SanitizedTransaction>>,
        storage_runtime_policy: StorageRuntimePolicy,
        block_assembly_stats: Arc<BlockAssemblyStats>,
        execution_bridge_override: Option<ExecutionBridge>,
    ) -> std::result::Result<Self, StageError> {
        if incoming_transactions.is_empty() {
            return Err(StageError::InvalidStoragePolicy(
                "at least one incoming transaction input is required".to_string(),
            ));
        }
        if storage_runtime_policy.snapshot_catalog_path.is_none() {
            match storage_runtime_policy.startup_policy {
                StorageStartupPolicy::RestoreLatestIfAvailable
                    if storage_runtime_policy
                        .startup_strict_restore_policy
                        .restore_latest_requires_snapshot =>
                {
                    return Err(StageError::StorageStartupStrictRestoreRequiresCatalogPath {
                        startup_policy: "restore_latest_if_available",
                    });
                }
                StorageStartupPolicy::RestoreSpecificIfAvailable { .. }
                    if storage_runtime_policy
                        .startup_strict_restore_policy
                        .restore_specific_requires_snapshot =>
                {
                    return Err(StageError::StorageStartupStrictRestoreRequiresCatalogPath {
                        startup_policy: "restore_specific_if_available",
                    });
                }
                _ => {}
            }
        }

        let mut hot_state_store = HotStateStore::new();
        let snapshot_catalog = match storage_runtime_policy.snapshot_catalog_path.as_deref() {
            Some(path) => SnapshotCatalog::load_from_file_if_exists(path)
                .map_err(|error| StageError::StorageCatalogLoad {
                    path: path.to_path_buf(),
                    message: error.to_string(),
                })?
                .unwrap_or_default(),
            None => SnapshotCatalog::new(),
        };

        match storage_runtime_policy.startup_policy {
            StorageStartupPolicy::SkipRestore => {}
            StorageStartupPolicy::RestoreLatestIfAvailable => {
                if let Some(snapshot) = snapshot_catalog.restore_latest_snapshot() {
                    hot_state_store.restore_from_snapshot(&snapshot);
                } else if storage_runtime_policy
                    .startup_strict_restore_policy
                    .restore_latest_requires_snapshot
                {
                    return Err(StageError::StorageStartupMissingLatestSnapshot);
                }
            }
            StorageStartupPolicy::RestoreSpecificIfAvailable { fragment_id } => {
                if let Ok(snapshot) = snapshot_catalog.restore_snapshot(fragment_id) {
                    hot_state_store.restore_from_snapshot(&snapshot);
                } else if storage_runtime_policy
                    .startup_strict_restore_policy
                    .restore_specific_requires_snapshot
                {
                    return Err(StageError::StorageStartupMissingSpecificSnapshot { fragment_id });
                }
            }
        }

        let restored_fragment_id = hot_state_store.last_fragment_id;
        let restored_executed_transactions = hot_state_store.committed_transactions;
        let execution_bridge = execution_bridge_override.unwrap_or_else(|| {
            build_execution_bridge(&storage_runtime_policy, restored_fragment_id)
        });
        let leader_schedule_policy = storage_runtime_policy.leader_schedule_policy;
        let startup_slot = leader_schedule_policy
            .initial_slot
            .max(restored_fragment_id);
        let replay_controller_policy = storage_runtime_policy.replay_controller_policy;
        let replay_window_policy = storage_runtime_policy.replay_window_policy;
        let mut bank_timeline = BankTimeline::new(replay_window_policy);
        bank_timeline.seed_from_restored_state(&hot_state_store);
        block_assembly_stats.set_replay_window_checkpoint_depth(bank_timeline.len() as u64);
        let incoming_transaction_count = incoming_transactions.len();

        Ok(Self {
            incoming_transactions,
            next_incoming_transaction_index: 0,
            closed_incoming_transactions: vec![false; incoming_transaction_count],
            closed_incoming_transaction_count: 0,
            fragment_counter: restored_fragment_id,
            buffered_transactions: 0,
            buffered_cost_units: 0,
            buffered_ticks: 0,
            pending_retry: None,
            dropped_fragments: 0,
            consecutive_execution_errors: 0,
            consecutive_transient_failures: 0,
            cooldown_ticks_remaining: 0,
            consecutive_replay_conflicts: 0,
            replay_safety_hold_ticks_remaining: 0,
            consecutive_reorg_directives: 0,
            fork_choice_quarantine_ticks_remaining: 0,
            execution_bridge,
            replay_boundary_state: ReplayBoundaryState {
                last_applied_fragment_id: restored_fragment_id,
                total_executed_transactions: restored_executed_transactions,
            },
            leader_gate_state: LeaderGateState {
                is_current_leader: true,
                next_leader_slot: startup_slot,
            },
            hot_state_store,
            snapshot_catalog,
            block_assembly_stats,
            storage_runtime_policy,
            slot_pipeline: SlotPipelineStateMachine::new(startup_slot),
            replay_controller: ReplayController::new(
                restored_fragment_id,
                replay_controller_policy.candidate_confirmation_threshold,
                replay_controller_policy.candidate_confirmation_max_failed_ratio_bps,
                replay_controller_policy.max_candidates,
                replay_controller_policy.reorg_signal_weight,
                replay_controller_policy.fragment_recency_weight,
                replay_controller_policy.failed_transaction_ratio_penalty_weight,
                replay_controller_policy.candidate_stale_fragment_lag,
                replay_controller_policy.candidate_switch_min_score_delta,
            ),
            publication_gate: PublicationGate::new(),
            bank_timeline,
        })
    }

    fn delay_to_ticks(delay_millis: u64) -> u32 {
        let base_tick_millis = 2_u64;
        let ticks = delay_millis.div_ceil(base_tick_millis).max(1);
        ticks.min(u32::MAX as u64) as u32
    }

    fn persist_catalog_if_configured(&self) -> RuntimeResult<()> {
        if let Some(path) = self.storage_runtime_policy.snapshot_catalog_path.as_ref() {
            self.snapshot_catalog
                .persist_to_file(path)
                .map_err(|error| {
                    RuntimeError::service_failure(
                        self.name(),
                        &StageError::StorageCatalogPersist {
                            path: path.clone(),
                            message: error.to_string(),
                        }
                        .to_string(),
                    )
                })?;
        }
        Ok(())
    }

    fn commit_fragment(
        &mut self,
        fragment_id: u64,
        transaction_count: usize,
        total_cost_units: u64,
    ) -> RuntimeResult<()> {
        let committed_record = CommittedFragmentRecord {
            fragment_id,
            transaction_count,
            total_cost_units,
        };
        self.hot_state_store
            .apply_committed_fragment(&committed_record)
            .map_err(|error| RuntimeError::service_failure(self.name(), &error.to_string()))?;
        self.snapshot_catalog
            .maybe_write_snapshot(
                &committed_record,
                &self.hot_state_store,
                self.storage_runtime_policy.snapshot_interval,
            )
            .map_err(|error| RuntimeError::service_failure(self.name(), &error.to_string()))?;
        self.snapshot_catalog.enforce_retention(
            self.storage_runtime_policy
                .snapshot_retention_policy
                .max_catalog_snapshots,
        );
        self.bank_timeline
            .record_commit(&committed_record, &self.hot_state_store);
        self.block_assembly_stats
            .set_replay_window_checkpoint_depth(self.bank_timeline.len() as u64);
        self.persist_catalog_if_configured()?;
        self.block_assembly_stats.increment_committed_fragments();
        Ok(())
    }
}

fn build_execution_bridge(
    storage_runtime_policy: &StorageRuntimePolicy,
    restored_fragment_id: u64,
) -> ExecutionBridge {
    let (execution_engine, state_controller): (
        Arc<dyn ExecutionEngine>,
        Option<Arc<dyn ExecutionStateController>>,
    ) = match storage_runtime_policy.execution_engine_policy {
        ExecutionEnginePolicy::Heuristic => (Arc::new(HeuristicExecutionEngine::new()), None),
        ExecutionEnginePolicy::RuntimeLike => {
            let mut seeded_store = karstflow_storage::RuntimeStateStore::new();
            if restored_fragment_id > 0 {
                seeded_store.seed_checkpoint(restored_fragment_id);
            }
            let state_store = Arc::new(std::sync::Mutex::new(seeded_store));
            let adapter = Arc::new(StorageBackedRuntimeAdapter::with_state_store_and_policies(
                state_store,
                storage_runtime_policy.runtime_like_account_state_apply_policy,
                storage_runtime_policy.runtime_like_program_cache_apply_policy,
            ));
            let execution_engine: Arc<dyn ExecutionEngine> =
                Arc::new(RuntimeLikeExecutionEngine::with_adapter(adapter.clone()));
            let state_controller: Arc<dyn ExecutionStateController> = adapter;
            (execution_engine, Some(state_controller))
        }
    };
    ExecutionBridge::with_engine_retry_policy_and_state_controller(
        execution_engine,
        storage_runtime_policy.execution_retry_policy,
        state_controller,
    )
}
