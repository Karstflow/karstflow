use super::{
    AccountAccessPattern, RuntimeBatchContext, RuntimeExecutionAdapter,
    RuntimeExecutionObservation, RuntimePreflightOutcome, RuntimeStateWriteIntent,
};
use crate::bridge::ExecutionStateController;
use crate::errors::ExecutionError;
use crate::types::ExecutionBatch;
use paradencer_storage::{RuntimeStateSnapshot, RuntimeStateStore};
use std::sync::{Arc, Mutex};

pub type RuntimeStateStoreSnapshot = RuntimeStateSnapshot;

pub struct StorageBackedRuntimeAdapter {
    state_store: Arc<Mutex<RuntimeStateStore>>,
}

impl StorageBackedRuntimeAdapter {
    pub fn new() -> Self {
        Self {
            state_store: Arc::new(Mutex::new(RuntimeStateStore::new())),
        }
    }

    pub fn with_state_store(state_store: Arc<Mutex<RuntimeStateStore>>) -> Self {
        Self { state_store }
    }

    pub fn with_state_store_and_policies(
        state_store: Arc<Mutex<RuntimeStateStore>>,
        _account_state_apply_policy: super::AccountStateApplyPolicy,
        _program_cache_apply_policy: super::ProgramCacheApplyPolicy,
    ) -> Self {
        Self { state_store }
    }

    pub fn state_snapshot(&self) -> std::result::Result<RuntimeStateStoreSnapshot, ExecutionError> {
        let store =
            self.state_store
                .lock()
                .map_err(|error| ExecutionError::AdapterMutexPoisoned {
                    fragment_id: 0,
                    lock_name: "state_store",
                    detail: error.to_string(),
                })?;
        Ok(store.snapshot())
    }
}

impl Default for StorageBackedRuntimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionStateController for StorageBackedRuntimeAdapter {
    fn rewind_to_fragment(
        &self,
        target_fragment_id: u64,
    ) -> std::result::Result<(), ExecutionError> {
        let mut store =
            self.state_store
                .lock()
                .map_err(|error| ExecutionError::AdapterMutexPoisoned {
                    fragment_id: target_fragment_id,
                    lock_name: "state_store",
                    detail: error.to_string(),
                })?;
        store
            .rewind_to_fragment(target_fragment_id)
            .map_err(|storage_error| ExecutionError::AdapterRollbackFailure {
                fragment_id: target_fragment_id,
                message: storage_error.to_string(),
            })?;
        Ok(())
    }
}

impl RuntimeExecutionAdapter for StorageBackedRuntimeAdapter {
    fn preflight_batch(
        &self,
        batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
    ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
        let total_cost_units = batch.estimated_total_cost_units.max(1);
        Ok(RuntimePreflightOutcome {
            total_cost_units,
            state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                fragment_id: batch.fragment_id,
            },
            account_access_pattern: AccountAccessPattern::ReadWriteMixed,
            requires_program_cache_refresh: false,
        })
    }

    fn execute_batch(
        &self,
        _batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
        preflight: &RuntimePreflightOutcome,
    ) -> RuntimeExecutionObservation {
        RuntimeExecutionObservation {
            failed_transactions: 0,
            failure_class: None,
            consumed_compute_units: preflight.total_cost_units,
            write_lock_contention_ratio_bps: 0,
        }
    }
}
