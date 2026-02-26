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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_batch(fragment_id: u64, cost: u64) -> ExecutionBatch {
        ExecutionBatch {
            fragment_id,
            transaction_count: 10,
            estimated_total_cost_units: cost,
            transactions: None,
        }
    }

    fn make_context() -> RuntimeBatchContext {
        RuntimeBatchContext {
            estimated_accounts_touched: 5,
            expected_program_invocations: 2,
            program_cache_hint: super::super::ProgramCacheHint::WarmPath,
        }
    }

    #[test]
    fn new_creates_default_adapter() {
        let adapter = StorageBackedRuntimeAdapter::new();
        let snapshot = adapter.state_snapshot().unwrap();
        assert_eq!(snapshot.last_fragment_id, 0);
    }

    #[test]
    fn default_creates_same_as_new() {
        let adapter = StorageBackedRuntimeAdapter::default();
        let snapshot = adapter.state_snapshot().unwrap();
        assert_eq!(snapshot.last_fragment_id, 0);
    }

    #[test]
    fn with_shared_state_store() {
        let store = Arc::new(Mutex::new(RuntimeStateStore::new()));
        let adapter = StorageBackedRuntimeAdapter::with_state_store(store.clone());
        // Mutating the shared store should be visible through the adapter
        store.lock().unwrap().seed_checkpoint(42);
        let snapshot = adapter.state_snapshot().unwrap();
        assert_eq!(snapshot.last_fragment_id, 42);
    }

    #[test]
    fn preflight_returns_commit_candidate() {
        let adapter = StorageBackedRuntimeAdapter::new();
        let batch = make_batch(100, 50_000);
        let context = make_context();

        let preflight = adapter.preflight_batch(&batch, &context).unwrap();

        assert_eq!(preflight.total_cost_units, 50_000);
        assert_eq!(
            preflight.state_write_intent,
            RuntimeStateWriteIntent::CommitCandidate { fragment_id: 100 }
        );
        assert_eq!(
            preflight.account_access_pattern,
            AccountAccessPattern::ReadWriteMixed
        );
        assert!(!preflight.requires_program_cache_refresh);
    }

    #[test]
    fn preflight_enforces_minimum_cost_of_one() {
        let adapter = StorageBackedRuntimeAdapter::new();
        let batch = make_batch(1, 0);
        let context = make_context();

        let preflight = adapter.preflight_batch(&batch, &context).unwrap();
        assert_eq!(preflight.total_cost_units, 1);
    }

    #[test]
    fn execute_batch_reports_zero_failures() {
        let adapter = StorageBackedRuntimeAdapter::new();
        let batch = make_batch(100, 50_000);
        let context = make_context();

        let preflight = adapter.preflight_batch(&batch, &context).unwrap();
        let observation = adapter.execute_batch(&batch, &context, &preflight);

        assert_eq!(observation.failed_transactions, 0);
        assert!(observation.failure_class.is_none());
        assert_eq!(observation.consumed_compute_units, 50_000);
        assert_eq!(observation.write_lock_contention_ratio_bps, 0);
    }

    #[test]
    fn rewind_to_fragment_succeeds_on_fresh_store() {
        let adapter = StorageBackedRuntimeAdapter::new();
        // Rewind to 0 on empty store should succeed
        let result = adapter.rewind_to_fragment(0);
        assert!(result.is_ok());
    }

    #[test]
    fn rewind_to_seeded_checkpoint() {
        let store = Arc::new(Mutex::new(RuntimeStateStore::new()));
        store.lock().unwrap().seed_checkpoint(10);
        let adapter = StorageBackedRuntimeAdapter::with_state_store(store);

        // Rewind to the seeded checkpoint
        let result = adapter.rewind_to_fragment(10);
        assert!(result.is_ok());
    }
}
