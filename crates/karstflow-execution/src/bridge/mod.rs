mod directives;
mod retry;

use crate::engine::{AccountBackedExecutionEngine, ExecutionEngine};
use crate::errors::ExecutionError;
use crate::types::{
    ExecutionBatch, ExecutionFailureClass, ExecutionOutcome, ForkChoiceDirective,
    LeaderGateDirective, LeaderGateState, ReplayBoundaryState, RetryDirective, RetryPolicy,
    SchedulerDirective,
};
use directives::{derive_scheduler_directive, evaluate_leader_gate, update_replay_boundary};
use retry::derive_retry_directive;
use std::sync::Arc;

pub trait ExecutionStateController: Send + Sync {
    fn rewind_to_fragment(
        &self,
        target_fragment_id: u64,
    ) -> std::result::Result<(), ExecutionError>;
}

pub struct ExecutionBridge {
    engine: Arc<dyn ExecutionEngine>,
    retry_policy: RetryPolicy,
    state_controller: Option<Arc<dyn ExecutionStateController>>,
}

impl ExecutionBridge {
    pub fn new() -> Self {
        Self::with_engine_and_retry_policy(
            Arc::new(AccountBackedExecutionEngine::new(
                karstflow_storage::AccountDatabase::new(),
            )),
            RetryPolicy::default(),
        )
    }

    pub fn with_engine(engine: Arc<dyn ExecutionEngine>) -> Self {
        Self::with_engine_and_retry_policy(engine, RetryPolicy::default())
    }

    pub fn with_engine_and_retry_policy(
        engine: Arc<dyn ExecutionEngine>,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self::with_engine_retry_policy_and_state_controller(engine, retry_policy, None)
    }

    pub fn with_engine_retry_policy_and_state_controller(
        engine: Arc<dyn ExecutionEngine>,
        retry_policy: RetryPolicy,
        state_controller: Option<Arc<dyn ExecutionStateController>>,
    ) -> Self {
        Self {
            engine,
            retry_policy,
            state_controller,
        }
    }

    pub fn with_retry_policy(retry_policy: RetryPolicy) -> Self {
        Self::with_engine_and_retry_policy(
            Arc::new(AccountBackedExecutionEngine::new(
                karstflow_storage::AccountDatabase::new(),
            )),
            retry_policy,
        )
    }

    pub fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        if batch.transaction_count == 0 {
            return Err(ExecutionError::EmptyBatch {
                fragment_id: batch.fragment_id,
            });
        }

        self.engine
            .try_execute_batch(batch)
            .map(|outcome| normalize_engine_outcome(outcome, batch))
    }

    pub fn execute_batch(&self, batch: &ExecutionBatch) -> ExecutionOutcome {
        self.execute_batch_with_error(batch).0
    }

    pub fn execute_batch_with_error(
        &self,
        batch: &ExecutionBatch,
    ) -> (ExecutionOutcome, Option<ExecutionError>) {
        match self.try_execute_batch(batch) {
            Ok(outcome) => (outcome, None),
            Err(error) => {
                let failure_class = classify_engine_error(&error);
                (
                    ExecutionOutcome {
                        fragment_id: batch.fragment_id,
                        executed_transactions: 0,
                        failed_transactions: fallback_failed_transactions(
                            failure_class,
                            batch.transaction_count,
                        ),
                        total_cost_units: normalized_batch_total_cost_units(batch),
                        failure_class,
                    },
                    Some(error),
                )
            }
        }
    }

    pub fn update_replay_boundary(
        &self,
        state: &mut ReplayBoundaryState,
        outcome: &ExecutionOutcome,
    ) -> ForkChoiceDirective {
        update_replay_boundary(state, outcome)
    }

    pub fn evaluate_leader_gate(&self, leader_gate_state: &LeaderGateState) -> LeaderGateDirective {
        evaluate_leader_gate(leader_gate_state)
    }

    pub fn derive_scheduler_directive(
        &self,
        leader_gate_state: &LeaderGateState,
        outcome: &ExecutionOutcome,
    ) -> SchedulerDirective {
        derive_scheduler_directive(leader_gate_state, outcome)
    }

    pub fn derive_retry_directive(&self, outcome: &ExecutionOutcome) -> RetryDirective {
        derive_retry_directive(&self.retry_policy, outcome)
    }

    pub fn rewind_execution_state_to_fragment(
        &self,
        target_fragment_id: u64,
    ) -> std::result::Result<bool, ExecutionError> {
        match self.state_controller.as_ref() {
            Some(controller) => {
                controller.rewind_to_fragment(target_fragment_id)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Default for ExecutionBridge {
    fn default() -> Self {
        Self::new()
    }
}

fn classify_engine_error(error: &ExecutionError) -> Option<ExecutionFailureClass> {
    match error {
        ExecutionError::EmptyBatch { .. }
        | ExecutionError::CostOverflow { .. }
        | ExecutionError::AdapterContractViolation { .. }
        | ExecutionError::AdapterReceiptMissing { .. }
        | ExecutionError::InvalidBatch { .. } => {
            Some(ExecutionFailureClass::DeterministicTransactionFailure)
        }
        ExecutionError::AdapterStateConflict { .. } => Some(ExecutionFailureClass::ReplayConflict),
        ExecutionError::AdapterApplyFailure { .. }
        | ExecutionError::AdapterRollbackFailure { .. }
        | ExecutionError::AdapterMutexPoisoned { .. }
        | ExecutionError::StorageBackend { .. } => {
            Some(ExecutionFailureClass::TransientSchedulerPressure)
        }
    }
}

fn fallback_failed_transactions(
    failure_class: Option<ExecutionFailureClass>,
    batch_transaction_count: usize,
) -> usize {
    match failure_class {
        Some(ExecutionFailureClass::ReplayConflict) => 0,
        _ => batch_transaction_count,
    }
}

fn normalize_engine_outcome(
    mut outcome: ExecutionOutcome,
    batch: &ExecutionBatch,
) -> ExecutionOutcome {
    outcome.fragment_id = batch.fragment_id;
    outcome.failed_transactions = outcome.failed_transactions.min(batch.transaction_count);
    if outcome.total_cost_units == 0 {
        outcome.total_cost_units = normalized_batch_total_cost_units(batch);
    }
    outcome.failure_class =
        normalize_failure_class_invariants(outcome.failed_transactions, outcome.failure_class);
    outcome.executed_transactions = batch
        .transaction_count
        .saturating_sub(outcome.failed_transactions);
    outcome
}

fn normalized_batch_total_cost_units(batch: &ExecutionBatch) -> u64 {
    if batch.transaction_count == 0 {
        0
    } else {
        batch.estimated_total_cost_units.max(1)
    }
}

fn normalize_failure_class_invariants(
    failed_transactions: usize,
    failure_class: Option<ExecutionFailureClass>,
) -> Option<ExecutionFailureClass> {
    match (failed_transactions, failure_class) {
        (0, Some(ExecutionFailureClass::DeterministicTransactionFailure))
        | (0, Some(ExecutionFailureClass::TransientSchedulerPressure))
        | (0, Some(ExecutionFailureClass::ResourceExhaustion)) => None,
        (failed, None) if failed > 0 => {
            Some(ExecutionFailureClass::DeterministicTransactionFailure)
        }
        _ => failure_class,
    }
}

#[cfg(test)]
mod tests;
