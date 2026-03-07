use super::{
    ExecutionBatch, ExecutionBridge, ExecutionError, ExecutionFailureClass, ExecutionOutcome,
    ForkChoiceDirective, LeaderGateDirective, LeaderGateState, ReplayBoundaryState, RetryDirective,
    RetryPolicy,
};
use crate::bridge::ExecutionStateController;
use crate::engine::{ExecutionEngine, HeuristicExecutionEngine};
use std::sync::{Arc, Mutex};

struct SuccessExecutionEngine;
struct FixedExecutionEngine;
struct OverreportingExecutionEngine;
struct MissingClassExecutionEngine;
struct ZeroFailedTransactionalClassExecutionEngine;
struct ZeroCostExecutionEngine;
struct FailingExecutionEngine {
    error: ExecutionError,
}

struct RecordingStateController {
    rewinds: Mutex<Vec<u64>>,
    fail_on_target: Option<u64>,
}

impl ExecutionEngine for SuccessExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions: batch.transaction_count,
            failed_transactions: 0,
            total_cost_units: batch.estimated_total_cost_units,
            failure_class: None,
        })
    }
}

impl ExecutionEngine for FixedExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions: 1,
            failed_transactions: batch.transaction_count.saturating_sub(1),
            total_cost_units: 123_456,
            failure_class: Some(ExecutionFailureClass::ResourceExhaustion),
        })
    }
}

impl ExecutionEngine for FailingExecutionEngine {
    fn try_execute_batch(
        &self,
        _batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Err(self.error.clone())
    }
}

impl ExecutionEngine for OverreportingExecutionEngine {
    fn try_execute_batch(
        &self,
        _batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: 999_999,
            executed_transactions: 1,
            failed_transactions: 10_000,
            total_cost_units: 88_000,
            failure_class: Some(ExecutionFailureClass::DeterministicTransactionFailure),
        })
    }
}

impl ExecutionEngine for MissingClassExecutionEngine {
    fn try_execute_batch(
        &self,
        _batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: 1,
            executed_transactions: 0,
            failed_transactions: 3,
            total_cost_units: 10_000,
            failure_class: None,
        })
    }
}

impl ExecutionEngine for ZeroFailedTransactionalClassExecutionEngine {
    fn try_execute_batch(
        &self,
        _batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: 1,
            executed_transactions: 0,
            failed_transactions: 0,
            total_cost_units: 10_000,
            failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
        })
    }
}

impl ExecutionEngine for ZeroCostExecutionEngine {
    fn try_execute_batch(
        &self,
        _batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Ok(ExecutionOutcome {
            fragment_id: 1,
            executed_transactions: 4,
            failed_transactions: 0,
            total_cost_units: 0,
            failure_class: None,
        })
    }
}

impl ExecutionStateController for RecordingStateController {
    fn rewind_to_fragment(
        &self,
        target_fragment_id: u64,
    ) -> std::result::Result<(), ExecutionError> {
        if self.fail_on_target == Some(target_fragment_id) {
            return Err(ExecutionError::AdapterRollbackFailure {
                fragment_id: target_fragment_id,
                message: "simulated rewind failure".to_string(),
            });
        }
        let mut rewinds = self.rewinds.lock().expect("rewinds mutex");
        rewinds.push(target_fragment_id);
        Ok(())
    }
}

#[test]
fn execution_bridge_produces_deterministic_outcome() {
    let bridge = ExecutionBridge::with_engine(Arc::new(SuccessExecutionEngine));
    let batch = ExecutionBatch::new(7, 64, 256_000);

    let outcome = bridge.execute_batch(&batch);
    assert_eq!(outcome.fragment_id, 7);
    assert_eq!(outcome.executed_transactions, 64);
    assert_eq!(outcome.failed_transactions, 0);
    assert_eq!(outcome.total_cost_units, 256_000);
    assert_eq!(outcome.failure_class, None);
}

#[test]
fn replay_boundary_updates_with_successful_outcome() {
    let bridge = ExecutionBridge::with_engine(Arc::new(SuccessExecutionEngine));
    let mut replay_state = ReplayBoundaryState {
        last_applied_fragment_id: 0,
        total_executed_transactions: 0,
    };
    let batch = ExecutionBatch::new(10, 8, 32_000);
    let outcome = bridge.execute_batch(&batch);

    let directive = bridge.update_replay_boundary(&mut replay_state, &outcome);
    assert_eq!(directive, ForkChoiceDirective::KeepCurrentFork);
    assert_eq!(replay_state.last_applied_fragment_id, 10);
    assert_eq!(replay_state.total_executed_transactions, 8);
}

#[test]
fn replay_boundary_total_executed_transactions_saturates_on_large_updates() {
    let bridge = ExecutionBridge::new();
    let mut replay_state = ReplayBoundaryState {
        last_applied_fragment_id: 0,
        total_executed_transactions: u64::MAX - 1,
    };
    let outcome = ExecutionOutcome {
        fragment_id: 11,
        executed_transactions: 10,
        failed_transactions: 0,
        total_cost_units: 100_000,
        failure_class: None,
    };

    let directive = bridge.update_replay_boundary(&mut replay_state, &outcome);
    assert_eq!(directive, ForkChoiceDirective::KeepCurrentFork);
    assert_eq!(replay_state.last_applied_fragment_id, 11);
    assert_eq!(replay_state.total_executed_transactions, u64::MAX);
}

#[test]
fn replay_boundary_considers_reorg_for_replay_conflict() {
    let bridge = ExecutionBridge::with_engine(Arc::new(HeuristicExecutionEngine::new()));
    let mut replay_state = ReplayBoundaryState {
        last_applied_fragment_id: 0,
        total_executed_transactions: 0,
    };
    let outcome = bridge
        .try_execute_batch(&ExecutionBatch::new(34, 64, 256_000))
        .unwrap();

    let directive = bridge.update_replay_boundary(&mut replay_state, &outcome);
    assert_eq!(directive, ForkChoiceDirective::ConsiderReorg);
}

#[test]
fn replay_boundary_keeps_fork_for_transient_pressure() {
    let bridge = ExecutionBridge::with_engine(Arc::new(HeuristicExecutionEngine::new()));
    let mut replay_state = ReplayBoundaryState {
        last_applied_fragment_id: 0,
        total_executed_transactions: 0,
    };
    let outcome = bridge
        .try_execute_batch(&ExecutionBatch::new(22, 64, 256_000))
        .unwrap();

    let directive = bridge.update_replay_boundary(&mut replay_state, &outcome);
    assert_eq!(directive, ForkChoiceDirective::KeepCurrentFork);
}

#[test]
fn leader_gate_holds_when_not_current_leader() {
    let bridge = ExecutionBridge::new();
    let gate_state = LeaderGateState {
        is_current_leader: false,
        next_leader_slot: 20,
    };
    let directive = bridge.evaluate_leader_gate(&gate_state);
    assert_eq!(directive, LeaderGateDirective::HoldForLeader);
}

#[test]
fn retry_directive_requests_backoff_on_failures() {
    let bridge = ExecutionBridge::new();
    let outcome = ExecutionOutcome {
        fragment_id: 15,
        executed_transactions: 60,
        failed_transactions: 4,
        total_cost_units: 200_000,
        failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
    };
    let directive = bridge.derive_retry_directive(&outcome);
    assert_eq!(
        directive,
        RetryDirective::RetryWithBackoff {
            retry_delay_millis: 50
        }
    );
}

#[test]
fn try_execute_batch_rejects_empty_batch() {
    let bridge = ExecutionBridge::new();
    let outcome = bridge.try_execute_batch(&ExecutionBatch::new(18, 0, 0));
    assert_eq!(
        outcome.unwrap_err(),
        ExecutionError::EmptyBatch { fragment_id: 18 }
    );
}

#[test]
fn execution_bridge_rewind_is_noop_without_state_controller() {
    let bridge = ExecutionBridge::new();
    let rewound = bridge.rewind_execution_state_to_fragment(77).unwrap();
    assert!(!rewound);
}

#[test]
fn execution_bridge_rewind_calls_state_controller_when_configured() {
    let controller = Arc::new(RecordingStateController {
        rewinds: Mutex::new(Vec::new()),
        fail_on_target: None,
    });
    let bridge = ExecutionBridge::with_engine_retry_policy_and_state_controller(
        Arc::new(FixedExecutionEngine),
        RetryPolicy::default(),
        Some(controller.clone()),
    );

    let rewound = bridge.rewind_execution_state_to_fragment(88).unwrap();
    assert!(rewound);
    assert_eq!(controller.rewinds.lock().unwrap().as_slice(), &[88]);
}

#[test]
fn execution_bridge_rewind_propagates_state_controller_error() {
    let controller = Arc::new(RecordingStateController {
        rewinds: Mutex::new(Vec::new()),
        fail_on_target: Some(99),
    });
    let bridge = ExecutionBridge::with_engine_retry_policy_and_state_controller(
        Arc::new(FixedExecutionEngine),
        RetryPolicy::default(),
        Some(controller),
    );

    let error = bridge.rewind_execution_state_to_fragment(99).unwrap_err();
    assert_eq!(
        error,
        ExecutionError::AdapterRollbackFailure {
            fragment_id: 99,
            message: "simulated rewind failure".to_string()
        }
    );
}

#[test]
fn execute_batch_marks_replay_conflict_for_fragment_multiple_of_17() {
    let bridge = ExecutionBridge::with_engine(Arc::new(HeuristicExecutionEngine::new()));
    let outcome = bridge.try_execute_batch(&ExecutionBatch::new(34, 64, 256_000));
    let outcome = outcome.unwrap();
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::ReplayConflict)
    );
    assert!(outcome.failed_transactions > 0);
}

#[test]
fn retry_directive_drops_fragment_for_deterministic_failure_class() {
    let bridge = ExecutionBridge::new();
    let outcome = ExecutionOutcome {
        fragment_id: 29,
        executed_transactions: 60,
        failed_transactions: 4,
        total_cost_units: 200_000,
        failure_class: Some(ExecutionFailureClass::DeterministicTransactionFailure),
    };
    let directive = bridge.derive_retry_directive(&outcome);
    assert_eq!(directive, RetryDirective::DropCurrentFragment);
}

#[test]
fn retry_directive_respects_custom_retry_policy_values() {
    let bridge = ExecutionBridge::with_retry_policy(RetryPolicy {
        replay_conflict_delay_millis: 7,
        transient_base_delay_millis: 10,
        transient_per_failed_tx_delay_millis: 2,
        transient_cap_millis: 100,
        resource_base_delay_millis: 50,
        resource_per_failed_tx_delay_millis: 3,
        resource_cap_millis: 200,
        fallback_min_delay_millis: 8,
        fallback_per_failed_tx_delay_millis: 4,
        max_retries_replay_conflict: 5,
        max_retries_transient_pressure: 4,
        max_retries_resource_exhaustion: 2,
        max_retries_fallback: 3,
    });

    let replay_outcome = ExecutionOutcome {
        fragment_id: 17,
        executed_transactions: 60,
        failed_transactions: 4,
        total_cost_units: 200_000,
        failure_class: Some(ExecutionFailureClass::ReplayConflict),
    };
    assert_eq!(
        bridge.derive_retry_directive(&replay_outcome),
        RetryDirective::RetryWithBackoff {
            retry_delay_millis: 7
        }
    );

    let transient_outcome = ExecutionOutcome {
        fragment_id: 11,
        executed_transactions: 60,
        failed_transactions: 4,
        total_cost_units: 200_000,
        failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
    };
    assert_eq!(
        bridge.derive_retry_directive(&transient_outcome),
        RetryDirective::RetryWithBackoff {
            retry_delay_millis: 18
        }
    );
}

#[test]
fn retry_directive_retries_replay_conflict_even_when_failed_transactions_is_zero() {
    let bridge = ExecutionBridge::with_retry_policy(RetryPolicy {
        replay_conflict_delay_millis: 11,
        ..RetryPolicy::default()
    });
    let outcome = ExecutionOutcome {
        fragment_id: 99,
        executed_transactions: 0,
        failed_transactions: 0,
        total_cost_units: 42_000,
        failure_class: Some(ExecutionFailureClass::ReplayConflict),
    };
    assert_eq!(
        bridge.derive_retry_directive(&outcome),
        RetryDirective::RetryWithBackoff {
            retry_delay_millis: 11
        }
    );
}

#[test]
fn retry_directive_saturates_delay_for_very_large_failed_transactions() {
    let bridge = ExecutionBridge::with_retry_policy(RetryPolicy {
        fallback_min_delay_millis: 1,
        fallback_per_failed_tx_delay_millis: u64::MAX,
        ..RetryPolicy::default()
    });
    let outcome = ExecutionOutcome {
        fragment_id: 1001,
        executed_transactions: 0,
        failed_transactions: usize::MAX,
        total_cost_units: 42_000,
        failure_class: None,
    };
    assert_eq!(
        bridge.derive_retry_directive(&outcome),
        RetryDirective::RetryWithBackoff {
            retry_delay_millis: u64::MAX
        }
    );
}

#[test]
fn scheduler_priority_escalates_for_resource_exhaustion() {
    let bridge = ExecutionBridge::new();
    let outcome = ExecutionOutcome {
        fragment_id: 50,
        executed_transactions: 10,
        failed_transactions: 20,
        total_cost_units: 80_000,
        failure_class: Some(ExecutionFailureClass::ResourceExhaustion),
    };
    let scheduler = bridge.derive_scheduler_directive(
        &LeaderGateState {
            is_current_leader: true,
            next_leader_slot: 9,
        },
        &outcome,
    );
    assert_eq!(scheduler.priority_class, 3);
}

#[test]
fn classify_resource_exhaustion_for_high_average_cost_batch() {
    let bridge = ExecutionBridge::with_engine(Arc::new(HeuristicExecutionEngine::new()));
    let outcome = bridge
        .try_execute_batch(&ExecutionBatch::new(19, 96, 1_200_000))
        .unwrap();
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::ResourceExhaustion)
    );
}

#[test]
fn classify_deterministic_failure_for_low_cost_pattern_batch() {
    let bridge = ExecutionBridge::with_engine(Arc::new(HeuristicExecutionEngine::new()));
    let outcome = bridge
        .try_execute_batch(&ExecutionBatch::new(14, 32, 32_000))
        .unwrap();
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::DeterministicTransactionFailure)
    );
}

#[test]
fn execution_bridge_supports_custom_execution_engine() {
    let bridge = ExecutionBridge::with_engine(Arc::new(FixedExecutionEngine));
    let outcome = bridge
        .try_execute_batch(&ExecutionBatch::new(9, 5, 10_000))
        .unwrap();
    assert_eq!(outcome.fragment_id, 9);
    assert_eq!(outcome.executed_transactions, 1);
    assert_eq!(outcome.failed_transactions, 4);
    assert_eq!(outcome.total_cost_units, 123_456);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::ResourceExhaustion)
    );
}

#[test]
fn execution_bridge_normalizes_invalid_engine_outcome_invariants() {
    let bridge = ExecutionBridge::with_engine(Arc::new(OverreportingExecutionEngine));
    let batch = ExecutionBatch::new(77, 8, 12_000);
    let outcome = bridge.try_execute_batch(&batch).unwrap();
    assert_eq!(outcome.fragment_id, 77);
    assert_eq!(outcome.failed_transactions, 8);
    assert_eq!(outcome.executed_transactions, 0);
    assert_eq!(outcome.total_cost_units, 88_000);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::DeterministicTransactionFailure)
    );
}

#[test]
fn execution_bridge_normalizes_missing_failure_class_when_failed_transactions_present() {
    let bridge = ExecutionBridge::with_engine(Arc::new(MissingClassExecutionEngine));
    let batch = ExecutionBatch::new(78, 8, 12_000);
    let outcome = bridge.try_execute_batch(&batch).unwrap();
    assert_eq!(outcome.fragment_id, 78);
    assert_eq!(outcome.failed_transactions, 3);
    assert_eq!(outcome.executed_transactions, 5);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::DeterministicTransactionFailure)
    );
}

#[test]
fn execution_bridge_normalizes_transactional_failure_class_with_zero_failures() {
    let bridge =
        ExecutionBridge::with_engine(Arc::new(ZeroFailedTransactionalClassExecutionEngine));
    let batch = ExecutionBatch::new(79, 8, 12_000);
    let outcome = bridge.try_execute_batch(&batch).unwrap();
    assert_eq!(outcome.fragment_id, 79);
    assert_eq!(outcome.failed_transactions, 0);
    assert_eq!(outcome.executed_transactions, 8);
    assert_eq!(outcome.failure_class, None);
}

#[test]
fn execution_bridge_normalizes_zero_total_cost_units_for_non_empty_batch() {
    let bridge = ExecutionBridge::with_engine(Arc::new(ZeroCostExecutionEngine));
    let batch = ExecutionBatch::new(80, 8, 12_000);
    let outcome = bridge.try_execute_batch(&batch).unwrap();
    assert_eq!(outcome.fragment_id, 80);
    assert_eq!(outcome.total_cost_units, 12_000);
}

#[test]
fn execute_batch_maps_adapter_state_conflict_to_replay_conflict() {
    let bridge = ExecutionBridge::with_engine(Arc::new(FailingExecutionEngine {
        error: ExecutionError::AdapterStateConflict {
            fragment_id: 44,
            detail: "pending receipt already exists".to_string(),
        },
    }));
    let outcome = bridge.execute_batch(&ExecutionBatch::new(44, 12, 42_000));
    assert_eq!(outcome.executed_transactions, 0);
    assert_eq!(outcome.failed_transactions, 0);
    assert_eq!(outcome.total_cost_units, 42_000);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::ReplayConflict)
    );
}

#[test]
fn execute_batch_maps_adapter_apply_failure_to_transient_pressure() {
    let bridge = ExecutionBridge::with_engine(Arc::new(FailingExecutionEngine {
        error: ExecutionError::AdapterApplyFailure {
            fragment_id: 45,
            message: "runtime state apply failed".to_string(),
        },
    }));
    let outcome = bridge.execute_batch(&ExecutionBatch::new(45, 10, 100_000));
    assert_eq!(outcome.failed_transactions, 10);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::TransientSchedulerPressure)
    );
}

#[test]
fn execute_batch_maps_adapter_contract_violation_to_deterministic_failure() {
    let bridge = ExecutionBridge::with_engine(Arc::new(FailingExecutionEngine {
        error: ExecutionError::AdapterContractViolation {
            fragment_id: 46,
            detail: "preflight returned mismatched write intent".to_string(),
        },
    }));
    let outcome = bridge.execute_batch(&ExecutionBatch::new(46, 9, 90_000));
    assert_eq!(outcome.executed_transactions, 0);
    assert_eq!(outcome.failed_transactions, 9);
    assert_eq!(outcome.total_cost_units, 90_000);
    assert_eq!(
        outcome.failure_class,
        Some(ExecutionFailureClass::DeterministicTransactionFailure)
    );
}

#[test]
fn execute_batch_with_error_normalizes_non_empty_zero_estimated_cost_to_one() {
    let bridge = ExecutionBridge::with_engine(Arc::new(FailingExecutionEngine {
        error: ExecutionError::AdapterApplyFailure {
            fragment_id: 47,
            message: "runtime apply failure".to_string(),
        },
    }));
    let (outcome, error) = bridge.execute_batch_with_error(&ExecutionBatch::new(47, 3, 0));
    assert!(error.is_some());
    assert_eq!(outcome.total_cost_units, 1);
    assert_eq!(outcome.failed_transactions, 3);
}

#[test]
fn execute_batch_with_error_keeps_zero_cost_for_empty_batch() {
    let bridge = ExecutionBridge::new();
    let (outcome, error) = bridge.execute_batch_with_error(&ExecutionBatch::new(48, 0, 0));
    assert!(matches!(
        error,
        Some(ExecutionError::EmptyBatch { fragment_id: 48 })
    ));
    assert_eq!(outcome.total_cost_units, 0);
    assert_eq!(outcome.failed_transactions, 0);
}
