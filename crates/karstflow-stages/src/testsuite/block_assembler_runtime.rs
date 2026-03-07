#![allow(clippy::field_reassign_with_default)]

use super::*;
use karstflow_execution::{
    ExecutionBridge, ExecutionEngine, ExecutionError, ExecutionOutcome, ExecutionStateController,
};
use karstflow_mesh::DualReceiver;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct AlwaysFailExecutionEngine;
struct AlwaysReplayConflictExecutionEngine;
struct AlwaysContractViolationExecutionEngine;
struct FailOnceThenSucceedExecutionEngine {
    attempts: AtomicUsize,
}

struct FirstSuccessThenReplayConflictExecutionEngine {
    attempts: AtomicUsize,
}

struct AlwaysFailStateController;

struct RewindCatalogReplayConflictEngine {
    attempts: AtomicUsize,
}

impl ExecutionEngine for AlwaysFailExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::AdapterApplyFailure {
            fragment_id: batch.fragment_id,
            message: "forced adapter apply failure in test".to_string(),
        })
    }
}

impl ExecutionEngine for AlwaysReplayConflictExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::AdapterStateConflict {
            fragment_id: batch.fragment_id,
            detail: "forced replay conflict".to_string(),
        })
    }
}

impl ExecutionEngine for AlwaysContractViolationExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "forced adapter contract violation".to_string(),
        })
    }
}

impl ExecutionEngine for FailOnceThenSucceedExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 0 {
            return Err(ExecutionError::AdapterApplyFailure {
                fragment_id: batch.fragment_id,
                message: "forced first-attempt apply failure".to_string(),
            });
        }
        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions: batch.transaction_count,
            failed_transactions: 0,
            total_cost_units: batch.estimated_total_cost_units,
            failure_class: None,
        })
    }
}

impl ExecutionEngine for FirstSuccessThenReplayConflictExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 0 {
            return Ok(ExecutionOutcome {
                fragment_id: batch.fragment_id,
                executed_transactions: batch.transaction_count,
                failed_transactions: 0,
                total_cost_units: batch.estimated_total_cost_units.max(1),
                failure_class: None,
            });
        }
        Err(ExecutionError::AdapterStateConflict {
            fragment_id: batch.fragment_id,
            detail: "forced replay conflict after first success".to_string(),
        })
    }
}

impl ExecutionStateController for AlwaysFailStateController {
    fn rewind_to_fragment(
        &self,
        target_fragment_id: u64,
    ) -> std::result::Result<(), ExecutionError> {
        Err(ExecutionError::AdapterRollbackFailure {
            fragment_id: target_fragment_id,
            message: "simulated execution-state rewind failure".to_string(),
        })
    }
}

impl ExecutionEngine for RewindCatalogReplayConflictEngine {
    fn try_execute_batch(
        &self,
        batch: &karstflow_execution::ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if batch.fragment_id == 2 && attempt >= 3 {
            return Err(ExecutionError::AdapterStateConflict {
                fragment_id: batch.fragment_id,
                detail: "forced replay conflict on reused fragment id".to_string(),
            });
        }
        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions: batch.transaction_count,
            failed_transactions: 0,
            total_cost_units: batch.estimated_total_cost_units.max(1),
            failure_class: None,
        })
    }
}

#[test]
fn block_assembler_defers_fragment_on_retry_directive() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        test_storage_runtime_policy(),
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 0);
}

#[test]
fn block_assembler_returns_runtime_error_on_fragment_counter_overflow() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        test_storage_runtime_policy(),
    )
    .unwrap();
    block_assembler.fragment_counter = u64::MAX;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
    }

    let mut overflow_error = None;
    for _ in 0..128 {
        if let Err(error) = block_assembler.tick(&context) {
            overflow_error = Some(error);
            break;
        }
    }
    let error = overflow_error.expect("fragment counter overflow must fail tick");
    assert!(error.to_string().contains("fragment counter overflow"));
}

#[test]
fn block_assembler_accepts_runtime_like_execution_engine_policy() {
    let (_transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(64);
    let block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            execution_engine_policy: ExecutionEnginePolicy::RuntimeLike,
            ..test_storage_runtime_policy()
        },
    );
    assert!(block_assembler.is_ok());
}

#[test]
fn block_assembler_fail_open_on_execution_error_records_telemetry_and_continues() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let policy = test_storage_runtime_policy();
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(AlwaysFailExecutionEngine),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.execution_error_total(), 1);
    assert_eq!(block_assembler.execution_error_adapter_apply_total(), 1);
    assert_eq!(
        block_assembler.execution_error_fail_open_continue_total(),
        1
    );
    assert_eq!(block_assembler.execution_error_fail_fast_halt_total(), 0);
    assert_eq!(block_assembler.execution_error_consecutive_current(), 1);
    assert_eq!(
        block_assembler.retry_scheduled_transient_pressure_total(),
        1
    );
    assert!(block_assembler.has_pending_retry());
    block_assembler.tick(&context).unwrap();
}

#[test]
fn block_assembler_fail_open_replay_conflict_error_schedules_retry_and_does_not_commit() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let mut policy = test_storage_runtime_policy();
    policy.execution_error_handling_policy = ExecutionErrorHandlingPolicy::FailOpen;
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(AlwaysReplayConflictExecutionEngine),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.execution_error_total(), 1);
    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.retry_scheduled_replay_conflict_total(), 1);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 0);
}

#[test]
fn block_assembler_fail_open_contract_violation_drops_without_retry() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let mut policy = test_storage_runtime_policy();
    policy.execution_error_handling_policy = ExecutionErrorHandlingPolicy::FailOpen;
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(AlwaysContractViolationExecutionEngine),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.execution_error_total(), 1);
    assert_eq!(
        block_assembler.execution_error_adapter_contract_violation_total(),
        1
    );
    assert_eq!(
        block_assembler.execution_error_fail_open_continue_total(),
        1
    );
    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_deterministic_total(), 1);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 0);
}

#[test]
fn block_assembler_fail_fast_on_execution_error_returns_runtime_error() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let mut policy = test_storage_runtime_policy();
    policy.execution_error_handling_policy = ExecutionErrorHandlingPolicy::FailFast;
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(AlwaysFailExecutionEngine),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
    }

    let mut got_error = false;
    for _ in 0..256 {
        if block_assembler.tick(&context).is_err() {
            got_error = true;
            break;
        }
    }
    assert!(got_error);
    assert_eq!(block_assembler.execution_error_total(), 1);
    assert_eq!(block_assembler.execution_error_adapter_apply_total(), 1);
    assert_eq!(
        block_assembler.execution_error_fail_open_continue_total(),
        0
    );
    assert_eq!(block_assembler.execution_error_fail_fast_halt_total(), 1);
    assert_eq!(block_assembler.execution_error_consecutive_current(), 1);
}

#[test]
fn block_assembler_fail_open_circuit_breaker_halts_after_consecutive_errors() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let mut policy = test_storage_runtime_policy();
    policy.execution_error_handling_policy = ExecutionErrorHandlingPolicy::FailOpen;
    policy.execution_error_fail_open_max_consecutive = 2;
    policy.retry_backoff_cap_millis = 1;
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(AlwaysFailExecutionEngine),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
    }

    let mut got_error = false;
    for _ in 0..256 {
        if block_assembler.tick(&context).is_err() {
            got_error = true;
            break;
        }
    }
    assert!(got_error);
    assert_eq!(block_assembler.execution_error_total(), 2);
    assert_eq!(
        block_assembler.execution_error_fail_open_continue_total(),
        1
    );
    assert_eq!(block_assembler.execution_error_fail_fast_halt_total(), 0);
    assert_eq!(block_assembler.execution_error_consecutive_current(), 2);
    assert_eq!(
        block_assembler.execution_error_fail_open_circuit_breaker_halt_total(),
        1
    );
}

#[test]
fn block_assembler_resets_consecutive_execution_errors_after_successful_retry() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let stats = Arc::new(BlockAssemblyStats::default());
    let mut policy = test_storage_runtime_policy();
    policy.execution_error_handling_policy = ExecutionErrorHandlingPolicy::FailOpen;
    policy.retry_backoff_cap_millis = 1;
    let retry_policy = policy.execution_retry_policy;
    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(FailOnceThenSucceedExecutionEngine {
            attempts: AtomicUsize::new(0),
        }),
        retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        stats,
        bridge,
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
    }

    for _ in 0..256 {
        block_assembler.tick(&context).unwrap();
        if !block_assembler.has_pending_retry()
            && block_assembler.hot_state_store.committed_fragments > 0
        {
            break;
        }
    }

    assert_eq!(block_assembler.execution_error_total(), 1);
    assert_eq!(block_assembler.execution_error_consecutive_current(), 0);
    assert_eq!(block_assembler.hot_state_store.committed_fragments, 1);
}

#[test]
fn block_assembler_applies_retry_budget_and_backoff_cap_from_runtime_policy() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            retry_backoff_cap_millis: 2,
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    for _ in 0..4 {
        block_assembler.tick(&context).unwrap();
    }

    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
}

#[test]
fn block_assembler_honors_short_execution_replay_retry_delay_policy() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            retry_backoff_cap_millis: 10_000,
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 2,
                ..RetryPolicy::default()
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);

    for _ in 0..3 {
        block_assembler.tick(&context).unwrap();
    }

    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
}

#[test]
fn block_assembler_applies_failure_class_retry_budget_for_replay_conflicts() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 5,
            retry_backoff_cap_millis: 10_000,
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 1,
                transient_base_delay_millis: 1,
                transient_per_failed_tx_delay_millis: 0,
                transient_cap_millis: 1,
                resource_base_delay_millis: 1,
                resource_per_failed_tx_delay_millis: 0,
                resource_cap_millis: 1,
                fallback_min_delay_millis: 1,
                fallback_per_failed_tx_delay_millis: 1,
                max_retries_replay_conflict: 1,
                max_retries_transient_pressure: 5,
                max_retries_resource_exhaustion: 5,
                max_retries_fallback: 5,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }
    assert!(block_assembler.has_pending_retry());

    for _ in 0..4 {
        block_assembler.tick(&context).unwrap();
    }
    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
    assert_eq!(block_assembler.dropped_replay_conflict_total(), 1);
}

#[test]
fn block_assembler_applies_failure_class_retry_budget_for_resource_exhaustion() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(256);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 5,
            retry_backoff_cap_millis: 10_000,
            assembly_policy: AssemblyPolicy {
                max_fragment_transactions: 192,
                max_fragment_cost_units: u64::MAX,
                max_fragment_wait_ticks: 64,
            },
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 1,
                transient_base_delay_millis: 1,
                transient_per_failed_tx_delay_millis: 0,
                transient_cap_millis: 1,
                resource_base_delay_millis: 1,
                resource_per_failed_tx_delay_millis: 0,
                resource_cap_millis: 1,
                fallback_min_delay_millis: 1,
                fallback_per_failed_tx_delay_millis: 1,
                max_retries_replay_conflict: 5,
                max_retries_transient_pressure: 5,
                max_retries_resource_exhaustion: 1,
                max_retries_fallback: 5,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=192_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 20_000,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }
    assert!(block_assembler.has_pending_retry());

    for _ in 0..4 {
        block_assembler.tick(&context).unwrap();
    }
    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
    assert_eq!(block_assembler.dropped_resource_exhaustion_total(), 1);
}

#[test]
fn block_assembler_honors_long_execution_replay_retry_delay_policy() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            retry_backoff_cap_millis: 10_000,
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 120,
                ..RetryPolicy::default()
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    for _ in 0..10 {
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);
}

#[test]
fn block_assembler_execution_health_policy_enters_and_drains_cooldown() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            execution_retry_policy: RetryPolicy {
                transient_base_delay_millis: 1,
                transient_per_failed_tx_delay_millis: 0,
                ..RetryPolicy::default()
            },
            execution_health_policy: ExecutionHealthPolicy {
                enabled: true,
                transient_failure_threshold: 1,
                cooldown_ticks: 3,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.cooldown_ticks_remaining(), 3);

    for _ in 0..3 {
        block_assembler.tick(&context).unwrap();
    }
    assert_eq!(block_assembler.cooldown_ticks_remaining(), 0);
    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);

    block_assembler.tick(&context).unwrap();
    block_assembler.tick(&context).unwrap();
    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
}

#[test]
fn block_assembler_execution_health_policy_disabled_does_not_enter_cooldown() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            execution_health_policy: ExecutionHealthPolicy {
                enabled: false,
                transient_failure_threshold: 1,
                cooldown_ticks: 7,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.cooldown_ticks_remaining(), 0);
}

#[test]
fn block_assembler_slot_pipeline_advances_on_commit() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        test_storage_runtime_policy(),
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.committed_fragments_count(), 1);
    assert_eq!(block_assembler.slot_pipeline_slot(), 1);
    assert_eq!(block_assembler.slot_pipeline_state_name(), "idle");
}

#[test]
fn block_assembler_slot_pipeline_advances_on_drop_after_retries() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            retry_backoff_cap_millis: 2,
            execution_retry_policy: RetryPolicy {
                transient_base_delay_millis: 1,
                transient_per_failed_tx_delay_millis: 0,
                transient_cap_millis: 1,
                ..RetryPolicy::default()
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }
    for _ in 0..6 {
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.dropped_fragments, 1);
    assert_eq!(block_assembler.slot_pipeline_slot(), 1);
    assert_eq!(block_assembler.slot_pipeline_state_name(), "idle");
}

#[test]
fn block_assembler_replay_controller_tracks_reorg_candidate_for_replay_conflict() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 2,
                ..RetryPolicy::default()
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert!(block_assembler.replay_controller_has_pending_candidate());
    assert_eq!(
        block_assembler.replay_controller_active_candidate_fragment_id(),
        Some(17)
    );
}

#[test]
fn block_assembler_replay_window_rewinds_to_checkpoint_on_confirmed_reorg_when_enabled() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(256);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            fork_choice_runtime_policy: ForkChoiceRuntimePolicy {
                enabled: true,
                reorg_retry_delay_millis: 2,
                max_reorg_retry_attempts: 1,
                hold_requires_confirmed_candidate: false,
            },
            replay_window_policy: ReplayWindowPolicy {
                max_checkpoints: 8,
                rewind_on_confirmed_reorg: true,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.committed_fragments_count(), 1);
    assert_eq!(block_assembler.replay_window_checkpoint_depth(), 1);

    block_assembler.fragment_counter = 16;
    for transaction_id in 1001..=1064_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    for _ in 0..6 {
        block_assembler.tick(&context).unwrap();
        if !block_assembler.has_pending_retry() {
            break;
        }
    }

    assert_eq!(block_assembler.replay_window_rewinds(), 1);
    assert_eq!(block_assembler.replay_window_catalog_snapshots_pruned(), 0);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 1);
    assert_eq!(block_assembler.fragment_counter, 1);
    assert!(!block_assembler.replay_controller_has_pending_candidate());
    assert_eq!(
        block_assembler
            .replay_boundary_state
            .last_applied_fragment_id,
        1
    );
}

#[test]
fn block_assembler_replay_window_does_not_rewind_when_disabled() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(256);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            fork_choice_runtime_policy: ForkChoiceRuntimePolicy {
                enabled: true,
                reorg_retry_delay_millis: 2,
                max_reorg_retry_attempts: 1,
                hold_requires_confirmed_candidate: false,
            },
            replay_window_policy: ReplayWindowPolicy {
                max_checkpoints: 8,
                rewind_on_confirmed_reorg: false,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    block_assembler.fragment_counter = 16;
    for transaction_id in 2001..=2064_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    for _ in 0..6 {
        block_assembler.tick(&context).unwrap();
        if !block_assembler.has_pending_retry() {
            break;
        }
    }

    assert_eq!(block_assembler.replay_window_rewinds(), 0);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 1);
}

#[test]
fn block_assembler_confirmed_reorg_rewind_failure_bubbles_runtime_error() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(256);
    let mut policy = test_storage_runtime_policy();
    policy.fork_choice_runtime_policy = ForkChoiceRuntimePolicy {
        enabled: true,
        reorg_retry_delay_millis: 2,
        max_reorg_retry_attempts: 1,
        hold_requires_confirmed_candidate: false,
    };
    policy.replay_window_policy = ReplayWindowPolicy {
        max_checkpoints: 8,
        rewind_on_confirmed_reorg: true,
    };
    policy
        .replay_controller_policy
        .candidate_confirmation_threshold = 1;

    let bridge = ExecutionBridge::with_engine_retry_policy_and_state_controller(
        Arc::new(FirstSuccessThenReplayConflictExecutionEngine {
            attempts: AtomicUsize::new(0),
        }),
        policy.execution_retry_policy,
        Some(Arc::new(AlwaysFailStateController)),
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        Arc::new(BlockAssemblyStats::default()),
        bridge,
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }
    assert_eq!(block_assembler.committed_fragments_count(), 1);

    for transaction_id in 1001..=1064_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
    }

    let mut got_error = false;
    for _ in 0..256 {
        if let Err(error) = block_assembler.tick(&context) {
            got_error = true;
            assert!(error
                .to_string()
                .contains("simulated execution-state rewind failure"));
            break;
        }
    }
    assert!(got_error);
    assert_eq!(block_assembler.replay_window_rewinds(), 0);
    assert_eq!(block_assembler.execution_state_rewind_failures(), 1);
    assert_eq!(block_assembler.execution_error_total(), 2);
    assert_eq!(block_assembler.execution_error_adapter_rollback_total(), 1);
}

#[test]
fn block_assembler_confirmed_reorg_rewind_persists_pruned_snapshot_catalog() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(512);
    let catalog_path = unique_temp_file("karstflow-reorg-rewind-catalog", "json");

    let mut policy = test_storage_runtime_policy();
    policy.snapshot_interval = 1;
    policy.snapshot_catalog_path = Some(catalog_path.clone());
    policy.fork_choice_runtime_policy = ForkChoiceRuntimePolicy {
        enabled: true,
        reorg_retry_delay_millis: 2,
        max_reorg_retry_attempts: 1,
        hold_requires_confirmed_candidate: false,
    };
    policy.replay_window_policy = ReplayWindowPolicy {
        max_checkpoints: 8,
        rewind_on_confirmed_reorg: true,
    };
    policy
        .replay_controller_policy
        .candidate_confirmation_threshold = 1;

    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(RewindCatalogReplayConflictEngine {
            attempts: AtomicUsize::new(0),
        }),
        policy.execution_retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        Arc::new(BlockAssemblyStats::default()),
        bridge,
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=192_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.committed_fragments_count(), 3);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 3);

    // Force a replay-conflict observation on fragment 2 after checkpoint 3 already exists.
    block_assembler.fragment_counter = 1;
    for transaction_id in 10_001..=10_064_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.replay_window_rewinds(), 1);
    assert_eq!(block_assembler.replay_window_catalog_snapshots_pruned(), 1);
    assert_eq!(block_assembler.hot_state_store.last_fragment_id, 2);
    assert_eq!(block_assembler.fragment_counter, 2);
    assert_eq!(block_assembler.slot_pipeline_slot(), 2);
    assert_eq!(block_assembler.next_leader_slot(), 2);
    assert!(!block_assembler.replay_controller_has_pending_candidate());

    let persisted_catalog = SnapshotCatalog::load_from_file(&catalog_path).unwrap();
    fs::remove_file(&catalog_path).unwrap();
    assert!(persisted_catalog.restore_snapshot(3).is_err());
    assert_eq!(
        persisted_catalog.restore_snapshot(2).unwrap().fragment_id,
        2
    );
    assert_eq!(persisted_catalog.last_snapshot_fragment_id, 2);
}

#[test]
fn block_assembler_confirmed_reorg_rewind_respects_leader_initial_slot_floor() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(512);
    let catalog_path = unique_temp_file("karstflow-reorg-rewind-slot-floor", "json");

    let mut policy = test_storage_runtime_policy();
    policy.snapshot_interval = 1;
    policy.snapshot_catalog_path = Some(catalog_path.clone());
    policy.fork_choice_runtime_policy = ForkChoiceRuntimePolicy {
        enabled: true,
        reorg_retry_delay_millis: 2,
        max_reorg_retry_attempts: 1,
        hold_requires_confirmed_candidate: false,
    };
    policy.replay_window_policy = ReplayWindowPolicy {
        max_checkpoints: 8,
        rewind_on_confirmed_reorg: true,
    };
    policy.leader_schedule_policy = LeaderSchedulePolicy {
        enabled: true,
        slot_cycle_length: 8,
        leader_slots_per_cycle: 2,
        hold_retry_delay_millis: 10,
        initial_slot: 11,
    };
    policy
        .replay_controller_policy
        .candidate_confirmation_threshold = 1;

    let bridge = ExecutionBridge::with_engine_and_retry_policy(
        Arc::new(RewindCatalogReplayConflictEngine {
            attempts: AtomicUsize::new(0),
        }),
        policy.execution_retry_policy,
    );
    let mut block_assembler = BlockAssembler::with_storage_policy_and_stats_and_execution_bridge(
        DualReceiver::Channel(transaction_inbound),
        policy,
        Arc::new(BlockAssemblyStats::default()),
        bridge,
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=192_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    block_assembler.fragment_counter = 1;
    for transaction_id in 20_001..=20_064_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    fs::remove_file(&catalog_path).unwrap();
    assert_eq!(block_assembler.replay_window_rewinds(), 1);
    assert_eq!(block_assembler.fragment_counter, 2);
    assert_eq!(block_assembler.slot_pipeline_slot(), 11);
    assert_eq!(block_assembler.next_leader_slot(), 11);
}

#[test]
fn block_assembler_replay_safety_policy_enters_and_drains_hold() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            execution_retry_policy: RetryPolicy {
                replay_conflict_delay_millis: 1,
                ..RetryPolicy::default()
            },
            replay_safety_policy: ReplaySafetyPolicy {
                enabled: true,
                replay_conflict_threshold: 1,
                hold_ticks: 2,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.replay_safety_hold_ticks_remaining(), 2);

    for _ in 0..2 {
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.replay_safety_hold_ticks_remaining(), 0);
    assert!(block_assembler.has_pending_retry());
}

#[test]
fn block_assembler_replay_safety_policy_disabled_does_not_enter_hold() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            replay_safety_policy: ReplaySafetyPolicy {
                enabled: false,
                replay_conflict_threshold: 1,
                hold_ticks: 9,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.replay_safety_hold_ticks_remaining(), 0);
}

#[test]
fn block_assembler_fork_choice_quarantine_enters_and_drains() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            fork_choice_quarantine_policy: ForkChoiceQuarantinePolicy {
                enabled: true,
                consecutive_reorg_threshold: 1,
                quarantine_ticks: 3,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.fork_choice_quarantine_ticks_remaining(), 3);

    for _ in 0..3 {
        block_assembler.tick(&context).unwrap();
    }
    assert_eq!(block_assembler.fork_choice_quarantine_ticks_remaining(), 0);
    assert!(block_assembler.has_pending_retry());
}

#[test]
fn block_assembler_fork_choice_quarantine_disabled_does_not_enter() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            fork_choice_quarantine_policy: ForkChoiceQuarantinePolicy {
                enabled: false,
                consecutive_reorg_threshold: 1,
                quarantine_ticks: 7,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.fork_choice_quarantine_ticks_remaining(), 0);
}

#[test]
fn block_assembler_holds_fragment_while_not_leader_and_commits_after_rotation() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            leader_schedule_policy: LeaderSchedulePolicy {
                enabled: true,
                slot_cycle_length: 4,
                leader_slots_per_cycle: 1,
                initial_slot: 1,
                hold_retry_delay_millis: 2,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.committed_fragments_count(), 0);

    for _ in 0..6 {
        block_assembler.tick(&context).unwrap();
        if block_assembler.committed_fragments_count() > 0 {
            break;
        }
    }

    assert_eq!(block_assembler.committed_fragments_count(), 1);
    assert!(!block_assembler.has_pending_retry());
}

#[test]
fn block_assembler_scheduler_policy_increases_retry_wait_for_priority_class_two() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            max_retry_attempts: 1,
            retry_backoff_cap_millis: 5_000,
            scheduler_runtime_policy: SchedulerRuntimePolicy {
                enabled: true,
                slot_duration_millis: 200,
                priority_penalty_class_2_millis: 300,
                priority_penalty_class_3_millis: 700,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    for _ in 0..40 {
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);
}

#[test]
fn block_assembler_fork_choice_policy_retries_reorg_then_drops() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            fork_choice_runtime_policy: ForkChoiceRuntimePolicy {
                enabled: true,
                reorg_retry_delay_millis: 2,
                max_reorg_retry_attempts: 1,
                hold_requires_confirmed_candidate: false,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    block_assembler.fragment_counter = 16;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 0);

    for _ in 0..6 {
        block_assembler.tick(&context).unwrap();
        if !block_assembler.has_pending_retry() {
            break;
        }
    }

    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
    assert_eq!(block_assembler.committed_fragments_count(), 0);
    assert_eq!(block_assembler.dropped_reorg_retry_exhausted_total(), 1);
}

#[test]
fn block_assembler_assembles_fragment_when_cost_budget_is_reached_before_tx_count() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            assembly_policy: AssemblyPolicy {
                max_fragment_transactions: 64,
                max_fragment_cost_units: 30,
                max_fragment_wait_ticks: 100,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=3_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert_eq!(block_assembler.committed_fragments_count(), 1);
}

#[test]
fn block_assembler_assembles_fragment_when_wait_ticks_budget_is_reached() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        StorageRuntimePolicy {
            assembly_policy: AssemblyPolicy {
                max_fragment_transactions: 64,
                max_fragment_cost_units: u64::MAX,
                max_fragment_wait_ticks: 2,
            },
            ..test_storage_runtime_policy()
        },
    )
    .unwrap();
    let context = ServiceContext::new(ShutdownSwitch::new());

    transaction_outbound
        .try_send(SanitizedTransaction {
            transaction_id: 700,
            estimated_cost_units: 10,
            dedup_fingerprint: 700,
            source: IngressSource::Quic,
            raw_payload: vec![],
        })
        .unwrap();
    block_assembler.tick(&context).unwrap();
    block_assembler.tick(&context).unwrap();
    block_assembler.tick(&context).unwrap();

    assert_eq!(block_assembler.committed_fragments_count(), 1);
}

#[test]
fn block_assembler_drops_fragment_after_retry_budget_exhaustion() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        test_storage_runtime_policy(),
    )
    .unwrap();
    block_assembler.fragment_counter = 10;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    for _ in 0..400 {
        block_assembler.tick(&context).unwrap();
        if !block_assembler.has_pending_retry() {
            break;
        }
    }

    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
}

#[test]
fn block_assembler_drops_deterministic_failure_without_retry() {
    let (transaction_outbound, transaction_inbound) = bounded_link::<SanitizedTransaction>(128);
    let mut block_assembler = BlockAssembler::with_storage_policy(
        DualReceiver::Channel(transaction_inbound),
        test_storage_runtime_policy(),
    )
    .unwrap();
    block_assembler.fragment_counter = 28;
    let context = ServiceContext::new(ShutdownSwitch::new());

    for transaction_id in 1..=64_u64 {
        transaction_outbound
            .try_send(SanitizedTransaction {
                transaction_id,
                estimated_cost_units: 10,
                dedup_fingerprint: transaction_id,
                source: IngressSource::Quic,
                raw_payload: vec![],
            })
            .unwrap();
        block_assembler.tick(&context).unwrap();
    }

    assert!(!block_assembler.has_pending_retry());
    assert_eq!(block_assembler.dropped_fragments, 1);
    assert_eq!(block_assembler.committed_fragments_count(), 0);
    assert_eq!(block_assembler.dropped_deterministic_total(), 1);
}
