use crate::stats::BlockAssemblyMetrics;
use paradencer_execution::{ExecutionError, ExecutionFailureClass};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct BlockAssemblyStats {
    deferred_retries: AtomicU64,
    dropped_fragments: AtomicU64,
    committed_fragments: AtomicU64,
    pending_retries: AtomicU64,
    execution_error_total: AtomicU64,
    execution_error_empty_batch: AtomicU64,
    execution_error_cost_overflow: AtomicU64,
    execution_error_adapter_apply: AtomicU64,
    execution_error_adapter_rollback: AtomicU64,
    execution_error_adapter_state_conflict: AtomicU64,
    execution_error_adapter_contract_violation: AtomicU64,
    execution_error_adapter_receipt_missing: AtomicU64,
    execution_error_adapter_mutex_poisoned: AtomicU64,
    execution_error_fail_open_continue: AtomicU64,
    execution_error_fail_fast_halt: AtomicU64,
    execution_error_fail_open_circuit_breaker_halt: AtomicU64,
    execution_error_consecutive_current: AtomicU64,
    retry_scheduled_replay_conflict: AtomicU64,
    retry_scheduled_transient_pressure: AtomicU64,
    retry_scheduled_resource_exhaustion: AtomicU64,
    retry_scheduled_fallback: AtomicU64,
    dropped_replay_conflict: AtomicU64,
    dropped_deterministic: AtomicU64,
    dropped_transient_pressure: AtomicU64,
    dropped_resource_exhaustion: AtomicU64,
    dropped_fallback: AtomicU64,
    dropped_reorg_retry_exhausted: AtomicU64,
    leader_gate_permit: AtomicU64,
    leader_gate_hold: AtomicU64,
    fork_choice_keep: AtomicU64,
    fork_choice_reorg: AtomicU64,
    execution_health_cooldown_entries: AtomicU64,
    execution_health_cooldown_skipped_ticks: AtomicU64,
    replay_safety_hold_entries: AtomicU64,
    replay_safety_hold_skipped_ticks: AtomicU64,
    fork_choice_quarantine_entries: AtomicU64,
    fork_choice_quarantine_skipped_ticks: AtomicU64,
    slot_transition_committed: AtomicU64,
    slot_transition_dropped: AtomicU64,
    slot_transition_reorg_pending: AtomicU64,
    replay_controller_holds: AtomicU64,
    replay_controller_confirmed_candidates: AtomicU64,
    replay_controller_candidate_switches: AtomicU64,
    replay_controller_stale_candidates_pruned: AtomicU64,
    replay_controller_switch_suppressed: AtomicU64,
    replay_controller_active_candidate_failed_ratio_bps: AtomicU64,
    replay_controller_tracked_candidates: AtomicU64,
    replay_window_checkpoint_depth: AtomicU64,
    replay_window_rewinds: AtomicU64,
    replay_window_catalog_snapshots_pruned: AtomicU64,
    execution_state_rewind_failures: AtomicU64,
}

impl BlockAssemblyStats {
    pub(crate) fn increment_deferred_retries(&self) {
        self.deferred_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_dropped_fragments(&self) {
        self.dropped_fragments.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_committed_fragments(&self) {
        self.committed_fragments.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_pending_retries(&self, pending: u64) {
        self.pending_retries.store(pending, Ordering::Relaxed);
    }

    pub(crate) fn record_execution_error(&self, error: &ExecutionError) {
        self.execution_error_total.fetch_add(1, Ordering::Relaxed);
        match error {
            ExecutionError::EmptyBatch { .. } => {
                self.execution_error_empty_batch
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::CostOverflow { .. } => {
                self.execution_error_cost_overflow
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterApplyFailure { .. } => {
                self.execution_error_adapter_apply
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterRollbackFailure { .. } => {
                self.execution_error_adapter_rollback
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterStateConflict { .. } => {
                self.execution_error_adapter_state_conflict
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterContractViolation { .. } => {
                self.execution_error_adapter_contract_violation
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterReceiptMissing { .. } => {
                self.execution_error_adapter_receipt_missing
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::AdapterMutexPoisoned { .. } => {
                self.execution_error_adapter_mutex_poisoned
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::InvalidBatch { .. } => {
                self.execution_error_adapter_contract_violation
                    .fetch_add(1, Ordering::Relaxed);
            }
            ExecutionError::StorageBackend { .. } => {
                self.execution_error_adapter_apply
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn increment_execution_error_fail_open_continue(&self) {
        self.execution_error_fail_open_continue
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_execution_error_fail_fast_halt(&self) {
        self.execution_error_fail_fast_halt
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_execution_error_fail_open_circuit_breaker_halt(&self) {
        self.execution_error_fail_open_circuit_breaker_halt
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_execution_error_consecutive_current(&self, current: u64) {
        self.execution_error_consecutive_current
            .store(current, Ordering::Relaxed);
    }

    pub(crate) fn increment_retry_scheduled_for_failure_class(
        &self,
        failure_class: Option<ExecutionFailureClass>,
    ) {
        match failure_class {
            Some(ExecutionFailureClass::ReplayConflict) => {
                self.retry_scheduled_replay_conflict
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(ExecutionFailureClass::TransientSchedulerPressure) => {
                self.retry_scheduled_transient_pressure
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(ExecutionFailureClass::ResourceExhaustion) => {
                self.retry_scheduled_resource_exhaustion
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.retry_scheduled_fallback
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn increment_dropped_for_failure_class(
        &self,
        failure_class: Option<ExecutionFailureClass>,
    ) {
        match failure_class {
            Some(ExecutionFailureClass::ReplayConflict) => {
                self.dropped_replay_conflict.fetch_add(1, Ordering::Relaxed);
            }
            Some(ExecutionFailureClass::DeterministicTransactionFailure) => {
                self.dropped_deterministic.fetch_add(1, Ordering::Relaxed);
            }
            Some(ExecutionFailureClass::TransientSchedulerPressure) => {
                self.dropped_transient_pressure
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(ExecutionFailureClass::ResourceExhaustion) => {
                self.dropped_resource_exhaustion
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.dropped_fallback.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn increment_dropped_reorg_retry_exhausted(&self) {
        self.dropped_reorg_retry_exhausted
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_leader_gate_permit(&self) {
        self.leader_gate_permit.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_leader_gate_hold(&self) {
        self.leader_gate_hold.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_fork_choice_keep(&self) {
        self.fork_choice_keep.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_fork_choice_reorg(&self) {
        self.fork_choice_reorg.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_execution_health_cooldown_entries(&self) {
        self.execution_health_cooldown_entries
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_execution_health_cooldown_skipped_ticks(&self) {
        self.execution_health_cooldown_skipped_ticks
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_safety_hold_entries(&self) {
        self.replay_safety_hold_entries
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_safety_hold_skipped_ticks(&self) {
        self.replay_safety_hold_skipped_ticks
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_fork_choice_quarantine_entries(&self) {
        self.fork_choice_quarantine_entries
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_fork_choice_quarantine_skipped_ticks(&self) {
        self.fork_choice_quarantine_skipped_ticks
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_slot_transition_committed(&self) {
        self.slot_transition_committed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_slot_transition_dropped(&self) {
        self.slot_transition_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_slot_transition_reorg_pending(&self) {
        self.slot_transition_reorg_pending
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_controller_holds(&self) {
        self.replay_controller_holds.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_controller_confirmed_candidates(&self) {
        self.replay_controller_confirmed_candidates
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_controller_candidate_switches(&self) {
        self.replay_controller_candidate_switches
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_controller_stale_candidates_pruned(&self, count: u64) {
        self.replay_controller_stale_candidates_pruned
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_controller_switch_suppressed(&self) {
        self.replay_controller_switch_suppressed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_replay_controller_active_candidate_failed_ratio_bps(&self, ratio_bps: u64) {
        self.replay_controller_active_candidate_failed_ratio_bps
            .store(ratio_bps, Ordering::Relaxed);
    }

    pub(crate) fn set_replay_controller_tracked_candidates(&self, tracked_candidates: u64) {
        self.replay_controller_tracked_candidates
            .store(tracked_candidates, Ordering::Relaxed);
    }

    pub(crate) fn set_replay_window_checkpoint_depth(&self, depth: u64) {
        self.replay_window_checkpoint_depth
            .store(depth, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_window_rewinds(&self) {
        self.replay_window_rewinds.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_replay_window_catalog_snapshots_pruned(&self, count: u64) {
        self.replay_window_catalog_snapshots_pruned
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn increment_execution_state_rewind_failures(&self) {
        self.execution_state_rewind_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> BlockAssemblyMetrics {
        BlockAssemblyMetrics {
            deferred_retries: self.deferred_retries.load(Ordering::Relaxed),
            dropped_fragments: self.dropped_fragments.load(Ordering::Relaxed),
            committed_fragments: self.committed_fragments.load(Ordering::Relaxed),
            pending_retries: self.pending_retries.load(Ordering::Relaxed),
            execution_error_total: self.execution_error_total.load(Ordering::Relaxed),
            execution_error_empty_batch: self.execution_error_empty_batch.load(Ordering::Relaxed),
            execution_error_cost_overflow: self
                .execution_error_cost_overflow
                .load(Ordering::Relaxed),
            execution_error_adapter_apply: self
                .execution_error_adapter_apply
                .load(Ordering::Relaxed),
            execution_error_adapter_rollback: self
                .execution_error_adapter_rollback
                .load(Ordering::Relaxed),
            execution_error_adapter_state_conflict: self
                .execution_error_adapter_state_conflict
                .load(Ordering::Relaxed),
            execution_error_adapter_contract_violation: self
                .execution_error_adapter_contract_violation
                .load(Ordering::Relaxed),
            execution_error_adapter_receipt_missing: self
                .execution_error_adapter_receipt_missing
                .load(Ordering::Relaxed),
            execution_error_adapter_mutex_poisoned: self
                .execution_error_adapter_mutex_poisoned
                .load(Ordering::Relaxed),
            execution_error_fail_open_continue: self
                .execution_error_fail_open_continue
                .load(Ordering::Relaxed),
            execution_error_fail_fast_halt: self
                .execution_error_fail_fast_halt
                .load(Ordering::Relaxed),
            execution_error_fail_open_circuit_breaker_halt: self
                .execution_error_fail_open_circuit_breaker_halt
                .load(Ordering::Relaxed),
            execution_error_consecutive_current: self
                .execution_error_consecutive_current
                .load(Ordering::Relaxed),
            retry_scheduled_replay_conflict: self
                .retry_scheduled_replay_conflict
                .load(Ordering::Relaxed),
            retry_scheduled_transient_pressure: self
                .retry_scheduled_transient_pressure
                .load(Ordering::Relaxed),
            retry_scheduled_resource_exhaustion: self
                .retry_scheduled_resource_exhaustion
                .load(Ordering::Relaxed),
            retry_scheduled_fallback: self.retry_scheduled_fallback.load(Ordering::Relaxed),
            dropped_replay_conflict: self.dropped_replay_conflict.load(Ordering::Relaxed),
            dropped_deterministic: self.dropped_deterministic.load(Ordering::Relaxed),
            dropped_transient_pressure: self.dropped_transient_pressure.load(Ordering::Relaxed),
            dropped_resource_exhaustion: self.dropped_resource_exhaustion.load(Ordering::Relaxed),
            dropped_fallback: self.dropped_fallback.load(Ordering::Relaxed),
            dropped_reorg_retry_exhausted: self
                .dropped_reorg_retry_exhausted
                .load(Ordering::Relaxed),
            leader_gate_permit: self.leader_gate_permit.load(Ordering::Relaxed),
            leader_gate_hold: self.leader_gate_hold.load(Ordering::Relaxed),
            fork_choice_keep: self.fork_choice_keep.load(Ordering::Relaxed),
            fork_choice_reorg: self.fork_choice_reorg.load(Ordering::Relaxed),
            execution_health_cooldown_entries: self
                .execution_health_cooldown_entries
                .load(Ordering::Relaxed),
            execution_health_cooldown_skipped_ticks: self
                .execution_health_cooldown_skipped_ticks
                .load(Ordering::Relaxed),
            replay_safety_hold_entries: self.replay_safety_hold_entries.load(Ordering::Relaxed),
            replay_safety_hold_skipped_ticks: self
                .replay_safety_hold_skipped_ticks
                .load(Ordering::Relaxed),
            fork_choice_quarantine_entries: self
                .fork_choice_quarantine_entries
                .load(Ordering::Relaxed),
            fork_choice_quarantine_skipped_ticks: self
                .fork_choice_quarantine_skipped_ticks
                .load(Ordering::Relaxed),
            slot_transition_committed: self.slot_transition_committed.load(Ordering::Relaxed),
            slot_transition_dropped: self.slot_transition_dropped.load(Ordering::Relaxed),
            slot_transition_reorg_pending: self
                .slot_transition_reorg_pending
                .load(Ordering::Relaxed),
            replay_controller_holds: self.replay_controller_holds.load(Ordering::Relaxed),
            replay_controller_confirmed_candidates: self
                .replay_controller_confirmed_candidates
                .load(Ordering::Relaxed),
            replay_controller_candidate_switches: self
                .replay_controller_candidate_switches
                .load(Ordering::Relaxed),
            replay_controller_stale_candidates_pruned: self
                .replay_controller_stale_candidates_pruned
                .load(Ordering::Relaxed),
            replay_controller_switch_suppressed: self
                .replay_controller_switch_suppressed
                .load(Ordering::Relaxed),
            replay_controller_active_candidate_failed_ratio_bps: self
                .replay_controller_active_candidate_failed_ratio_bps
                .load(Ordering::Relaxed),
            replay_controller_tracked_candidates: self
                .replay_controller_tracked_candidates
                .load(Ordering::Relaxed),
            replay_window_checkpoint_depth: self
                .replay_window_checkpoint_depth
                .load(Ordering::Relaxed),
            replay_window_rewinds: self.replay_window_rewinds.load(Ordering::Relaxed),
            replay_window_catalog_snapshots_pruned: self
                .replay_window_catalog_snapshots_pruned
                .load(Ordering::Relaxed),
            execution_state_rewind_failures: self
                .execution_state_rewind_failures
                .load(Ordering::Relaxed),
        }
    }
}
