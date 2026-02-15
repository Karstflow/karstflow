use super::publication_gate::{LeaderPublicationAction, ReorgPublicationAction};
use super::replay_controller::ReplayPublicationDecision;
use super::{BlockAssembler, PendingRetryFragment};
use crate::AssembledBlockFragment;
use crate::ExecutionErrorHandlingPolicy;
use paradencer_execution::{
    ExecutionBatch, ExecutionFailureClass, ForkChoiceDirective, RetryDirective,
};
use paradencer_runtime::{RuntimeError, RuntimeResult, Service};

impl BlockAssembler {
    fn attempt_fragment(
        &mut self,
        fragment_id: u64,
        transaction_count: usize,
        total_cost_units: u64,
        retries_attempted: u8,
    ) -> RuntimeResult<()> {
        self.slot_pipeline.on_fragment_execution_start();
        self.refresh_leader_gate_state();
        let leader_gate_directive = self
            .execution_bridge
            .evaluate_leader_gate(&self.leader_gate_state);
        match self.publication_gate.decide_leader_action(
            leader_gate_directive,
            self.storage_runtime_policy
                .leader_schedule_policy
                .hold_retry_delay_millis,
        ) {
            LeaderPublicationAction::Proceed => {
                self.block_assembly_stats.increment_leader_gate_permit();
            }
            LeaderPublicationAction::HoldForLeader { retry_delay_millis } => {
                self.block_assembly_stats.increment_leader_gate_hold();
                self.slot_pipeline.on_retry_scheduled();
                self.pending_retry = Some(PendingRetryFragment {
                    fragment_id,
                    transaction_count,
                    total_cost_units,
                    retries_attempted,
                    wait_ticks_remaining: Self::delay_to_ticks(retry_delay_millis),
                });
                self.block_assembly_stats.increment_deferred_retries();
                self.block_assembly_stats.set_pending_retries(1);
                self.leader_gate_state.next_leader_slot =
                    self.leader_gate_state.next_leader_slot.saturating_add(1);
                return Ok(());
            }
        }

        let (execution_outcome, execution_error) =
            self.execution_bridge
                .execute_batch_with_error(&ExecutionBatch::new(
                    fragment_id,
                    transaction_count,
                    total_cost_units,
                ));
        if let Some(error) = execution_error.as_ref() {
            self.block_assembly_stats.record_execution_error(error);
            self.consecutive_execution_errors = self.consecutive_execution_errors.saturating_add(1);
            self.block_assembly_stats
                .set_execution_error_consecutive_current(self.consecutive_execution_errors as u64);
            if matches!(
                self.storage_runtime_policy.execution_error_handling_policy,
                ExecutionErrorHandlingPolicy::FailFast
            ) {
                self.block_assembly_stats
                    .increment_execution_error_fail_fast_halt();
                return Err(RuntimeError::service_failure(
                    self.name(),
                    &error.to_string(),
                ));
            }
            let max_consecutive = self
                .storage_runtime_policy
                .execution_error_fail_open_max_consecutive;
            if max_consecutive > 0 && self.consecutive_execution_errors >= max_consecutive {
                self.block_assembly_stats
                    .increment_execution_error_fail_open_circuit_breaker_halt();
                return Err(RuntimeError::service_failure(
                    self.name(),
                    "execution error fail-open circuit breaker triggered",
                ));
            }
            self.block_assembly_stats
                .increment_execution_error_fail_open_continue();
        } else {
            self.consecutive_execution_errors = 0;
            self.block_assembly_stats
                .set_execution_error_consecutive_current(0);
        }
        let fork_directive = self
            .execution_bridge
            .update_replay_boundary(&mut self.replay_boundary_state, &execution_outcome);
        let total_transactions = execution_outcome
            .executed_transactions
            .saturating_add(execution_outcome.failed_transactions);
        let failed_transaction_ratio_bps = if total_transactions == 0 {
            0
        } else {
            ((execution_outcome.failed_transactions as u64)
                .saturating_mul(10_000)
                .saturating_div(total_transactions as u64)) as u32
        };
        let replay_observation = self.replay_controller.observe_fork_choice(
            fragment_id,
            fork_directive,
            failed_transaction_ratio_bps,
        );
        if replay_observation.stale_candidates_pruned > 0 {
            self.block_assembly_stats
                .increment_replay_controller_stale_candidates_pruned(
                    replay_observation.stale_candidates_pruned as u64,
                );
        }
        if replay_observation.switch_suppressed_by_hysteresis {
            self.block_assembly_stats
                .increment_replay_controller_switch_suppressed();
        }
        self.block_assembly_stats
            .set_replay_controller_active_candidate_failed_ratio_bps(
                replay_observation.active_candidate_failed_ratio_bps as u64,
            );
        self.block_assembly_stats
            .set_replay_controller_tracked_candidates(
                replay_observation.tracked_candidate_count as u64,
            );
        let scheduler_directive = self
            .execution_bridge
            .derive_scheduler_directive(&self.leader_gate_state, &execution_outcome);
        let retry_directive = self
            .execution_bridge
            .derive_retry_directive(&execution_outcome);
        self.update_execution_health_state(&execution_outcome);
        self.update_replay_safety_state(&execution_outcome);
        self.update_fork_choice_quarantine_state(fork_directive);

        let current_scheduler_slot = self.leader_gate_state.next_leader_slot;
        self.leader_gate_state.next_leader_slot = scheduler_directive.target_slot.saturating_add(1);

        match fork_directive {
            ForkChoiceDirective::KeepCurrentFork => {
                self.block_assembly_stats.increment_fork_choice_keep()
            }
            ForkChoiceDirective::ConsiderReorg => {
                self.block_assembly_stats.increment_fork_choice_reorg();
                self.slot_pipeline.on_reorg_detected();
                self.block_assembly_stats
                    .increment_slot_transition_reorg_pending();
                if replay_observation.publication_decision
                    == ReplayPublicationDecision::HoldForReorgCandidate
                {
                    self.block_assembly_stats
                        .increment_replay_controller_holds();
                    if replay_observation.active_candidate_confirmed {
                        self.block_assembly_stats
                            .increment_replay_controller_confirmed_candidates();
                    }
                    if replay_observation.active_candidate_changed {
                        self.block_assembly_stats
                            .increment_replay_controller_candidate_switches();
                    }
                }
                if replay_observation.active_candidate_confirmed {
                    if let Some(checkpoint) = self.bank_timeline.maybe_rewind_on_confirmed_reorg(
                        replay_observation.active_candidate_fragment_id,
                    ) {
                        if let Err(error) = self
                            .execution_bridge
                            .rewind_execution_state_to_fragment(checkpoint.fragment_id)
                        {
                            self.block_assembly_stats.record_execution_error(&error);
                            self.block_assembly_stats
                                .increment_execution_state_rewind_failures();
                            return Err(RuntimeError::service_failure(
                                self.name(),
                                &error.to_string(),
                            ));
                        }
                        self.hot_state_store.last_fragment_id = checkpoint.fragment_id;
                        self.hot_state_store.committed_fragments = checkpoint.committed_fragments;
                        self.hot_state_store.committed_transactions =
                            checkpoint.committed_transactions;
                        self.fragment_counter = checkpoint.fragment_id;
                        let rewind_slot = checkpoint.fragment_id.max(
                            self.storage_runtime_policy
                                .leader_schedule_policy
                                .initial_slot,
                        );
                        self.leader_gate_state.next_leader_slot = rewind_slot;
                        self.slot_pipeline.rewind_to_slot(rewind_slot);
                        let pruned_snapshots = self
                            .snapshot_catalog
                            .rewind_to_fragment(checkpoint.fragment_id);
                        self.block_assembly_stats
                            .increment_replay_window_catalog_snapshots_pruned(
                                pruned_snapshots as u64,
                            );
                        self.replay_controller
                            .on_rewind_to_fragment(checkpoint.fragment_id);
                        self.replay_boundary_state.last_applied_fragment_id =
                            checkpoint.fragment_id;
                        self.replay_boundary_state.total_executed_transactions =
                            checkpoint.committed_transactions;
                        self.block_assembly_stats
                            .set_replay_window_checkpoint_depth(self.bank_timeline.len() as u64);
                        self.persist_catalog_if_configured()?;
                        self.block_assembly_stats.increment_replay_window_rewinds();
                    }
                }
                if self.publication_gate.decide_reorg_action(
                    fork_directive,
                    &replay_observation,
                    self.storage_runtime_policy
                        .fork_choice_runtime_policy
                        .enabled,
                    self.storage_runtime_policy
                        .fork_choice_runtime_policy
                        .hold_requires_confirmed_candidate,
                ) == ReorgPublicationAction::HoldForReorgRetry
                {
                    self.handle_reorg_retry_or_drop(
                        fragment_id,
                        transaction_count,
                        total_cost_units,
                        retries_attempted,
                    );
                    return Ok(());
                }
            }
        }

        match retry_directive {
            RetryDirective::NoRetry => {
                self.pending_retry = None;
                self.block_assembly_stats.set_pending_retries(0);
                self.consecutive_transient_failures = 0;
                self.commit_fragment(
                    fragment_id,
                    transaction_count,
                    execution_outcome.total_cost_units,
                )?;
                self.slot_pipeline.on_fragment_committed();
                self.block_assembly_stats
                    .increment_slot_transition_committed();
                self.slot_pipeline.advance_slot();
            }
            RetryDirective::DropCurrentFragment => {
                self.pending_retry = None;
                self.block_assembly_stats
                    .increment_dropped_for_failure_class(execution_outcome.failure_class);
                self.drop_current_fragment();
                self.consecutive_transient_failures = 0;
            }
            RetryDirective::RetryWithBackoff { retry_delay_millis } => {
                let failure_class_retry_budget =
                    self.retry_budget_for_failure_class(execution_outcome.failure_class);
                let effective_retry_budget = self
                    .storage_runtime_policy
                    .max_retry_attempts
                    .min(failure_class_retry_budget);
                if retries_attempted >= effective_retry_budget {
                    self.pending_retry = None;
                    self.block_assembly_stats
                        .increment_dropped_for_failure_class(execution_outcome.failure_class);
                    self.drop_current_fragment();
                    self.consecutive_transient_failures = 0;
                } else {
                    let scheduler_adjusted_delay = self.apply_scheduler_retry_delay(
                        retry_delay_millis,
                        current_scheduler_slot,
                        scheduler_directive.target_slot,
                        scheduler_directive.priority_class,
                    );
                    let capped_retry_delay = scheduler_adjusted_delay
                        .min(self.storage_runtime_policy.retry_backoff_cap_millis);
                    self.pending_retry = Some(PendingRetryFragment {
                        fragment_id,
                        transaction_count,
                        total_cost_units,
                        retries_attempted: retries_attempted.saturating_add(1),
                        wait_ticks_remaining: Self::delay_to_ticks(capped_retry_delay),
                    });
                    self.slot_pipeline.on_retry_scheduled();
                    self.block_assembly_stats.increment_deferred_retries();
                    self.block_assembly_stats
                        .increment_retry_scheduled_for_failure_class(
                            execution_outcome.failure_class,
                        );
                    self.block_assembly_stats.set_pending_retries(1);
                }
            }
        }

        Ok(())
    }

    fn apply_scheduler_retry_delay(
        &self,
        retry_delay_millis: u64,
        current_scheduler_slot: u64,
        target_scheduler_slot: u64,
        priority_class: u8,
    ) -> u64 {
        let policy = self.storage_runtime_policy.scheduler_runtime_policy;
        if !policy.enabled {
            return retry_delay_millis;
        }

        let slot_delay = target_scheduler_slot
            .saturating_sub(current_scheduler_slot)
            .saturating_mul(policy.slot_duration_millis);
        let priority_penalty = match priority_class {
            3 => policy.priority_penalty_class_3_millis,
            2 => policy.priority_penalty_class_2_millis,
            _ => 0,
        };
        retry_delay_millis.max(slot_delay.saturating_add(priority_penalty))
    }

    fn update_execution_health_state(
        &mut self,
        execution_outcome: &paradencer_execution::ExecutionOutcome,
    ) {
        let policy = self.storage_runtime_policy.execution_health_policy;
        if !policy.enabled {
            return;
        }

        let is_transient_failure = matches!(
            execution_outcome.failure_class,
            Some(ExecutionFailureClass::TransientSchedulerPressure)
                | Some(ExecutionFailureClass::ResourceExhaustion)
        );
        if is_transient_failure {
            self.consecutive_transient_failures =
                self.consecutive_transient_failures.saturating_add(1);
            if self.consecutive_transient_failures >= policy.transient_failure_threshold {
                self.cooldown_ticks_remaining = policy.cooldown_ticks;
                self.consecutive_transient_failures = 0;
                self.block_assembly_stats
                    .increment_execution_health_cooldown_entries();
            }
        } else {
            self.consecutive_transient_failures = 0;
        }
    }

    fn update_replay_safety_state(
        &mut self,
        execution_outcome: &paradencer_execution::ExecutionOutcome,
    ) {
        let policy = self.storage_runtime_policy.replay_safety_policy;
        if !policy.enabled {
            return;
        }

        if matches!(
            execution_outcome.failure_class,
            Some(ExecutionFailureClass::ReplayConflict)
        ) {
            self.consecutive_replay_conflicts = self.consecutive_replay_conflicts.saturating_add(1);
            if self.consecutive_replay_conflicts >= policy.replay_conflict_threshold {
                self.replay_safety_hold_ticks_remaining = policy.hold_ticks;
                self.consecutive_replay_conflicts = 0;
                self.block_assembly_stats
                    .increment_replay_safety_hold_entries();
            }
        } else {
            self.consecutive_replay_conflicts = 0;
        }
    }

    fn update_fork_choice_quarantine_state(&mut self, fork_directive: ForkChoiceDirective) {
        let policy = self.storage_runtime_policy.fork_choice_quarantine_policy;
        if !policy.enabled {
            return;
        }

        if matches!(fork_directive, ForkChoiceDirective::ConsiderReorg) {
            self.consecutive_reorg_directives = self.consecutive_reorg_directives.saturating_add(1);
            if self.consecutive_reorg_directives >= policy.consecutive_reorg_threshold {
                self.fork_choice_quarantine_ticks_remaining = policy.quarantine_ticks;
                self.consecutive_reorg_directives = 0;
                self.block_assembly_stats
                    .increment_fork_choice_quarantine_entries();
            }
        } else {
            self.consecutive_reorg_directives = 0;
        }
    }

    fn handle_reorg_retry_or_drop(
        &mut self,
        fragment_id: u64,
        transaction_count: usize,
        total_cost_units: u64,
        retries_attempted: u8,
    ) {
        let policy = self.storage_runtime_policy.fork_choice_runtime_policy;
        if retries_attempted >= policy.max_reorg_retry_attempts {
            self.pending_retry = None;
            self.block_assembly_stats
                .increment_dropped_reorg_retry_exhausted();
            self.drop_current_fragment();
            return;
        }

        self.pending_retry = Some(PendingRetryFragment {
            fragment_id,
            transaction_count,
            total_cost_units,
            retries_attempted: retries_attempted.saturating_add(1),
            wait_ticks_remaining: Self::delay_to_ticks(policy.reorg_retry_delay_millis),
        });
        self.slot_pipeline.on_retry_scheduled();
        self.block_assembly_stats.increment_deferred_retries();
        self.block_assembly_stats.set_pending_retries(1);
    }

    fn retry_budget_for_failure_class(&self, failure_class: Option<ExecutionFailureClass>) -> u8 {
        let retry_policy = self.storage_runtime_policy.execution_retry_policy;
        match failure_class {
            Some(ExecutionFailureClass::ReplayConflict) => retry_policy.max_retries_replay_conflict,
            Some(ExecutionFailureClass::TransientSchedulerPressure) => {
                retry_policy.max_retries_transient_pressure
            }
            Some(ExecutionFailureClass::ResourceExhaustion) => {
                retry_policy.max_retries_resource_exhaustion
            }
            _ => retry_policy.max_retries_fallback,
        }
    }

    fn drop_current_fragment(&mut self) {
        self.slot_pipeline.on_fragment_dropped();
        self.block_assembly_stats
            .increment_slot_transition_dropped();
        self.slot_pipeline.advance_slot();
        self.dropped_fragments = self.dropped_fragments.saturating_add(1);
        self.block_assembly_stats.increment_dropped_fragments();
        self.block_assembly_stats.set_pending_retries(0);
    }

    pub(super) fn process_pending_retry(&mut self) -> RuntimeResult<()> {
        let pending = match self.pending_retry {
            Some(pending) => pending,
            None => return Ok(()),
        };

        if pending.wait_ticks_remaining > 0 {
            self.pending_retry = Some(PendingRetryFragment {
                wait_ticks_remaining: pending.wait_ticks_remaining.saturating_sub(1),
                ..pending
            });
            return Ok(());
        }

        self.attempt_fragment(
            pending.fragment_id,
            pending.transaction_count,
            pending.total_cost_units,
            pending.retries_attempted,
        )
    }

    fn should_assemble_fragment(&self) -> bool {
        let policy = self.storage_runtime_policy.assembly_policy;
        self.buffered_transactions >= policy.max_fragment_transactions
            || self.buffered_cost_units >= policy.max_fragment_cost_units
            || self.buffered_ticks >= policy.max_fragment_wait_ticks
    }

    pub(super) fn try_assemble_buffered_fragment(&mut self) -> RuntimeResult<()> {
        if self.pending_retry.is_some() || self.buffered_transactions == 0 {
            return Ok(());
        }
        if !self.should_assemble_fragment() {
            return Ok(());
        }

        self.fragment_counter = self.fragment_counter.checked_add(1).ok_or_else(|| {
            RuntimeError::service_failure(self.name(), "fragment counter overflow")
        })?;
        let assembled_fragment = AssembledBlockFragment {
            fragment_id: self.fragment_counter,
            transaction_count: self.buffered_transactions,
        };
        self.attempt_fragment(
            assembled_fragment.fragment_id,
            assembled_fragment.transaction_count,
            self.buffered_cost_units,
            0,
        )?;
        self.buffered_transactions = 0;
        self.buffered_cost_units = 0;
        self.buffered_ticks = 0;
        Ok(())
    }

    fn refresh_leader_gate_state(&mut self) {
        let policy = self.storage_runtime_policy.leader_schedule_policy;
        if !policy.enabled {
            self.leader_gate_state.is_current_leader = true;
            return;
        }

        let slot_cycle_length = policy.slot_cycle_length.max(1);
        let leader_slots = policy.leader_slots_per_cycle.clamp(1, slot_cycle_length);
        let slot_in_cycle = self.leader_gate_state.next_leader_slot % slot_cycle_length;
        self.leader_gate_state.is_current_leader = slot_in_cycle < leader_slots;
    }

    #[cfg(test)]
    pub(crate) fn has_pending_retry(&self) -> bool {
        self.pending_retry.is_some()
    }

    #[cfg(test)]
    pub(crate) fn committed_fragments_count(&self) -> u64 {
        self.hot_state_store.committed_fragments
    }

    #[cfg(test)]
    pub(crate) fn cooldown_ticks_remaining(&self) -> u32 {
        self.cooldown_ticks_remaining
    }

    #[cfg(test)]
    pub(crate) fn replay_safety_hold_ticks_remaining(&self) -> u32 {
        self.replay_safety_hold_ticks_remaining
    }

    #[cfg(test)]
    pub(crate) fn fork_choice_quarantine_ticks_remaining(&self) -> u32 {
        self.fork_choice_quarantine_ticks_remaining
    }

    #[cfg(test)]
    pub(crate) fn slot_pipeline_state_name(&self) -> &'static str {
        match self.slot_pipeline.state {
            super::slot_pipeline::SlotPipelineState::Idle => "idle",
            super::slot_pipeline::SlotPipelineState::CollectingTransactions => "collecting",
            super::slot_pipeline::SlotPipelineState::ExecutingFragment => "executing",
            super::slot_pipeline::SlotPipelineState::WaitingRetry => "waiting_retry",
            super::slot_pipeline::SlotPipelineState::ReorgPending => "reorg_pending",
            super::slot_pipeline::SlotPipelineState::Committed => "committed",
            super::slot_pipeline::SlotPipelineState::Dropped => "dropped",
        }
    }

    #[cfg(test)]
    pub(crate) fn slot_pipeline_slot(&self) -> u64 {
        self.slot_pipeline.current_slot
    }

    #[cfg(test)]
    pub(crate) fn next_leader_slot(&self) -> u64 {
        self.leader_gate_state.next_leader_slot
    }

    #[cfg(test)]
    pub(crate) fn replay_controller_has_pending_candidate(&self) -> bool {
        self.replay_controller.has_pending_candidate()
    }

    #[cfg(test)]
    pub(crate) fn replay_controller_active_candidate_fragment_id(&self) -> Option<u64> {
        self.replay_controller.active_candidate_fragment_id()
    }

    #[cfg(test)]
    pub(crate) fn replay_window_checkpoint_depth(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .replay_window_checkpoint_depth
    }

    #[cfg(test)]
    pub(crate) fn replay_window_rewinds(&self) -> u64 {
        self.block_assembly_stats.snapshot().replay_window_rewinds
    }

    #[cfg(test)]
    pub(crate) fn replay_window_catalog_snapshots_pruned(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .replay_window_catalog_snapshots_pruned
    }

    #[cfg(test)]
    pub(crate) fn execution_state_rewind_failures(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_state_rewind_failures
    }

    #[cfg(test)]
    pub(crate) fn execution_error_total(&self) -> u64 {
        self.block_assembly_stats.snapshot().execution_error_total
    }

    #[cfg(test)]
    pub(crate) fn execution_error_adapter_apply_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_adapter_apply
    }

    #[cfg(test)]
    pub(crate) fn execution_error_adapter_rollback_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_adapter_rollback
    }

    #[cfg(test)]
    pub(crate) fn execution_error_adapter_contract_violation_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_adapter_contract_violation
    }

    #[cfg(test)]
    pub(crate) fn execution_error_fail_open_continue_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_fail_open_continue
    }

    #[cfg(test)]
    pub(crate) fn execution_error_fail_fast_halt_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_fail_fast_halt
    }

    #[cfg(test)]
    pub(crate) fn execution_error_fail_open_circuit_breaker_halt_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_fail_open_circuit_breaker_halt
    }

    #[cfg(test)]
    pub(crate) fn execution_error_consecutive_current(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .execution_error_consecutive_current
    }

    #[cfg(test)]
    pub(crate) fn retry_scheduled_replay_conflict_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .retry_scheduled_replay_conflict
    }

    #[cfg(test)]
    pub(crate) fn retry_scheduled_transient_pressure_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .retry_scheduled_transient_pressure
    }

    #[cfg(test)]
    pub(crate) fn dropped_replay_conflict_total(&self) -> u64 {
        self.block_assembly_stats.snapshot().dropped_replay_conflict
    }

    #[cfg(test)]
    pub(crate) fn dropped_deterministic_total(&self) -> u64 {
        self.block_assembly_stats.snapshot().dropped_deterministic
    }

    #[cfg(test)]
    pub(crate) fn dropped_resource_exhaustion_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .dropped_resource_exhaustion
    }

    #[cfg(test)]
    pub(crate) fn dropped_reorg_retry_exhausted_total(&self) -> u64 {
        self.block_assembly_stats
            .snapshot()
            .dropped_reorg_retry_exhausted
    }
}
