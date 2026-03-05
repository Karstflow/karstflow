use crate::numeric::usize_to_u64_saturating;
use crate::types::{
    ExecutionFailureClass, ExecutionOutcome, ForkChoiceDirective, LeaderGateDirective,
    LeaderGateState, ReplayBoundaryState, SchedulerDirective,
};

pub(super) fn update_replay_boundary(
    state: &mut ReplayBoundaryState,
    outcome: &ExecutionOutcome,
) -> ForkChoiceDirective {
    state.last_applied_fragment_id = outcome.fragment_id;
    state.total_executed_transactions = state
        .total_executed_transactions
        .saturating_add(usize_to_u64_saturating(outcome.executed_transactions));

    match outcome.failure_class {
        Some(ExecutionFailureClass::ReplayConflict)
        | Some(ExecutionFailureClass::DeterministicTransactionFailure) => {
            ForkChoiceDirective::ConsiderReorg
        }
        _ => ForkChoiceDirective::KeepCurrentFork,
    }
}

pub(super) fn evaluate_leader_gate(leader_gate_state: &LeaderGateState) -> LeaderGateDirective {
    if leader_gate_state.is_current_leader {
        LeaderGateDirective::PermitExecution
    } else {
        LeaderGateDirective::HoldForLeader
    }
}

pub(super) fn derive_scheduler_directive(
    leader_gate_state: &LeaderGateState,
    outcome: &ExecutionOutcome,
) -> SchedulerDirective {
    let target_slot = if leader_gate_state.is_current_leader {
        leader_gate_state.next_leader_slot
    } else {
        leader_gate_state.next_leader_slot.saturating_add(1)
    };
    let priority_class = if outcome.failed_transactions == 0 {
        1
    } else if matches!(
        outcome.failure_class,
        Some(ExecutionFailureClass::ResourceExhaustion)
    ) {
        3
    } else {
        2
    };

    SchedulerDirective {
        target_slot,
        priority_class,
    }
}
