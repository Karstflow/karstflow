use super::replay_controller::{ReplayObservation, ReplayPublicationDecision};
use karstflow_execution::{ForkChoiceDirective, LeaderGateDirective};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaderPublicationAction {
    Proceed,
    HoldForLeader { retry_delay_millis: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReorgPublicationAction {
    Continue,
    HoldForReorgRetry,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PublicationGate;

impl PublicationGate {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn decide_leader_action(
        &self,
        leader_gate_directive: LeaderGateDirective,
        hold_retry_delay_millis: u64,
    ) -> LeaderPublicationAction {
        match leader_gate_directive {
            LeaderGateDirective::PermitExecution => LeaderPublicationAction::Proceed,
            LeaderGateDirective::HoldForLeader => LeaderPublicationAction::HoldForLeader {
                retry_delay_millis: hold_retry_delay_millis,
            },
        }
    }

    pub(super) fn decide_reorg_action(
        &self,
        fork_directive: ForkChoiceDirective,
        replay_observation: &ReplayObservation,
        fork_choice_runtime_enabled: bool,
        hold_requires_confirmed_candidate: bool,
    ) -> ReorgPublicationAction {
        let should_hold_for_reorg = matches!(fork_directive, ForkChoiceDirective::ConsiderReorg)
            && replay_observation.publication_decision
                == ReplayPublicationDecision::HoldForReorgCandidate
            && (!hold_requires_confirmed_candidate
                || replay_observation.active_candidate_confirmed)
            && fork_choice_runtime_enabled;

        if should_hold_for_reorg {
            ReorgPublicationAction::HoldForReorgRetry
        } else {
            ReorgPublicationAction::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LeaderPublicationAction, PublicationGate, ReorgPublicationAction};
    use crate::block_assembler::replay_controller::{ReplayObservation, ReplayPublicationDecision};
    use karstflow_execution::{ForkChoiceDirective, LeaderGateDirective};

    #[test]
    fn publication_gate_holds_when_leader_gate_requests_hold() {
        let gate = PublicationGate::new();
        let decision = gate.decide_leader_action(LeaderGateDirective::HoldForLeader, 25);
        assert_eq!(
            decision,
            LeaderPublicationAction::HoldForLeader {
                retry_delay_millis: 25
            }
        );
    }

    #[test]
    fn publication_gate_holds_for_reorg_only_when_runtime_policy_is_enabled() {
        let gate = PublicationGate::new();
        let observation = ReplayObservation {
            publication_decision: ReplayPublicationDecision::HoldForReorgCandidate,
            active_candidate_fragment_id: Some(7),
            active_candidate_failed_ratio_bps: 1_200,
            tracked_candidate_count: 2,
            active_candidate_confirmed: false,
            active_candidate_changed: false,
            stale_candidates_pruned: 0,
            switch_suppressed_by_hysteresis: false,
        };
        let disabled = gate.decide_reorg_action(
            ForkChoiceDirective::ConsiderReorg,
            &observation,
            false,
            false,
        );
        assert_eq!(disabled, ReorgPublicationAction::Continue);

        let enabled = gate.decide_reorg_action(
            ForkChoiceDirective::ConsiderReorg,
            &observation,
            true,
            false,
        );
        assert_eq!(enabled, ReorgPublicationAction::HoldForReorgRetry);
    }

    #[test]
    fn publication_gate_can_require_confirmed_candidate_for_reorg_hold() {
        let gate = PublicationGate::new();
        let unconfirmed = ReplayObservation {
            publication_decision: ReplayPublicationDecision::HoldForReorgCandidate,
            active_candidate_fragment_id: Some(7),
            active_candidate_failed_ratio_bps: 1_200,
            tracked_candidate_count: 2,
            active_candidate_confirmed: false,
            active_candidate_changed: false,
            stale_candidates_pruned: 0,
            switch_suppressed_by_hysteresis: false,
        };
        let decision =
            gate.decide_reorg_action(ForkChoiceDirective::ConsiderReorg, &unconfirmed, true, true);
        assert_eq!(decision, ReorgPublicationAction::Continue);

        let confirmed = ReplayObservation {
            active_candidate_confirmed: true,
            ..unconfirmed
        };
        let decision =
            gate.decide_reorg_action(ForkChoiceDirective::ConsiderReorg, &confirmed, true, true);
        assert_eq!(decision, ReorgPublicationAction::HoldForReorgRetry);
    }
}
