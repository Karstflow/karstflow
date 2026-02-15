use super::fork_choice_engine::ForkChoiceEngine;
use paradencer_execution::ForkChoiceDirective;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayPublicationDecision {
    PublishOnCanonical,
    HoldForReorgCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayObservation {
    pub(crate) publication_decision: ReplayPublicationDecision,
    pub(crate) active_candidate_fragment_id: Option<u64>,
    pub(crate) active_candidate_failed_ratio_bps: u32,
    pub(crate) tracked_candidate_count: usize,
    pub(crate) active_candidate_confirmed: bool,
    pub(crate) active_candidate_changed: bool,
    pub(crate) stale_candidates_pruned: usize,
    pub(crate) switch_suppressed_by_hysteresis: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplayCandidate {
    pub(super) fragment_id: u64,
    pub(super) consecutive_reorg_signals: u32,
    pub(super) average_failed_transaction_ratio_bps: u32,
    pub(super) observations: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayController {
    canonical_fragment_id: u64,
    reorg_candidates: Vec<ReplayCandidate>,
    active_candidate_fragment_id: Option<u64>,
    candidate_confirmation_threshold: u32,
    candidate_confirmation_max_failed_ratio_bps: u32,
    max_candidates: usize,
    candidate_stale_fragment_lag: u64,
    candidate_switch_min_score_delta: u64,
    fork_choice_engine: ForkChoiceEngine,
}

impl ReplayController {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        canonical_fragment_id: u64,
        candidate_confirmation_threshold: u32,
        candidate_confirmation_max_failed_ratio_bps: u32,
        max_candidates: usize,
        reorg_signal_weight: u64,
        fragment_recency_weight: u64,
        failed_transaction_ratio_penalty_weight: u64,
        candidate_stale_fragment_lag: u64,
        candidate_switch_min_score_delta: u64,
    ) -> Self {
        Self {
            canonical_fragment_id,
            reorg_candidates: Vec::new(),
            active_candidate_fragment_id: None,
            candidate_confirmation_threshold: candidate_confirmation_threshold.max(1),
            candidate_confirmation_max_failed_ratio_bps,
            max_candidates: max_candidates.max(1),
            candidate_stale_fragment_lag: candidate_stale_fragment_lag.max(1),
            candidate_switch_min_score_delta: candidate_switch_min_score_delta.max(1),
            fork_choice_engine: ForkChoiceEngine::with_weights(
                reorg_signal_weight,
                fragment_recency_weight,
                failed_transaction_ratio_penalty_weight,
            ),
        }
    }

    pub(crate) fn observe_fork_choice(
        &mut self,
        fragment_id: u64,
        directive: ForkChoiceDirective,
        failed_transaction_ratio_bps: u32,
    ) -> ReplayObservation {
        match directive {
            ForkChoiceDirective::KeepCurrentFork => {
                let active_candidate_changed = self.active_candidate_fragment_id.is_some();
                self.canonical_fragment_id = fragment_id;
                self.reorg_candidates.clear();
                self.active_candidate_fragment_id = None;
                ReplayObservation {
                    publication_decision: ReplayPublicationDecision::PublishOnCanonical,
                    active_candidate_fragment_id: None,
                    active_candidate_failed_ratio_bps: 0,
                    tracked_candidate_count: 0,
                    active_candidate_confirmed: false,
                    active_candidate_changed,
                    stale_candidates_pruned: 0,
                    switch_suppressed_by_hysteresis: false,
                }
            }
            ForkChoiceDirective::ConsiderReorg => {
                let stale_candidates_pruned = self.prune_stale_candidates(fragment_id);
                let (active_candidate_changed, switch_suppressed_by_hysteresis) =
                    self.track_reorg_candidate(fragment_id, failed_transaction_ratio_bps);
                ReplayObservation {
                    publication_decision: ReplayPublicationDecision::HoldForReorgCandidate,
                    active_candidate_fragment_id: self.active_candidate_fragment_id,
                    active_candidate_failed_ratio_bps: self.active_candidate_failed_ratio_bps(),
                    tracked_candidate_count: self.reorg_candidates.len(),
                    active_candidate_confirmed: self.active_candidate_is_confirmed(),
                    active_candidate_changed,
                    stale_candidates_pruned,
                    switch_suppressed_by_hysteresis,
                }
            }
        }
    }

    pub(crate) fn on_rewind_to_fragment(&mut self, fragment_id: u64) {
        self.canonical_fragment_id = fragment_id;
        self.reorg_candidates.clear();
        self.active_candidate_fragment_id = None;
    }

    fn track_reorg_candidate(
        &mut self,
        fragment_id: u64,
        failed_transaction_ratio_bps: u32,
    ) -> (bool, bool) {
        let previous_active = self.active_candidate_fragment_id;
        match self
            .reorg_candidates
            .iter_mut()
            .find(|candidate| candidate.fragment_id == fragment_id)
        {
            Some(candidate) => {
                candidate.consecutive_reorg_signals =
                    candidate.consecutive_reorg_signals.saturating_add(1);
                let next_observations = candidate.observations.saturating_add(1);
                let current_total = u64::from(candidate.average_failed_transaction_ratio_bps)
                    .saturating_mul(u64::from(candidate.observations));
                let updated_total =
                    current_total.saturating_add(u64::from(failed_transaction_ratio_bps));
                candidate.average_failed_transaction_ratio_bps =
                    (updated_total / u64::from(next_observations)) as u32;
                candidate.observations = next_observations;
            }
            None => self.reorg_candidates.push(ReplayCandidate {
                fragment_id,
                consecutive_reorg_signals: 1,
                average_failed_transaction_ratio_bps: failed_transaction_ratio_bps,
                observations: 1,
            }),
        }

        let (next_active, switch_suppressed_by_hysteresis) = self
            .fork_choice_engine
            .select_active_candidate_with_hysteresis(
                &mut self.reorg_candidates,
                self.max_candidates,
                previous_active,
                self.candidate_switch_min_score_delta,
            );
        self.active_candidate_fragment_id = next_active;
        (
            self.active_candidate_fragment_id != previous_active,
            switch_suppressed_by_hysteresis,
        )
    }

    fn prune_stale_candidates(&mut self, latest_fragment_id: u64) -> usize {
        let before_count = self.reorg_candidates.len();
        self.reorg_candidates.retain(|candidate| {
            latest_fragment_id.saturating_sub(candidate.fragment_id)
                <= self.candidate_stale_fragment_lag
        });
        let pruned_count = before_count.saturating_sub(self.reorg_candidates.len());
        if self.reorg_candidates.is_empty() {
            self.active_candidate_fragment_id = None;
            return pruned_count;
        }
        if self
            .active_candidate_fragment_id
            .map(|active_fragment_id| {
                self.reorg_candidates
                    .iter()
                    .any(|candidate| candidate.fragment_id == active_fragment_id)
            })
            .unwrap_or(false)
        {
            return pruned_count;
        }
        self.active_candidate_fragment_id = self
            .fork_choice_engine
            .select_active_candidate(&mut self.reorg_candidates, self.max_candidates);
        pruned_count
    }

    #[cfg(test)]
    pub(crate) fn has_pending_candidate(&self) -> bool {
        !self.reorg_candidates.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn canonical_fragment_id(&self) -> u64 {
        self.canonical_fragment_id
    }

    pub(crate) fn active_candidate_is_confirmed(&self) -> bool {
        match self.active_candidate_fragment_id {
            Some(active_fragment_id) => match self
                .reorg_candidates
                .iter()
                .find(|candidate| candidate.fragment_id == active_fragment_id)
            {
                Some(candidate) => {
                    candidate.consecutive_reorg_signals >= self.candidate_confirmation_threshold
                        && candidate.average_failed_transaction_ratio_bps
                            <= self.candidate_confirmation_max_failed_ratio_bps
                }
                None => false,
            },
            None => false,
        }
    }

    fn active_candidate_failed_ratio_bps(&self) -> u32 {
        self.active_candidate_fragment_id
            .and_then(|active_fragment_id| {
                self.reorg_candidates
                    .iter()
                    .find(|candidate| candidate.fragment_id == active_fragment_id)
            })
            .map(|candidate| candidate.average_failed_transaction_ratio_bps)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn active_candidate_fragment_id(&self) -> Option<u64> {
        self.active_candidate_fragment_id
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayController, ReplayPublicationDecision};
    use paradencer_execution::ForkChoiceDirective;

    #[test]
    fn replay_controller_tracks_pending_candidate_on_reorg_signal() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 50, 128, 25_000);
        let observation =
            controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        assert_eq!(
            observation.publication_decision,
            ReplayPublicationDecision::HoldForReorgCandidate
        );
        assert!(controller.has_pending_candidate());
        assert!(!controller.active_candidate_is_confirmed());
        assert_eq!(controller.active_candidate_fragment_id(), Some(11));
        assert_eq!(observation.active_candidate_failed_ratio_bps, 1_000);
        assert_eq!(observation.tracked_candidate_count, 1);
        assert_eq!(controller.canonical_fragment_id(), 10);
    }

    #[test]
    fn replay_controller_confirms_candidate_after_threshold() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 50, 128, 25_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        assert!(controller.active_candidate_is_confirmed());
    }

    #[test]
    fn replay_controller_selects_best_candidate_across_competing_branches() {
        let mut controller = ReplayController::new(10, 3, 9_000, 8, 1_000_000, 1, 50, 128, 25_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        controller.observe_fork_choice(12, ForkChoiceDirective::ConsiderReorg, 900);
        controller.observe_fork_choice(12, ForkChoiceDirective::ConsiderReorg, 900);
        assert_eq!(controller.active_candidate_fragment_id(), Some(12));
        assert!(!controller.active_candidate_is_confirmed());
        controller.observe_fork_choice(12, ForkChoiceDirective::ConsiderReorg, 900);
        assert!(controller.active_candidate_is_confirmed());
    }

    #[test]
    fn replay_controller_clears_candidate_when_canonical_progresses() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 50, 128, 25_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        let observation =
            controller.observe_fork_choice(12, ForkChoiceDirective::KeepCurrentFork, 0);
        assert_eq!(
            observation.publication_decision,
            ReplayPublicationDecision::PublishOnCanonical
        );
        assert!(!controller.has_pending_candidate());
        assert_eq!(controller.canonical_fragment_id(), 12);
    }

    #[test]
    fn replay_controller_penalizes_high_failed_ratio_candidates() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 200, 128, 25_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 8_000);
        controller.observe_fork_choice(12, ForkChoiceDirective::ConsiderReorg, 1_500);
        assert_eq!(controller.active_candidate_fragment_id(), Some(12));
    }

    #[test]
    fn replay_controller_prunes_stale_candidates_by_fragment_lag() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 50, 2, 1);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        controller.observe_fork_choice(12, ForkChoiceDirective::ConsiderReorg, 1_000);
        assert_eq!(controller.active_candidate_fragment_id(), Some(12));

        let observation =
            controller.observe_fork_choice(14, ForkChoiceDirective::ConsiderReorg, 900);
        assert_eq!(observation.tracked_candidate_count, 2);
        assert_eq!(observation.stale_candidates_pruned, 1);
        assert_eq!(controller.active_candidate_fragment_id(), Some(14));
    }

    #[test]
    fn replay_controller_suppresses_small_score_delta_switches() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 10, 1, 1, 128, 50);
        let first = controller.observe_fork_choice(100, ForkChoiceDirective::ConsiderReorg, 100);
        assert!(!first.switch_suppressed_by_hysteresis);
        let second = controller.observe_fork_choice(101, ForkChoiceDirective::ConsiderReorg, 99);
        assert!(second.switch_suppressed_by_hysteresis);
        assert_eq!(controller.active_candidate_fragment_id(), Some(100));
    }

    #[test]
    fn replay_controller_does_not_confirm_candidate_above_failed_ratio_threshold() {
        let mut controller = ReplayController::new(10, 2, 1_500, 8, 1_000_000, 1, 50, 128, 1);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 2_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 2_000);
        assert!(!controller.active_candidate_is_confirmed());
    }

    #[test]
    fn replay_controller_resets_candidates_on_rewind() {
        let mut controller = ReplayController::new(10, 2, 9_000, 8, 1_000_000, 1, 50, 128, 1);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        controller.observe_fork_choice(11, ForkChoiceDirective::ConsiderReorg, 1_000);
        assert!(controller.has_pending_candidate());
        assert_eq!(controller.active_candidate_fragment_id(), Some(11));

        controller.on_rewind_to_fragment(9);
        assert_eq!(controller.canonical_fragment_id(), 9);
        assert!(!controller.has_pending_candidate());
        assert_eq!(controller.active_candidate_fragment_id(), None);
    }
}
