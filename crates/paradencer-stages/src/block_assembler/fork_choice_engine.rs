use super::replay_controller::ReplayCandidate;

#[derive(Debug, Clone)]
pub(super) struct ForkChoiceEngine {
    reorg_signal_weight: u64,
    fragment_recency_weight: u64,
    failed_transaction_ratio_penalty_weight: u64,
}

impl ForkChoiceEngine {
    pub(super) fn new() -> Self {
        Self::with_weights(1_000_000, 1, 50)
    }

    pub(super) fn with_weights(
        reorg_signal_weight: u64,
        fragment_recency_weight: u64,
        failed_transaction_ratio_penalty_weight: u64,
    ) -> Self {
        Self {
            reorg_signal_weight: reorg_signal_weight.max(1),
            fragment_recency_weight: fragment_recency_weight.max(1),
            failed_transaction_ratio_penalty_weight,
        }
    }

    pub(super) fn select_active_candidate(
        &self,
        candidates: &mut Vec<ReplayCandidate>,
        max_candidates: usize,
    ) -> Option<u64> {
        self.select_active_candidate_with_hysteresis(candidates, max_candidates, None, 0)
            .0
    }

    pub(super) fn select_active_candidate_with_hysteresis(
        &self,
        candidates: &mut Vec<ReplayCandidate>,
        max_candidates: usize,
        current_active: Option<u64>,
        min_switch_score_delta: u64,
    ) -> (Option<u64>, bool) {
        candidates.sort_by_key(|candidate| std::cmp::Reverse(self.score(candidate)));
        candidates.truncate(max_candidates.max(1));
        let Some(best_candidate) = candidates.first() else {
            return (None, false);
        };
        let best_fragment_id = best_candidate.fragment_id;
        let best_score = self.score(best_candidate);

        let Some(current_active) = current_active else {
            return (Some(best_fragment_id), false);
        };
        if current_active == best_fragment_id {
            return (Some(best_fragment_id), false);
        }

        let Some(current_score) = candidates
            .iter()
            .find(|candidate| candidate.fragment_id == current_active)
            .map(|candidate| self.score(candidate))
        else {
            return (Some(best_fragment_id), false);
        };
        let score_delta = best_score.saturating_sub(current_score);
        if score_delta < min_switch_score_delta {
            return (Some(current_active), true);
        }

        (Some(best_fragment_id), false)
    }

    fn score(&self, candidate: &ReplayCandidate) -> u64 {
        let base_score = (candidate.consecutive_reorg_signals as u64)
            .saturating_mul(self.reorg_signal_weight)
            .saturating_add(
                candidate
                    .fragment_id
                    .saturating_mul(self.fragment_recency_weight),
            );
        let failed_ratio_penalty = (candidate.average_failed_transaction_ratio_bps as u64)
            .saturating_mul(self.failed_transaction_ratio_penalty_weight);
        base_score.saturating_sub(failed_ratio_penalty)
    }
}

impl Default for ForkChoiceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ForkChoiceEngine;
    use crate::block_assembler::replay_controller::ReplayCandidate;

    #[test]
    fn fork_choice_engine_prefers_candidate_with_higher_signal_strength() {
        let engine = ForkChoiceEngine::new();
        let mut candidates = vec![
            ReplayCandidate {
                fragment_id: 100,
                consecutive_reorg_signals: 1,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
            ReplayCandidate {
                fragment_id: 42,
                consecutive_reorg_signals: 3,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
        ];

        let selected = engine.select_active_candidate(&mut candidates, 8);
        assert_eq!(selected, Some(42));
    }

    #[test]
    fn fork_choice_engine_breaks_ties_with_fragment_recency() {
        let engine = ForkChoiceEngine::new();
        let mut candidates = vec![
            ReplayCandidate {
                fragment_id: 17,
                consecutive_reorg_signals: 2,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
            ReplayCandidate {
                fragment_id: 34,
                consecutive_reorg_signals: 2,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
        ];

        let selected = engine.select_active_candidate(&mut candidates, 8);
        assert_eq!(selected, Some(34));
    }

    #[test]
    fn fork_choice_engine_respects_custom_weights() {
        let engine = ForkChoiceEngine::with_weights(1, 10_000, 50);
        let mut candidates = vec![
            ReplayCandidate {
                fragment_id: 25,
                consecutive_reorg_signals: 2,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
            ReplayCandidate {
                fragment_id: 30,
                consecutive_reorg_signals: 1,
                average_failed_transaction_ratio_bps: 500,
                observations: 1,
            },
        ];

        let selected = engine.select_active_candidate(&mut candidates, 8);
        assert_eq!(selected, Some(30));
    }

    #[test]
    fn fork_choice_engine_penalizes_candidates_with_higher_failed_ratio() {
        let engine = ForkChoiceEngine::with_weights(1_000_000, 1, 200);
        let mut candidates = vec![
            ReplayCandidate {
                fragment_id: 60,
                consecutive_reorg_signals: 2,
                average_failed_transaction_ratio_bps: 8_000,
                observations: 2,
            },
            ReplayCandidate {
                fragment_id: 59,
                consecutive_reorg_signals: 2,
                average_failed_transaction_ratio_bps: 2_000,
                observations: 2,
            },
        ];

        let selected = engine.select_active_candidate(&mut candidates, 8);
        assert_eq!(selected, Some(59));
    }

    #[test]
    fn fork_choice_engine_holds_active_candidate_when_switch_delta_is_too_small() {
        let engine = ForkChoiceEngine::with_weights(1_000_000, 1, 1);
        let mut candidates = vec![
            ReplayCandidate {
                fragment_id: 101,
                consecutive_reorg_signals: 4,
                average_failed_transaction_ratio_bps: 100,
                observations: 2,
            },
            ReplayCandidate {
                fragment_id: 102,
                consecutive_reorg_signals: 4,
                average_failed_transaction_ratio_bps: 99,
                observations: 2,
            },
        ];
        let (selected, suppressed) =
            engine.select_active_candidate_with_hysteresis(&mut candidates, 8, Some(101), 10);
        assert_eq!(selected, Some(101));
        assert!(suppressed);
    }
}
