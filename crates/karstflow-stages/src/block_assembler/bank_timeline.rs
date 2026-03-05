use crate::ReplayWindowPolicy;
use karstflow_storage::{CommittedFragmentRecord, HotStateStore};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BankCheckpoint {
    pub(super) fragment_id: u64,
    pub(super) committed_fragments: u64,
    pub(super) committed_transactions: u64,
}

#[derive(Debug, Clone)]
pub(super) struct BankTimeline {
    policy: ReplayWindowPolicy,
    checkpoints: VecDeque<BankCheckpoint>,
}

impl BankTimeline {
    pub(super) fn new(policy: ReplayWindowPolicy) -> Self {
        Self {
            policy,
            checkpoints: VecDeque::new(),
        }
    }

    pub(super) fn seed_from_restored_state(&mut self, hot_state_store: &HotStateStore) {
        if hot_state_store.last_fragment_id == 0 {
            return;
        }
        self.checkpoints.push_back(BankCheckpoint {
            fragment_id: hot_state_store.last_fragment_id,
            committed_fragments: hot_state_store.committed_fragments,
            committed_transactions: hot_state_store.committed_transactions,
        });
        self.truncate_to_limit();
    }

    pub(super) fn record_commit(
        &mut self,
        committed_record: &CommittedFragmentRecord,
        hot_state_store: &HotStateStore,
    ) {
        self.checkpoints.push_back(BankCheckpoint {
            fragment_id: committed_record.fragment_id,
            committed_fragments: hot_state_store.committed_fragments,
            committed_transactions: hot_state_store.committed_transactions,
        });
        self.truncate_to_limit();
    }

    pub(super) fn maybe_rewind_on_confirmed_reorg(
        &mut self,
        target_fragment_id: Option<u64>,
    ) -> Option<BankCheckpoint> {
        if !self.policy.rewind_on_confirmed_reorg {
            return None;
        }
        let target_fragment_id = target_fragment_id?;
        let checkpoint = self
            .checkpoints
            .iter()
            .rev()
            .find(|checkpoint| checkpoint.fragment_id <= target_fragment_id)
            .copied()?;
        while self
            .checkpoints
            .back()
            .is_some_and(|tail| tail.fragment_id > checkpoint.fragment_id)
        {
            let _ = self.checkpoints.pop_back();
        }
        Some(checkpoint)
    }

    pub(super) fn len(&self) -> usize {
        self.checkpoints.len()
    }

    fn truncate_to_limit(&mut self) {
        while self.checkpoints.len() > self.policy.max_checkpoints.max(1) {
            let _ = self.checkpoints.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BankTimeline;
    use crate::ReplayWindowPolicy;
    use karstflow_storage::{CommittedFragmentRecord, HotStateStore};

    #[test]
    fn bank_timeline_keeps_only_configured_number_of_checkpoints() {
        let mut timeline = BankTimeline::new(ReplayWindowPolicy {
            max_checkpoints: 2,
            rewind_on_confirmed_reorg: false,
        });
        let mut state = HotStateStore::new();
        for fragment_id in 1..=3_u64 {
            let record = CommittedFragmentRecord {
                fragment_id,
                transaction_count: 2,
                total_cost_units: 20,
            };
            state.apply_committed_fragment(&record).unwrap();
            timeline.record_commit(&record, &state);
        }
        assert_eq!(timeline.len(), 2);
    }

    #[test]
    fn bank_timeline_returns_rewind_checkpoint_when_enabled() {
        let mut timeline = BankTimeline::new(ReplayWindowPolicy {
            max_checkpoints: 4,
            rewind_on_confirmed_reorg: true,
        });
        let mut state = HotStateStore::new();
        for fragment_id in 1..=3_u64 {
            let record = CommittedFragmentRecord {
                fragment_id,
                transaction_count: 2,
                total_cost_units: 20,
            };
            state.apply_committed_fragment(&record).unwrap();
            timeline.record_commit(&record, &state);
        }
        let checkpoint = timeline.maybe_rewind_on_confirmed_reorg(Some(2)).unwrap();
        assert_eq!(checkpoint.fragment_id, 2);
        assert_eq!(checkpoint.committed_transactions, 4);
        assert_eq!(timeline.len(), 2);

        let repeated = timeline.maybe_rewind_on_confirmed_reorg(Some(3)).unwrap();
        assert_eq!(repeated.fragment_id, 2);
        assert_eq!(timeline.len(), 2);
    }
}
