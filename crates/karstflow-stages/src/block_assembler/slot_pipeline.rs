#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotPipelineState {
    Idle,
    CollectingTransactions,
    ExecutingFragment,
    WaitingRetry,
    ReorgPending,
    Committed,
    Dropped,
}

#[derive(Debug, Clone)]
pub(crate) struct SlotPipelineStateMachine {
    pub(crate) current_slot: u64,
    pub(crate) state: SlotPipelineState,
}

impl SlotPipelineStateMachine {
    pub(crate) fn new(initial_slot: u64) -> Self {
        Self {
            current_slot: initial_slot,
            state: SlotPipelineState::Idle,
        }
    }

    pub(crate) fn on_transaction_buffered(&mut self) {
        if matches!(self.state, SlotPipelineState::Idle) {
            self.state = SlotPipelineState::CollectingTransactions;
        }
    }

    pub(crate) fn on_fragment_execution_start(&mut self) {
        self.state = SlotPipelineState::ExecutingFragment;
    }

    pub(crate) fn on_retry_scheduled(&mut self) {
        self.state = SlotPipelineState::WaitingRetry;
    }

    pub(crate) fn on_reorg_detected(&mut self) {
        self.state = SlotPipelineState::ReorgPending;
    }

    pub(crate) fn on_fragment_committed(&mut self) {
        self.state = SlotPipelineState::Committed;
    }

    pub(crate) fn on_fragment_dropped(&mut self) {
        self.state = SlotPipelineState::Dropped;
    }

    pub(crate) fn advance_slot(&mut self) {
        self.current_slot = self.current_slot.saturating_add(1);
        self.state = SlotPipelineState::Idle;
    }

    pub(crate) fn rewind_to_slot(&mut self, slot: u64) {
        self.current_slot = slot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_idle_at_given_slot() {
        let sm = SlotPipelineStateMachine::new(42);
        assert_eq!(sm.current_slot, 42);
        assert_eq!(sm.state, SlotPipelineState::Idle);
    }

    #[test]
    fn transaction_buffered_transitions_from_idle_to_collecting() {
        let mut sm = SlotPipelineStateMachine::new(0);
        sm.on_transaction_buffered();
        assert_eq!(sm.state, SlotPipelineState::CollectingTransactions);
    }

    #[test]
    fn transaction_buffered_is_noop_when_not_idle() {
        let mut sm = SlotPipelineStateMachine::new(0);
        sm.on_fragment_execution_start();
        assert_eq!(sm.state, SlotPipelineState::ExecutingFragment);
        sm.on_transaction_buffered();
        assert_eq!(sm.state, SlotPipelineState::ExecutingFragment);
    }

    #[test]
    fn full_lifecycle_idle_to_committed() {
        let mut sm = SlotPipelineStateMachine::new(10);
        sm.on_transaction_buffered();
        sm.on_fragment_execution_start();
        assert_eq!(sm.state, SlotPipelineState::ExecutingFragment);
        sm.on_fragment_committed();
        assert_eq!(sm.state, SlotPipelineState::Committed);
    }

    #[test]
    fn retry_scheduled_sets_waiting_state() {
        let mut sm = SlotPipelineStateMachine::new(0);
        sm.on_retry_scheduled();
        assert_eq!(sm.state, SlotPipelineState::WaitingRetry);
    }

    #[test]
    fn reorg_detected_sets_reorg_pending() {
        let mut sm = SlotPipelineStateMachine::new(0);
        sm.on_reorg_detected();
        assert_eq!(sm.state, SlotPipelineState::ReorgPending);
    }

    #[test]
    fn dropped_sets_dropped_state() {
        let mut sm = SlotPipelineStateMachine::new(0);
        sm.on_fragment_dropped();
        assert_eq!(sm.state, SlotPipelineState::Dropped);
    }

    #[test]
    fn advance_slot_resets_to_idle_and_increments() {
        let mut sm = SlotPipelineStateMachine::new(5);
        sm.on_fragment_committed();
        sm.advance_slot();
        assert_eq!(sm.current_slot, 6);
        assert_eq!(sm.state, SlotPipelineState::Idle);
    }

    #[test]
    fn advance_slot_saturates_at_max() {
        let mut sm = SlotPipelineStateMachine::new(u64::MAX);
        sm.advance_slot();
        assert_eq!(sm.current_slot, u64::MAX);
        assert_eq!(sm.state, SlotPipelineState::Idle);
    }

    #[test]
    fn rewind_to_slot_changes_slot_but_preserves_state() {
        let mut sm = SlotPipelineStateMachine::new(100);
        sm.on_fragment_execution_start();
        sm.rewind_to_slot(50);
        assert_eq!(sm.current_slot, 50);
        assert_eq!(sm.state, SlotPipelineState::ExecutingFragment);
    }
}
