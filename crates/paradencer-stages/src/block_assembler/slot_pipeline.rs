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
