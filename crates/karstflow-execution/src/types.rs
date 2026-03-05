#[derive(Debug, Clone)]
pub struct ExecutionBatch {
    pub fragment_id: u64,
    pub transaction_count: usize,
    pub estimated_total_cost_units: u64,
    pub transactions: Option<Vec<karstflow_storage::Transaction>>,
}

impl ExecutionBatch {
    pub fn new(
        fragment_id: u64,
        transaction_count: usize,
        estimated_total_cost_units: u64,
    ) -> Self {
        Self {
            fragment_id,
            transaction_count,
            estimated_total_cost_units,
            transactions: None,
        }
    }

    pub fn with_transactions(
        fragment_id: u64,
        transactions: Vec<karstflow_storage::Transaction>,
        estimated_total_cost_units: u64,
    ) -> Self {
        let transaction_count = transactions.len();
        Self {
            fragment_id,
            transaction_count,
            estimated_total_cost_units,
            transactions: Some(transactions),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionFailureClass {
    TransientSchedulerPressure,
    ReplayConflict,
    DeterministicTransactionFailure,
    ResourceExhaustion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub fragment_id: u64,
    pub executed_transactions: usize,
    pub failed_transactions: usize,
    pub total_cost_units: u64,
    pub failure_class: Option<ExecutionFailureClass>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayBoundaryState {
    pub last_applied_fragment_id: u64,
    pub total_executed_transactions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkChoiceDirective {
    KeepCurrentFork,
    ConsiderReorg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaderGateState {
    pub is_current_leader: bool,
    pub next_leader_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderGateDirective {
    PermitExecution,
    HoldForLeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerDirective {
    pub target_slot: u64,
    pub priority_class: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDirective {
    NoRetry,
    RetryWithBackoff { retry_delay_millis: u64 },
    DropCurrentFragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub replay_conflict_delay_millis: u64,
    pub transient_base_delay_millis: u64,
    pub transient_per_failed_tx_delay_millis: u64,
    pub transient_cap_millis: u64,
    pub resource_base_delay_millis: u64,
    pub resource_per_failed_tx_delay_millis: u64,
    pub resource_cap_millis: u64,
    pub fallback_min_delay_millis: u64,
    pub fallback_per_failed_tx_delay_millis: u64,
    pub max_retries_replay_conflict: u8,
    pub max_retries_transient_pressure: u8,
    pub max_retries_resource_exhaustion: u8,
    pub max_retries_fallback: u8,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            replay_conflict_delay_millis: 25,
            transient_base_delay_millis: 30,
            transient_per_failed_tx_delay_millis: 5,
            transient_cap_millis: 250,
            resource_base_delay_millis: 200,
            resource_per_failed_tx_delay_millis: 20,
            resource_cap_millis: 2_000,
            fallback_min_delay_millis: 50,
            fallback_per_failed_tx_delay_millis: 10,
            max_retries_replay_conflict: 3,
            max_retries_transient_pressure: 2,
            max_retries_resource_exhaustion: 1,
            max_retries_fallback: 2,
        }
    }
}
