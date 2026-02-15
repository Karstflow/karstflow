use super::ExecutionEngine;
use crate::errors::ExecutionError;
use crate::numeric::{u128_to_u64_saturating, usize_to_u128_saturating, usize_to_u64_saturating};
use crate::types::{ExecutionBatch, ExecutionFailureClass, ExecutionOutcome};

pub struct HeuristicExecutionEngine;

impl HeuristicExecutionEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HeuristicExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionEngine for HeuristicExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let transaction_count_u64 =
            u64::try_from(batch.transaction_count).map_err(|_| ExecutionError::CostOverflow {
                fragment_id: batch.fragment_id,
                transaction_count: batch.transaction_count,
            })?;
        let fallback_cost_units =
            transaction_count_u64
                .checked_mul(4_000)
                .ok_or(ExecutionError::CostOverflow {
                    fragment_id: batch.fragment_id,
                    transaction_count: batch.transaction_count,
                })?;
        let total_cost_units = batch.estimated_total_cost_units.max(fallback_cost_units);
        let (failed_transactions, failure_class) = classify_failures(batch);
        let executed_transactions = batch.transaction_count.saturating_sub(failed_transactions);

        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions,
            failed_transactions,
            total_cost_units,
            failure_class,
        })
    }
}

fn classify_failures(batch: &ExecutionBatch) -> (usize, Option<ExecutionFailureClass>) {
    let average_cost_units = if batch.transaction_count == 0 {
        0
    } else {
        average_cost_units(batch.estimated_total_cost_units, batch.transaction_count)
    };

    if batch.transaction_count >= 192
        || (batch.transaction_count >= 96 && average_cost_units >= 12_000)
    {
        let failed = (batch.transaction_count / 4).max(1);
        return (failed, Some(ExecutionFailureClass::ResourceExhaustion));
    }
    if batch.fragment_id.is_multiple_of(17)
        || (batch.transaction_count >= 32
            && batch
                .fragment_id
                .wrapping_add(usize_to_u64_saturating(batch.transaction_count))
                .wrapping_add(average_cost_units)
                .is_multiple_of(97))
    {
        let failed = (batch.transaction_count / 8).max(1);
        return (failed, Some(ExecutionFailureClass::ReplayConflict));
    }
    if batch.fragment_id.is_multiple_of(11)
        || (batch.transaction_count >= 128 && average_cost_units >= 7_000)
    {
        let failed = (batch.transaction_count / 16).max(1);
        return (
            failed,
            Some(ExecutionFailureClass::TransientSchedulerPressure),
        );
    }
    if batch.fragment_id.is_multiple_of(29)
        || (batch.transaction_count >= 16
            && average_cost_units <= 1_500
            && batch.fragment_id.is_multiple_of(7))
    {
        let failed = (batch.transaction_count / 32).max(1);
        return (
            failed,
            Some(ExecutionFailureClass::DeterministicTransactionFailure),
        );
    }
    (0, None)
}

fn average_cost_units(total_cost_units: u64, transaction_count: usize) -> u64 {
    if transaction_count == 0 {
        return 0;
    }
    let denominator = usize_to_u128_saturating(transaction_count);
    let value = u128::from(total_cost_units) / denominator;
    u128_to_u64_saturating(value)
}
