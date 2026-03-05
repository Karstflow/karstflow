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

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(fragment_id: u64, tx_count: usize, cost: u64) -> ExecutionBatch {
        ExecutionBatch {
            fragment_id,
            transaction_count: tx_count,
            estimated_total_cost_units: cost,
            transactions: None,
        }
    }

    #[test]
    fn no_failures_for_small_batch() {
        let engine = HeuristicExecutionEngine::new();
        // fragment_id=1 doesn't trigger any modulo-based rules
        let result = engine.try_execute_batch(&batch(1, 10, 40_000)).unwrap();
        assert_eq!(result.executed_transactions, 10);
        assert_eq!(result.failed_transactions, 0);
        assert!(result.failure_class.is_none());
    }

    #[test]
    fn resource_exhaustion_for_large_batch() {
        let engine = HeuristicExecutionEngine::new();
        // 192+ transactions triggers ResourceExhaustion
        let result = engine.try_execute_batch(&batch(1, 200, 800_000)).unwrap();
        assert!(result.failed_transactions > 0);
        assert_eq!(
            result.failure_class,
            Some(ExecutionFailureClass::ResourceExhaustion)
        );
        // Failed = tx_count / 4 = 50
        assert_eq!(result.failed_transactions, 50);
        assert_eq!(result.executed_transactions, 150);
    }

    #[test]
    fn resource_exhaustion_for_high_cost_medium_batch() {
        let engine = HeuristicExecutionEngine::new();
        // 96+ tx with average >= 12000 triggers ResourceExhaustion
        let result = engine.try_execute_batch(&batch(1, 100, 1_200_000)).unwrap();
        assert_eq!(
            result.failure_class,
            Some(ExecutionFailureClass::ResourceExhaustion)
        );
    }

    #[test]
    fn replay_conflict_on_fragment_id_multiple_of_17() {
        let engine = HeuristicExecutionEngine::new();
        // fragment_id=17 triggers ReplayConflict
        let result = engine.try_execute_batch(&batch(17, 10, 40_000)).unwrap();
        assert!(result.failed_transactions > 0);
        assert_eq!(
            result.failure_class,
            Some(ExecutionFailureClass::ReplayConflict)
        );
        // Failed = tx_count / 8 = max(1, 1)
        assert_eq!(result.failed_transactions, 1);
    }

    #[test]
    fn transient_pressure_on_fragment_id_multiple_of_11() {
        let engine = HeuristicExecutionEngine::new();
        // fragment_id=11 (not multiple of 17), triggers TransientSchedulerPressure
        let result = engine.try_execute_batch(&batch(11, 10, 40_000)).unwrap();
        assert!(result.failed_transactions > 0);
        assert_eq!(
            result.failure_class,
            Some(ExecutionFailureClass::TransientSchedulerPressure)
        );
    }

    #[test]
    fn deterministic_failure_on_fragment_id_multiple_of_29() {
        let engine = HeuristicExecutionEngine::new();
        // fragment_id=29 (not multiple of 17 or 11), triggers DeterministicTransactionFailure
        let result = engine.try_execute_batch(&batch(29, 10, 40_000)).unwrap();
        assert!(result.failed_transactions > 0);
        assert_eq!(
            result.failure_class,
            Some(ExecutionFailureClass::DeterministicTransactionFailure)
        );
    }

    #[test]
    fn fallback_cost_used_when_estimated_is_zero() {
        let engine = HeuristicExecutionEngine::new();
        let result = engine.try_execute_batch(&batch(1, 10, 0)).unwrap();
        // fallback = 10 * 4000 = 40_000
        assert_eq!(result.total_cost_units, 40_000);
    }

    #[test]
    fn estimated_cost_used_when_higher_than_fallback() {
        let engine = HeuristicExecutionEngine::new();
        let result = engine.try_execute_batch(&batch(1, 10, 100_000)).unwrap();
        // estimated 100_000 > fallback 40_000
        assert_eq!(result.total_cost_units, 100_000);
    }

    #[test]
    fn cost_overflow_returns_error() {
        let engine = HeuristicExecutionEngine::new();
        // usize::MAX can't fit in u64 on 128-bit platforms; on 64-bit it
        // overflows the checked_mul(4000). Use a value that overflows.
        let big = (u64::MAX / 4_000 + 1) as usize;
        let result = engine.try_execute_batch(&batch(1, big, 0));
        assert!(result.is_err());
    }

    #[test]
    fn empty_batch_succeeds() {
        let engine = HeuristicExecutionEngine::new();
        let result = engine.try_execute_batch(&batch(1, 0, 0)).unwrap();
        assert_eq!(result.executed_transactions, 0);
        assert_eq!(result.failed_transactions, 0);
        assert!(result.failure_class.is_none());
    }

    #[test]
    fn average_cost_units_divides_correctly() {
        assert_eq!(average_cost_units(100_000, 10), 10_000);
        assert_eq!(average_cost_units(0, 10), 0);
        assert_eq!(average_cost_units(100_000, 0), 0);
        assert_eq!(average_cost_units(7, 2), 3); // integer division
    }

    #[test]
    fn default_impl_creates_engine() {
        let _engine: HeuristicExecutionEngine = Default::default();
    }
}
