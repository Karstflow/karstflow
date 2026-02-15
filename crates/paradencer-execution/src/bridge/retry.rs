use crate::numeric::usize_to_u64_saturating;
use crate::types::{ExecutionFailureClass, ExecutionOutcome, RetryDirective, RetryPolicy};

pub(super) fn derive_retry_directive(
    retry_policy: &RetryPolicy,
    outcome: &ExecutionOutcome,
) -> RetryDirective {
    let failed_transactions_u64 = usize_to_u64_saturating(outcome.failed_transactions);
    match outcome.failure_class {
        Some(ExecutionFailureClass::ReplayConflict) => RetryDirective::RetryWithBackoff {
            retry_delay_millis: retry_policy.replay_conflict_delay_millis,
        },
        Some(ExecutionFailureClass::DeterministicTransactionFailure) => {
            RetryDirective::DropCurrentFragment
        }
        Some(ExecutionFailureClass::TransientSchedulerPressure) => {
            if outcome.failed_transactions == 0 {
                return RetryDirective::NoRetry;
            }
            let delay = retry_policy.transient_base_delay_millis.saturating_add(
                failed_transactions_u64
                    .saturating_mul(retry_policy.transient_per_failed_tx_delay_millis),
            );
            RetryDirective::RetryWithBackoff {
                retry_delay_millis: delay.min(retry_policy.transient_cap_millis),
            }
        }
        Some(ExecutionFailureClass::ResourceExhaustion) => {
            if outcome.failed_transactions == 0 {
                return RetryDirective::NoRetry;
            }
            let delay = retry_policy.resource_base_delay_millis.saturating_add(
                failed_transactions_u64
                    .saturating_mul(retry_policy.resource_per_failed_tx_delay_millis),
            );
            RetryDirective::RetryWithBackoff {
                retry_delay_millis: delay.min(retry_policy.resource_cap_millis),
            }
        }
        None => {
            if outcome.failed_transactions == 0 {
                return RetryDirective::NoRetry;
            }
            let delay = failed_transactions_u64
                .saturating_mul(retry_policy.fallback_per_failed_tx_delay_millis)
                .max(retry_policy.fallback_min_delay_millis);
            RetryDirective::RetryWithBackoff {
                retry_delay_millis: delay,
            }
        }
    }
}
