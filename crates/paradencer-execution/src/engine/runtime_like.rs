use super::{
    AccountAccessPattern, ExecutionEngine, ProgramCacheHint, RuntimeBatchContext,
    RuntimeExecutionAdapter, RuntimeExecutionEffects, RuntimeExecutionObservation,
    RuntimePreflightOutcome, RuntimeStateWriteIntent,
};
use crate::errors::ExecutionError;
use crate::numeric::{u128_to_u64_saturating, u128_to_usize_saturating, usize_to_u128_saturating};
use crate::types::{ExecutionBatch, ExecutionFailureClass, ExecutionOutcome};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFailureSignal {
    pub failed_transactions: usize,
    pub failure_class: Option<ExecutionFailureClass>,
}

pub struct SyntheticRuntimeAdapter;

impl SyntheticRuntimeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyntheticRuntimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeExecutionAdapter for SyntheticRuntimeAdapter {
    fn preflight_batch(
        &self,
        batch: &ExecutionBatch,
        context: &RuntimeBatchContext,
    ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
        let transaction_count_u64 =
            u64::try_from(batch.transaction_count).map_err(|_| ExecutionError::CostOverflow {
                fragment_id: batch.fragment_id,
                transaction_count: batch.transaction_count,
            })?;
        let fallback_cost_units =
            transaction_count_u64
                .checked_mul(5_000)
                .ok_or(ExecutionError::CostOverflow {
                    fragment_id: batch.fragment_id,
                    transaction_count: batch.transaction_count,
                })?;
        let total_cost_units = batch.estimated_total_cost_units.max(fallback_cost_units);
        let account_access_pattern = if context.estimated_accounts_touched > batch.transaction_count
        {
            AccountAccessPattern::ReadWriteMixed
        } else {
            AccountAccessPattern::ReadMostly
        };
        let requires_program_cache_refresh = batch.transaction_count > 0
            && matches!(context.program_cache_hint, ProgramCacheHint::ColdPath);

        Ok(RuntimePreflightOutcome {
            total_cost_units,
            state_write_intent: if batch.transaction_count == 0 {
                RuntimeStateWriteIntent::None
            } else {
                RuntimeStateWriteIntent::CommitCandidate {
                    fragment_id: batch.fragment_id,
                }
            },
            account_access_pattern,
            requires_program_cache_refresh,
        })
    }

    fn execute_batch(
        &self,
        batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
        preflight: &RuntimePreflightOutcome,
    ) -> RuntimeExecutionObservation {
        let (failed_transactions, failure_class) =
            classify_failures(batch, preflight.total_cost_units);
        let write_lock_contention_ratio_bps = if batch.transaction_count == 0 {
            0
        } else if failed_transactions > 0 {
            2_500
        } else {
            400
        };
        RuntimeExecutionObservation {
            failed_transactions,
            failure_class,
            consumed_compute_units: preflight.total_cost_units,
            write_lock_contention_ratio_bps,
        }
    }
}

pub struct RuntimeLikeExecutionEngine {
    adapter: Arc<dyn RuntimeExecutionAdapter>,
}

impl RuntimeLikeExecutionEngine {
    pub fn new() -> Self {
        Self {
            adapter: Arc::new(SyntheticRuntimeAdapter::new()),
        }
    }

    pub fn with_adapter(adapter: Arc<dyn RuntimeExecutionAdapter>) -> Self {
        Self { adapter }
    }
}

impl Default for RuntimeLikeExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionEngine for RuntimeLikeExecutionEngine {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError> {
        let context = build_runtime_batch_context(batch)?;
        let preflight = self.adapter.preflight_batch(batch, &context)?;
        validate_preflight_contract(batch, &context, &preflight)?;
        validate_state_write_intent(batch, &preflight)?;
        let observation = self.adapter.execute_batch(batch, &context, &preflight);
        validate_execution_observation(batch, &preflight, &observation)?;
        let mut normalized_failure_class = observation.failure_class;

        if !matches!(preflight.state_write_intent, RuntimeStateWriteIntent::None) {
            let effects = self
                .adapter
                .summarize_effects(batch, &context, &preflight, &observation);
            validate_effects_summary(batch, &preflight, &effects)?;
            let plan = self
                .adapter
                .prepare_effects(batch, &context, &preflight, &effects)?;
            validate_effects_plan(batch, &preflight, &effects, &plan)?;
            let apply_report = match self
                .adapter
                .apply_effects(batch, &context, &preflight, &plan)
            {
                Ok(report) => report,
                Err(error) => {
                    if plan.requires_rollback_on_error {
                        if let Err(rollback_error) = self
                            .adapter
                            .rollback_effects(batch, &context, &preflight, &plan)
                        {
                            return Err(wrap_adapter_rollback_error_with_cause(
                                batch.fragment_id,
                                &error,
                                rollback_error,
                            ));
                        }
                    }
                    return Err(wrap_adapter_apply_error(batch.fragment_id, error));
                }
            };
            if let Err(error) = validate_apply_report(batch, &plan, &apply_report) {
                if plan.requires_rollback_on_error {
                    if let Err(rollback_error) = self
                        .adapter
                        .rollback_effects(batch, &context, &preflight, &plan)
                    {
                        return Err(wrap_adapter_rollback_error_with_cause(
                            batch.fragment_id,
                            &error,
                            rollback_error,
                        ));
                    }
                }
                return Err(error);
            }
            normalized_failure_class = normalize_failure_class(observation.failure_class, &effects);
        }

        let signal = normalize_runtime_failure_signal(
            RuntimeFailureSignal {
                failed_transactions: observation.failed_transactions,
                failure_class: normalized_failure_class,
            },
            batch.transaction_count,
        );
        let executed_transactions = batch
            .transaction_count
            .saturating_sub(signal.failed_transactions);

        Ok(ExecutionOutcome {
            fragment_id: batch.fragment_id,
            executed_transactions,
            failed_transactions: signal.failed_transactions,
            total_cost_units: preflight.total_cost_units,
            failure_class: signal.failure_class,
        })
    }
}

fn wrap_adapter_apply_error(fragment_id: u64, error: ExecutionError) -> ExecutionError {
    match error {
        ExecutionError::AdapterApplyFailure { .. }
        | ExecutionError::AdapterStateConflict { .. }
        | ExecutionError::AdapterContractViolation { .. }
        | ExecutionError::AdapterReceiptMissing { .. }
        | ExecutionError::AdapterMutexPoisoned { .. } => error,
        other => ExecutionError::AdapterApplyFailure {
            fragment_id,
            message: other.to_string(),
        },
    }
}

fn wrap_adapter_rollback_error(fragment_id: u64, error: ExecutionError) -> ExecutionError {
    match error {
        ExecutionError::AdapterRollbackFailure { .. }
        | ExecutionError::AdapterContractViolation { .. }
        | ExecutionError::AdapterReceiptMissing { .. }
        | ExecutionError::AdapterMutexPoisoned { .. } => error,
        other => ExecutionError::AdapterRollbackFailure {
            fragment_id,
            message: other.to_string(),
        },
    }
}

fn wrap_adapter_rollback_error_with_cause(
    fragment_id: u64,
    cause: &ExecutionError,
    rollback_error: ExecutionError,
) -> ExecutionError {
    let cause_suffix = format!("; prior error: {cause}");
    match rollback_error {
        ExecutionError::AdapterRollbackFailure {
            fragment_id,
            mut message,
        } => {
            message.push_str(&cause_suffix);
            ExecutionError::AdapterRollbackFailure {
                fragment_id,
                message,
            }
        }
        ExecutionError::AdapterContractViolation {
            fragment_id,
            mut detail,
        } => {
            detail.push_str(&cause_suffix);
            ExecutionError::AdapterContractViolation {
                fragment_id,
                detail,
            }
        }
        ExecutionError::AdapterMutexPoisoned {
            fragment_id,
            lock_name,
            mut detail,
        } => {
            detail.push_str(&cause_suffix);
            ExecutionError::AdapterMutexPoisoned {
                fragment_id,
                lock_name,
                detail,
            }
        }
        other => wrap_adapter_rollback_error(fragment_id, other),
    }
}

fn normalize_failure_class(
    failure_class: Option<ExecutionFailureClass>,
    effects: &RuntimeExecutionEffects,
) -> Option<ExecutionFailureClass> {
    match failure_class {
        Some(ExecutionFailureClass::TransientSchedulerPressure)
            if effects.account_state_delta.written_accounts > 512 =>
        {
            Some(ExecutionFailureClass::ResourceExhaustion)
        }
        other => other,
    }
}

fn normalize_runtime_failure_signal(
    signal: RuntimeFailureSignal,
    transaction_count: usize,
) -> RuntimeFailureSignal {
    RuntimeFailureSignal {
        failed_transactions: signal.failed_transactions.min(transaction_count),
        failure_class: signal.failure_class,
    }
}

fn validate_state_write_intent(
    batch: &ExecutionBatch,
    preflight: &RuntimePreflightOutcome,
) -> std::result::Result<(), ExecutionError> {
    match (batch.transaction_count, preflight.state_write_intent) {
        (0, RuntimeStateWriteIntent::None) => Ok(()),
        (0, RuntimeStateWriteIntent::CommitCandidate { fragment_id }) => {
            Err(ExecutionError::AdapterContractViolation {
                fragment_id: batch.fragment_id,
                detail: format!(
                    "empty batch must not request commit-candidate intent (got fragment_id={fragment_id})"
                ),
            })
        }
        (_, RuntimeStateWriteIntent::None) => Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "non-empty batch returned no-write intent".to_string(),
        }),
        (_, RuntimeStateWriteIntent::CommitCandidate { fragment_id })
            if fragment_id != batch.fragment_id =>
        {
            Err(ExecutionError::AdapterContractViolation {
                fragment_id: batch.fragment_id,
                detail: format!(
                    "commit-candidate fragment mismatch: expected {}, got {fragment_id}",
                    batch.fragment_id
                ),
            })
        }
        _ => Ok(()),
    }
}

fn validate_preflight_contract(
    batch: &ExecutionBatch,
    context: &RuntimeBatchContext,
    preflight: &RuntimePreflightOutcome,
) -> std::result::Result<(), ExecutionError> {
    if batch.transaction_count > 0 && preflight.total_cost_units == 0 {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "non-empty batch preflight must report non-zero cost budget".to_string(),
        });
    }
    if batch.transaction_count == 0 && preflight.total_cost_units != 0 {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "empty batch preflight must report zero cost budget (got {})",
                preflight.total_cost_units
            ),
        });
    }
    if batch.transaction_count == 0
        && !matches!(
            preflight.account_access_pattern,
            AccountAccessPattern::ReadMostly
        )
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "empty batch preflight must report ReadMostly access pattern".to_string(),
        });
    }
    if batch.transaction_count == 0 && preflight.requires_program_cache_refresh {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "empty batch preflight must not request program-cache refresh".to_string(),
        });
    }
    if context.estimated_accounts_touched > batch.transaction_count
        && matches!(
            preflight.account_access_pattern,
            AccountAccessPattern::ReadMostly
        )
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "preflight account-access pattern mismatch: context estimated_accounts_touched={} exceeds transaction_count={} but adapter reported ReadMostly",
                context.estimated_accounts_touched, batch.transaction_count
            ),
        });
    }
    if batch.transaction_count > 0
        && matches!(context.program_cache_hint, ProgramCacheHint::ColdPath)
        && !preflight.requires_program_cache_refresh
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail:
                "preflight program-cache refresh mismatch: ColdPath context requires refresh intent"
                    .to_string(),
        });
    }
    Ok(())
}

fn validate_execution_observation(
    batch: &ExecutionBatch,
    preflight: &RuntimePreflightOutcome,
    observation: &RuntimeExecutionObservation,
) -> std::result::Result<(), ExecutionError> {
    if batch.transaction_count == 0 {
        if observation.write_lock_contention_ratio_bps != 0 {
            return Err(ExecutionError::AdapterContractViolation {
                fragment_id: batch.fragment_id,
                detail: format!(
                    "empty batch observation must report zero contention ratio (got {})",
                    observation.write_lock_contention_ratio_bps
                ),
            });
        }
        if observation.failure_class.is_some() {
            return Err(ExecutionError::AdapterContractViolation {
                fragment_id: batch.fragment_id,
                detail: "empty batch observation must not report failure class".to_string(),
            });
        }
    }
    if observation.failed_transactions > batch.transaction_count {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "observed failed transaction count exceeds batch size: failed={}, batch_size={}",
                observation.failed_transactions, batch.transaction_count
            ),
        });
    }
    if observation.consumed_compute_units > preflight.total_cost_units {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "observed consumed compute exceeds preflight budget: consumed={}, budget={}",
                observation.consumed_compute_units, preflight.total_cost_units
            ),
        });
    }
    if observation.write_lock_contention_ratio_bps > 10_000 {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "write-lock contention ratio out of range (bps={} > 10000)",
                observation.write_lock_contention_ratio_bps
            ),
        });
    }
    if observation.failed_transactions > 0 && observation.failure_class.is_none() {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "failed transactions reported without failure class attribution".to_string(),
        });
    }
    if observation.failed_transactions == 0
        && matches!(
            observation.failure_class,
            Some(ExecutionFailureClass::DeterministicTransactionFailure)
                | Some(ExecutionFailureClass::TransientSchedulerPressure)
                | Some(ExecutionFailureClass::ResourceExhaustion)
        )
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "transactional failure class reported with zero failed transactions"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_apply_report(
    batch: &ExecutionBatch,
    plan: &super::RuntimeEffectsPlan,
    report: &super::RuntimeApplyReport,
) -> std::result::Result<(), ExecutionError> {
    let expected_account_writes = report.channels.account_state.applied_writes;
    let expected_program_cache_ops = report
        .channels
        .program_cache
        .applied_loads
        .checked_add(report.channels.program_cache.applied_evictions)
        .and_then(|sum| sum.checked_add(report.channels.program_cache.applied_invalidations))
        .ok_or_else(|| ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "apply-report program-cache aggregate overflow".to_string(),
        })?;
    if report.applied_account_writes != expected_account_writes {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "apply-report account-write aggregate mismatch: aggregate={}, channels={expected_account_writes}",
                report.applied_account_writes
            ),
        });
    }
    if report.applied_program_cache_ops != expected_program_cache_ops {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "apply-report program-cache aggregate mismatch: aggregate={}, channels={expected_program_cache_ops}",
                report.applied_program_cache_ops
            ),
        });
    }

    let account_target = &plan.channels.account_state;
    let program_target = &plan.channels.program_cache;
    let account_applied = &report.channels.account_state;
    let program_applied = &report.channels.program_cache;

    if account_applied.applied_writes > account_target.target_writes
        || account_applied.applied_data_bytes > account_target.target_data_bytes
        || account_applied.applied_rent_epoch_updates > account_target.target_rent_epoch_updates
        || program_applied.applied_loads > program_target.target_loads
        || program_applied.applied_evictions > program_target.target_evictions
        || program_applied.applied_invalidations > program_target.target_invalidations
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "apply-report exceeds prepared channel targets".to_string(),
        });
    }

    if matches!(
        plan.channels.apply_policies.account_state,
        super::AccountStateApplyPolicy::Strict
    ) && (account_applied.applied_writes != account_target.target_writes
        || account_applied.applied_data_bytes != account_target.target_data_bytes
        || account_applied.applied_rent_epoch_updates != account_target.target_rent_epoch_updates)
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "strict account-state apply policy requires exact target application"
                .to_string(),
        });
    }

    if matches!(
        plan.channels.apply_policies.program_cache,
        super::ProgramCacheApplyPolicy::Strict
    ) && (program_applied.applied_loads != program_target.target_loads
        || program_applied.applied_evictions != program_target.target_evictions
        || program_applied.applied_invalidations != program_target.target_invalidations)
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "strict program-cache apply policy requires exact target application"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_effects_plan(
    batch: &ExecutionBatch,
    preflight: &RuntimePreflightOutcome,
    effects: &RuntimeExecutionEffects,
    plan: &super::RuntimeEffectsPlan,
) -> std::result::Result<(), ExecutionError> {
    if plan.effects != *effects {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "effects plan embedded summary diverges from adapter effects summary"
                .to_string(),
        });
    }

    let account_effects = &effects.account_state_delta;
    let program_effects = &effects.program_cache_delta;
    let account_plan = &plan.channels.account_state;
    let program_plan = &plan.channels.program_cache;

    if account_plan.target_writes > account_effects.written_accounts
        || account_plan.target_data_bytes > account_effects.total_data_bytes_written
        || account_plan.target_rent_epoch_updates > account_effects.rent_epoch_updates
        || program_plan.target_loads > program_effects.loaded_programs
        || program_plan.target_evictions > program_effects.evicted_programs
        || program_plan.target_invalidations > program_effects.invalidated_programs
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "effects plan targets exceed summarized effects".to_string(),
        });
    }

    if matches!(
        plan.channels.apply_policies.account_state,
        super::AccountStateApplyPolicy::Strict
    ) && (account_plan.target_writes != account_effects.written_accounts
        || account_plan.target_data_bytes != account_effects.total_data_bytes_written
        || account_plan.target_rent_epoch_updates != account_effects.rent_epoch_updates)
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "strict account-state policy requires full effects-plan coverage".to_string(),
        });
    }

    if matches!(
        plan.channels.apply_policies.program_cache,
        super::ProgramCacheApplyPolicy::Strict
    ) && (program_plan.target_loads != program_effects.loaded_programs
        || program_plan.target_evictions != program_effects.evicted_programs
        || program_plan.target_invalidations != program_effects.invalidated_programs)
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "strict program-cache policy requires full effects-plan coverage".to_string(),
        });
    }

    if matches!(
        preflight.state_write_intent,
        RuntimeStateWriteIntent::CommitCandidate { .. }
    ) && batch.transaction_count > 0
        && !plan.requires_rollback_on_error
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "commit-candidate effects plan must require rollback on apply/report failures"
                .to_string(),
        });
    }

    Ok(())
}

fn validate_effects_summary(
    batch: &ExecutionBatch,
    preflight: &RuntimePreflightOutcome,
    effects: &RuntimeExecutionEffects,
) -> std::result::Result<(), ExecutionError> {
    let account = &effects.account_state_delta;
    let program_cache = &effects.program_cache_delta;

    if account.written_accounts == 0
        && (account.total_data_bytes_written > 0 || account.rent_epoch_updates > 0)
    {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: "account effects report data/rent updates while written_accounts is zero"
                .to_string(),
        });
    }
    if account.rent_epoch_updates > account.written_accounts {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "account effects rent_epoch_updates exceeds written_accounts: rent_updates={}, written_accounts={}",
                account.rent_epoch_updates, account.written_accounts
            ),
        });
    }
    if !preflight.requires_program_cache_refresh && program_cache.invalidated_programs > 0 {
        return Err(ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "program-cache invalidations reported without refresh intent: invalidated_programs={}",
                program_cache.invalidated_programs
            ),
        });
    }
    Ok(())
}

fn build_runtime_batch_context(
    batch: &ExecutionBatch,
) -> std::result::Result<RuntimeBatchContext, ExecutionError> {
    let expected_program_invocations = batch
        .transaction_count
        .checked_mul(2)
        .ok_or_else(|| ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "runtime batch-context overflow: expected_program_invocations for transaction_count={}",
                batch.transaction_count
            ),
        })?;
    let estimated_accounts_touched = batch
        .transaction_count
        .checked_mul(8)
        .ok_or_else(|| ExecutionError::AdapterContractViolation {
            fragment_id: batch.fragment_id,
            detail: format!(
                "runtime batch-context overflow: estimated_accounts_touched for transaction_count={}",
                batch.transaction_count
            ),
        })?;
    let program_cache_hint = if batch.transaction_count >= 192 {
        ProgramCacheHint::HotPath
    } else if batch.transaction_count >= 64 {
        ProgramCacheHint::WarmPath
    } else {
        ProgramCacheHint::ColdPath
    };
    Ok(RuntimeBatchContext {
        estimated_accounts_touched,
        expected_program_invocations,
        program_cache_hint,
    })
}

fn classify_failures(
    batch: &ExecutionBatch,
    total_cost_units: u64,
) -> (usize, Option<ExecutionFailureClass>) {
    if batch.transaction_count == 0 {
        return (0, None);
    }
    let average_cost_units = average_cost_units(total_cost_units, batch.transaction_count);

    if batch.transaction_count >= 256 || average_cost_units >= 15_000 {
        let failed = scaled_floor_usize(batch.transaction_count, 3, 10).max(1);
        return (failed, Some(ExecutionFailureClass::ResourceExhaustion));
    }

    if batch.fragment_id.is_multiple_of(19)
        || (batch.transaction_count >= 64
            && batch
                .fragment_id
                .wrapping_mul(31)
                .wrapping_add(total_cost_units)
                .is_multiple_of(211))
    {
        let failed = (batch.transaction_count / 6).max(1);
        return (failed, Some(ExecutionFailureClass::ReplayConflict));
    }

    if batch.fragment_id.is_multiple_of(13)
        || (batch.transaction_count >= 96 && average_cost_units >= 8_000)
    {
        let failed = (batch.transaction_count / 12).max(1);
        return (
            failed,
            Some(ExecutionFailureClass::TransientSchedulerPressure),
        );
    }

    if batch.fragment_id.is_multiple_of(37)
        || (batch.transaction_count >= 24
            && average_cost_units <= 1_200
            && batch.fragment_id.is_multiple_of(5))
    {
        let failed = (batch.transaction_count / 24).max(1);
        return (
            failed,
            Some(ExecutionFailureClass::DeterministicTransactionFailure),
        );
    }

    (0, None)
}

fn scaled_floor_usize(value: usize, numerator: u32, denominator: u32) -> usize {
    debug_assert!(denominator != 0);
    let scaled = usize_to_u128_saturating(value).saturating_mul(u128::from(numerator))
        / u128::from(denominator);
    u128_to_usize_saturating(scaled)
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
    use super::{
        AccountAccessPattern, RuntimeBatchContext, RuntimeExecutionAdapter,
        RuntimeExecutionEffects, RuntimeExecutionObservation, RuntimeLikeExecutionEngine,
        RuntimePreflightOutcome, RuntimeStateWriteIntent,
    };
    use crate::engine::ExecutionEngine;
    use crate::engine::{
        AccountStateApplyPolicy, ProgramCacheApplyPolicy, RuntimeEffectsApplyPolicies,
    };
    use crate::errors::ExecutionError;
    use crate::types::{ExecutionBatch, ExecutionFailureClass};
    use std::sync::{Arc, Mutex};

    struct FixedRuntimeAdapter;

    impl RuntimeExecutionAdapter for FixedRuntimeAdapter {
        fn preflight_batch(
            &self,
            batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
        ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
            Ok(RuntimePreflightOutcome {
                total_cost_units: 999_999,
                state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                    fragment_id: batch.fragment_id,
                },
                account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                requires_program_cache_refresh: true,
            })
        }

        fn execute_batch(
            &self,
            batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
        ) -> RuntimeExecutionObservation {
            RuntimeExecutionObservation {
                failed_transactions: (batch.transaction_count / 2).max(1),
                failure_class: Some(ExecutionFailureClass::ReplayConflict),
                consumed_compute_units: 999_999,
                write_lock_contention_ratio_bps: 3_000,
            }
        }

        fn summarize_effects(
            &self,
            _batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
            observation: &RuntimeExecutionObservation,
        ) -> RuntimeExecutionEffects {
            RuntimeExecutionEffects {
                account_state_delta: super::super::AccountStateDeltaSummary {
                    written_accounts: 32,
                    total_data_bytes_written: observation.consumed_compute_units,
                    rent_epoch_updates: 2,
                },
                program_cache_delta: super::super::ProgramCacheDeltaSummary {
                    loaded_programs: 3,
                    evicted_programs: 1,
                    invalidated_programs: 1,
                },
            }
        }
    }

    #[test]
    fn runtime_like_engine_supports_custom_adapter() {
        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(FixedRuntimeAdapter));
        let outcome = engine
            .try_execute_batch(&ExecutionBatch::new(41, 10, 1_000))
            .unwrap();
        assert_eq!(outcome.fragment_id, 41);
        assert_eq!(outcome.executed_transactions, 5);
        assert_eq!(outcome.failed_transactions, 5);
        assert_eq!(outcome.total_cost_units, 999_999);
        assert_eq!(
            outcome.failure_class,
            Some(ExecutionFailureClass::ReplayConflict)
        );
    }

    #[test]
    fn runtime_like_engine_default_adapter_processes_batch() {
        let engine = RuntimeLikeExecutionEngine::new();
        let outcome = engine
            .try_execute_batch(&ExecutionBatch::new(21, 32, 64_000))
            .unwrap();
        assert_eq!(outcome.fragment_id, 21);
        assert_eq!(
            outcome.executed_transactions + outcome.failed_transactions,
            32
        );
    }

    #[test]
    fn runtime_like_engine_empty_batch_uses_no_write_intent() {
        let engine = RuntimeLikeExecutionEngine::new();
        let outcome = engine
            .try_execute_batch(&ExecutionBatch::new(7_001, 0, 0))
            .unwrap();
        assert_eq!(outcome.executed_transactions, 0);
        assert_eq!(outcome.failed_transactions, 0);
        assert_eq!(outcome.failure_class, None);
    }

    #[test]
    fn runtime_like_normalizes_transient_to_resource_when_effects_are_large() {
        struct HeavyEffectsAdapter;

        impl RuntimeExecutionAdapter for HeavyEffectsAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units,
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: batch.transaction_count / 4,
                    failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 3_500,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 1_024,
                        total_data_bytes_written: observation.consumed_compute_units,
                        rent_epoch_updates: 16,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 10,
                        evicted_programs: 2,
                        invalidated_programs: 2,
                    },
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(HeavyEffectsAdapter));
        let outcome = engine
            .try_execute_batch(&ExecutionBatch::new(77, 64, 250_000))
            .unwrap();
        assert_eq!(
            outcome.failure_class,
            Some(ExecutionFailureClass::ResourceExhaustion)
        );
    }

    #[derive(Default)]
    struct LifecycleCounters {
        prepare_calls: u32,
        apply_calls: u32,
        rollback_calls: u32,
    }

    struct FailingApplyAdapter {
        counters: Arc<Mutex<LifecycleCounters>>,
        rollback_fails: bool,
    }

    impl RuntimeExecutionAdapter for FailingApplyAdapter {
        fn preflight_batch(
            &self,
            batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
        ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
            Ok(RuntimePreflightOutcome {
                total_cost_units: batch.estimated_total_cost_units.max(1),
                state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                    fragment_id: batch.fragment_id,
                },
                account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                requires_program_cache_refresh: true,
            })
        }

        fn execute_batch(
            &self,
            _batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            preflight: &RuntimePreflightOutcome,
        ) -> RuntimeExecutionObservation {
            RuntimeExecutionObservation {
                failed_transactions: 1,
                failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
                consumed_compute_units: preflight.total_cost_units,
                write_lock_contention_ratio_bps: 2_000,
            }
        }

        fn summarize_effects(
            &self,
            _batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
            _observation: &RuntimeExecutionObservation,
        ) -> RuntimeExecutionEffects {
            RuntimeExecutionEffects {
                account_state_delta: super::super::AccountStateDeltaSummary {
                    written_accounts: 128,
                    total_data_bytes_written: 8192,
                    rent_epoch_updates: 4,
                },
                program_cache_delta: super::super::ProgramCacheDeltaSummary {
                    loaded_programs: 4,
                    evicted_programs: 1,
                    invalidated_programs: 1,
                },
            }
        }

        fn prepare_effects(
            &self,
            _batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
            effects: &RuntimeExecutionEffects,
        ) -> std::result::Result<super::super::RuntimeEffectsPlan, ExecutionError> {
            self.counters.lock().unwrap().prepare_calls += 1;
            Ok(super::super::RuntimeEffectsPlan {
                effects: *effects,
                channels: super::super::RuntimeEffectsChannelsPlan {
                    account_state: super::super::AccountStateEffectsPlan {
                        target_writes: effects.account_state_delta.written_accounts,
                        target_data_bytes: effects.account_state_delta.total_data_bytes_written,
                        target_rent_epoch_updates: effects.account_state_delta.rent_epoch_updates,
                    },
                    program_cache: super::super::ProgramCacheEffectsPlan {
                        target_loads: effects.program_cache_delta.loaded_programs,
                        target_evictions: effects.program_cache_delta.evicted_programs,
                        target_invalidations: effects.program_cache_delta.invalidated_programs,
                    },
                    apply_policies: super::super::RuntimeEffectsApplyPolicies {
                        account_state: super::super::AccountStateApplyPolicy::Strict,
                        program_cache: super::super::ProgramCacheApplyPolicy::Strict,
                    },
                },
                requires_rollback_on_error: true,
            })
        }

        fn apply_effects(
            &self,
            batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
            _plan: &super::super::RuntimeEffectsPlan,
        ) -> std::result::Result<super::super::RuntimeApplyReport, ExecutionError> {
            self.counters.lock().unwrap().apply_calls += 1;
            Err(ExecutionError::AdapterApplyFailure {
                fragment_id: batch.fragment_id,
                message: "forced apply failure".to_string(),
            })
        }

        fn rollback_effects(
            &self,
            batch: &ExecutionBatch,
            _context: &RuntimeBatchContext,
            _preflight: &RuntimePreflightOutcome,
            _plan: &super::super::RuntimeEffectsPlan,
        ) -> std::result::Result<(), ExecutionError> {
            self.counters.lock().unwrap().rollback_calls += 1;
            if self.rollback_fails {
                Err(ExecutionError::AdapterRollbackFailure {
                    fragment_id: batch.fragment_id,
                    message: "forced rollback failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn runtime_like_apply_failure_triggers_rollback_path() {
        let counters = Arc::new(Mutex::new(LifecycleCounters::default()));
        let adapter = FailingApplyAdapter {
            counters: counters.clone(),
            rollback_fails: false,
        };
        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(adapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(501, 32, 10_000))
            .unwrap_err();
        match error {
            ExecutionError::AdapterApplyFailure { fragment_id, .. } => {
                assert_eq!(fragment_id, 501);
            }
            other => panic!("unexpected error: {other}"),
        }
        let counters = counters.lock().unwrap();
        assert_eq!(counters.prepare_calls, 1);
        assert_eq!(counters.apply_calls, 1);
        assert_eq!(counters.rollback_calls, 1);
    }

    #[test]
    fn runtime_like_rollback_failure_overrides_apply_error() {
        let counters = Arc::new(Mutex::new(LifecycleCounters::default()));
        let adapter = FailingApplyAdapter {
            counters: counters.clone(),
            rollback_fails: true,
        };
        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(adapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(777, 16, 5_000))
            .unwrap_err();
        match error {
            ExecutionError::AdapterRollbackFailure {
                fragment_id,
                message,
            } => {
                assert_eq!(fragment_id, 777);
                assert!(message.contains("forced rollback failure"));
                assert!(message.contains("forced apply failure"));
            }
            other => panic!("unexpected error: {other}"),
        }
        let counters = counters.lock().unwrap();
        assert_eq!(counters.prepare_calls, 1);
        assert_eq!(counters.apply_calls, 1);
        assert_eq!(counters.rollback_calls, 1);
    }

    #[test]
    fn runtime_like_uses_custom_channel_apply_policies() {
        struct PolicyProbeAdapter {
            observed: Arc<Mutex<Option<RuntimeEffectsApplyPolicies>>>,
        }

        impl RuntimeExecutionAdapter for PolicyProbeAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 200,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 100,
                        total_data_bytes_written: 10_000,
                        rent_epoch_updates: 5,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 10,
                        evicted_programs: 4,
                        invalidated_programs: 2,
                    },
                }
            }

            fn select_effects_apply_policies(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _effects: &RuntimeExecutionEffects,
            ) -> RuntimeEffectsApplyPolicies {
                RuntimeEffectsApplyPolicies {
                    account_state: AccountStateApplyPolicy::Lenient,
                    program_cache: ProgramCacheApplyPolicy::Strict,
                }
            }

            fn apply_effects(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<super::super::RuntimeApplyReport, ExecutionError> {
                self.observed
                    .lock()
                    .unwrap()
                    .replace(plan.channels.apply_policies);
                Err(ExecutionError::AdapterApplyFailure {
                    fragment_id: batch.fragment_id,
                    message: "policy probe".to_string(),
                })
            }
        }

        let observed = Arc::new(Mutex::new(None));
        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(PolicyProbeAdapter {
            observed: observed.clone(),
        }));
        let _ = engine.try_execute_batch(&ExecutionBatch::new(910, 8, 1_000));
        let policies = observed.lock().unwrap().expect("policies must be captured");
        assert_eq!(policies.account_state, AccountStateApplyPolicy::Lenient);
        assert_eq!(policies.program_cache, ProgramCacheApplyPolicy::Strict);
    }

    #[test]
    fn runtime_like_rejects_observation_failed_transactions_over_batch_size() {
        struct OverreportingAdapter;

        impl RuntimeExecutionAdapter for OverreportingAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 10_000,
                    failure_class: Some(ExecutionFailureClass::DeterministicTransactionFailure),
                    consumed_compute_units: 1_000,
                    write_lock_contention_ratio_bps: 500,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(OverreportingAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(9_123, 8, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 9_123,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_observation_with_failed_transactions_without_class() {
        struct MissingClassAdapter;

        impl RuntimeExecutionAdapter for MissingClassAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 2,
                    failure_class: None,
                    consumed_compute_units: 1_000,
                    write_lock_contention_ratio_bps: 500,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(MissingClassAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(9_124, 8, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 9_124,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_observation_with_transactional_class_and_zero_failures() {
        struct ZeroFailedTransactionalClassAdapter;

        impl RuntimeExecutionAdapter for ZeroFailedTransactionalClassAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: Some(ExecutionFailureClass::TransientSchedulerPressure),
                    consumed_compute_units: 1_000,
                    write_lock_contention_ratio_bps: 500,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(ZeroFailedTransactionalClassAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(9_125, 8, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 9_125,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_preflight_contract_violation_for_non_empty_batch() {
        struct NoWriteIntentAdapter;

        impl RuntimeExecutionAdapter for NoWriteIntentAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::None,
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: 1_000,
                    write_lock_contention_ratio_bps: 10,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(NoWriteIntentAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(123, 4, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 123,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_preflight_zero_cost_for_non_empty_batch() {
        struct ZeroBudgetAdapter;

        impl RuntimeExecutionAdapter for ZeroBudgetAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: 0,
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: 0,
                    write_lock_contention_ratio_bps: 10,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(ZeroBudgetAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(124, 4, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 124,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_read_mostly_preflight_when_context_is_write_mixed() {
        struct InconsistentAccessPatternAdapter;

        impl RuntimeExecutionAdapter for InconsistentAccessPatternAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadMostly,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(InconsistentAccessPatternAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(126, 4, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 126,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_missing_program_cache_refresh_for_cold_path_context() {
        struct MissingRefreshIntentAdapter;

        impl RuntimeExecutionAdapter for MissingRefreshIntentAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(MissingRefreshIntentAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(127, 4, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 127,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_empty_batch_with_non_read_mostly_access_pattern() {
        struct EmptyBatchAccessPatternAdapter;

        impl RuntimeExecutionAdapter for EmptyBatchAccessPatternAdapter {
            fn preflight_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: 0,
                    state_write_intent: RuntimeStateWriteIntent::None,
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: 0,
                    write_lock_contention_ratio_bps: 0,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(EmptyBatchAccessPatternAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(128, 0, 0))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 128,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_empty_batch_observation_with_failure_class() {
        struct EmptyBatchFailureClassAdapter;

        impl RuntimeExecutionAdapter for EmptyBatchFailureClassAdapter {
            fn preflight_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: 0,
                    state_write_intent: RuntimeStateWriteIntent::None,
                    account_access_pattern: AccountAccessPattern::ReadMostly,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: Some(ExecutionFailureClass::ReplayConflict),
                    consumed_compute_units: 0,
                    write_lock_contention_ratio_bps: 0,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(EmptyBatchFailureClassAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(129, 0, 0))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 129,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_empty_batch_observation_with_nonzero_contention() {
        struct EmptyBatchContentionAdapter;

        impl RuntimeExecutionAdapter for EmptyBatchContentionAdapter {
            fn preflight_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: 0,
                    state_write_intent: RuntimeStateWriteIntent::None,
                    account_access_pattern: AccountAccessPattern::ReadMostly,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: 0,
                    write_lock_contention_ratio_bps: 1,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(EmptyBatchContentionAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(130, 0, 0))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 130,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_empty_batch_preflight_with_refresh_intent() {
        struct EmptyBatchRefreshIntentAdapter;

        impl RuntimeExecutionAdapter for EmptyBatchRefreshIntentAdapter {
            fn preflight_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: 0,
                    state_write_intent: RuntimeStateWriteIntent::None,
                    account_access_pattern: AccountAccessPattern::ReadMostly,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: 0,
                    write_lock_contention_ratio_bps: 0,
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(EmptyBatchRefreshIntentAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(133, 0, 0))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 133,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_batch_context_overflow_for_huge_batch_size() {
        let engine = RuntimeLikeExecutionEngine::new();
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(125, usize::MAX, 1))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 125,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_scaled_floor_helper_handles_large_values_without_overflow() {
        let value = usize::MAX;
        let scaled = super::scaled_floor_usize(value, 3, 10);
        assert!(scaled > 0);
        assert!(scaled <= value);
    }

    #[test]
    fn runtime_like_rejects_apply_report_contract_violation() {
        struct InvalidApplyReportAdapter {
            rollback_calls: Arc<Mutex<u32>>,
        }

        impl RuntimeExecutionAdapter for InvalidApplyReportAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 50,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 4,
                        total_data_bytes_written: 400,
                        rent_epoch_updates: 2,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 2,
                        evicted_programs: 1,
                        invalidated_programs: 1,
                    },
                }
            }

            fn apply_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<super::super::RuntimeApplyReport, ExecutionError> {
                Ok(super::super::RuntimeApplyReport {
                    applied_account_writes: 3,
                    applied_program_cache_ops: 4,
                    channels: super::super::RuntimeEffectsChannelsApplyReport {
                        account_state: super::super::AccountStateApplyReport {
                            applied_writes: 4,
                            applied_data_bytes: 400,
                            applied_rent_epoch_updates: 2,
                        },
                        program_cache: super::super::ProgramCacheApplyReport {
                            applied_loads: 2,
                            applied_evictions: 1,
                            applied_invalidations: 1,
                        },
                    },
                })
            }

            fn rollback_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<(), ExecutionError> {
                let mut calls = self.rollback_calls.lock().expect("rollback counter lock");
                *calls += 1;
                Ok(())
            }
        }

        let rollback_calls = Arc::new(Mutex::new(0_u32));
        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(InvalidApplyReportAdapter {
                rollback_calls: rollback_calls.clone(),
            }));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(211, 6, 3_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 211,
                ..
            }
        ));
        let calls = rollback_calls.lock().expect("rollback counter lock");
        assert_eq!(*calls, 1);
    }

    #[test]
    fn runtime_like_surfaces_apply_report_violation_as_cause_when_rollback_fails() {
        struct InvalidApplyReportRollbackFailsAdapter;

        impl RuntimeExecutionAdapter for InvalidApplyReportRollbackFailsAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 20,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 4,
                        total_data_bytes_written: 400,
                        rent_epoch_updates: 2,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 2,
                        evicted_programs: 1,
                        invalidated_programs: 1,
                    },
                }
            }

            fn apply_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<super::super::RuntimeApplyReport, ExecutionError> {
                Ok(super::super::RuntimeApplyReport {
                    applied_account_writes: 3,
                    applied_program_cache_ops: 4,
                    channels: super::super::RuntimeEffectsChannelsApplyReport {
                        account_state: super::super::AccountStateApplyReport {
                            applied_writes: 4,
                            applied_data_bytes: 400,
                            applied_rent_epoch_updates: 2,
                        },
                        program_cache: super::super::ProgramCacheApplyReport {
                            applied_loads: 2,
                            applied_evictions: 1,
                            applied_invalidations: 1,
                        },
                    },
                })
            }

            fn rollback_effects(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<(), ExecutionError> {
                Err(ExecutionError::AdapterRollbackFailure {
                    fragment_id: batch.fragment_id,
                    message: "forced rollback failure".to_string(),
                })
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(
            InvalidApplyReportRollbackFailsAdapter,
        ));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(222, 6, 3_000))
            .unwrap_err();
        match error {
            ExecutionError::AdapterRollbackFailure {
                fragment_id,
                message,
            } => {
                assert_eq!(fragment_id, 222);
                assert!(message.contains("forced rollback failure"));
                assert!(message.contains("apply-report account-write aggregate mismatch"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn runtime_like_rejects_apply_report_program_cache_aggregate_overflow() {
        struct OverflowingApplyReportAdapter;

        impl RuntimeExecutionAdapter for OverflowingApplyReportAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 1,
                        total_data_bytes_written: 64,
                        rent_epoch_updates: 0,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: usize::MAX,
                        evicted_programs: 1,
                        invalidated_programs: 0,
                    },
                }
            }

            fn apply_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _plan: &super::super::RuntimeEffectsPlan,
            ) -> std::result::Result<super::super::RuntimeApplyReport, ExecutionError> {
                Ok(super::super::RuntimeApplyReport {
                    applied_account_writes: 1,
                    applied_program_cache_ops: 0,
                    channels: super::super::RuntimeEffectsChannelsApplyReport {
                        account_state: super::super::AccountStateApplyReport {
                            applied_writes: 1,
                            applied_data_bytes: 64,
                            applied_rent_epoch_updates: 0,
                        },
                        program_cache: super::super::ProgramCacheApplyReport {
                            applied_loads: usize::MAX,
                            applied_evictions: 1,
                            applied_invalidations: 0,
                        },
                    },
                })
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(OverflowingApplyReportAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(212, 1, 1_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 212,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_execution_observation_budget_violation() {
        struct OverconsumingAdapter;

        impl RuntimeExecutionAdapter for OverconsumingAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units.saturating_add(1),
                    write_lock_contention_ratio_bps: 100,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(OverconsumingAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(303, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 303,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_execution_observation_contention_range_violation() {
        struct InvalidContentionAdapter;

        impl RuntimeExecutionAdapter for InvalidContentionAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10_001,
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(InvalidContentionAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(304, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 304,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_strict_effects_plan_with_partial_account_targets() {
        struct PartialPlanAdapter;

        impl RuntimeExecutionAdapter for PartialPlanAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 20,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 10,
                        total_data_bytes_written: 1_000,
                        rent_epoch_updates: 2,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 2,
                        evicted_programs: 1,
                        invalidated_programs: 1,
                    },
                }
            }

            fn prepare_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                effects: &RuntimeExecutionEffects,
            ) -> std::result::Result<super::super::RuntimeEffectsPlan, ExecutionError> {
                Ok(super::super::RuntimeEffectsPlan {
                    effects: *effects,
                    channels: super::super::RuntimeEffectsChannelsPlan {
                        account_state: super::super::AccountStateEffectsPlan {
                            target_writes: 8,
                            target_data_bytes: effects.account_state_delta.total_data_bytes_written,
                            target_rent_epoch_updates: effects
                                .account_state_delta
                                .rent_epoch_updates,
                        },
                        program_cache: super::super::ProgramCacheEffectsPlan {
                            target_loads: effects.program_cache_delta.loaded_programs,
                            target_evictions: effects.program_cache_delta.evicted_programs,
                            target_invalidations: effects.program_cache_delta.invalidated_programs,
                        },
                        apply_policies: super::super::RuntimeEffectsApplyPolicies {
                            account_state: super::super::AccountStateApplyPolicy::Strict,
                            program_cache: super::super::ProgramCacheApplyPolicy::Strict,
                        },
                    },
                    requires_rollback_on_error: true,
                })
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(PartialPlanAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(307, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 307,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_commit_candidate_plan_without_rollback_requirement() {
        struct NoRollbackPlanAdapter;

        impl RuntimeExecutionAdapter for NoRollbackPlanAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 20,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 4,
                        total_data_bytes_written: 256,
                        rent_epoch_updates: 1,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 1,
                        evicted_programs: 0,
                        invalidated_programs: 1,
                    },
                }
            }

            fn prepare_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                effects: &RuntimeExecutionEffects,
            ) -> std::result::Result<super::super::RuntimeEffectsPlan, ExecutionError> {
                Ok(super::super::RuntimeEffectsPlan {
                    effects: *effects,
                    channels: super::super::RuntimeEffectsChannelsPlan {
                        account_state: super::super::AccountStateEffectsPlan {
                            target_writes: effects.account_state_delta.written_accounts,
                            target_data_bytes: effects.account_state_delta.total_data_bytes_written,
                            target_rent_epoch_updates: effects
                                .account_state_delta
                                .rent_epoch_updates,
                        },
                        program_cache: super::super::ProgramCacheEffectsPlan {
                            target_loads: effects.program_cache_delta.loaded_programs,
                            target_evictions: effects.program_cache_delta.evicted_programs,
                            target_invalidations: effects.program_cache_delta.invalidated_programs,
                        },
                        apply_policies: super::super::RuntimeEffectsApplyPolicies {
                            account_state: super::super::AccountStateApplyPolicy::Strict,
                            program_cache: super::super::ProgramCacheApplyPolicy::Strict,
                        },
                    },
                    requires_rollback_on_error: false,
                })
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(NoRollbackPlanAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(308, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 308,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_effects_plan_with_diverged_embedded_effects_summary() {
        struct DivergedPlanEffectsAdapter;

        impl RuntimeExecutionAdapter for DivergedPlanEffectsAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: true,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 20,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 4,
                        total_data_bytes_written: 400,
                        rent_epoch_updates: 1,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 2,
                        evicted_programs: 1,
                        invalidated_programs: 1,
                    },
                }
            }

            fn prepare_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                effects: &RuntimeExecutionEffects,
            ) -> std::result::Result<super::super::RuntimeEffectsPlan, ExecutionError> {
                let mut diverged = *effects;
                diverged.account_state_delta.written_accounts = diverged
                    .account_state_delta
                    .written_accounts
                    .saturating_add(1);
                Ok(super::super::RuntimeEffectsPlan {
                    effects: diverged,
                    channels: super::super::RuntimeEffectsChannelsPlan {
                        account_state: super::super::AccountStateEffectsPlan {
                            target_writes: effects.account_state_delta.written_accounts,
                            target_data_bytes: effects.account_state_delta.total_data_bytes_written,
                            target_rent_epoch_updates: effects
                                .account_state_delta
                                .rent_epoch_updates,
                        },
                        program_cache: super::super::ProgramCacheEffectsPlan {
                            target_loads: effects.program_cache_delta.loaded_programs,
                            target_evictions: effects.program_cache_delta.evicted_programs,
                            target_invalidations: effects.program_cache_delta.invalidated_programs,
                        },
                        apply_policies: super::super::RuntimeEffectsApplyPolicies {
                            account_state: super::super::AccountStateApplyPolicy::Strict,
                            program_cache: super::super::ProgramCacheApplyPolicy::Strict,
                        },
                    },
                    requires_rollback_on_error: true,
                })
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(DivergedPlanEffectsAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(309, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 309,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_effects_with_rent_updates_over_written_accounts() {
        struct InvalidEffectsAdapter;

        impl RuntimeExecutionAdapter for InvalidEffectsAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 2,
                        total_data_bytes_written: 128,
                        rent_epoch_updates: 3,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 1,
                        evicted_programs: 0,
                        invalidated_programs: 0,
                    },
                }
            }
        }

        let engine = RuntimeLikeExecutionEngine::with_adapter(Arc::new(InvalidEffectsAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(305, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 305,
                ..
            }
        ));
    }

    #[test]
    fn runtime_like_rejects_effects_with_program_cache_invalidation_without_refresh_intent() {
        struct InvalidProgramCacheEffectsAdapter;

        impl RuntimeExecutionAdapter for InvalidProgramCacheEffectsAdapter {
            fn preflight_batch(
                &self,
                batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
            ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError> {
                Ok(RuntimePreflightOutcome {
                    total_cost_units: batch.estimated_total_cost_units.max(1),
                    state_write_intent: RuntimeStateWriteIntent::CommitCandidate {
                        fragment_id: batch.fragment_id,
                    },
                    account_access_pattern: AccountAccessPattern::ReadWriteMixed,
                    requires_program_cache_refresh: false,
                })
            }

            fn execute_batch(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                preflight: &RuntimePreflightOutcome,
            ) -> RuntimeExecutionObservation {
                RuntimeExecutionObservation {
                    failed_transactions: 0,
                    failure_class: None,
                    consumed_compute_units: preflight.total_cost_units,
                    write_lock_contention_ratio_bps: 10,
                }
            }

            fn summarize_effects(
                &self,
                _batch: &ExecutionBatch,
                _context: &RuntimeBatchContext,
                _preflight: &RuntimePreflightOutcome,
                _observation: &RuntimeExecutionObservation,
            ) -> RuntimeExecutionEffects {
                RuntimeExecutionEffects {
                    account_state_delta: super::super::AccountStateDeltaSummary {
                        written_accounts: 2,
                        total_data_bytes_written: 128,
                        rent_epoch_updates: 1,
                    },
                    program_cache_delta: super::super::ProgramCacheDeltaSummary {
                        loaded_programs: 1,
                        evicted_programs: 0,
                        invalidated_programs: 2,
                    },
                }
            }
        }

        let engine =
            RuntimeLikeExecutionEngine::with_adapter(Arc::new(InvalidProgramCacheEffectsAdapter));
        let error = engine
            .try_execute_batch(&ExecutionBatch::new(306, 8, 10_000))
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::AdapterContractViolation {
                fragment_id: 306,
                ..
            }
        ));
    }
}
