use crate::errors::ExecutionError;
use crate::numeric::usize_to_u64_saturating;
use crate::types::{ExecutionBatch, ExecutionFailureClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStateWriteIntent {
    None,
    CommitCandidate { fragment_id: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAccessPattern {
    ReadMostly,
    ReadWriteMixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramCacheHint {
    HotPath,
    WarmPath,
    ColdPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeBatchContext {
    pub estimated_accounts_touched: usize,
    pub expected_program_invocations: usize,
    pub program_cache_hint: ProgramCacheHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimePreflightOutcome {
    pub total_cost_units: u64,
    pub state_write_intent: RuntimeStateWriteIntent,
    pub account_access_pattern: AccountAccessPattern,
    pub requires_program_cache_refresh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeExecutionObservation {
    pub failed_transactions: usize,
    pub failure_class: Option<ExecutionFailureClass>,
    pub consumed_compute_units: u64,
    pub write_lock_contention_ratio_bps: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStateDeltaSummary {
    pub written_accounts: usize,
    pub total_data_bytes_written: u64,
    pub rent_epoch_updates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramCacheDeltaSummary {
    pub loaded_programs: usize,
    pub evicted_programs: usize,
    pub invalidated_programs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeExecutionEffects {
    pub account_state_delta: AccountStateDeltaSummary,
    pub program_cache_delta: ProgramCacheDeltaSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStateEffectsPlan {
    pub target_writes: usize,
    pub target_data_bytes: u64,
    pub target_rent_epoch_updates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramCacheEffectsPlan {
    pub target_loads: usize,
    pub target_evictions: usize,
    pub target_invalidations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStateApplyPolicy {
    Strict,
    Lenient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramCacheApplyPolicy {
    Strict,
    Lenient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEffectsApplyPolicies {
    pub account_state: AccountStateApplyPolicy,
    pub program_cache: ProgramCacheApplyPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEffectsChannelsPlan {
    pub account_state: AccountStateEffectsPlan,
    pub program_cache: ProgramCacheEffectsPlan,
    pub apply_policies: RuntimeEffectsApplyPolicies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEffectsPlan {
    pub effects: RuntimeExecutionEffects,
    pub channels: RuntimeEffectsChannelsPlan,
    pub requires_rollback_on_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStateApplyReport {
    pub applied_writes: usize,
    pub applied_data_bytes: u64,
    pub applied_rent_epoch_updates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramCacheApplyReport {
    pub applied_loads: usize,
    pub applied_evictions: usize,
    pub applied_invalidations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEffectsChannelsApplyReport {
    pub account_state: AccountStateApplyReport,
    pub program_cache: ProgramCacheApplyReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeApplyReport {
    pub applied_account_writes: usize,
    pub applied_program_cache_ops: usize,
    pub channels: RuntimeEffectsChannelsApplyReport,
}

pub trait RuntimeExecutionAdapter: Send + Sync {
    fn preflight_batch(
        &self,
        batch: &ExecutionBatch,
        context: &RuntimeBatchContext,
    ) -> std::result::Result<RuntimePreflightOutcome, ExecutionError>;

    fn execute_batch(
        &self,
        batch: &ExecutionBatch,
        context: &RuntimeBatchContext,
        preflight: &RuntimePreflightOutcome,
    ) -> RuntimeExecutionObservation;

    fn summarize_effects(
        &self,
        batch: &ExecutionBatch,
        context: &RuntimeBatchContext,
        preflight: &RuntimePreflightOutcome,
        observation: &RuntimeExecutionObservation,
    ) -> RuntimeExecutionEffects {
        let failed = observation.failed_transactions.min(batch.transaction_count);
        let written_accounts = context
            .estimated_accounts_touched
            .saturating_sub(failed.saturating_mul(2));
        let written_accounts_u64 = usize_to_u64_saturating(written_accounts);
        let total_data_bytes_written = written_accounts_u64
            .saturating_mul(128)
            .saturating_add((observation.consumed_compute_units / 16).min(64 * 1024));
        let rent_epoch_updates = written_accounts / 16;

        let invalidated_programs = if preflight.requires_program_cache_refresh {
            context.expected_program_invocations / 4
        } else {
            0
        };
        let loaded_programs = context.expected_program_invocations / 8;
        let evicted_programs = invalidated_programs / 2;

        RuntimeExecutionEffects {
            account_state_delta: AccountStateDeltaSummary {
                written_accounts,
                total_data_bytes_written,
                rent_epoch_updates,
            },
            program_cache_delta: ProgramCacheDeltaSummary {
                loaded_programs,
                evicted_programs,
                invalidated_programs,
            },
        }
    }

    fn prepare_effects(
        &self,
        batch: &ExecutionBatch,
        context: &RuntimeBatchContext,
        preflight: &RuntimePreflightOutcome,
        effects: &RuntimeExecutionEffects,
    ) -> std::result::Result<RuntimeEffectsPlan, ExecutionError> {
        let requires_rollback_on_error = matches!(
            preflight.state_write_intent,
            RuntimeStateWriteIntent::CommitCandidate { .. }
        ) && batch.transaction_count > 0;
        let apply_policies = self.select_effects_apply_policies(batch, context, preflight, effects);
        let channels = RuntimeEffectsChannelsPlan {
            account_state: AccountStateEffectsPlan {
                target_writes: effects.account_state_delta.written_accounts,
                target_data_bytes: effects.account_state_delta.total_data_bytes_written,
                target_rent_epoch_updates: effects.account_state_delta.rent_epoch_updates,
            },
            program_cache: ProgramCacheEffectsPlan {
                target_loads: effects.program_cache_delta.loaded_programs,
                target_evictions: effects.program_cache_delta.evicted_programs,
                target_invalidations: effects.program_cache_delta.invalidated_programs,
            },
            apply_policies,
        };
        Ok(RuntimeEffectsPlan {
            effects: *effects,
            channels,
            requires_rollback_on_error,
        })
    }

    fn select_effects_apply_policies(
        &self,
        _batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
        _preflight: &RuntimePreflightOutcome,
        _effects: &RuntimeExecutionEffects,
    ) -> RuntimeEffectsApplyPolicies {
        RuntimeEffectsApplyPolicies {
            account_state: AccountStateApplyPolicy::Strict,
            program_cache: ProgramCacheApplyPolicy::Strict,
        }
    }

    fn apply_effects(
        &self,
        batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
        _preflight: &RuntimePreflightOutcome,
        plan: &RuntimeEffectsPlan,
    ) -> std::result::Result<RuntimeApplyReport, ExecutionError> {
        let channels = apply_channels_plan(&plan.channels);
        let applied_program_cache_ops = checked_program_cache_ops(
            batch.fragment_id,
            channels.program_cache.applied_loads,
            channels.program_cache.applied_evictions,
            channels.program_cache.applied_invalidations,
        )?;
        Ok(RuntimeApplyReport {
            applied_account_writes: channels.account_state.applied_writes,
            applied_program_cache_ops,
            channels,
        })
    }

    fn rollback_effects(
        &self,
        _batch: &ExecutionBatch,
        _context: &RuntimeBatchContext,
        _preflight: &RuntimePreflightOutcome,
        _plan: &RuntimeEffectsPlan,
    ) -> std::result::Result<(), ExecutionError> {
        Ok(())
    }
}

fn apply_account_state_channel(
    plan: &AccountStateEffectsPlan,
    policy: AccountStateApplyPolicy,
) -> AccountStateApplyReport {
    match policy {
        AccountStateApplyPolicy::Strict => AccountStateApplyReport {
            applied_writes: plan.target_writes,
            applied_data_bytes: plan.target_data_bytes,
            applied_rent_epoch_updates: plan.target_rent_epoch_updates,
        },
        AccountStateApplyPolicy::Lenient => AccountStateApplyReport {
            applied_writes: plan.target_writes.saturating_sub(plan.target_writes / 50),
            applied_data_bytes: plan
                .target_data_bytes
                .saturating_sub(plan.target_data_bytes / 50),
            applied_rent_epoch_updates: plan
                .target_rent_epoch_updates
                .saturating_sub(plan.target_rent_epoch_updates / 20),
        },
    }
}

fn apply_program_cache_channel(
    plan: &ProgramCacheEffectsPlan,
    policy: ProgramCacheApplyPolicy,
) -> ProgramCacheApplyReport {
    match policy {
        ProgramCacheApplyPolicy::Strict => ProgramCacheApplyReport {
            applied_loads: plan.target_loads,
            applied_evictions: plan.target_evictions,
            applied_invalidations: plan.target_invalidations,
        },
        ProgramCacheApplyPolicy::Lenient => ProgramCacheApplyReport {
            applied_loads: plan.target_loads.saturating_sub(plan.target_loads / 20),
            applied_evictions: plan
                .target_evictions
                .saturating_sub(plan.target_evictions / 20),
            applied_invalidations: plan
                .target_invalidations
                .saturating_sub(plan.target_invalidations / 20),
        },
    }
}

pub(crate) fn apply_channels_plan(
    plan: &RuntimeEffectsChannelsPlan,
) -> RuntimeEffectsChannelsApplyReport {
    let account_state =
        apply_account_state_channel(&plan.account_state, plan.apply_policies.account_state);
    let program_cache =
        apply_program_cache_channel(&plan.program_cache, plan.apply_policies.program_cache);
    RuntimeEffectsChannelsApplyReport {
        account_state,
        program_cache,
    }
}

fn checked_program_cache_ops(
    fragment_id: u64,
    applied_loads: usize,
    applied_evictions: usize,
    applied_invalidations: usize,
) -> std::result::Result<usize, ExecutionError> {
    applied_loads
        .checked_add(applied_evictions)
        .and_then(|sum| sum.checked_add(applied_invalidations))
        .ok_or_else(|| ExecutionError::AdapterContractViolation {
            fragment_id,
            detail: "program-cache apply-report aggregate overflow".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // apply_account_state_channel tests
    // -----------------------------------------------------------------------

    #[test]
    fn account_state_strict_passes_through_unchanged() {
        let plan = AccountStateEffectsPlan {
            target_writes: 100,
            target_data_bytes: 4096,
            target_rent_epoch_updates: 20,
        };
        let report = apply_account_state_channel(&plan, AccountStateApplyPolicy::Strict);
        assert_eq!(report.applied_writes, 100);
        assert_eq!(report.applied_data_bytes, 4096);
        assert_eq!(report.applied_rent_epoch_updates, 20);
    }

    #[test]
    fn account_state_lenient_reduces_values() {
        let plan = AccountStateEffectsPlan {
            target_writes: 1000,
            target_data_bytes: 50_000,
            target_rent_epoch_updates: 200,
        };
        let report = apply_account_state_channel(&plan, AccountStateApplyPolicy::Lenient);
        assert!(report.applied_writes < plan.target_writes);
        assert!(report.applied_data_bytes < plan.target_data_bytes);
        assert!(report.applied_rent_epoch_updates < plan.target_rent_epoch_updates);
    }

    #[test]
    fn account_state_lenient_with_zero_values() {
        let plan = AccountStateEffectsPlan {
            target_writes: 0,
            target_data_bytes: 0,
            target_rent_epoch_updates: 0,
        };
        let report = apply_account_state_channel(&plan, AccountStateApplyPolicy::Lenient);
        assert_eq!(report.applied_writes, 0);
        assert_eq!(report.applied_data_bytes, 0);
        assert_eq!(report.applied_rent_epoch_updates, 0);
    }

    // -----------------------------------------------------------------------
    // apply_program_cache_channel tests
    // -----------------------------------------------------------------------

    #[test]
    fn program_cache_strict_passes_through_unchanged() {
        let plan = ProgramCacheEffectsPlan {
            target_loads: 50,
            target_evictions: 10,
            target_invalidations: 5,
        };
        let report = apply_program_cache_channel(&plan, ProgramCacheApplyPolicy::Strict);
        assert_eq!(report.applied_loads, 50);
        assert_eq!(report.applied_evictions, 10);
        assert_eq!(report.applied_invalidations, 5);
    }

    #[test]
    fn program_cache_lenient_reduces_values() {
        let plan = ProgramCacheEffectsPlan {
            target_loads: 1000,
            target_evictions: 200,
            target_invalidations: 100,
        };
        let report = apply_program_cache_channel(&plan, ProgramCacheApplyPolicy::Lenient);
        assert!(report.applied_loads < plan.target_loads);
        assert!(report.applied_evictions < plan.target_evictions);
        assert!(report.applied_invalidations < plan.target_invalidations);
    }

    // -----------------------------------------------------------------------
    // apply_channels_plan tests
    // -----------------------------------------------------------------------

    #[test]
    fn channels_plan_applies_both_policies() {
        let plan = RuntimeEffectsChannelsPlan {
            account_state: AccountStateEffectsPlan {
                target_writes: 100,
                target_data_bytes: 8192,
                target_rent_epoch_updates: 10,
            },
            program_cache: ProgramCacheEffectsPlan {
                target_loads: 25,
                target_evictions: 5,
                target_invalidations: 3,
            },
            apply_policies: RuntimeEffectsApplyPolicies {
                account_state: AccountStateApplyPolicy::Strict,
                program_cache: ProgramCacheApplyPolicy::Strict,
            },
        };
        let report = apply_channels_plan(&plan);
        assert_eq!(report.account_state.applied_writes, 100);
        assert_eq!(report.program_cache.applied_loads, 25);
    }

    #[test]
    fn channels_plan_mixed_policies() {
        let plan = RuntimeEffectsChannelsPlan {
            account_state: AccountStateEffectsPlan {
                target_writes: 1000,
                target_data_bytes: 50_000,
                target_rent_epoch_updates: 100,
            },
            program_cache: ProgramCacheEffectsPlan {
                target_loads: 500,
                target_evictions: 100,
                target_invalidations: 50,
            },
            apply_policies: RuntimeEffectsApplyPolicies {
                account_state: AccountStateApplyPolicy::Lenient,
                program_cache: ProgramCacheApplyPolicy::Strict,
            },
        };
        let report = apply_channels_plan(&plan);
        // Account state should be reduced (lenient)
        assert!(report.account_state.applied_writes < 1000);
        // Program cache should be exact (strict)
        assert_eq!(report.program_cache.applied_loads, 500);
    }

    // -----------------------------------------------------------------------
    // checked_program_cache_ops tests
    // -----------------------------------------------------------------------

    #[test]
    fn checked_ops_sums_correctly() {
        let result = checked_program_cache_ops(1, 10, 20, 30).unwrap();
        assert_eq!(result, 60);
    }

    #[test]
    fn checked_ops_with_zeros() {
        let result = checked_program_cache_ops(1, 0, 0, 0).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn checked_ops_overflow_returns_error() {
        let result = checked_program_cache_ops(42, usize::MAX, 1, 0);
        assert!(result.is_err());
        match result {
            Err(ExecutionError::AdapterContractViolation { fragment_id, .. }) => {
                assert_eq!(fragment_id, 42);
            }
            _ => panic!("expected AdapterContractViolation"),
        }
    }

    // -----------------------------------------------------------------------
    // RuntimeStateWriteIntent tests
    // -----------------------------------------------------------------------

    #[test]
    fn write_intent_none_vs_commit() {
        assert_ne!(
            RuntimeStateWriteIntent::None,
            RuntimeStateWriteIntent::CommitCandidate { fragment_id: 1 }
        );
    }
}
