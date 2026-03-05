mod account_backed;
mod heuristic;
mod runtime_adapter;
mod runtime_like;
mod storage_adapter;

use crate::errors::ExecutionError;
use crate::types::{ExecutionBatch, ExecutionOutcome};

pub use account_backed::AccountBackedExecutionEngine;
pub use heuristic::HeuristicExecutionEngine;
pub use runtime_adapter::{
    AccountAccessPattern, AccountStateApplyPolicy, AccountStateApplyReport,
    AccountStateDeltaSummary, AccountStateEffectsPlan, ProgramCacheApplyPolicy,
    ProgramCacheApplyReport, ProgramCacheDeltaSummary, ProgramCacheEffectsPlan, ProgramCacheHint,
    RuntimeApplyReport, RuntimeBatchContext, RuntimeEffectsApplyPolicies,
    RuntimeEffectsChannelsApplyReport, RuntimeEffectsChannelsPlan, RuntimeEffectsPlan,
    RuntimeExecutionAdapter, RuntimeExecutionEffects, RuntimeExecutionObservation,
    RuntimePreflightOutcome, RuntimeStateWriteIntent,
};
pub use runtime_like::{RuntimeFailureSignal, RuntimeLikeExecutionEngine, SyntheticRuntimeAdapter};
pub use storage_adapter::{RuntimeStateStoreSnapshot, StorageBackedRuntimeAdapter};

pub trait ExecutionEngine: Send + Sync {
    fn try_execute_batch(
        &self,
        batch: &ExecutionBatch,
    ) -> std::result::Result<ExecutionOutcome, ExecutionError>;
}
