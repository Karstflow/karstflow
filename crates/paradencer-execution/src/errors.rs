use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("execution batch for fragment {fragment_id} has no transactions")]
    EmptyBatch { fragment_id: u64 },
    #[error(
        "execution cost overflow for fragment {fragment_id}: transaction_count={transaction_count}"
    )]
    CostOverflow {
        fragment_id: u64,
        transaction_count: usize,
    },
    #[error("execution adapter apply-effects failure for fragment {fragment_id}: {message}")]
    AdapterApplyFailure { fragment_id: u64, message: String },
    #[error("execution adapter rollback-effects failure for fragment {fragment_id}: {message}")]
    AdapterRollbackFailure { fragment_id: u64, message: String },
    #[error("execution adapter state conflict for fragment {fragment_id}: {detail}")]
    AdapterStateConflict { fragment_id: u64, detail: String },
    #[error("execution adapter contract violation for fragment {fragment_id}: {detail}")]
    AdapterContractViolation { fragment_id: u64, detail: String },
    #[error("execution adapter rollback receipt is missing for fragment {fragment_id}")]
    AdapterReceiptMissing { fragment_id: u64 },
    #[error(
        "execution adapter mutex poisoned for fragment {fragment_id} in lock '{lock_name}': {detail}"
    )]
    AdapterMutexPoisoned {
        fragment_id: u64,
        lock_name: &'static str,
        detail: String,
    },

    #[error("invalid execution batch for fragment {fragment_id}: {detail}")]
    InvalidBatch { fragment_id: u64, detail: String },

    #[error("storage backend error for fragment {fragment_id}: {detail}")]
    StorageBackend { fragment_id: u64, detail: String },
}
