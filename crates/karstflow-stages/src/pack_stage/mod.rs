/// Transaction scheduler (pack) stage.
///
/// Receives verified, blockhash-validated transactions and arranges them
/// into microblocks for parallel execution. The scheduler prioritizes
/// transactions by fee, detects write-lock conflicts between accounts,
/// and respects per-block cost limits.
///
/// This corresponds to the pack tile which is responsible for
/// maximizing validator profitability by selecting and ordering transactions.
mod conflict_detector;
pub mod cost_model;
mod priority_queue;
mod scheduler;
pub mod unwritable;

pub use conflict_detector::{AccountLock, ConflictDetector, LockKind};
pub use cost_model::{compute_cost, CostInput, CostResult};
pub use priority_queue::{PackedTransaction, TransactionQueue};
pub use scheduler::{
    Microblock, MicroblockRebate, PackConfig, PackLimits, PackOutcome, PackPacer, PackScheduler,
    PackStats, PackStatsSnapshot,
};
pub use unwritable::is_unwritable;
