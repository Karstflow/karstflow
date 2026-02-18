/// Transaction scheduler (pack) stage.
///
/// Receives verified, blockhash-validated transactions and arranges them
/// into microblocks for parallel execution. The scheduler prioritizes
/// transactions by fee, detects write-lock conflicts between accounts,
/// and respects per-block cost limits.
///
/// This corresponds to Firedancer's pack tile which is responsible for
/// maximizing validator profitability by selecting and ordering transactions.
mod conflict_detector;
mod priority_queue;
mod scheduler;

pub use conflict_detector::{AccountLock, ConflictDetector, LockKind};
pub use priority_queue::{PackedTransaction, TransactionQueue};
pub use scheduler::{
    Microblock, PackConfig, PackLimits, PackOutcome, PackScheduler, PackStats, PackStatsSnapshot,
};
