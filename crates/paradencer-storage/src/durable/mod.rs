/// Persistent key-value storage backend.
///
/// Custom file-backed implementation with per-CF append-only log files
/// and in-memory hash index. No external database dependencies.
pub mod account_encoding;
mod batch;
mod compaction;
mod engine;
mod file_store;
mod metrics;
mod read_cache;
pub mod recovery;
mod wal;

pub use batch::{WriteBatch, WriteOp};
pub use compaction::{compact_below_slot, compact_below_slot_and_reclaim, CompactionStats};
pub use engine::{FullRecoveryStats, StorageEngine};
pub use file_store::{CfCompactionStats, FileDurableStore};
pub use metrics::MetricsSnapshot;
pub use read_cache::CacheStats;
pub use recovery::{recover_accounts, recover_accounts_parallel, RecoveryStats};

use crate::StorageError;

/// Key-value pair from a scan operation.
pub type ScanEntry = (Vec<u8>, Vec<u8>);

/// Backend for persisting key-value data to disk.
///
/// Implementations organize data into named column families (logical namespaces).
/// All operations are thread-safe.
pub trait DurableStore: Send + Sync {
    /// Retrieve a value by column family and key.
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Store a key-value pair in the given column family.
    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Remove a key from the given column family.
    fn delete(&self, cf: &str, key: &[u8]) -> Result<(), StorageError>;

    /// Apply a batch of writes atomically.
    fn write_batch(&self, batch: &WriteBatch) -> Result<(), StorageError>;

    /// Check if a key exists without reading the value.
    fn contains(&self, cf: &str, key: &[u8]) -> Result<bool, StorageError>;

    /// Scan all key-value pairs whose key starts with the given prefix.
    fn prefix_scan(&self, cf: &str, prefix: &[u8]) -> Result<Vec<ScanEntry>, StorageError>;

    /// Scan all key-value pairs in [start, end) range.
    fn range_scan(
        &self,
        cf: &str,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError>;

    /// Flush all pending writes to disk.
    fn flush(&self) -> Result<(), StorageError>;

    /// Approximate disk usage in bytes.
    fn disk_usage(&self) -> Result<u64, StorageError>;

    /// Number of keys in a column family.
    fn count(&self, cf: &str) -> Result<u64, StorageError>;
}
