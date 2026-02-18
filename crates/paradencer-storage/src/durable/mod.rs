/// Persistent key-value storage backend.
///
/// Provides a trait-based abstraction over embedded databases (sled, etc.)
/// for persisting account state, blockstore data, and metadata across restarts.
mod batch;
mod sled_store;

pub use batch::{WriteBatch, WriteOp};
pub use sled_store::SledDurableStore;

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
