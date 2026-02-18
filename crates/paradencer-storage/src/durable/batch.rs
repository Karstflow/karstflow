/// Atomic write batch for durable storage.
///
/// Collects multiple put/delete operations and applies them as a single
/// atomic unit. If any operation fails, none are applied.
use paradencer_constants::durable_store::MAX_WRITE_BATCH_SIZE;

use crate::StorageError;

/// A single write operation within a batch.
#[derive(Debug, Clone)]
pub enum WriteOp {
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: String,
        key: Vec<u8>,
    },
}

/// Collects write operations for atomic application.
#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    ops: Vec<WriteOp>,
}

impl WriteBatch {
    /// Create an empty batch.
    #[inline]
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Create a batch with pre-allocated capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ops: Vec::with_capacity(capacity),
        }
    }

    /// Add a put operation to the batch.
    pub fn put(&mut self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        if self.ops.len() >= MAX_WRITE_BATCH_SIZE {
            return Err(StorageError::WriteBatchTooLarge {
                size: self.ops.len() + 1,
                max: MAX_WRITE_BATCH_SIZE,
            });
        }
        self.ops.push(WriteOp::Put {
            cf: cf.to_owned(),
            key: key.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    /// Add a delete operation to the batch.
    pub fn delete(&mut self, cf: &str, key: &[u8]) -> Result<(), StorageError> {
        if self.ops.len() >= MAX_WRITE_BATCH_SIZE {
            return Err(StorageError::WriteBatchTooLarge {
                size: self.ops.len() + 1,
                max: MAX_WRITE_BATCH_SIZE,
            });
        }
        self.ops.push(WriteOp::Delete {
            cf: cf.to_owned(),
            key: key.to_vec(),
        });
        Ok(())
    }

    /// Number of operations in the batch.
    #[inline]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Iterate over the operations.
    #[inline]
    pub fn ops(&self) -> &[WriteOp] {
        &self.ops
    }

    /// Clear all operations.
    #[inline]
    pub fn clear(&mut self) {
        self.ops.clear();
    }
}
