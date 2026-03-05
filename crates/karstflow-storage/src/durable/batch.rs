/// Atomic write batch for durable storage.
///
/// Collects multiple put/delete operations and applies them as a single
/// atomic unit. If any operation fails, none are applied.
use karstflow_constants::durable_store::MAX_WRITE_BATCH_SIZE;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_batch_is_empty() {
        let batch = WriteBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn with_capacity_is_empty() {
        let batch = WriteBatch::with_capacity(100);
        assert!(batch.is_empty());
    }

    #[test]
    fn put_adds_operation() {
        let mut batch = WriteBatch::new();
        batch.put("accounts", b"key1", b"value1").unwrap();
        assert_eq!(batch.len(), 1);

        if let WriteOp::Put { cf, key, value } = &batch.ops()[0] {
            assert_eq!(cf, "accounts");
            assert_eq!(key, b"key1");
            assert_eq!(value, b"value1");
        } else {
            panic!("expected Put operation");
        }
    }

    #[test]
    fn delete_adds_operation() {
        let mut batch = WriteBatch::new();
        batch.delete("accounts", b"key1").unwrap();
        assert_eq!(batch.len(), 1);

        if let WriteOp::Delete { cf, key } = &batch.ops()[0] {
            assert_eq!(cf, "accounts");
            assert_eq!(key, b"key1");
        } else {
            panic!("expected Delete operation");
        }
    }

    #[test]
    fn mixed_operations() {
        let mut batch = WriteBatch::new();
        batch.put("cf1", b"k1", b"v1").unwrap();
        batch.delete("cf2", b"k2").unwrap();
        batch.put("cf1", b"k3", b"v3").unwrap();
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn clear_removes_all() {
        let mut batch = WriteBatch::new();
        batch.put("cf", b"k", b"v").unwrap();
        batch.delete("cf", b"k2").unwrap();
        assert_eq!(batch.len(), 2);

        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn put_rejects_at_max_size() {
        let mut batch = WriteBatch::new();
        for i in 0..MAX_WRITE_BATCH_SIZE {
            batch.put("cf", format!("k{i}").as_bytes(), b"v").unwrap();
        }
        assert_eq!(batch.len(), MAX_WRITE_BATCH_SIZE);

        let result = batch.put("cf", b"overflow", b"v");
        assert!(result.is_err());
    }

    #[test]
    fn delete_rejects_at_max_size() {
        let mut batch = WriteBatch::new();
        for i in 0..MAX_WRITE_BATCH_SIZE {
            batch.put("cf", format!("k{i}").as_bytes(), b"v").unwrap();
        }

        let result = batch.delete("cf", b"overflow");
        assert!(result.is_err());
    }

    #[test]
    fn default_is_empty() {
        let batch: WriteBatch = Default::default();
        assert!(batch.is_empty());
    }
}
