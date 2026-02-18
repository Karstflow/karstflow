//! Storage backend abstraction for the blockstore.
//!
//! Supports two modes: in-memory (for testing) and persistent (backed
//! by a DurableStore with append-only log files on disk).

use super::BlockstoreError;
use crate::durable::DurableStore;
use crate::FileDurableStore;
use paradencer_constants::blockstore::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// A single column family store: key -> value.
type ColumnStore = RwLock<HashMap<Vec<u8>, Vec<u8>>>;

/// A key-value pair from the backend store.
type KeyValuePair = (Vec<u8>, Vec<u8>);

/// Standard blockstore column families.
const BLOCKSTORE_CFS: &[&str] = &[
    CF_SLOT_META,
    CF_DATA_SHRED,
    CF_CODE_SHRED,
    CF_DEAD_SLOTS,
    CF_DUPLICATE_SLOTS,
    CF_ROOTS,
    CF_ERASURE_META,
    CF_BLOCK_HEIGHT,
];

/// Inner storage variant.
enum BackendInner {
    /// In-memory storage for testing.
    InMemory {
        stores: HashMap<String, ColumnStore>,
    },
    /// Persistent storage backed by DurableStore.
    Persistent { store: Arc<dyn DurableStore> },
}

/// Key-value storage backend for the blockstore.
///
/// Organizes data into column families (CFs). In-memory mode uses
/// RwLock-protected HashMaps. Persistent mode delegates to a DurableStore.
pub struct BlockstoreBackend {
    inner: BackendInner,
}

impl BlockstoreBackend {
    /// Create a new in-memory backend with all standard column families.
    pub fn in_memory() -> Self {
        let mut stores = HashMap::new();
        for cf in BLOCKSTORE_CFS {
            stores.insert(cf.to_string(), RwLock::new(HashMap::new()));
        }
        Self {
            inner: BackendInner::InMemory { stores },
        }
    }

    /// Open a persistent backend at the given path.
    ///
    /// Creates or reopens the file-backed store and rebuilds all indexes
    /// from the existing data files.
    pub fn open(path: &Path) -> Result<Self, BlockstoreError> {
        let store_path = path.join("blockstore");
        let store = FileDurableStore::open(&store_path)
            .map_err(|e| BlockstoreError::BackendError(format!("open durable store: {e}")))?;
        Ok(Self {
            inner: BackendInner::Persistent {
                store: Arc::new(store),
            },
        })
    }

    /// Create a persistent backend from an existing DurableStore.
    pub fn with_durable_store(store: Arc<dyn DurableStore>) -> Self {
        Self {
            inner: BackendInner::Persistent { store },
        }
    }

    /// Get a value from a column family.
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let guard = store.read().expect("backend lock poisoned");
                Ok(guard.get(key).cloned())
            }
            BackendInner::Persistent { store } => store
                .get(cf, key)
                .map_err(|e| BlockstoreError::BackendError(e.to_string())),
        }
    }

    /// Put a value into a column family.
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let mut guard = store.write().expect("backend lock poisoned");
                guard.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            BackendInner::Persistent { store } => store
                .put(cf, key, value)
                .map_err(|e| BlockstoreError::BackendError(e.to_string())),
        }
    }

    /// Delete a key from a column family.
    pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let mut guard = store.write().expect("backend lock poisoned");
                guard.remove(key);
                Ok(())
            }
            BackendInner::Persistent { store } => store
                .delete(cf, key)
                .map_err(|e| BlockstoreError::BackendError(e.to_string())),
        }
    }

    /// Get all key-value pairs with a given prefix in a column family.
    pub fn prefix_scan(
        &self,
        cf: &str,
        prefix: &[u8],
    ) -> Result<Vec<KeyValuePair>, BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let guard = store.read().expect("backend lock poisoned");
                let results: Vec<_> = guard
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(results)
            }
            BackendInner::Persistent { store } => store
                .prefix_scan(cf, prefix)
                .map_err(|e| BlockstoreError::BackendError(e.to_string())),
        }
    }

    /// Delete all keys with a given prefix. Returns the number of keys deleted.
    pub fn delete_prefix(&self, cf: &str, prefix: &[u8]) -> Result<usize, BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let mut guard = store.write().expect("backend lock poisoned");
                let keys_to_remove: Vec<Vec<u8>> = guard
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect();
                let count = keys_to_remove.len();
                for key in keys_to_remove {
                    guard.remove(&key);
                }
                Ok(count)
            }
            BackendInner::Persistent { store } => {
                // Scan matching keys, then delete each.
                let entries = store
                    .prefix_scan(cf, prefix)
                    .map_err(|e| BlockstoreError::BackendError(e.to_string()))?;
                let count = entries.len();
                for (key, _) in &entries {
                    store
                        .delete(cf, key)
                        .map_err(|e| BlockstoreError::BackendError(e.to_string()))?;
                }
                Ok(count)
            }
        }
    }

    /// Get all keys in a column family. Useful for cleanup operations.
    pub fn all_keys(&self, cf: &str) -> Result<Vec<Vec<u8>>, BlockstoreError> {
        match &self.inner {
            BackendInner::InMemory { stores } => {
                let store = stores.get(cf).ok_or_else(|| {
                    BlockstoreError::BackendError(format!("unknown column family: {cf}"))
                })?;
                let guard = store.read().expect("backend lock poisoned");
                Ok(guard.keys().cloned().collect())
            }
            BackendInner::Persistent { store } => {
                // Empty prefix matches all keys.
                let entries = store
                    .prefix_scan(cf, &[])
                    .map_err(|e| BlockstoreError::BackendError(e.to_string()))?;
                Ok(entries.into_iter().map(|(k, _)| k).collect())
            }
        }
    }

    /// Flush all pending writes to disk (persistent mode only).
    pub fn flush(&self) -> Result<(), BlockstoreError> {
        if let BackendInner::Persistent { store } = &self.inner {
            store
                .flush()
                .map_err(|e| BlockstoreError::BackendError(e.to_string()))?;
        }
        Ok(())
    }

    /// Returns true if this backend is persistent.
    pub fn is_persistent(&self) -> bool {
        matches!(&self.inner, BackendInner::Persistent { .. })
    }
}
