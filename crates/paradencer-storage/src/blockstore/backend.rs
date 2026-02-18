//! Storage backend abstraction.
//!
//! // TODO: Replace in-memory HashMap with DurableStore-backed persistent
//! // storage (Cycle 3 of the persistent storage plan).

use super::BlockstoreError;
use paradencer_constants::blockstore::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// A single column family store: key -> value.
type ColumnStore = RwLock<HashMap<Vec<u8>, Vec<u8>>>;

/// A key-value pair from the backend store.
type KeyValuePair = (Vec<u8>, Vec<u8>);

/// Key-value storage backend for the blockstore.
///
/// Organizes data into column families (CFs), each backed by a separate
/// RwLock-protected HashMap. This provides isolation and reduces lock
/// contention between different data types.
pub struct BlockstoreBackend {
    /// Column family stores: cf_name -> (key -> value).
    stores: HashMap<String, ColumnStore>,
}

impl BlockstoreBackend {
    /// Create a new in-memory backend with all standard column families.
    pub fn in_memory() -> Self {
        let mut stores = HashMap::new();
        for cf in &[
            CF_SLOT_META,
            CF_DATA_SHRED,
            CF_CODE_SHRED,
            CF_DEAD_SLOTS,
            CF_DUPLICATE_SLOTS,
            CF_ROOTS,
            CF_ERASURE_META,
            CF_BLOCK_HEIGHT,
        ] {
            stores.insert(cf.to_string(), RwLock::new(HashMap::new()));
        }
        Self { stores }
    }

    /// Open a persistent backend at the given path.
    ///
    /// // TODO: Wire to DurableStore for actual persistence (Cycle 3).
    pub fn open(_path: &std::path::Path) -> Result<Self, BlockstoreError> {
        Ok(Self::in_memory())
    }

    /// Get a value from a column family.
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
        })?;
        let guard = store.read().expect("backend lock poisoned");
        Ok(guard.get(key).cloned())
    }

    /// Put a value into a column family.
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
        })?;
        let mut guard = store.write().expect("backend lock poisoned");
        guard.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Delete a key from a column family.
    pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
        })?;
        let mut guard = store.write().expect("backend lock poisoned");
        guard.remove(key);
        Ok(())
    }

    /// Get all key-value pairs with a given prefix in a column family.
    pub fn prefix_scan(
        &self,
        cf: &str,
        prefix: &[u8],
    ) -> Result<Vec<KeyValuePair>, BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
        })?;
        let guard = store.read().expect("backend lock poisoned");
        let results: Vec<_> = guard
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(results)
    }

    /// Delete all keys with a given prefix. Returns the number of keys deleted.
    pub fn delete_prefix(&self, cf: &str, prefix: &[u8]) -> Result<usize, BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
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

    /// Get all keys in a column family. Useful for cleanup operations.
    pub fn all_keys(&self, cf: &str) -> Result<Vec<Vec<u8>>, BlockstoreError> {
        let store = self.stores.get(cf).ok_or_else(|| {
            BlockstoreError::BackendError(format!("unknown column family: {}", cf))
        })?;
        let guard = store.read().expect("backend lock poisoned");
        Ok(guard.keys().cloned().collect())
    }
}
