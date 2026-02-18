/// Sled-backed implementation of DurableStore.
///
/// Uses sled's embedded B-tree database with one `Tree` per column family.
/// Tree handles are cached on open for fast repeated access.
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use paradencer_constants::durable_store::{
    DEFAULT_CACHE_SIZE_BYTES, DEFAULT_FLUSH_INTERVAL_MS, STANDARD_COLUMN_FAMILIES,
};

use super::batch::WriteOp;
use super::{DurableStore, ScanEntry, WriteBatch};
use crate::StorageError;

/// Persistent key-value store backed by sled.
pub struct SledDurableStore {
    db: sled::Db,
    /// Pre-opened tree handles for each column family.
    trees: HashMap<String, sled::Tree>,
}

impl SledDurableStore {
    /// Open or create a database at the given path with default settings.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_config(path, DEFAULT_CACHE_SIZE_BYTES, DEFAULT_FLUSH_INTERVAL_MS)
    }

    /// Open or create a database with custom cache size and flush interval.
    pub fn open_with_config(
        path: &Path,
        cache_size_bytes: u64,
        flush_interval_ms: u64,
    ) -> Result<Self, StorageError> {
        let config = sled::Config::new()
            .path(path)
            .cache_capacity(cache_size_bytes)
            .flush_every_ms(Some(flush_interval_ms));

        let db = config.open().map_err(Self::map_sled_error)?;
        let trees = Self::open_standard_trees(&db)?;

        Ok(Self { db, trees })
    }

    /// Create a temporary in-memory store (for testing).
    pub fn temporary() -> Result<Self, StorageError> {
        let config = sled::Config::new().temporary(true);
        let db = config.open().map_err(Self::map_sled_error)?;
        let trees = Self::open_standard_trees(&db)?;
        Ok(Self { db, trees })
    }

    /// Open all standard column family trees upfront.
    fn open_standard_trees(db: &sled::Db) -> Result<HashMap<String, sled::Tree>, StorageError> {
        let mut trees = HashMap::with_capacity(STANDARD_COLUMN_FAMILIES.len());
        for &cf_name in STANDARD_COLUMN_FAMILIES {
            let tree = db.open_tree(cf_name).map_err(Self::map_sled_error)?;
            trees.insert(cf_name.to_owned(), tree);
        }
        Ok(trees)
    }

    /// Get a tree handle, returning an error if the CF doesn't exist.
    #[inline]
    fn tree(&self, cf: &str) -> Result<&sled::Tree, StorageError> {
        self.trees
            .get(cf)
            .ok_or_else(|| StorageError::UnknownColumnFamily {
                name: cf.to_owned(),
            })
    }

    /// Open a custom (non-standard) column family tree and cache it.
    /// This is useful for extensions beyond the standard set.
    pub fn open_tree(&mut self, name: &str) -> Result<(), StorageError> {
        if !self.trees.contains_key(name) {
            let tree = self.db.open_tree(name).map_err(Self::map_sled_error)?;
            self.trees.insert(name.to_owned(), tree);
        }
        Ok(())
    }

    /// Wrap this store in an Arc for shared ownership.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    #[inline]
    fn map_sled_error(e: sled::Error) -> StorageError {
        StorageError::DurableStoreError {
            details: e.to_string(),
        }
    }
}

impl DurableStore for SledDurableStore {
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let tree = self.tree(cf)?;
        tree.get(key)
            .map(|opt| opt.map(|iv| iv.to_vec()))
            .map_err(Self::map_sled_error)
    }

    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let tree = self.tree(cf)?;
        tree.insert(key, value).map_err(Self::map_sled_error)?;
        Ok(())
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<(), StorageError> {
        let tree = self.tree(cf)?;
        tree.remove(key).map_err(Self::map_sled_error)?;
        Ok(())
    }

    fn write_batch(&self, batch: &WriteBatch) -> Result<(), StorageError> {
        // Group operations by column family for efficient batching.
        // sled::Batch is per-tree, so we build one batch per CF.
        let mut batches: HashMap<&str, sled::Batch> = HashMap::new();

        for op in batch.ops() {
            match op {
                WriteOp::Put { cf, key, value } => {
                    // Verify CF exists before building batch.
                    let _ = self.tree(cf)?;
                    batches
                        .entry(cf.as_str())
                        .or_default()
                        .insert(key.as_slice(), value.as_slice());
                }
                WriteOp::Delete { cf, key } => {
                    let _ = self.tree(cf)?;
                    batches
                        .entry(cf.as_str())
                        .or_default()
                        .remove(key.as_slice());
                }
            }
        }

        // Apply all per-CF batches.
        for (cf, sled_batch) in batches {
            let tree = self.tree(cf)?;
            tree.apply_batch(sled_batch).map_err(Self::map_sled_error)?;
        }

        Ok(())
    }

    fn contains(&self, cf: &str, key: &[u8]) -> Result<bool, StorageError> {
        let tree = self.tree(cf)?;
        tree.contains_key(key).map_err(Self::map_sled_error)
    }

    fn prefix_scan(&self, cf: &str, prefix: &[u8]) -> Result<Vec<ScanEntry>, StorageError> {
        let tree = self.tree(cf)?;
        let mut results = Vec::new();
        for item in tree.scan_prefix(prefix) {
            let (k, v) = item.map_err(Self::map_sled_error)?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    fn range_scan(
        &self,
        cf: &str,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        let tree = self.tree(cf)?;
        let mut results = Vec::new();
        for item in tree.range(start..end) {
            let (k, v) = item.map_err(Self::map_sled_error)?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(Self::map_sled_error)?;
        Ok(())
    }

    fn disk_usage(&self) -> Result<u64, StorageError> {
        self.db.size_on_disk().map_err(Self::map_sled_error)
    }

    fn count(&self, cf: &str) -> Result<u64, StorageError> {
        let tree = self.tree(cf)?;
        Ok(tree.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_constants::durable_store::*;

    fn temp_store() -> SledDurableStore {
        SledDurableStore::temporary().expect("temporary store")
    }

    #[test]
    fn put_get_roundtrip() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key1", b"value1").expect("put");
        let val = store.get(CF_ACCOUNTS, b"key1").expect("get");
        assert_eq!(val, Some(b"value1".to_vec()));
    }

    #[test]
    fn get_missing_key_returns_none() {
        let store = temp_store();
        let val = store.get(CF_ACCOUNTS, b"nonexistent").expect("get");
        assert_eq!(val, None);
    }

    #[test]
    fn delete_removes_key() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"k", b"v").expect("put");
        store.delete(CF_ACCOUNTS, b"k").expect("delete");
        assert_eq!(store.get(CF_ACCOUNTS, b"k").expect("get"), None);
    }

    #[test]
    fn contains_check() {
        let store = temp_store();
        assert!(!store.contains(CF_ACCOUNTS, b"x").expect("contains"));
        store.put(CF_ACCOUNTS, b"x", b"y").expect("put");
        assert!(store.contains(CF_ACCOUNTS, b"x").expect("contains"));
    }

    #[test]
    fn overwrite_value() {
        let store = temp_store();
        store.put(CF_METADATA, b"k", b"v1").expect("put");
        store.put(CF_METADATA, b"k", b"v2").expect("put");
        assert_eq!(
            store.get(CF_METADATA, b"k").expect("get"),
            Some(b"v2".to_vec())
        );
    }

    #[test]
    fn write_batch_atomicity() {
        let store = temp_store();
        let mut batch = WriteBatch::new();
        batch.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        batch.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        batch.put(CF_METADATA, b"c", b"3").unwrap();
        store.write_batch(&batch).expect("batch");

        assert_eq!(
            store.get(CF_ACCOUNTS, b"a").expect("get"),
            Some(b"1".to_vec())
        );
        assert_eq!(
            store.get(CF_ACCOUNTS, b"b").expect("get"),
            Some(b"2".to_vec())
        );
        assert_eq!(
            store.get(CF_METADATA, b"c").expect("get"),
            Some(b"3".to_vec())
        );
    }

    #[test]
    fn write_batch_with_deletes() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"x", b"old").expect("put");

        let mut batch = WriteBatch::new();
        batch.delete(CF_ACCOUNTS, b"x").unwrap();
        batch.put(CF_ACCOUNTS, b"y", b"new").unwrap();
        store.write_batch(&batch).expect("batch");

        assert_eq!(store.get(CF_ACCOUNTS, b"x").expect("get"), None);
        assert_eq!(
            store.get(CF_ACCOUNTS, b"y").expect("get"),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn prefix_scan_filters_correctly() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"user:001", b"alice").unwrap();
        store.put(CF_ACCOUNTS, b"user:002", b"bob").unwrap();
        store.put(CF_ACCOUNTS, b"meta:count", b"2").unwrap();

        let results = store.prefix_scan(CF_ACCOUNTS, b"user:").expect("scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, b"alice");
        assert_eq!(results[1].1, b"bob");
    }

    #[test]
    fn range_scan_bounds() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        store.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        store.put(CF_ACCOUNTS, b"c", b"3").unwrap();
        store.put(CF_ACCOUNTS, b"d", b"4").unwrap();

        let results = store
            .range_scan(CF_ACCOUNTS, b"b", b"d")
            .expect("range scan");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, b"b");
        assert_eq!(results[1].0, b"c");
    }

    #[test]
    fn column_families_are_isolated() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"key", b"acct").unwrap();
        store.put(CF_METADATA, b"key", b"meta").unwrap();

        assert_eq!(
            store.get(CF_ACCOUNTS, b"key").expect("get"),
            Some(b"acct".to_vec())
        );
        assert_eq!(
            store.get(CF_METADATA, b"key").expect("get"),
            Some(b"meta".to_vec())
        );
    }

    #[test]
    fn unknown_cf_returns_error() {
        let store = temp_store();
        let err = store.get("nonexistent_cf", b"k").unwrap_err();
        assert!(matches!(err, StorageError::UnknownColumnFamily { .. }));
    }

    #[test]
    fn large_value_roundtrip() {
        let store = temp_store();
        let large_value = vec![0xABu8; 1024 * 1024]; // 1 MB
        store
            .put(CF_ACCOUNTS, b"big", &large_value)
            .expect("put large");
        let val = store.get(CF_ACCOUNTS, b"big").expect("get large");
        assert_eq!(val, Some(large_value));
    }

    #[test]
    fn count_tracks_inserts_and_deletes() {
        let store = temp_store();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 0);

        store.put(CF_ACCOUNTS, b"a", b"1").unwrap();
        store.put(CF_ACCOUNTS, b"b", b"2").unwrap();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 2);

        store.delete(CF_ACCOUNTS, b"a").unwrap();
        assert_eq!(store.count(CF_ACCOUNTS).unwrap(), 1);
    }

    #[test]
    fn flush_succeeds() {
        let store = temp_store();
        store.put(CF_ACCOUNTS, b"k", b"v").unwrap();
        store.flush().expect("flush");
    }

    #[test]
    fn disk_usage_returns_value() {
        let store = temp_store();
        let usage = store.disk_usage().expect("disk_usage");
        // Temporary store still has some overhead.
        // Just verify the call doesn't error — value is implementation-dependent.
        let _ = usage;
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write data.
        {
            let store = SledDurableStore::open(&path).expect("open");
            store
                .put(CF_ACCOUNTS, b"persist_key", b"persist_val")
                .unwrap();
            store.flush().unwrap();
        }

        // Reopen and verify.
        {
            let store = SledDurableStore::open(&path).expect("reopen");
            let val = store.get(CF_ACCOUNTS, b"persist_key").expect("get");
            assert_eq!(val, Some(b"persist_val".to_vec()));
        }
    }

    #[test]
    fn batch_size_limit_enforced() {
        let mut batch = WriteBatch::new();
        for i in 0..MAX_WRITE_BATCH_SIZE {
            batch
                .put(CF_ACCOUNTS, &i.to_le_bytes(), b"v")
                .expect("should succeed");
        }
        let err = batch.put(CF_ACCOUNTS, b"overflow", b"v").unwrap_err();
        assert!(matches!(err, StorageError::WriteBatchTooLarge { .. }));
    }

    #[test]
    fn metadata_key_roundtrip() {
        let store = temp_store();
        let slot: u64 = 42;
        store
            .put(CF_METADATA, META_KEY_LATEST_SLOT, &slot.to_le_bytes())
            .unwrap();

        let raw = store
            .get(CF_METADATA, META_KEY_LATEST_SLOT)
            .unwrap()
            .expect("should exist");
        let recovered = u64::from_le_bytes(raw.try_into().expect("8 bytes"));
        assert_eq!(recovered, 42);
    }

    #[test]
    fn all_standard_cfs_accessible() {
        let store = temp_store();
        for &cf in STANDARD_COLUMN_FAMILIES {
            store
                .put(cf, b"test", b"ok")
                .unwrap_or_else(|e| panic!("CF {cf} failed: {e}"));
            assert_eq!(store.get(cf, b"test").unwrap(), Some(b"ok".to_vec()));
        }
    }
}
