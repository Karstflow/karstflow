//! Shred storage operations.
//!
//! Handles inserting and querying individual shreds in the blockstore backend.
//! Shred keys are encoded as slot (u64 big-endian) + index (u32 big-endian)
//! to enable efficient prefix scans by slot.

use super::backend::BlockstoreBackend;
use super::meta::SlotMeta;
use super::BlockstoreError;
use karstflow_constants::blockstore::{CF_CODE_SHRED, CF_DATA_SHRED};

/// Handles inserting and querying shreds in the blockstore.
pub struct ShredStore<'a> {
    backend: &'a BlockstoreBackend,
}

impl<'a> ShredStore<'a> {
    /// Create a new ShredStore wrapping the given backend.
    pub fn new(backend: &'a BlockstoreBackend) -> Self {
        Self { backend }
    }

    /// Insert a data shred and update slot meta.
    pub fn insert_data(
        &self,
        slot: u64,
        index: u32,
        data: &[u8],
        meta: &mut SlotMeta,
    ) -> Result<(), BlockstoreError> {
        let key = shred_key(slot, index);
        self.backend.put(CF_DATA_SHRED, &key, data)?;
        meta.received_data_shreds += 1;
        Ok(())
    }

    /// Insert a coding shred.
    pub fn insert_coding(&self, slot: u64, index: u32, data: &[u8]) -> Result<(), BlockstoreError> {
        let key = shred_key(slot, index);
        self.backend.put(CF_CODE_SHRED, &key, data)
    }

    /// Retrieve a data shred by slot and index.
    pub fn get_data(&self, slot: u64, index: u32) -> Result<Option<Vec<u8>>, BlockstoreError> {
        let key = shred_key(slot, index);
        self.backend.get(CF_DATA_SHRED, &key)
    }

    /// Retrieve a coding shred by slot and index.
    pub fn get_coding(&self, slot: u64, index: u32) -> Result<Option<Vec<u8>>, BlockstoreError> {
        let key = shred_key(slot, index);
        self.backend.get(CF_CODE_SHRED, &key)
    }

    /// Get all data shreds for a slot, returned as (index, data) pairs
    /// sorted by index.
    pub fn get_slot_data_shreds(&self, slot: u64) -> Result<Vec<(u32, Vec<u8>)>, BlockstoreError> {
        let prefix = slot.to_be_bytes();
        let results = self.backend.prefix_scan(CF_DATA_SHRED, &prefix)?;

        let mut shreds: Vec<(u32, Vec<u8>)> = results
            .into_iter()
            .filter_map(|(key, value)| {
                if key.len() >= 12 {
                    let index = u32::from_be_bytes(key[8..12].try_into().ok()?);
                    Some((index, value))
                } else {
                    None
                }
            })
            .collect();

        shreds.sort_by_key(|(index, _)| *index);
        Ok(shreds)
    }
}

/// Encode a shred key as slot (u64 BE) + index (u32 BE).
fn shred_key(slot: u64, index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&slot.to_be_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> BlockstoreBackend {
        BlockstoreBackend::in_memory()
    }

    #[test]
    fn shred_key_encoding() {
        let key = shred_key(1, 42);
        assert_eq!(key.len(), 12);
        let slot = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let index = u32::from_be_bytes(key[8..12].try_into().unwrap());
        assert_eq!(slot, 1);
        assert_eq!(index, 42);
    }

    #[test]
    fn insert_and_get_data_shred() {
        let b = backend();
        let store = ShredStore::new(&b);
        let mut meta = SlotMeta::new(1, Some(0));
        store.insert_data(1, 0, b"shred_data", &mut meta).unwrap();
        assert_eq!(meta.received_data_shreds, 1);

        let data = store.get_data(1, 0).unwrap();
        assert_eq!(data, Some(b"shred_data".to_vec()));
    }

    #[test]
    fn insert_and_get_coding_shred() {
        let b = backend();
        let store = ShredStore::new(&b);
        store.insert_coding(1, 0, b"coding_data").unwrap();

        let data = store.get_coding(1, 0).unwrap();
        assert_eq!(data, Some(b"coding_data".to_vec()));
    }

    #[test]
    fn get_missing_shred_returns_none() {
        let b = backend();
        let store = ShredStore::new(&b);
        assert!(store.get_data(99, 0).unwrap().is_none());
        assert!(store.get_coding(99, 0).unwrap().is_none());
    }

    #[test]
    fn get_slot_data_shreds_sorted() {
        let b = backend();
        let store = ShredStore::new(&b);
        let mut meta = SlotMeta::new(1, Some(0));

        // Insert out of order
        store.insert_data(1, 2, b"d2", &mut meta).unwrap();
        store.insert_data(1, 0, b"d0", &mut meta).unwrap();
        store.insert_data(1, 1, b"d1", &mut meta).unwrap();

        let shreds = store.get_slot_data_shreds(1).unwrap();
        assert_eq!(shreds.len(), 3);
        assert_eq!(shreds[0], (0, b"d0".to_vec()));
        assert_eq!(shreds[1], (1, b"d1".to_vec()));
        assert_eq!(shreds[2], (2, b"d2".to_vec()));
    }

    #[test]
    fn get_slot_data_shreds_empty_slot() {
        let b = backend();
        let store = ShredStore::new(&b);
        let shreds = store.get_slot_data_shreds(42).unwrap();
        assert!(shreds.is_empty());
    }

    #[test]
    fn data_and_coding_are_independent() {
        let b = backend();
        let store = ShredStore::new(&b);
        let mut meta = SlotMeta::new(1, Some(0));
        store.insert_data(1, 0, b"data", &mut meta).unwrap();
        store.insert_coding(1, 0, b"coding").unwrap();

        assert_eq!(store.get_data(1, 0).unwrap(), Some(b"data".to_vec()));
        assert_eq!(store.get_coding(1, 0).unwrap(), Some(b"coding".to_vec()));
    }
}
