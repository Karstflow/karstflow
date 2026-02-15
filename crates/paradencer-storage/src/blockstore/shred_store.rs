//! Shred storage operations.
//!
//! Handles inserting and querying individual shreds in the blockstore backend.
//! Shred keys are encoded as slot (u64 big-endian) + index (u32 big-endian)
//! to enable efficient prefix scans by slot.

use super::backend::BlockstoreBackend;
use super::meta::SlotMeta;
use super::BlockstoreError;
use paradencer_constants::blockstore::{CF_CODE_SHRED, CF_DATA_SHRED};

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
