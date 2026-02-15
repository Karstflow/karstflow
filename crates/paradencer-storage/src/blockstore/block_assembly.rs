//! Block assembly from stored shreds.
//!
//! Reassembles a complete block from stored data shreds once a slot
//! is marked complete.

use super::meta::SlotMeta;
use super::shred_store::ShredStore;
use super::BlockstoreError;

/// Assembles complete blocks from stored data shreds.
pub struct BlockAssembler;

impl BlockAssembler {
    /// Attempt to assemble a block from stored shreds for a slot.
    ///
    /// Returns an error if the slot is not complete or shreds are missing.
    pub fn assemble(
        store: &ShredStore,
        slot: u64,
        meta: &SlotMeta,
    ) -> Result<AssembledBlock, BlockstoreError> {
        if !meta.is_complete() {
            return Err(BlockstoreError::SlotNotFound(slot));
        }

        let shreds = store.get_slot_data_shreds(slot)?;
        if shreds.is_empty() {
            return Err(BlockstoreError::SlotNotFound(slot));
        }

        // Concatenate all data shreds in order to produce the raw entry data
        let total_size: usize = shreds.iter().map(|(_, data)| data.len()).sum();
        let mut entries = Vec::with_capacity(total_size);
        for (_, data) in &shreds {
            entries.extend_from_slice(data);
        }

        let parent_slot = meta.parent_slot.unwrap_or(0);

        Ok(AssembledBlock {
            slot,
            parent_slot,
            data_size: entries.len(),
            entries,
        })
    }
}

/// A fully assembled block ready for replay.
#[derive(Debug)]
pub struct AssembledBlock {
    /// Slot number.
    pub slot: u64,
    /// Parent slot number.
    pub parent_slot: u64,
    /// Raw entry data assembled from shreds.
    pub entries: Vec<u8>,
    /// Total size of assembled data in bytes.
    pub data_size: usize,
}
