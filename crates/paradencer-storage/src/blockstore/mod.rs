//! Persistent ledger storage (blockstore).
//!
//! Stores shreds, slot metadata, and block assembly state.
//! Uses an embedded key-value store for persistence.

pub(crate) mod backend;
mod block_assembly;
mod cleanup;
mod meta;
mod shred_store;

#[cfg(test)]
mod tests;

pub use block_assembly::{AssembledBlock, BlockAssembler};
pub use cleanup::BlockstoreCleanup;
pub use meta::{ErasureMeta, SlotMeta, SlotStatus};
pub use shred_store::ShredStore;

use backend::BlockstoreBackend;
use paradencer_constants::blockstore::*;
use std::collections::BTreeSet;
use std::sync::RwLock;

/// Persistent ledger storage for shreds and block metadata.
pub struct Blockstore {
    pub(crate) backend: BlockstoreBackend,
    /// Cached set of root slots for fast lookups.
    roots: RwLock<BTreeSet<u64>>,
    /// Lowest slot that has been cleaned up; all data below is purged.
    lowest_cleanup_slot: RwLock<u64>,
}

impl Blockstore {
    /// Open or create a blockstore at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, BlockstoreError> {
        Ok(Self {
            backend: BlockstoreBackend::open(path)?,
            roots: RwLock::new(BTreeSet::new()),
            lowest_cleanup_slot: RwLock::new(0),
        })
    }

    /// Create an in-memory blockstore (for testing).
    pub fn in_memory() -> Self {
        Self {
            backend: BlockstoreBackend::in_memory(),
            roots: RwLock::new(BTreeSet::new()),
            lowest_cleanup_slot: RwLock::new(0),
        }
    }

    /// Insert a data shred.
    pub fn insert_data_shred(
        &self,
        slot: u64,
        index: u32,
        data: &[u8],
    ) -> Result<(), BlockstoreError> {
        if index as usize >= MAX_DATA_SHREDS_PER_SLOT {
            return Err(BlockstoreError::ShredIndexOutOfRange { slot, index });
        }
        if data.is_empty() {
            return Err(BlockstoreError::InvalidShredData);
        }

        // Update slot meta
        let mut meta = self.get_or_create_slot_meta(slot)?;
        let store = ShredStore::new(&self.backend);
        store.insert_data(slot, index, data, &mut meta)?;
        self.save_slot_meta(&meta)?;

        Ok(())
    }

    /// Insert a coding shred.
    pub fn insert_coding_shred(
        &self,
        slot: u64,
        index: u32,
        data: &[u8],
    ) -> Result<(), BlockstoreError> {
        if index as usize >= MAX_CODING_SHREDS_PER_SLOT {
            return Err(BlockstoreError::ShredIndexOutOfRange { slot, index });
        }
        if data.is_empty() {
            return Err(BlockstoreError::InvalidShredData);
        }

        // Update slot meta
        let mut meta = self.get_or_create_slot_meta(slot)?;
        let store = ShredStore::new(&self.backend);
        store.insert_coding(slot, index, data)?;
        meta.received_coding_shreds += 1;
        self.save_slot_meta(&meta)?;

        Ok(())
    }

    /// Get slot metadata.
    pub fn get_slot_meta(&self, slot: u64) -> Result<Option<SlotMeta>, BlockstoreError> {
        let key = slot.to_be_bytes();
        match self.backend.get(CF_SLOT_META, &key)? {
            Some(data) => {
                let meta = SlotMeta::deserialize(&data)?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Get a data shred by slot and index.
    pub fn get_data_shred(
        &self,
        slot: u64,
        index: u32,
    ) -> Result<Option<Vec<u8>>, BlockstoreError> {
        let store = ShredStore::new(&self.backend);
        store.get_data(slot, index)
    }

    /// Check if a slot is complete (all data shreds received).
    pub fn is_slot_complete(&self, slot: u64) -> bool {
        self.get_slot_meta(slot)
            .ok()
            .flatten()
            .map(|meta| meta.is_complete())
            .unwrap_or(false)
    }

    /// Mark a slot as dead (unrecoverable).
    pub fn mark_dead(&self, slot: u64) -> Result<(), BlockstoreError> {
        let mut meta = self.get_or_create_slot_meta(slot)?;
        if meta.status == SlotStatus::Dead {
            return Err(BlockstoreError::SlotAlreadyDead(slot));
        }
        meta.status = SlotStatus::Dead;
        self.save_slot_meta(&meta)?;

        // Also record in dead slots column family
        let key = slot.to_be_bytes();
        self.backend.put(CF_DEAD_SLOTS, &key, &[1])?;

        Ok(())
    }

    /// Mark a slot as duplicate.
    pub fn mark_duplicate(&self, slot: u64) -> Result<(), BlockstoreError> {
        let mut meta = self.get_or_create_slot_meta(slot)?;
        meta.status = SlotStatus::Duplicate;
        self.save_slot_meta(&meta)?;

        let key = slot.to_be_bytes();
        self.backend.put(CF_DUPLICATE_SLOTS, &key, &[1])?;

        Ok(())
    }

    /// Check if a slot is a root.
    pub fn is_root(&self, slot: u64) -> bool {
        self.roots
            .read()
            .expect("roots lock poisoned")
            .contains(&slot)
    }

    /// Set a slot as root.
    pub fn set_root(&self, slot: u64) -> Result<(), BlockstoreError> {
        let key = slot.to_be_bytes();
        self.backend.put(CF_ROOTS, &key, &[1])?;
        self.roots
            .write()
            .expect("roots lock poisoned")
            .insert(slot);
        Ok(())
    }

    /// Get the latest root slot.
    pub fn latest_root(&self) -> Option<u64> {
        self.roots
            .read()
            .expect("roots lock poisoned")
            .iter()
            .next_back()
            .copied()
    }

    /// Get all root slots.
    pub fn roots(&self) -> Vec<u64> {
        self.roots
            .read()
            .expect("roots lock poisoned")
            .iter()
            .copied()
            .collect()
    }

    /// Purge slots below the given slot.
    /// Returns the number of slots purged.
    pub fn purge_slots_below(&self, min_slot: u64) -> Result<usize, BlockstoreError> {
        let purged = BlockstoreCleanup::purge_below(&self.backend, min_slot)?;

        // Remove purged roots from the cached set
        let mut roots = self.roots.write().expect("roots lock poisoned");
        let to_remove: Vec<u64> = roots
            .iter()
            .copied()
            .take_while(|&s| s < min_slot)
            .collect();
        for s in &to_remove {
            roots.remove(s);
        }

        // Update cleanup marker
        let mut lowest = self
            .lowest_cleanup_slot
            .write()
            .expect("cleanup lock poisoned");
        if min_slot > *lowest {
            *lowest = min_slot;
        }

        Ok(purged)
    }

    /// Get or create a SlotMeta for the given slot.
    fn get_or_create_slot_meta(&self, slot: u64) -> Result<SlotMeta, BlockstoreError> {
        match self.get_slot_meta(slot)? {
            Some(meta) => Ok(meta),
            None => {
                let parent = if slot > 0 { Some(slot - 1) } else { None };
                Ok(SlotMeta::new(slot, parent))
            }
        }
    }

    /// Save slot metadata to the backend.
    fn save_slot_meta(&self, meta: &SlotMeta) -> Result<(), BlockstoreError> {
        let key = meta.slot.to_be_bytes();
        let data = meta.serialize();
        self.backend.put(CF_SLOT_META, &key, &data)
    }
}

/// Errors that can occur in blockstore operations.
#[derive(Debug)]
pub enum BlockstoreError {
    /// Storage backend operation failed.
    BackendError(String),
    /// Slot was not found.
    SlotNotFound(u64),
    /// Shred index is out of the allowed range.
    ShredIndexOutOfRange { slot: u64, index: u32 },
    /// Attempted to mark an already-dead slot as dead.
    SlotAlreadyDead(u64),
    /// Shred data is invalid (empty or corrupt).
    InvalidShredData,
    /// Deserialization of stored data failed.
    DeserializationError(String),
}

impl std::fmt::Display for BlockstoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendError(msg) => write!(f, "Backend error: {}", msg),
            Self::SlotNotFound(slot) => write!(f, "Slot not found: {}", slot),
            Self::ShredIndexOutOfRange { slot, index } => {
                write!(
                    f,
                    "Shred index out of range: slot={}, index={}",
                    slot, index
                )
            }
            Self::SlotAlreadyDead(slot) => write!(f, "Slot already dead: {}", slot),
            Self::InvalidShredData => write!(f, "Invalid shred data"),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for BlockstoreError {}
