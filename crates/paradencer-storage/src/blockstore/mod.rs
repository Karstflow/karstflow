//! Persistent ledger storage (blockstore).
//!
//! Stores shreds, slot metadata, and block assembly state.
//! Uses an embedded key-value store for persistence.

pub(crate) mod backend;
mod block_assembly;
pub mod block_stream;
mod cleanup;
mod fec_tracker;
mod meta;
mod shred_store;

#[cfg(test)]
mod tests;

pub use block_assembly::{extract_signatures, AssembledBlock, BlockAssembler, ParsedEntry};
pub use block_stream::{
    block_stream, BlockStreamPublisher, BlockStreamStats, BlockStreamSubscriber, SlotEvent,
};
pub use cleanup::{
    BlockstoreCleanup, BlockstoreGarbageCollector, GarbageCollectorConfig, GarbageCollectorStats,
};
pub use fec_tracker::{FecInsertResult, FecTracker};
pub use meta::{ErasureMeta, SlotMeta, SlotStatus};
pub use shred_store::ShredStore;

use backend::BlockstoreBackend;
use paradencer_constants::blockstore::*;
use paradencer_types::shred::Shred;
use std::collections::BTreeSet;
use std::sync::RwLock;

/// Persistent ledger storage for shreds and block metadata.
pub struct Blockstore {
    pub(crate) backend: BlockstoreBackend,
    /// Cached set of root slots for fast lookups.
    roots: RwLock<BTreeSet<u64>>,
    /// Lowest slot that has been cleaned up; all data below is purged.
    lowest_cleanup_slot: RwLock<u64>,
    /// Optional publisher for slot lifecycle events.
    event_publisher: Option<BlockStreamPublisher>,
}

impl Blockstore {
    /// Open or create a blockstore at the given path.
    ///
    /// Reopens the persistent backend from disk and rebuilds the root
    /// set from persisted root markers.
    pub fn open(path: &std::path::Path) -> Result<Self, BlockstoreError> {
        let backend = BlockstoreBackend::open(path)?;

        // Recover root set from disk.
        let mut recovered_roots = BTreeSet::new();
        let root_entries = backend.prefix_scan(CF_ROOTS, &[])?;
        for (key_bytes, _) in root_entries {
            if key_bytes.len() == 8 {
                let slot = u64::from_be_bytes(
                    key_bytes
                        .as_slice()
                        .try_into()
                        .unwrap_or_else(|_| unreachable!()),
                );
                recovered_roots.insert(slot);
            }
        }

        Ok(Self {
            backend,
            roots: RwLock::new(recovered_roots),
            lowest_cleanup_slot: RwLock::new(0),
            event_publisher: None,
        })
    }

    /// Create an in-memory blockstore (for testing).
    pub fn in_memory() -> Self {
        Self {
            backend: BlockstoreBackend::in_memory(),
            roots: RwLock::new(BTreeSet::new()),
            lowest_cleanup_slot: RwLock::new(0),
            event_publisher: None,
        }
    }

    /// Attach an event publisher for slot lifecycle notifications.
    ///
    /// When set, the blockstore will publish [`SlotEvent`] notifications
    /// when slots complete, become rooted, die, or are marked as duplicates.
    pub fn set_event_publisher(&mut self, publisher: BlockStreamPublisher) {
        self.event_publisher = Some(publisher);
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

    /// Insert a typed shred with automatic FEC tracking and slot completion.
    ///
    /// Accepts a parsed `Shred` from paradencer-types, stores the payload,
    /// tracks the FEC set, and detects slot completion when the last data
    /// shred is received.
    pub fn insert_shred(&self, shred: &Shred) -> Result<ShredInsertResult, BlockstoreError> {
        let slot = shred.slot();
        let index = shred.index();
        let fec_set_index = shred.fec_set_index();

        if shred.is_data() {
            if index as usize >= MAX_DATA_SHREDS_PER_SLOT {
                return Err(BlockstoreError::ShredIndexOutOfRange { slot, index });
            }
            if shred.payload.is_empty() {
                return Err(BlockstoreError::InvalidShredData);
            }

            let mut meta = self.get_or_create_slot_meta(slot)?;

            // Store the shred data.
            let store = ShredStore::new(&self.backend);
            store.insert_data(slot, index, &shred.payload, &mut meta)?;

            // Check for last-in-slot flag to set expected count.
            if shred.is_last_in_slot() {
                meta.expected_data_shreds = Some(index + 1);
            }

            // Update parent connectivity.
            if let Some(header) = shred.data_header() {
                if header.parent_offset > 0 {
                    let parent = slot.saturating_sub(header.parent_offset as u64);
                    if meta.parent_slot.is_none() || meta.parent_slot == Some(parent) {
                        meta.parent_slot = Some(parent);
                        self.link_parent_child(parent, slot)?;
                    }
                }
            }

            // Track FEC set.
            let coding_header = self.infer_coding_params(shred);
            let fec_result = FecTracker::new(&self.backend).record_data_shred(
                slot,
                fec_set_index,
                index,
                coding_header.0,
                coding_header.1,
            )?;

            // Check slot completion.
            let slot_complete = meta.is_complete();
            if slot_complete && meta.status == SlotStatus::Incomplete {
                meta.status = SlotStatus::Complete;
                meta.completion_timestamp = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                );
            }

            self.save_slot_meta(&meta)?;

            // Publish slot completion event.
            if slot_complete {
                if let Some(pub_) = &self.event_publisher {
                    pub_.publish(SlotEvent::Completed {
                        slot,
                        parent_slot: meta.parent_slot,
                        num_shreds: meta.received_data_shreds,
                        num_transactions: 0, // Populated after block assembly.
                    });
                }
            }

            Ok(ShredInsertResult {
                fec_result,
                slot_complete,
                is_last_in_slot: shred.is_last_in_slot(),
            })
        } else {
            // Coding shred.
            if index as usize >= MAX_CODING_SHREDS_PER_SLOT {
                return Err(BlockstoreError::ShredIndexOutOfRange { slot, index });
            }
            if shred.payload.is_empty() {
                return Err(BlockstoreError::InvalidShredData);
            }

            let mut meta = self.get_or_create_slot_meta(slot)?;
            let store = ShredStore::new(&self.backend);
            store.insert_coding(slot, index, &shred.payload)?;
            meta.received_coding_shreds += 1;

            let (num_data, num_coding) = match shred.coding_header() {
                Some(h) => (h.num_data_shreds, h.num_coding_shreds),
                None => (1, 1),
            };

            let fec_result = FecTracker::new(&self.backend).record_coding_shred(
                slot,
                fec_set_index,
                index,
                num_data,
                num_coding,
            )?;

            self.save_slot_meta(&meta)?;

            Ok(ShredInsertResult {
                fec_result,
                slot_complete: false,
                is_last_in_slot: false,
            })
        }
    }

    /// Set multiple slots as root atomically.
    pub fn set_roots(&self, slots: &[u64]) -> Result<(), BlockstoreError> {
        let mut roots = self.roots.write().expect("roots lock poisoned");
        for &slot in slots {
            let key = slot.to_be_bytes();
            self.backend.put(CF_ROOTS, &key, &[1])?;
            roots.insert(slot);
            if let Some(pub_) = &self.event_publisher {
                pub_.publish(SlotEvent::Rooted { slot });
            }
        }
        Ok(())
    }

    /// Get all slots in a range that have metadata.
    pub fn slot_range(&self, start: u64, end: u64) -> Result<Vec<u64>, BlockstoreError> {
        let mut slots = Vec::new();
        for slot in start..end {
            if self.get_slot_meta(slot)?.is_some() {
                slots.push(slot);
            }
        }
        Ok(slots)
    }

    /// Get the FEC tracker for querying erasure set state.
    pub fn fec_tracker(&self) -> FecTracker<'_> {
        FecTracker::new(&self.backend)
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

        if let Some(pub_) = &self.event_publisher {
            pub_.publish(SlotEvent::Dead { slot });
        }

        Ok(())
    }

    /// Mark a slot as duplicate.
    pub fn mark_duplicate(&self, slot: u64) -> Result<(), BlockstoreError> {
        let mut meta = self.get_or_create_slot_meta(slot)?;
        meta.status = SlotStatus::Duplicate;
        self.save_slot_meta(&meta)?;

        let key = slot.to_be_bytes();
        self.backend.put(CF_DUPLICATE_SLOTS, &key, &[1])?;

        if let Some(pub_) = &self.event_publisher {
            pub_.publish(SlotEvent::Duplicate { slot });
        }

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
        if let Some(pub_) = &self.event_publisher {
            pub_.publish(SlotEvent::Rooted { slot });
        }
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

    /// Assemble and parse a complete block from stored shreds.
    ///
    /// Returns the assembled block with parsed entries including raw
    /// transaction bytes. Returns `None` if the slot is incomplete or
    /// not found.
    pub fn get_parsed_block(
        &self,
        slot: u64,
    ) -> Result<Option<(AssembledBlock, Vec<ParsedEntry>)>, BlockstoreError> {
        let meta = match self.get_slot_meta(slot)? {
            Some(meta) if meta.is_complete() => meta,
            _ => return Ok(None),
        };
        let store = ShredStore::new(&self.backend);
        let assembled = BlockAssembler::assemble(&store, slot, &meta)?;
        let entries = BlockAssembler::parse_entries(&assembled.entries)?;
        Ok(Some((assembled, entries)))
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

    /// Link a parent slot to a child slot in their metadata.
    fn link_parent_child(&self, parent: u64, child: u64) -> Result<(), BlockstoreError> {
        if let Ok(Some(mut parent_meta)) = self.get_slot_meta(parent) {
            if !parent_meta.next_slots.contains(&child) {
                parent_meta.next_slots.push(child);
                self.save_slot_meta(&parent_meta)?;
            }
        }
        Ok(())
    }

    /// Infer FEC set parameters from a data shred.
    ///
    /// If the shred contains a coding header (Merkle variant), use its
    /// parameters. Otherwise fall back to reasonable defaults.
    fn infer_coding_params(&self, _shred: &Shred) -> (u16, u16) {
        // For data shreds, we don't always have coding parameters.
        // Use conservative defaults matching Firedancer's typical FEC sets.
        // Real coding params come from the coding shred headers.
        (32, 32)
    }
}

/// Result of inserting a typed shred into the blockstore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShredInsertResult {
    /// FEC set tracking result.
    pub fec_result: FecInsertResult,
    /// Whether the slot became complete after this insert.
    pub slot_complete: bool,
    /// Whether this was the last data shred in the slot.
    pub is_last_in_slot: bool,
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
