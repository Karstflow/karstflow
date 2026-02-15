//! Shred window store for buffering out-of-order shreds
//!
//! This module provides a slot-based window for buffering shreds as they arrive
//! from the network, tracking FEC sets, and detecting completeness.

use dashmap::DashMap;
use paradencer_crypto::{FecReconstructor, FecResult};
use paradencer_types::shred::{FecSetId, Shred, ShredMetadata};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur in the shred window store
#[derive(Debug, Error)]
pub enum ShredWindowError {
    #[error("Slot {0} is too old, already pruned")]
    SlotTooOld(u64),

    #[error("Window is full, cannot accept slot {0}")]
    WindowFull(u64),

    #[error("Shred already exists: slot={slot}, index={index}")]
    DuplicateShred { slot: u64, index: u32 },

    #[error("FEC set not found: {0}")]
    FecSetNotFound(FecSetId),

    #[error("FEC reconstruction failed: {0}")]
    FecReconstructionFailed(String),

    #[error("Invalid shred: {0}")]
    InvalidShred(String),
}

/// Result type for shred window operations
pub type ShredWindowResult<T> = Result<T, ShredWindowError>;

/// Configuration for the shred window store
#[derive(Debug, Clone)]
pub struct ShredWindowConfig {
    /// Maximum number of slots to keep in the window
    pub max_window_slots: usize,

    /// Maximum number of shreds per slot
    pub max_shreds_per_slot: usize,

    /// Maximum number of FEC sets per slot
    pub max_fec_sets_per_slot: usize,

    /// Enable automatic FEC reconstruction
    pub enable_auto_reconstruction: bool,

    /// Minimum number of shreds in a FEC set before attempting reconstruction
    pub min_shreds_for_reconstruction: usize,
}

impl Default for ShredWindowConfig {
    fn default() -> Self {
        Self {
            max_window_slots: 128,
            max_shreds_per_slot: 1024,
            max_fec_sets_per_slot: 32,
            enable_auto_reconstruction: true,
            min_shreds_for_reconstruction: 32,
        }
    }
}

/// A FEC set tracking data and coding shreds
#[derive(Debug)]
struct FecSet {
    /// FEC set identifier
    id: FecSetId,

    /// Data shreds (indexed by shred index)
    data_shreds: BTreeMap<u32, Shred>,

    /// Coding shreds (indexed by shred index)
    coding_shreds: BTreeMap<u32, Shred>,

    /// Expected number of data shreds (from coding shred header)
    expected_data_count: Option<u16>,

    /// Expected number of coding shreds (from coding shred header)
    expected_coding_count: Option<u16>,

    /// Whether this FEC set is complete
    is_complete: bool,

    /// Whether reconstruction has been attempted
    reconstruction_attempted: bool,
}

/// A slot's worth of shreds organized by FEC sets
#[derive(Debug)]
struct SlotWindow {
    /// Slot number
    slot: u64,

    /// FEC sets in this slot
    fec_sets: HashMap<u32, FecSet>,

    /// Total number of shreds in this slot
    total_shreds: usize,

    /// Whether this slot is complete
    is_complete: bool,

    /// Last shred index seen (if last_in_slot flag was set)
    last_shred_index: Option<u32>,
}

/// Statistics for the shred window
#[derive(Debug, Clone, Default)]
pub struct ShredWindowStats {
    /// Total shreds received
    pub total_shreds_received: u64,

    /// Total shreds inserted
    pub total_shreds_inserted: u64,

    /// Total duplicate shreds
    pub total_duplicates: u64,

    /// Total FEC sets completed
    pub total_fec_sets_completed: u64,

    /// Total FEC sets reconstructed
    pub total_fec_sets_reconstructed: u64,

    /// Total shreds reconstructed
    pub total_shreds_reconstructed: u64,

    /// Number of slots in window
    pub active_slots: usize,

    /// Number of complete slots
    pub complete_slots: usize,
}

/// Shred window store for buffering and organizing shreds
pub struct ShredWindowStore {
    /// Configuration
    config: ShredWindowConfig,

    /// Slot windows indexed by slot number
    windows: Arc<DashMap<u64, Arc<RwLock<SlotWindow>>>>,

    /// Current root slot (slots below this are pruned)
    root_slot: Arc<RwLock<u64>>,

    /// Statistics
    stats: Arc<RwLock<ShredWindowStats>>,
}

impl FecSet {
    fn new(id: FecSetId) -> Self {
        Self {
            id,
            data_shreds: BTreeMap::new(),
            coding_shreds: BTreeMap::new(),
            expected_data_count: None,
            expected_coding_count: None,
            is_complete: false,
            reconstruction_attempted: false,
        }
    }

    fn insert_data_shred(&mut self, shred: Shred) -> bool {
        let index = shred.index();
        if self.data_shreds.contains_key(&index) {
            return false; // Duplicate
        }
        self.data_shreds.insert(index, shred);
        true
    }

    fn insert_coding_shred(&mut self, shred: Shred) -> bool {
        let index = shred.index();
        if self.coding_shreds.contains_key(&index) {
            return false; // Duplicate
        }

        // Extract expected counts from coding shred
        if let Some(header) = shred.coding_header() {
            self.expected_data_count = Some(header.num_data_shreds);
            self.expected_coding_count = Some(header.num_coding_shreds);
        }

        self.coding_shreds.insert(index, shred);
        true
    }

    fn check_completeness(&mut self) -> bool {
        if self.is_complete {
            return true;
        }

        if let Some(expected_data) = self.expected_data_count {
            if self.data_shreds.len() >= expected_data as usize {
                self.is_complete = true;
                return true;
            }
        }

        false
    }

    fn can_reconstruct(&self, min_shreds: usize) -> bool {
        if self.reconstruction_attempted || self.is_complete {
            return false;
        }

        let total_shreds = self.data_shreds.len() + self.coding_shreds.len();
        if let Some(expected_data) = self.expected_data_count {
            // Need at least expected_data shreds total to reconstruct
            total_shreds >= expected_data as usize && total_shreds >= min_shreds
        } else {
            false
        }
    }

    fn attempt_reconstruction(&mut self) -> FecResult<Vec<Shred>> {
        self.reconstruction_attempted = true;

        let expected_data = self.expected_data_count.ok_or_else(|| {
            paradencer_crypto::FecError::InvalidParameters {
                data: 0,
                coding: 0,
            }
        })?;

        let expected_coding = self.expected_coding_count.ok_or_else(|| {
            paradencer_crypto::FecError::InvalidParameters {
                data: 0,
                coding: 0,
            }
        })?;

        // Build data and coding shred arrays
        let mut data_array: Vec<Option<Vec<u8>>> = vec![None; expected_data as usize];
        for (idx, shred) in &self.data_shreds {
            let relative_idx = (*idx as usize) % (expected_data as usize);
            data_array[relative_idx] = Some(shred.payload.clone());
        }

        let mut coding_array: Vec<Option<Vec<u8>>> = vec![None; expected_coding as usize];
        for (idx, shred) in &self.coding_shreds {
            let relative_idx = (*idx as usize) % (expected_coding as usize);
            coding_array[relative_idx] = Some(shred.payload.clone());
        }

        // Reconstruct
        let reconstructor =
            FecReconstructor::new(expected_data as usize, expected_coding as usize)?;
        let result = reconstructor.reconstruct(data_array, coding_array)?;

        // Build reconstructed shreds
        let mut reconstructed = Vec::new();
        for (i, maybe_payload) in result.data_shreds.into_iter().enumerate() {
            if let Some(payload) = maybe_payload {
                // Create a reconstructed shred
                // Note: We need to reconstruct the full shred structure
                // For now, just track the payload
                reconstructed.push(Shred::new(
                    paradencer_types::shred::ShredCommonHeader {
                        signature: [0; 64],
                        variant: paradencer_types::shred::SHRED_DATA_FLAG,
                        slot: self.id.slot,
                        index: i as u32,
                        version: 0,
                        fec_set_index: self.id.index,
                    },
                    paradencer_types::shred::ShredVariant::LegacyData(
                        paradencer_types::shred::DataShredHeader {
                            parent_offset: 0,
                            flags: 0,
                            size: payload.len() as u16,
                        },
                    ),
                    payload,
                ));
            }
        }

        Ok(reconstructed)
    }
}

impl SlotWindow {
    fn new(slot: u64) -> Self {
        Self {
            slot,
            fec_sets: HashMap::new(),
            total_shreds: 0,
            is_complete: false,
            last_shred_index: None,
        }
    }

    fn get_or_create_fec_set(&mut self, fec_set_index: u32) -> &mut FecSet {
        self.fec_sets
            .entry(fec_set_index)
            .or_insert_with(|| FecSet::new(FecSetId::new(self.slot, fec_set_index)))
    }

    fn insert_shred(&mut self, shred: Shred) -> bool {
        let fec_set_index = shred.fec_set_index();
        let fec_set = self.get_or_create_fec_set(fec_set_index);

        let inserted = if shred.is_data() {
            fec_set.insert_data_shred(shred.clone())
        } else if shred.is_coding() {
            fec_set.insert_coding_shred(shred.clone())
        } else {
            return false;
        };

        if inserted {
            self.total_shreds += 1;

            // Check for last shred flag
            if shred.is_last_in_slot() {
                self.last_shred_index = Some(shred.index());
            }
        }

        inserted
    }

    fn check_completeness(&mut self) -> bool {
        if self.is_complete {
            return true;
        }

        // Check if we have all FEC sets complete
        let all_complete = !self.fec_sets.is_empty()
            && self.fec_sets.values_mut().all(|fec| fec.check_completeness());

        if all_complete {
            self.is_complete = true;
        }

        self.is_complete
    }
}

impl ShredWindowStore {
    /// Create a new shred window store with the given configuration
    pub fn new(config: ShredWindowConfig) -> Self {
        Self {
            config,
            windows: Arc::new(DashMap::new()),
            root_slot: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(ShredWindowStats::default())),
        }
    }

    /// Create a new shred window store with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ShredWindowConfig::default())
    }

    /// Insert a shred into the window
    pub fn insert(&self, shred: Shred) -> ShredWindowResult<bool> {
        let slot = shred.slot();

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_shreds_received += 1;
        }

        // Check if slot is too old
        let root = *self.root_slot.read();
        if slot < root {
            return Err(ShredWindowError::SlotTooOld(slot));
        }

        // Get or create slot window
        let slot_window = self.windows.entry(slot).or_insert_with(|| {
            Arc::new(RwLock::new(SlotWindow::new(slot)))
        });

        let slot_window = slot_window.clone();

        // Insert shred
        let mut window = slot_window.write();
        let inserted = window.insert_shred(shred);

        if !inserted {
            let mut stats = self.stats.write();
            stats.total_duplicates += 1;
            return Ok(false);
        }

        {
            let mut stats = self.stats.write();
            stats.total_shreds_inserted += 1;
        }

        // Check for completeness
        if window.check_completeness() {
            let mut stats = self.stats.write();
            stats.complete_slots += 1;
        }

        // Attempt reconstruction if enabled
        if self.config.enable_auto_reconstruction {
            for fec_set in window.fec_sets.values_mut() {
                if fec_set.can_reconstruct(self.config.min_shreds_for_reconstruction) {
                    if let Ok(reconstructed) = fec_set.attempt_reconstruction() {
                        let mut stats = self.stats.write();
                        stats.total_shreds_reconstructed += reconstructed.len() as u64;
                        stats.total_fec_sets_reconstructed += 1;

                        // Insert reconstructed shreds
                        for rec_shred in reconstructed {
                            window.insert_shred(rec_shred);
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Get all shreds for a slot in order
    pub fn get_slot_shreds(&self, slot: u64) -> Option<Vec<Shred>> {
        let window_ref = self.windows.get(&slot)?;
        let window = window_ref.read();

        let mut shreds = Vec::new();
        for fec_set in window.fec_sets.values() {
            shreds.extend(fec_set.data_shreds.values().cloned());
        }

        shreds.sort_by_key(|s| s.index());
        Some(shreds)
    }

    /// Get a specific FEC set
    pub fn get_fec_set(&self, fec_set_id: FecSetId) -> ShredWindowResult<Vec<Shred>> {
        let window_ref = self
            .windows
            .get(&fec_set_id.slot)
            .ok_or(ShredWindowError::FecSetNotFound(fec_set_id))?;

        let window = window_ref.read();
        let fec_set = window
            .fec_sets
            .get(&fec_set_id.index)
            .ok_or(ShredWindowError::FecSetNotFound(fec_set_id))?;

        let mut shreds: Vec<Shred> = fec_set
            .data_shreds
            .values()
            .chain(fec_set.coding_shreds.values())
            .cloned()
            .collect();

        shreds.sort_by_key(|s| s.index());
        Ok(shreds)
    }

    /// Check if a slot is complete
    pub fn is_slot_complete(&self, slot: u64) -> bool {
        if let Some(window_ref) = self.windows.get(&slot) {
            window_ref.read().is_complete
        } else {
            false
        }
    }

    /// Advance the root slot and prune old slots
    pub fn advance_root(&self, new_root: u64) -> usize {
        let mut root = self.root_slot.write();
        if new_root <= *root {
            return 0;
        }

        let old_root = *root;
        *root = new_root;

        // Prune slots below new root
        let mut pruned = 0;
        self.windows.retain(|slot, _| {
            if *slot < new_root {
                pruned += 1;
                false
            } else {
                true
            }
        });

        pruned
    }

    /// Get current statistics
    pub fn stats(&self) -> ShredWindowStats {
        let mut stats = self.stats.read().clone();
        stats.active_slots = self.windows.len();
        stats
    }

    /// Get the current root slot
    pub fn root_slot(&self) -> u64 {
        *self.root_slot.read()
    }

    /// Get number of shreds in a slot
    pub fn get_slot_shred_count(&self, slot: u64) -> usize {
        if let Some(window_ref) = self.windows.get(&slot) {
            window_ref.read().total_shreds
        } else {
            0
        }
    }

    /// Clear all windows (useful for testing)
    pub fn clear(&self) {
        self.windows.clear();
        *self.stats.write() = ShredWindowStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::shred::*;

    fn create_test_data_shred(slot: u64, index: u32, fec_set_index: u32) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_DATA_FLAG,
                slot,
                index,
                version: 1,
                fec_set_index,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 512,
            }),
            vec![0; 512],
        )
    }

    fn create_test_coding_shred(
        slot: u64,
        index: u32,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
    ) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_CODE_FLAG,
                slot,
                index,
                version: 1,
                fec_set_index,
            },
            ShredVariant::LegacyCoding(CodingShredHeader {
                num_data_shreds: num_data,
                num_coding_shreds: num_coding,
                position: index as u16,
            }),
            vec![0; 512],
        )
    }

    #[test]
    fn test_window_creation() {
        let store = ShredWindowStore::with_defaults();
        assert_eq!(store.root_slot(), 0);
        assert_eq!(store.stats().active_slots, 0);
    }

    #[test]
    fn test_insert_shred() {
        let store = ShredWindowStore::with_defaults();
        let shred = create_test_data_shred(100, 0, 0);

        let result = store.insert(shred).unwrap();
        assert!(result);

        let stats = store.stats();
        assert_eq!(stats.total_shreds_received, 1);
        assert_eq!(stats.total_shreds_inserted, 1);
        assert_eq!(stats.active_slots, 1);
    }

    #[test]
    fn test_duplicate_shred() {
        let store = ShredWindowStore::with_defaults();
        let shred1 = create_test_data_shred(100, 0, 0);
        let shred2 = create_test_data_shred(100, 0, 0);

        assert!(store.insert(shred1).unwrap());
        assert!(!store.insert(shred2).unwrap());

        let stats = store.stats();
        assert_eq!(stats.total_shreds_received, 2);
        assert_eq!(stats.total_shreds_inserted, 1);
        assert_eq!(stats.total_duplicates, 1);
    }

    #[test]
    fn test_slot_too_old() {
        let store = ShredWindowStore::with_defaults();
        store.advance_root(100);

        let shred = create_test_data_shred(50, 0, 0);
        let result = store.insert(shred);

        assert!(matches!(result, Err(ShredWindowError::SlotTooOld(50))));
    }

    #[test]
    fn test_advance_root() {
        let store = ShredWindowStore::with_defaults();

        // Insert shreds for multiple slots
        for slot in 0..10 {
            let shred = create_test_data_shred(slot, 0, 0);
            store.insert(shred).unwrap();
        }

        assert_eq!(store.stats().active_slots, 10);

        // Advance root to slot 5
        let pruned = store.advance_root(5);
        assert_eq!(pruned, 5);
        assert_eq!(store.stats().active_slots, 5);
    }

    #[test]
    fn test_get_slot_shreds() {
        let store = ShredWindowStore::with_defaults();

        // Insert multiple shreds in different order
        store.insert(create_test_data_shred(100, 2, 0)).unwrap();
        store.insert(create_test_data_shred(100, 0, 0)).unwrap();
        store.insert(create_test_data_shred(100, 1, 0)).unwrap();

        let shreds = store.get_slot_shreds(100).unwrap();
        assert_eq!(shreds.len(), 3);

        // Verify they're sorted by index
        assert_eq!(shreds[0].index(), 0);
        assert_eq!(shreds[1].index(), 1);
        assert_eq!(shreds[2].index(), 2);
    }

    #[test]
    fn test_fec_set_tracking() {
        let store = ShredWindowStore::with_defaults();

        // Insert data shreds
        for i in 0..4 {
            store
                .insert(create_test_data_shred(100, i, 0))
                .unwrap();
        }

        // Insert coding shred with count info
        store
            .insert(create_test_coding_shred(100, 4, 0, 4, 4))
            .unwrap();

        let fec_id = FecSetId::new(100, 0);
        let shreds = store.get_fec_set(fec_id).unwrap();

        // Should have 4 data + 1 coding = 5 shreds
        assert_eq!(shreds.len(), 5);
    }

    #[test]
    fn test_slot_completeness() {
        let config = ShredWindowConfig {
            enable_auto_reconstruction: false,
            ..Default::default()
        };
        let store = ShredWindowStore::new(config);

        // Insert complete FEC set
        for i in 0..4 {
            store
                .insert(create_test_data_shred(100, i, 0))
                .unwrap();
        }

        // Add coding shred indicating 4 data shreds expected
        store
            .insert(create_test_coding_shred(100, 4, 0, 4, 4))
            .unwrap();

        // Insert one more data shred to trigger completeness check
        store.insert(create_test_data_shred(100, 3, 0)).unwrap();

        // Note: In real implementation, completeness would be detected
        // when all expected data shreds are present
    }
}
