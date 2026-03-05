//! FEC (Forward Error Correction) set completion tracking.
//!
//! Tracks which data and coding shreds have been received for each
//! FEC set, and detects when a set is complete (all data shreds received,
//! or enough combined shreds for erasure recovery).

use super::backend::BlockstoreBackend;
use super::meta::ErasureMeta;
use super::BlockstoreError;
use karstflow_constants::blockstore::CF_ERASURE_META;
use std::collections::HashSet;

/// Tracks FEC set completion state.
///
/// Each FEC set consists of `num_data` data shreds and `num_coding`
/// coding shreds. The set is "complete" when all data shreds are
/// received. The set is "recoverable" when at least `num_data` total
/// shreds (data + coding combined) are available.
pub struct FecTracker<'a> {
    backend: &'a BlockstoreBackend,
}

/// Result of inserting a shred into an FEC set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecInsertResult {
    /// Shred accepted, set still incomplete.
    Incomplete,
    /// All data shreds received — set is complete without recovery.
    Complete,
    /// Enough shreds received for erasure recovery.
    Recoverable,
    /// Shred was a duplicate (already received this index).
    Duplicate,
}

/// Serialized FEC set state stored in the backend.
///
/// Format:
///   num_data_shreds: u16 (2 bytes)
///   num_coding_shreds: u16 (2 bytes)
///   received_data_count: u16 (2 bytes)
///   received_coding_count: u16 (2 bytes)
///   received_data_indices: [u32] (4 bytes each)
///   received_coding_indices: [u32] (4 bytes each)
struct FecSetState {
    num_data_shreds: u16,
    num_coding_shreds: u16,
    received_data: HashSet<u32>,
    received_coding: HashSet<u32>,
}

impl FecSetState {
    fn new(num_data: u16, num_coding: u16) -> Self {
        Self {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            received_data: HashSet::new(),
            received_coding: HashSet::new(),
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(8 + self.received_data.len() * 4 + self.received_coding.len() * 4);
        buf.extend_from_slice(&self.num_data_shreds.to_be_bytes());
        buf.extend_from_slice(&self.num_coding_shreds.to_be_bytes());
        buf.extend_from_slice(&(self.received_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.received_coding.len() as u16).to_be_bytes());
        let mut data_indices: Vec<u32> = self.received_data.iter().copied().collect();
        data_indices.sort_unstable();
        for idx in &data_indices {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        let mut coding_indices: Vec<u32> = self.received_coding.iter().copied().collect();
        coding_indices.sort_unstable();
        for idx in &coding_indices {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, BlockstoreError> {
        if data.len() < 8 {
            return Err(BlockstoreError::DeserializationError(
                "FEC state too short".to_string(),
            ));
        }
        let num_data = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let num_coding = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let data_count = u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize;
        let coding_count = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;

        let mut pos = 8;
        let mut received_data = HashSet::with_capacity(data_count);
        for _ in 0..data_count {
            if pos + 4 > data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "FEC state truncated (data indices)".to_string(),
                ));
            }
            received_data.insert(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
            pos += 4;
        }
        let mut received_coding = HashSet::with_capacity(coding_count);
        for _ in 0..coding_count {
            if pos + 4 > data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "FEC state truncated (coding indices)".to_string(),
                ));
            }
            received_coding.insert(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
            pos += 4;
        }

        Ok(Self {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            received_data,
            received_coding,
        })
    }

    fn is_complete(&self) -> bool {
        self.received_data.len() as u16 >= self.num_data_shreds
    }

    fn is_recoverable(&self) -> bool {
        let total_received = self.received_data.len() + self.received_coding.len();
        total_received >= self.num_data_shreds as usize
    }
}

impl<'a> FecTracker<'a> {
    pub fn new(backend: &'a BlockstoreBackend) -> Self {
        Self { backend }
    }

    /// Record a received data shred in an FEC set.
    ///
    /// `fec_set_index` is the base index of the FEC set within the slot.
    /// `shred_index` is the index of this specific data shred.
    pub fn record_data_shred(
        &self,
        slot: u64,
        fec_set_index: u32,
        shred_index: u32,
        num_data: u16,
        num_coding: u16,
    ) -> Result<FecInsertResult, BlockstoreError> {
        let key = fec_key(slot, fec_set_index);
        let mut state = self.load_or_create(slot, fec_set_index, num_data, num_coding)?;

        if !state.received_data.insert(shred_index) {
            return Ok(FecInsertResult::Duplicate);
        }

        self.backend
            .put(CF_ERASURE_META, &key, &state.serialize())?;

        if state.is_complete() {
            Ok(FecInsertResult::Complete)
        } else if state.is_recoverable() {
            Ok(FecInsertResult::Recoverable)
        } else {
            Ok(FecInsertResult::Incomplete)
        }
    }

    /// Record a received coding shred in an FEC set.
    pub fn record_coding_shred(
        &self,
        slot: u64,
        fec_set_index: u32,
        shred_index: u32,
        num_data: u16,
        num_coding: u16,
    ) -> Result<FecInsertResult, BlockstoreError> {
        let key = fec_key(slot, fec_set_index);
        let mut state = self.load_or_create(slot, fec_set_index, num_data, num_coding)?;

        if !state.received_coding.insert(shred_index) {
            return Ok(FecInsertResult::Duplicate);
        }

        self.backend
            .put(CF_ERASURE_META, &key, &state.serialize())?;

        if state.is_complete() {
            Ok(FecInsertResult::Complete)
        } else if state.is_recoverable() {
            Ok(FecInsertResult::Recoverable)
        } else {
            Ok(FecInsertResult::Incomplete)
        }
    }

    /// Get the erasure metadata for an FEC set.
    pub fn get_erasure_meta(
        &self,
        slot: u64,
        fec_set_index: u32,
    ) -> Result<Option<ErasureMeta>, BlockstoreError> {
        let key = fec_key(slot, fec_set_index);
        match self.backend.get(CF_ERASURE_META, &key)? {
            Some(data) => {
                let state = FecSetState::deserialize(&data)?;
                Ok(Some(ErasureMeta::new(
                    slot,
                    fec_set_index,
                    state.num_data_shreds as u32,
                    state.num_coding_shreds as u32,
                )))
            }
            None => Ok(None),
        }
    }

    /// Check if an FEC set is complete.
    pub fn is_fec_set_complete(
        &self,
        slot: u64,
        fec_set_index: u32,
    ) -> Result<bool, BlockstoreError> {
        let key = fec_key(slot, fec_set_index);
        match self.backend.get(CF_ERASURE_META, &key)? {
            Some(data) => {
                let state = FecSetState::deserialize(&data)?;
                Ok(state.is_complete())
            }
            None => Ok(false),
        }
    }

    fn load_or_create(
        &self,
        _slot: u64,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
    ) -> Result<FecSetState, BlockstoreError> {
        let key = fec_key(_slot, fec_set_index);
        match self.backend.get(CF_ERASURE_META, &key)? {
            Some(data) => FecSetState::deserialize(&data),
            None => Ok(FecSetState::new(num_data, num_coding)),
        }
    }
}

/// Encode FEC set key as slot (u64 BE) + fec_set_index (u32 BE).
fn fec_key(slot: u64, fec_set_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&slot.to_be_bytes());
    key.extend_from_slice(&fec_set_index.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::backend::BlockstoreBackend;

    fn backend() -> BlockstoreBackend {
        BlockstoreBackend::in_memory()
    }

    #[test]
    fn track_data_shreds_to_completion() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        // FEC set with 3 data shreds and 2 coding shreds.
        let r1 = tracker.record_data_shred(1, 0, 0, 3, 2).unwrap();
        assert_eq!(r1, FecInsertResult::Incomplete);

        let r2 = tracker.record_data_shred(1, 0, 1, 3, 2).unwrap();
        assert_eq!(r2, FecInsertResult::Incomplete);

        let r3 = tracker.record_data_shred(1, 0, 2, 3, 2).unwrap();
        assert_eq!(r3, FecInsertResult::Complete);
    }

    #[test]
    fn coding_shreds_enable_recovery() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        // FEC set: 3 data, 2 coding. Need 3 total for recovery.
        let r1 = tracker.record_data_shred(1, 0, 0, 3, 2).unwrap();
        assert_eq!(r1, FecInsertResult::Incomplete);

        let r2 = tracker.record_data_shred(1, 0, 1, 3, 2).unwrap();
        assert_eq!(r2, FecInsertResult::Incomplete);

        // Add a coding shred — now we have 2 data + 1 coding = 3 total = recoverable.
        let r3 = tracker.record_coding_shred(1, 0, 0, 3, 2).unwrap();
        assert_eq!(r3, FecInsertResult::Recoverable);
    }

    #[test]
    fn duplicate_shred_detected() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        tracker.record_data_shred(1, 0, 0, 3, 2).unwrap();
        let dup = tracker.record_data_shred(1, 0, 0, 3, 2).unwrap();
        assert_eq!(dup, FecInsertResult::Duplicate);
    }

    #[test]
    fn erasure_meta_retrieval() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        tracker.record_data_shred(5, 10, 0, 4, 3).unwrap();
        let meta = tracker.get_erasure_meta(5, 10).unwrap().unwrap();
        assert_eq!(meta.slot, 5);
        assert_eq!(meta.fec_set_index, 10);
        assert_eq!(meta.num_data_shreds, 4);
        assert_eq!(meta.num_coding_shreds, 3);
    }

    #[test]
    fn fec_set_complete_query() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        assert!(!tracker.is_fec_set_complete(1, 0).unwrap());

        tracker.record_data_shred(1, 0, 0, 1, 1).unwrap();
        assert!(tracker.is_fec_set_complete(1, 0).unwrap());
    }

    #[test]
    fn multiple_fec_sets_independent() {
        let b = backend();
        let tracker = FecTracker::new(&b);

        tracker.record_data_shred(1, 0, 0, 2, 1).unwrap();
        tracker.record_data_shred(1, 10, 10, 3, 1).unwrap();

        // First set needs 1 more data shred.
        assert!(!tracker.is_fec_set_complete(1, 0).unwrap());
        // Second set needs 2 more.
        assert!(!tracker.is_fec_set_complete(1, 10).unwrap());
    }

    #[test]
    fn nonexistent_fec_set_returns_none() {
        let b = backend();
        let tracker = FecTracker::new(&b);
        assert!(tracker.get_erasure_meta(99, 0).unwrap().is_none());
    }

    #[test]
    fn state_serialization_roundtrip() {
        let mut state = FecSetState::new(5, 3);
        state.received_data.insert(0);
        state.received_data.insert(2);
        state.received_data.insert(4);
        state.received_coding.insert(1);

        let bytes = state.serialize();
        let restored = FecSetState::deserialize(&bytes).unwrap();

        assert_eq!(restored.num_data_shreds, 5);
        assert_eq!(restored.num_coding_shreds, 3);
        assert_eq!(restored.received_data.len(), 3);
        assert_eq!(restored.received_coding.len(), 1);
        assert!(restored.received_data.contains(&0));
        assert!(restored.received_data.contains(&2));
        assert!(restored.received_data.contains(&4));
        assert!(restored.received_coding.contains(&1));
    }
}
