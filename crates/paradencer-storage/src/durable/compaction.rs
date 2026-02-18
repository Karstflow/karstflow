// Data compaction for the durable store.
//
// Removes stale records below a minimum slot threshold to reclaim
// disk space. Operates on both account and blockstore column families.

use paradencer_constants::durable_store::{
    CF_BLOCK_HEIGHT, CF_CODE_SHRED, CF_DATA_SHRED, CF_DEAD_SLOTS, CF_DUPLICATE_SLOTS,
    CF_ERASURE_META, CF_ROOTS, CF_SLOT_META,
};

use super::DurableStore;
use crate::StorageError;

/// Statistics from a compaction operation.
#[derive(Debug, Clone, Default)]
pub struct CompactionStats {
    /// Total number of records removed.
    pub records_removed: u64,
    /// Approximate bytes reclaimed (from removed record sizes).
    pub bytes_reclaimed: u64,
    /// Number of column families compacted.
    pub families_compacted: u64,
}

/// Slot-keyed column families eligible for compaction.
///
/// All these CFs use 8-byte big-endian slot numbers as keys (or key prefixes).
const SLOT_KEYED_CFS: &[&str] = &[
    CF_SLOT_META,
    CF_DATA_SHRED,
    CF_CODE_SHRED,
    CF_DEAD_SLOTS,
    CF_DUPLICATE_SLOTS,
    CF_ROOTS,
    CF_ERASURE_META,
    CF_BLOCK_HEIGHT,
];

/// Remove all slot-keyed records below `min_slot` from the durable store.
///
/// Scans each blockstore column family for keys whose leading 8 bytes
/// (interpreted as a big-endian u64 slot number) are below `min_slot`,
/// and deletes them.
pub fn compact_below_slot(
    store: &dyn DurableStore,
    min_slot: u64,
) -> Result<CompactionStats, StorageError> {
    let mut stats = CompactionStats::default();

    for &cf in SLOT_KEYED_CFS {
        // Scan all keys in this CF.
        let entries = store.prefix_scan(cf, &[])?;
        let mut removed_in_cf = 0u64;

        for (key, value) in &entries {
            // Extract slot from the first 8 bytes of the key.
            if key.len() >= 8 {
                let slot =
                    u64::from_be_bytes(key[..8].try_into().unwrap_or_else(|_| unreachable!()));
                if slot < min_slot {
                    // Approximate byte cost of this record.
                    stats.bytes_reclaimed += (key.len() + value.len()) as u64;
                    store.delete(cf, key)?;
                    removed_in_cf += 1;
                }
            }
        }

        if removed_in_cf > 0 {
            stats.records_removed += removed_in_cf;
            stats.families_compacted += 1;
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable::FileDurableStore;
    use std::sync::Arc;

    fn test_store() -> Arc<FileDurableStore> {
        FileDurableStore::temporary()
            .expect("temporary store")
            .into_arc()
    }

    #[test]
    fn compact_empty_store() {
        let store = test_store();
        let stats = compact_below_slot(store.as_ref(), 100).expect("compact");
        assert_eq!(stats.records_removed, 0);
        assert_eq!(stats.families_compacted, 0);
    }

    #[test]
    fn compact_removes_old_slot_meta() {
        let store = test_store();

        // Insert slot meta for slots 5, 10, 15.
        for slot in [5u64, 10, 15] {
            store
                .put(CF_SLOT_META, &slot.to_be_bytes(), b"meta")
                .unwrap();
        }

        let stats = compact_below_slot(store.as_ref(), 12).expect("compact");
        assert_eq!(stats.records_removed, 2); // slots 5 and 10
        assert_eq!(stats.families_compacted, 1);

        // Slot 15 should remain.
        assert!(store
            .get(CF_SLOT_META, &15u64.to_be_bytes())
            .unwrap()
            .is_some());
        // Slots 5 and 10 should be gone.
        assert!(store
            .get(CF_SLOT_META, &5u64.to_be_bytes())
            .unwrap()
            .is_none());
        assert!(store
            .get(CF_SLOT_META, &10u64.to_be_bytes())
            .unwrap()
            .is_none());
    }

    #[test]
    fn compact_removes_from_multiple_cfs() {
        let store = test_store();

        let old_slot = 5u64.to_be_bytes();
        let new_slot = 15u64.to_be_bytes();

        store.put(CF_SLOT_META, &old_slot, b"meta").unwrap();
        store.put(CF_SLOT_META, &new_slot, b"meta").unwrap();
        store.put(CF_ROOTS, &old_slot, &[1]).unwrap();
        store.put(CF_ROOTS, &new_slot, &[1]).unwrap();
        store.put(CF_DEAD_SLOTS, &old_slot, &[1]).unwrap();

        let stats = compact_below_slot(store.as_ref(), 10).expect("compact");
        assert_eq!(stats.records_removed, 3); // one from each of 3 CFs
        assert_eq!(stats.families_compacted, 3);
    }

    #[test]
    fn compact_shred_data_with_composite_key() {
        let store = test_store();

        // Data shreds use slot (8 bytes) + index (4 bytes) as key.
        let mut old_key = Vec::new();
        old_key.extend_from_slice(&5u64.to_be_bytes());
        old_key.extend_from_slice(&0u32.to_be_bytes());

        let mut new_key = Vec::new();
        new_key.extend_from_slice(&15u64.to_be_bytes());
        new_key.extend_from_slice(&0u32.to_be_bytes());

        store.put(CF_DATA_SHRED, &old_key, b"old_shred").unwrap();
        store.put(CF_DATA_SHRED, &new_key, b"new_shred").unwrap();

        let stats = compact_below_slot(store.as_ref(), 10).expect("compact");
        assert_eq!(stats.records_removed, 1);

        // New shred should remain.
        assert!(store.get(CF_DATA_SHRED, &new_key).unwrap().is_some());
        // Old shred should be gone.
        assert!(store.get(CF_DATA_SHRED, &old_key).unwrap().is_none());
    }

    #[test]
    fn compact_at_slot_zero_removes_nothing() {
        let store = test_store();
        store
            .put(CF_SLOT_META, &0u64.to_be_bytes(), b"genesis")
            .unwrap();
        store
            .put(CF_SLOT_META, &1u64.to_be_bytes(), b"slot1")
            .unwrap();

        let stats = compact_below_slot(store.as_ref(), 0).expect("compact");
        assert_eq!(stats.records_removed, 0);
    }

    #[test]
    fn compact_tracks_bytes_reclaimed() {
        let store = test_store();

        let big_value = vec![0xAA; 1024];
        store
            .put(CF_DATA_SHRED, &1u64.to_be_bytes(), &big_value)
            .unwrap();

        let stats = compact_below_slot(store.as_ref(), 100).expect("compact");
        assert!(stats.bytes_reclaimed >= 1024);
    }
}
