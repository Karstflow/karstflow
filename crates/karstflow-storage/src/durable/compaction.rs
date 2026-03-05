// Data compaction for the durable store.
//
// Two levels of compaction:
// 1. Logical: removes stale slot-keyed records below a minimum slot threshold.
// 2. Physical: rewrites CF files with only live records, reclaiming disk space.
//
// Logical compaction deletes old blockstore entries (slot-keyed CFs).
// Physical compaction (via FileDurableStore::compact_cf) rewrites files to
// eliminate dead space from overwrites and deletes.

use karstflow_constants::durable_store::{
    CF_BLOCK_HEIGHT, CF_BLOCK_TIME, CF_CODE_SHRED, CF_DATA_SHRED, CF_DEAD_SLOTS,
    CF_DUPLICATE_SLOTS, CF_ERASURE_META, CF_ROOTS, CF_SLOT_META, COMPACTION_DEAD_SPACE_RATIO,
};

use super::file_store::CfCompactionStats;
use super::DurableStore;
use super::FileDurableStore;
use crate::StorageError;

/// Statistics from a compaction operation.
#[derive(Debug, Clone, Default)]
pub struct CompactionStats {
    /// Total number of records removed (logical deletion).
    pub records_removed: u64,
    /// Approximate bytes from deleted records.
    pub bytes_removed: u64,
    /// Number of column families with logical deletions.
    pub families_compacted: u64,
    /// Per-CF physical compaction results (file rewrites).
    pub physical_compaction: Vec<(String, CfCompactionStats)>,
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
    CF_BLOCK_TIME,
];

/// Remove all slot-keyed records below `min_slot` from the durable store,
/// then optionally compact CF files to reclaim disk space.
///
/// Phase 1: Scans each blockstore column family for keys whose leading 8 bytes
/// (interpreted as a big-endian u64 slot number) are below `min_slot`,
/// and deletes them.
///
/// Phase 2: If `reclaim_space` is true, rewrites CF files that exceed the
/// dead space threshold to physically reclaim disk space.
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
                    stats.bytes_removed += (key.len() + value.len()) as u64;
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

/// Full compaction: logical slot-based deletion + physical file rewrite.
///
/// Deletes old slot-keyed records, then rewrites any CF files with
/// dead space exceeding the configured threshold.
pub fn compact_below_slot_and_reclaim(
    store: &FileDurableStore,
    min_slot: u64,
) -> Result<CompactionStats, StorageError> {
    // Phase 1: Logical deletion of old slot-keyed records.
    let mut stats = compact_below_slot(store, min_slot)?;

    // Phase 2: Physical compaction of CFs exceeding the dead space threshold.
    let physical = store.compact_all(COMPACTION_DEAD_SPACE_RATIO)?;
    stats.physical_compaction = physical;

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
        assert!(stats.bytes_removed >= 1024);
    }

    // --- Physical compaction tests ---

    #[test]
    fn compact_cf_reclaims_dead_space() {
        let store = FileDurableStore::temporary().expect("temp");

        // Write 100 records, then overwrite them all.
        for i in 0u32..100 {
            store
                .put(CF_SLOT_META, &i.to_be_bytes(), b"original")
                .unwrap();
        }
        let size_before_overwrites = store.disk_usage().unwrap();

        for i in 0u32..100 {
            store
                .put(CF_SLOT_META, &i.to_be_bytes(), b"updated!")
                .unwrap();
        }
        let size_after_overwrites = store.disk_usage().unwrap();
        assert!(size_after_overwrites > size_before_overwrites);

        // Dead ratio should be significant.
        let ratio = store.dead_ratio(CF_SLOT_META).unwrap();
        assert!(ratio > 0.3, "expected high dead ratio, got {ratio}");

        // Compact the CF.
        let stats = store.compact_cf(CF_SLOT_META).unwrap();
        assert_eq!(stats.records_rewritten, 100);
        assert!(stats.bytes_reclaimed > 0);
        assert!(stats.bytes_after < stats.bytes_before);

        // All records should still be accessible.
        for i in 0u32..100 {
            let val = store
                .get(CF_SLOT_META, &i.to_be_bytes())
                .unwrap()
                .expect("should exist");
            assert_eq!(val, b"updated!");
        }

        // Dead ratio should be zero after compaction.
        let ratio_after = store.dead_ratio(CF_SLOT_META).unwrap();
        assert_eq!(ratio_after, 0.0);
    }

    #[test]
    fn compact_cf_handles_empty_cf() {
        let store = FileDurableStore::temporary().expect("temp");
        let stats = store.compact_cf(CF_SLOT_META).unwrap();
        assert_eq!(stats.records_rewritten, 0);
        assert_eq!(stats.bytes_reclaimed, 0);
    }

    #[test]
    fn compact_cf_handles_no_dead_space() {
        let store = FileDurableStore::temporary().expect("temp");
        for i in 0u32..10 {
            store.put(CF_SLOT_META, &i.to_be_bytes(), b"val").unwrap();
        }

        let stats = store.compact_cf(CF_SLOT_META).unwrap();
        assert_eq!(stats.records_rewritten, 10);
        assert_eq!(stats.bytes_reclaimed, 0);
    }

    #[test]
    fn compact_cf_after_deletes() {
        let store = FileDurableStore::temporary().expect("temp");

        // Write 50 records, delete 25.
        for i in 0u32..50 {
            store.put(CF_SLOT_META, &i.to_be_bytes(), b"data").unwrap();
        }
        for i in 0u32..25 {
            store.delete(CF_SLOT_META, &i.to_be_bytes()).unwrap();
        }

        let stats = store.compact_cf(CF_SLOT_META).unwrap();
        assert_eq!(stats.records_rewritten, 25);
        assert!(stats.bytes_reclaimed > 0);

        // Remaining records intact.
        for i in 25u32..50 {
            assert!(store.get(CF_SLOT_META, &i.to_be_bytes()).unwrap().is_some());
        }
        // Deleted records stay gone.
        for i in 0u32..25 {
            assert!(store.get(CF_SLOT_META, &i.to_be_bytes()).unwrap().is_none());
        }
    }

    #[test]
    fn compact_cf_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("testdb");

        // Write + overwrite + compact.
        {
            let store = FileDurableStore::open(&path).expect("open");
            for i in 0u32..20 {
                store.put(CF_SLOT_META, &i.to_be_bytes(), b"v1").unwrap();
            }
            for i in 0u32..20 {
                store.put(CF_SLOT_META, &i.to_be_bytes(), b"v2").unwrap();
            }
            let stats = store.compact_cf(CF_SLOT_META).unwrap();
            assert!(stats.bytes_reclaimed > 0);
            store.flush().unwrap();
        }

        // Reopen and verify all records are intact.
        {
            let store = FileDurableStore::open(&path).expect("reopen");
            for i in 0u32..20 {
                let val = store
                    .get(CF_SLOT_META, &i.to_be_bytes())
                    .unwrap()
                    .expect("should exist");
                assert_eq!(val, b"v2");
            }
            // Dead ratio should be 0 after compaction+reopen.
            assert_eq!(store.dead_ratio(CF_SLOT_META).unwrap(), 0.0);
        }
    }

    #[test]
    fn compact_all_with_threshold() {
        let store = FileDurableStore::temporary().expect("temp");

        // Create dead space in one CF but not another.
        for i in 0u32..50 {
            store
                .put(CF_SLOT_META, &i.to_be_bytes(), b"original")
                .unwrap();
        }
        for i in 0u32..50 {
            store
                .put(CF_SLOT_META, &i.to_be_bytes(), b"rewritten")
                .unwrap();
        }
        // CF_ROOTS has no dead space.
        store.put(CF_ROOTS, &0u64.to_be_bytes(), &[1]).unwrap();

        let results = store.compact_all(0.3).unwrap();
        // Only CF_SLOT_META should have been compacted.
        assert!(
            results.iter().any(|(name, _)| name == CF_SLOT_META),
            "CF_SLOT_META should be compacted"
        );
        assert!(
            !results.iter().any(|(name, _)| name == CF_ROOTS),
            "CF_ROOTS should NOT be compacted"
        );
    }

    #[test]
    fn compact_below_slot_and_reclaim_full_cycle() {
        let store = FileDurableStore::temporary().expect("temp");

        // Write slot-keyed data with overwrites.
        for slot in 0u64..100 {
            store
                .put(CF_SLOT_META, &slot.to_be_bytes(), b"meta_v1")
                .unwrap();
        }
        for slot in 0u64..100 {
            store
                .put(CF_SLOT_META, &slot.to_be_bytes(), b"meta_v2")
                .unwrap();
        }

        let size_before = store.disk_usage().unwrap();

        // Full compaction: delete slots < 50, then reclaim space.
        let stats = compact_below_slot_and_reclaim(&store, 50).unwrap();
        assert_eq!(stats.records_removed, 50);
        assert!(!stats.physical_compaction.is_empty());

        let size_after = store.disk_usage().unwrap();
        assert!(
            size_after < size_before,
            "disk usage should decrease: before={size_before}, after={size_after}"
        );

        // Remaining records intact.
        for slot in 50u64..100 {
            assert!(store
                .get(CF_SLOT_META, &slot.to_be_bytes())
                .unwrap()
                .is_some());
        }
    }
}
