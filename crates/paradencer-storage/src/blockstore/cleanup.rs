//! Blockstore cleanup and pruning.
//!
//! Removes old slot data to keep storage usage bounded.

use super::backend::BlockstoreBackend;
use super::BlockstoreError;
use paradencer_constants::blockstore::*;

/// Handles blockstore cleanup and pruning operations.
pub struct BlockstoreCleanup;

impl BlockstoreCleanup {
    /// Purge all data for slots below min_slot.
    ///
    /// Iterates over all column families and removes entries whose keys
    /// encode a slot number below the given threshold. Returns the total
    /// number of entries removed.
    pub fn purge_below(
        backend: &BlockstoreBackend,
        min_slot: u64,
    ) -> Result<usize, BlockstoreError> {
        let mut total_purged = 0;

        // Purge slot-keyed column families (8-byte slot key)
        for cf in &[
            CF_SLOT_META,
            CF_DEAD_SLOTS,
            CF_DUPLICATE_SLOTS,
            CF_ROOTS,
            CF_BLOCK_HEIGHT,
        ] {
            let keys = backend.all_keys(cf)?;
            for key in keys {
                if key.len() >= 8 {
                    let slot = u64::from_be_bytes(key[..8].try_into().unwrap_or([0; 8]));
                    if slot < min_slot {
                        backend.delete(cf, &key)?;
                        total_purged += 1;
                    }
                }
            }
        }

        // Purge shred column families (12-byte key: slot + index)
        for cf in &[CF_DATA_SHRED, CF_CODE_SHRED] {
            let keys = backend.all_keys(cf)?;
            for key in keys {
                if key.len() >= 8 {
                    let slot = u64::from_be_bytes(key[..8].try_into().unwrap_or([0; 8]));
                    if slot < min_slot {
                        backend.delete(cf, &key)?;
                        total_purged += 1;
                    }
                }
            }
        }

        // Purge erasure meta
        let keys = backend.all_keys(CF_ERASURE_META)?;
        for key in keys {
            if key.len() >= 8 {
                let slot = u64::from_be_bytes(key[..8].try_into().unwrap_or([0; 8]));
                if slot < min_slot {
                    backend.delete(CF_ERASURE_META, &key)?;
                    total_purged += 1;
                }
            }
        }

        Ok(total_purged)
    }

    /// Calculate the slot below which data can be cleaned up.
    pub fn cleanup_threshold(latest_root: u64) -> u64 {
        latest_root.saturating_sub(DEFAULT_ROOTS_TO_RETAIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> BlockstoreBackend {
        BlockstoreBackend::in_memory()
    }

    fn put_slot_entry(b: &BlockstoreBackend, cf: &str, slot: u64) {
        let key = slot.to_be_bytes().to_vec();
        b.put(cf, &key, b"data").unwrap();
    }

    fn put_shred_entry(b: &BlockstoreBackend, cf: &str, slot: u64, index: u32) {
        let mut key = Vec::with_capacity(12);
        key.extend_from_slice(&slot.to_be_bytes());
        key.extend_from_slice(&index.to_be_bytes());
        b.put(cf, &key, b"shred").unwrap();
    }

    #[test]
    fn cleanup_threshold_basic() {
        assert_eq!(BlockstoreCleanup::cleanup_threshold(2000), 1000);
    }

    #[test]
    fn cleanup_threshold_saturates_at_zero() {
        assert_eq!(BlockstoreCleanup::cleanup_threshold(500), 0);
    }

    #[test]
    fn purge_removes_old_slot_meta() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 5);
        put_slot_entry(&b, CF_SLOT_META, 10);
        put_slot_entry(&b, CF_SLOT_META, 15);

        let purged = BlockstoreCleanup::purge_below(&b, 10).unwrap();
        assert!(purged >= 1); // slot 5 should be purged

        // slot 5 should be gone
        assert!(b.get(CF_SLOT_META, &5u64.to_be_bytes()).unwrap().is_none());
        // slot 10 should remain
        assert!(b.get(CF_SLOT_META, &10u64.to_be_bytes()).unwrap().is_some());
        // slot 15 should remain
        assert!(b.get(CF_SLOT_META, &15u64.to_be_bytes()).unwrap().is_some());
    }

    #[test]
    fn purge_removes_old_shreds() {
        let b = backend();
        put_shred_entry(&b, CF_DATA_SHRED, 3, 0);
        put_shred_entry(&b, CF_DATA_SHRED, 3, 1);
        put_shred_entry(&b, CF_DATA_SHRED, 10, 0);
        put_shred_entry(&b, CF_CODE_SHRED, 3, 0);
        put_shred_entry(&b, CF_CODE_SHRED, 10, 0);

        let purged = BlockstoreCleanup::purge_below(&b, 5).unwrap();
        // Should purge: slot 3 data shred 0, slot 3 data shred 1, slot 3 code shred 0 = 3
        assert_eq!(purged, 3);
    }

    #[test]
    fn purge_returns_zero_when_nothing_to_purge() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 100);
        let purged = BlockstoreCleanup::purge_below(&b, 50).unwrap();
        assert_eq!(purged, 0);
    }

    #[test]
    fn purge_handles_empty_store() {
        let b = backend();
        let purged = BlockstoreCleanup::purge_below(&b, 100).unwrap();
        assert_eq!(purged, 0);
    }
}
