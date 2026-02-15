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
