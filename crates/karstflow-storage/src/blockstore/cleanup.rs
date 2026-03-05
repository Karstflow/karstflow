//! Blockstore cleanup, pruning, and garbage collection.
//!
//! Provides both immediate purge operations and a configurable garbage
//! collector that can be driven periodically (e.g., once per root advance)
//! to keep storage usage bounded.

use super::backend::BlockstoreBackend;
use super::BlockstoreError;
use karstflow_constants::blockstore::*;
use std::sync::atomic::{AtomicU64, Ordering};

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
            CF_BLOCK_TIME,
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

// ---------------------------------------------------------------------------
// Garbage Collector — periodic, incremental cleanup
// ---------------------------------------------------------------------------

/// Configuration for the blockstore garbage collector.
#[derive(Debug, Clone)]
pub struct GarbageCollectorConfig {
    /// Number of finalized root slots to retain before purging.
    /// Older slots will be cleaned up. Default: `DEFAULT_ROOTS_TO_RETAIN`.
    pub slots_to_retain: u64,
    /// Minimum number of roots that must advance between GC runs.
    /// Prevents running GC on every root update. Default: 100.
    pub min_roots_between_runs: u64,
    /// Maximum number of entries to purge in a single GC step.
    /// Limits the burst latency of a GC pass. 0 means unlimited. Default: 10_000.
    pub max_purge_per_step: usize,
}

impl Default for GarbageCollectorConfig {
    fn default() -> Self {
        Self {
            slots_to_retain: DEFAULT_ROOTS_TO_RETAIN,
            min_roots_between_runs: 100,
            max_purge_per_step: 10_000,
        }
    }
}

/// Statistics for the garbage collector.
#[derive(Debug, Default)]
pub struct GarbageCollectorStats {
    /// Total entries purged across all GC runs.
    pub total_purged: AtomicU64,
    /// Number of GC runs completed.
    pub runs_completed: AtomicU64,
    /// Number of GC runs skipped (root hasn't advanced enough).
    pub runs_skipped: AtomicU64,
    /// The last slot below which data was purged.
    pub last_purge_slot: AtomicU64,
}

/// Incremental garbage collector for the blockstore.
///
/// Designed to be called periodically (e.g., on each root advance) from a
/// service tick loop. Tracks the last purge point and only runs when enough
/// roots have advanced to justify a new GC pass.
pub struct BlockstoreGarbageCollector {
    config: GarbageCollectorConfig,
    stats: GarbageCollectorStats,
    last_gc_root: u64,
}

impl BlockstoreGarbageCollector {
    pub fn new(config: GarbageCollectorConfig) -> Self {
        Self {
            config,
            stats: GarbageCollectorStats::default(),
            last_gc_root: 0,
        }
    }

    /// Attempt a GC step given the current latest root.
    ///
    /// Returns the number of entries purged, or 0 if GC was skipped
    /// (root hasn't advanced enough since last run).
    pub fn maybe_gc(
        &mut self,
        backend: &BlockstoreBackend,
        latest_root: u64,
    ) -> Result<usize, BlockstoreError> {
        // Check if enough roots have advanced since last GC.
        if latest_root < self.last_gc_root + self.config.min_roots_between_runs {
            self.stats.runs_skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(0);
        }

        let purge_below = latest_root.saturating_sub(self.config.slots_to_retain);
        if purge_below == 0 {
            return Ok(0);
        }

        let purged = if self.config.max_purge_per_step > 0 {
            Self::purge_below_incremental(backend, purge_below, self.config.max_purge_per_step)?
        } else {
            BlockstoreCleanup::purge_below(backend, purge_below)?
        };

        self.last_gc_root = latest_root;
        self.stats
            .total_purged
            .fetch_add(purged as u64, Ordering::Relaxed);
        self.stats.runs_completed.fetch_add(1, Ordering::Relaxed);
        self.stats
            .last_purge_slot
            .store(purge_below, Ordering::Relaxed);

        Ok(purged)
    }

    /// Get the GC statistics.
    pub fn stats(&self) -> &GarbageCollectorStats {
        &self.stats
    }

    /// Purge entries incrementally, stopping after `max_entries` deletions.
    ///
    /// Returns the actual number of entries purged. If the return value equals
    /// `max_entries`, there may be more data to purge on the next call.
    fn purge_below_incremental(
        backend: &BlockstoreBackend,
        min_slot: u64,
        max_entries: usize,
    ) -> Result<usize, BlockstoreError> {
        let mut remaining = max_entries;
        let mut total_purged = 0;

        let all_cfs = [
            CF_SLOT_META,
            CF_DEAD_SLOTS,
            CF_DUPLICATE_SLOTS,
            CF_ROOTS,
            CF_BLOCK_HEIGHT,
            CF_BLOCK_TIME,
            CF_DATA_SHRED,
            CF_CODE_SHRED,
            CF_ERASURE_META,
        ];

        for cf in &all_cfs {
            if remaining == 0 {
                break;
            }
            let keys = backend.all_keys(cf)?;
            for key in keys {
                if remaining == 0 {
                    break;
                }
                if key.len() >= 8 {
                    let slot = u64::from_be_bytes(key[..8].try_into().unwrap_or([0; 8]));
                    if slot < min_slot {
                        backend.delete(cf, &key)?;
                        total_purged += 1;
                        remaining -= 1;
                    }
                }
            }
        }

        Ok(total_purged)
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

    // --- Garbage Collector tests ---

    #[test]
    fn gc_skips_when_root_not_advanced_enough() {
        let b = backend();
        let config = GarbageCollectorConfig {
            min_roots_between_runs: 100,
            ..Default::default()
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        let purged = gc.maybe_gc(&b, 50).unwrap();
        assert_eq!(purged, 0);
        assert_eq!(gc.stats().runs_skipped.load(Ordering::Relaxed), 1);
        assert_eq!(gc.stats().runs_completed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn gc_runs_when_root_advances_past_threshold() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 5);
        put_slot_entry(&b, CF_SLOT_META, 10);
        put_slot_entry(&b, CF_SLOT_META, 2000);

        let config = GarbageCollectorConfig {
            slots_to_retain: 100,
            min_roots_between_runs: 10,
            max_purge_per_step: 0, // unlimited
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        // Root at 2000, retain 100 → purge below 1900.
        let purged = gc.maybe_gc(&b, 2000).unwrap();
        assert!(purged >= 2); // slots 5 and 10 should be purged
        assert_eq!(gc.stats().runs_completed.load(Ordering::Relaxed), 1);
        assert_eq!(gc.stats().last_purge_slot.load(Ordering::Relaxed), 1900);

        // Slot 2000 should remain.
        assert!(b
            .get(CF_SLOT_META, &2000u64.to_be_bytes())
            .unwrap()
            .is_some());
    }

    #[test]
    fn gc_incremental_respects_max_purge() {
        let b = backend();
        for slot in 0..20 {
            put_slot_entry(&b, CF_SLOT_META, slot);
        }

        let config = GarbageCollectorConfig {
            slots_to_retain: 5,
            min_roots_between_runs: 1,
            max_purge_per_step: 3, // Only purge 3 at a time.
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        // Root at 100, retain 5 → purge below 95. All 20 entries are below 95.
        let purged = gc.maybe_gc(&b, 100).unwrap();
        assert_eq!(purged, 3); // Capped at 3.
        assert_eq!(gc.stats().total_purged.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn gc_does_not_purge_when_root_too_low() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 5);

        let config = GarbageCollectorConfig {
            slots_to_retain: 1000,
            min_roots_between_runs: 1,
            max_purge_per_step: 0,
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        // Root at 500, retain 1000 → purge below 0 (saturates). Nothing to purge.
        let purged = gc.maybe_gc(&b, 500).unwrap();
        assert_eq!(purged, 0);
    }

    #[test]
    fn gc_second_run_requires_root_advance() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 5);

        let config = GarbageCollectorConfig {
            slots_to_retain: 10,
            min_roots_between_runs: 50,
            max_purge_per_step: 0,
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        // First run succeeds.
        let purged1 = gc.maybe_gc(&b, 100).unwrap();
        assert!(purged1 >= 1);

        // Second run at 120 is skipped (only +20 roots, need +50).
        put_slot_entry(&b, CF_SLOT_META, 80);
        let purged2 = gc.maybe_gc(&b, 120).unwrap();
        assert_eq!(purged2, 0);

        // Third run at 200 succeeds (+100 from first run).
        let purged3 = gc.maybe_gc(&b, 200).unwrap();
        assert!(purged3 >= 1);
    }

    #[test]
    fn gc_purges_shreds_and_meta() {
        let b = backend();
        put_slot_entry(&b, CF_SLOT_META, 5);
        put_shred_entry(&b, CF_DATA_SHRED, 5, 0);
        put_shred_entry(&b, CF_DATA_SHRED, 5, 1);
        put_shred_entry(&b, CF_CODE_SHRED, 5, 0);
        put_slot_entry(&b, CF_SLOT_META, 200);

        let config = GarbageCollectorConfig {
            slots_to_retain: 10,
            min_roots_between_runs: 1,
            max_purge_per_step: 0,
        };
        let mut gc = BlockstoreGarbageCollector::new(config);

        let purged = gc.maybe_gc(&b, 100).unwrap();
        // Should purge: meta(5), data_shred(5,0), data_shred(5,1), code_shred(5,0) = 4.
        assert_eq!(purged, 4);
        assert_eq!(gc.stats().total_purged.load(Ordering::Relaxed), 4);

        // Slot 200 data should remain.
        assert!(b
            .get(CF_SLOT_META, &200u64.to_be_bytes())
            .unwrap()
            .is_some());
    }
}
