/// Background storage maintenance service.
///
/// Runs periodic housekeeping tasks on the storage engine:
/// - **Auto-compaction**: rewrites column family files that have accumulated
///   significant dead space from overwrites and deletes.
/// - **Flush**: ensures all pending writes are durable on disk.
/// - **Blockstore compaction**: removes slot-keyed records below a given
///   minimum slot to reclaim space from old data.
///
/// Designed as a poll-driven service that runs a single `tick()` call
/// periodically. Each tick checks elapsed time since the last maintenance
/// operation and runs the appropriate action if the interval has passed.
/// This matches the tile model used throughout the node runtime.
use std::sync::Arc;
use std::time::{Duration, Instant};

use karstflow_constants::durable_store::{
    MAINTENANCE_COMPACT_INTERVAL_SECS, MAINTENANCE_DEFAULT_RETAIN_SLOTS,
    MAINTENANCE_FLUSH_INTERVAL_SECS,
};

use crate::durable::{CfCompactionStats, CompactionStats, StorageEngine};
use crate::StorageError;

/// Configuration for the storage maintenance service.
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Interval between auto-compaction checks.
    pub compact_interval: Duration,
    /// Interval between flush-to-disk operations.
    pub flush_interval: Duration,
    /// Number of slots to retain below the current root.
    /// Blockstore data older than `root - retain_slots` is eligible for removal.
    pub retain_slots: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            compact_interval: Duration::from_secs(MAINTENANCE_COMPACT_INTERVAL_SECS),
            flush_interval: Duration::from_secs(MAINTENANCE_FLUSH_INTERVAL_SECS),
            retain_slots: MAINTENANCE_DEFAULT_RETAIN_SLOTS,
        }
    }
}

/// Summary of a single maintenance tick.
#[derive(Debug, Clone, Default)]
pub struct MaintenanceReport {
    /// Whether an auto-compaction pass was run.
    pub compacted: bool,
    /// Per-CF compaction results from the auto-compaction pass.
    pub compaction_results: Vec<(String, CfCompactionStats)>,
    /// Whether a flush was performed.
    pub flushed: bool,
    /// Whether blockstore slot compaction was run.
    pub slots_compacted: bool,
    /// Blockstore compaction statistics (if run).
    pub slot_compaction_stats: Option<CompactionStats>,
}

/// Background storage maintenance service.
///
/// Holds a reference to the `StorageEngine` and tracks timing for
/// periodic maintenance operations. Call `tick()` from the node
/// runtime's service loop at the configured tick interval.
pub struct StorageMaintenanceService {
    engine: Arc<StorageEngine>,
    config: MaintenanceConfig,
    last_compact: Instant,
    last_flush: Instant,
    /// Current root slot for blockstore compaction.
    /// Updated externally via `set_root_slot()`.
    root_slot: u64,
    /// Last slot used as compaction boundary (avoids redundant work).
    last_compacted_below_slot: u64,
}

impl StorageMaintenanceService {
    /// Create a new maintenance service with default configuration.
    pub fn new(engine: Arc<StorageEngine>) -> Self {
        Self::with_config(engine, MaintenanceConfig::default())
    }

    /// Create a new maintenance service with custom configuration.
    pub fn with_config(engine: Arc<StorageEngine>, config: MaintenanceConfig) -> Self {
        let now = Instant::now();
        Self {
            engine,
            config,
            last_compact: now,
            last_flush: now,
            root_slot: 0,
            last_compacted_below_slot: 0,
        }
    }

    /// Update the current root slot for blockstore compaction decisions.
    ///
    /// Called by consensus when a new root is finalized. The maintenance
    /// service uses this to determine which old slot data can be removed.
    pub fn set_root_slot(&mut self, slot: u64) {
        self.root_slot = slot;
    }

    /// Run one tick of maintenance.
    ///
    /// Checks elapsed timers and performs operations that are due.
    /// Returns quickly when no work is needed. Non-blocking in the
    /// common case; compaction and flush may block briefly on I/O.
    pub fn tick(&mut self) -> Result<MaintenanceReport, StorageError> {
        let now = Instant::now();
        let mut report = MaintenanceReport::default();

        // Check if flush is due.
        if now.duration_since(self.last_flush) >= self.config.flush_interval {
            self.engine.flush()?;
            self.last_flush = now;
            report.flushed = true;
        }

        // Check if auto-compaction is due.
        if now.duration_since(self.last_compact) >= self.config.compact_interval {
            let results = self.engine.auto_compact()?;
            self.last_compact = now;
            report.compacted = true;
            report.compaction_results = results;

            // Also compact old blockstore data if root has advanced.
            let min_slot = self.root_slot.saturating_sub(self.config.retain_slots);
            if min_slot > self.last_compacted_below_slot {
                let stats = self.engine.compact(min_slot)?;
                self.last_compacted_below_slot = min_slot;
                report.slots_compacted = true;
                report.slot_compaction_stats = Some(stats);
            }
        }

        Ok(report)
    }

    /// Force an immediate compaction pass regardless of timers.
    pub fn force_compact(&mut self) -> Result<MaintenanceReport, StorageError> {
        let mut report = MaintenanceReport::default();

        let results = self.engine.auto_compact()?;
        self.last_compact = Instant::now();
        report.compacted = true;
        report.compaction_results = results;

        Ok(report)
    }

    /// Force an immediate flush regardless of timers.
    pub fn force_flush(&mut self) -> Result<(), StorageError> {
        self.engine.flush()?;
        self.last_flush = Instant::now();
        Ok(())
    }

    /// Current disk usage across all column families.
    pub fn disk_usage(&self) -> Result<u64, StorageError> {
        self.engine.disk_usage()
    }

    /// Total dead bytes awaiting compaction.
    pub fn total_dead_bytes(&self) -> u64 {
        self.engine.total_dead_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> Arc<StorageEngine> {
        let dir = tempfile::tempdir().expect("tmpdir");
        Arc::new(StorageEngine::open(dir.path()).expect("open"))
    }

    fn test_engine_with_dir(dir: &std::path::Path) -> Arc<StorageEngine> {
        Arc::new(StorageEngine::open(dir).expect("open"))
    }

    #[test]
    fn maintenance_creates_with_defaults() {
        let engine = test_engine();
        let service = StorageMaintenanceService::new(engine);
        assert_eq!(
            service.config.compact_interval,
            Duration::from_secs(MAINTENANCE_COMPACT_INTERVAL_SECS)
        );
        assert_eq!(
            service.config.flush_interval,
            Duration::from_secs(MAINTENANCE_FLUSH_INTERVAL_SECS)
        );
        assert_eq!(
            service.config.retain_slots,
            MAINTENANCE_DEFAULT_RETAIN_SLOTS
        );
    }

    #[test]
    fn maintenance_tick_flushes_on_schedule() {
        let engine = test_engine();
        let config = MaintenanceConfig {
            flush_interval: Duration::from_millis(0),    // Immediate
            compact_interval: Duration::from_secs(3600), // Never during test
            retain_slots: 1000,
        };
        let mut service = StorageMaintenanceService::with_config(engine, config);

        let report = service.tick().expect("tick");
        assert!(report.flushed);
        assert!(!report.compacted);
    }

    #[test]
    fn maintenance_tick_compacts_on_schedule() {
        let engine = test_engine();
        let config = MaintenanceConfig {
            flush_interval: Duration::from_secs(3600), // Never during test
            compact_interval: Duration::from_millis(0), // Immediate
            retain_slots: 1000,
        };
        let mut service = StorageMaintenanceService::with_config(engine, config);

        let report = service.tick().expect("tick");
        assert!(report.compacted);
        assert!(!report.flushed);
        // No dead space in fresh store — no CFs should be compacted.
        assert!(report.compaction_results.is_empty());
    }

    #[test]
    fn maintenance_skips_when_intervals_not_elapsed() {
        let engine = test_engine();
        let config = MaintenanceConfig {
            flush_interval: Duration::from_secs(3600),
            compact_interval: Duration::from_secs(3600),
            retain_slots: 1000,
        };
        let mut service = StorageMaintenanceService::with_config(engine, config);

        let report = service.tick().expect("tick");
        assert!(!report.flushed);
        assert!(!report.compacted);
    }

    #[test]
    fn maintenance_slot_compaction_advances_boundary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = test_engine_with_dir(dir.path());

        // Insert slot-keyed data.
        let store = engine.account_store();
        for slot in 0u64..100 {
            store
                .put(
                    karstflow_constants::durable_store::CF_SLOT_META,
                    &slot.to_be_bytes(),
                    b"meta",
                )
                .expect("put");
        }

        let config = MaintenanceConfig {
            flush_interval: Duration::from_secs(3600),
            compact_interval: Duration::from_millis(0),
            retain_slots: 10,
        };
        let mut service = StorageMaintenanceService::with_config(engine, config);
        service.set_root_slot(50);

        let report = service.tick().expect("tick");
        assert!(report.compacted);
        assert!(report.slots_compacted);

        let stats = report.slot_compaction_stats.unwrap();
        assert_eq!(stats.records_removed, 40); // slots 0..40 (50 - 10 = 40)

        // Second tick should NOT re-compact (boundary hasn't advanced).
        // Reset compact timer to make compaction eligible again.
        service.last_compact = Instant::now() - Duration::from_secs(3600);
        let report2 = service.tick().expect("tick2");
        assert!(report2.compacted);
        assert!(!report2.slots_compacted); // No new boundary advancement
    }

    #[test]
    fn maintenance_force_compact() {
        let engine = test_engine();
        let mut service = StorageMaintenanceService::new(engine);

        let report = service.force_compact().expect("force compact");
        assert!(report.compacted);
        assert!(report.compaction_results.is_empty()); // No dead space
    }

    #[test]
    fn maintenance_force_flush() {
        let engine = test_engine();
        let mut service = StorageMaintenanceService::new(engine);
        service.force_flush().expect("force flush");
    }

    #[test]
    fn maintenance_disk_usage_reports() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = test_engine_with_dir(dir.path());
        let service = StorageMaintenanceService::new(engine.clone());

        let before = service.disk_usage().expect("usage");

        // Write data to increase usage.
        let store = engine.account_store();
        store
            .put(
                karstflow_constants::durable_store::CF_ACCOUNTS,
                b"test_key",
                &vec![0u8; 1024],
            )
            .expect("put");

        let after = service.disk_usage().expect("usage");
        assert!(after > before);
    }

    #[test]
    fn maintenance_dead_bytes_reports() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = test_engine_with_dir(dir.path());
        let service = StorageMaintenanceService::new(engine.clone());

        assert_eq!(service.total_dead_bytes(), 0);

        // Create dead space via overwrite.
        let store = engine.account_store();
        store
            .put(
                karstflow_constants::durable_store::CF_ACCOUNTS,
                b"key",
                b"value1",
            )
            .expect("put");
        store
            .put(
                karstflow_constants::durable_store::CF_ACCOUNTS,
                b"key",
                b"value2",
            )
            .expect("put");

        assert!(service.total_dead_bytes() > 0);
    }

    #[test]
    fn maintenance_compacts_dead_space() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let engine = test_engine_with_dir(dir.path());

        // Create significant dead space (>1MB to pass COMPACTION_MIN_DEAD_BYTES).
        let store = engine.account_store();
        let big_value = vec![0xCDu8; 8192];
        for i in 0u32..200 {
            store
                .put(
                    karstflow_constants::durable_store::CF_ACCOUNTS,
                    &i.to_le_bytes(),
                    &big_value,
                )
                .expect("put");
        }
        for i in 0u32..200 {
            store
                .put(
                    karstflow_constants::durable_store::CF_ACCOUNTS,
                    &i.to_le_bytes(),
                    &big_value,
                )
                .expect("put");
        }

        let dead_before = engine.total_dead_bytes();
        assert!(dead_before > 0);

        let mut service = StorageMaintenanceService::new(engine.clone());
        let report = service.force_compact().expect("compact");

        assert!(report.compacted);
        // Should have compacted the accounts CF.
        if dead_before >= 1024 * 1024 {
            assert!(
                !report.compaction_results.is_empty(),
                "expected compaction with {dead_before} dead bytes"
            );
        }
    }
}
