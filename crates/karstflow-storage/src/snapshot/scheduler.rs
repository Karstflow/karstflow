//! Snapshot scheduling policy.
//!
//! Determines when to take full and incremental snapshots based on
//! configurable slot intervals, and manages retention of old archives.

use super::metadata::SnapshotConfig;
use std::collections::VecDeque;
use std::path::PathBuf;

/// Action the validator should take at a given slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotAction {
    /// No snapshot needed at this slot.
    None,
    /// Take a full snapshot (all accounts).
    Full,
    /// Take an incremental snapshot (delta since last full).
    Incremental {
        /// Slot of the base full snapshot.
        base_slot: u64,
    },
}

/// Record of a snapshot that was created.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub slot: u64,
    pub is_full: bool,
    pub path: PathBuf,
}

/// Schedules snapshot creation based on slot progression.
///
/// Given a `SnapshotConfig`, determines at each slot whether a full
/// or incremental snapshot should be taken, and tracks created snapshots
/// for retention management.
pub struct SnapshotScheduler {
    config: SnapshotConfig,
    last_full_slot: Option<u64>,
    last_incremental_slot: Option<u64>,
    full_snapshots: VecDeque<SnapshotRecord>,
    incremental_snapshots: VecDeque<SnapshotRecord>,
}

impl SnapshotScheduler {
    pub fn new(config: SnapshotConfig) -> Self {
        Self {
            config,
            last_full_slot: None,
            last_incremental_slot: None,
            full_snapshots: VecDeque::new(),
            incremental_snapshots: VecDeque::new(),
        }
    }

    /// Check what snapshot action to take at the given slot.
    pub fn check_slot(&self, slot: u64) -> SnapshotAction {
        // Full snapshot takes precedence.
        if self.should_take_full(slot) {
            return SnapshotAction::Full;
        }

        if self.should_take_incremental(slot) {
            if let Some(base_slot) = self.last_full_slot {
                return SnapshotAction::Incremental { base_slot };
            }
            // No full snapshot exists yet — take a full instead.
            return SnapshotAction::Full;
        }

        SnapshotAction::None
    }

    /// Record that a full snapshot was created.
    pub fn record_full(&mut self, slot: u64, path: PathBuf) {
        self.last_full_slot = Some(slot);
        self.last_incremental_slot = Some(slot);
        // Clear incremental snapshots — they're invalidated by a new full.
        self.incremental_snapshots.clear();
        self.full_snapshots.push_back(SnapshotRecord {
            slot,
            is_full: true,
            path,
        });
    }

    /// Record that an incremental snapshot was created.
    pub fn record_incremental(&mut self, slot: u64, path: PathBuf) {
        self.last_incremental_slot = Some(slot);
        self.incremental_snapshots.push_back(SnapshotRecord {
            slot,
            is_full: false,
            path,
        });
    }

    /// Get paths of snapshots that should be deleted for retention.
    ///
    /// Returns paths of full and incremental snapshots that exceed
    /// the configured maximum counts, oldest first.
    pub fn expired_snapshots(&self) -> Vec<PathBuf> {
        let mut expired = Vec::new();

        let max_full = self.config.max_full_snapshots;
        if self.full_snapshots.len() > max_full {
            let excess = self.full_snapshots.len() - max_full;
            for record in self.full_snapshots.iter().take(excess) {
                expired.push(record.path.clone());
            }
        }

        let max_incr = self.config.max_incremental_snapshots;
        if self.incremental_snapshots.len() > max_incr {
            let excess = self.incremental_snapshots.len() - max_incr;
            for record in self.incremental_snapshots.iter().take(excess) {
                expired.push(record.path.clone());
            }
        }

        expired
    }

    /// Remove expired snapshot records from tracking (after deletion).
    pub fn purge_expired(&mut self) {
        let max_full = self.config.max_full_snapshots;
        while self.full_snapshots.len() > max_full {
            self.full_snapshots.pop_front();
        }

        let max_incr = self.config.max_incremental_snapshots;
        while self.incremental_snapshots.len() > max_incr {
            self.incremental_snapshots.pop_front();
        }
    }

    /// Slot of the most recent full snapshot.
    pub fn last_full_slot(&self) -> Option<u64> {
        self.last_full_slot
    }

    /// Slot of the most recent incremental snapshot.
    pub fn last_incremental_slot(&self) -> Option<u64> {
        self.last_incremental_slot
    }

    /// Number of full snapshots currently tracked.
    pub fn full_count(&self) -> usize {
        self.full_snapshots.len()
    }

    /// Number of incremental snapshots currently tracked.
    pub fn incremental_count(&self) -> usize {
        self.incremental_snapshots.len()
    }

    fn should_take_full(&self, slot: u64) -> bool {
        if self.config.full_snapshot_interval == 0 {
            return false;
        }
        match self.last_full_slot {
            None => slot > 0 && slot.is_multiple_of(self.config.full_snapshot_interval),
            Some(last) => slot >= last + self.config.full_snapshot_interval,
        }
    }

    fn should_take_incremental(&self, slot: u64) -> bool {
        if self.config.incremental_snapshot_interval == 0 {
            return false;
        }
        match self.last_incremental_slot {
            None => slot > 0 && slot.is_multiple_of(self.config.incremental_snapshot_interval),
            Some(last) => slot >= last + self.config.incremental_snapshot_interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SnapshotConfig {
        SnapshotConfig::new()
            .with_full_interval(100)
            .with_incremental_interval(25)
            .with_max_full_snapshots(3)
            .with_max_incremental_snapshots(5)
    }

    #[test]
    fn no_action_at_slot_zero() {
        let scheduler = SnapshotScheduler::new(test_config());
        assert_eq!(scheduler.check_slot(0), SnapshotAction::None);
    }

    #[test]
    fn full_snapshot_at_interval() {
        let scheduler = SnapshotScheduler::new(test_config());
        assert_eq!(scheduler.check_slot(100), SnapshotAction::Full);
        assert_eq!(scheduler.check_slot(200), SnapshotAction::Full);
    }

    #[test]
    fn incremental_before_first_full_becomes_full() {
        let scheduler = SnapshotScheduler::new(test_config());
        // At slot 25, incremental interval triggers but no full exists → Full.
        assert_eq!(scheduler.check_slot(25), SnapshotAction::Full);
    }

    #[test]
    fn incremental_after_full() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));

        // At slot 125, incremental interval triggers.
        assert_eq!(
            scheduler.check_slot(125),
            SnapshotAction::Incremental { base_slot: 100 }
        );
    }

    #[test]
    fn full_takes_precedence_over_incremental() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));

        // Slot 200 matches both full (100 interval) and incremental (25 interval).
        assert_eq!(scheduler.check_slot(200), SnapshotAction::Full);
    }

    #[test]
    fn no_action_between_intervals() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));

        assert_eq!(scheduler.check_slot(110), SnapshotAction::None);
        assert_eq!(scheduler.check_slot(120), SnapshotAction::None);
    }

    #[test]
    fn record_full_clears_incrementals() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));
        scheduler.record_incremental(125, PathBuf::from("/snap/incr-125"));
        scheduler.record_incremental(150, PathBuf::from("/snap/incr-150"));
        assert_eq!(scheduler.incremental_count(), 2);

        scheduler.record_full(200, PathBuf::from("/snap/full-200"));
        assert_eq!(scheduler.incremental_count(), 0);
    }

    #[test]
    fn expired_full_snapshots() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        for i in 1..=5 {
            scheduler.record_full(i * 100, PathBuf::from(format!("/snap/full-{}", i * 100)));
        }
        assert_eq!(scheduler.full_count(), 5);

        let expired = scheduler.expired_snapshots();
        assert_eq!(expired.len(), 2); // 5 - 3 max = 2 expired
        assert_eq!(expired[0], PathBuf::from("/snap/full-100"));
        assert_eq!(expired[1], PathBuf::from("/snap/full-200"));
    }

    #[test]
    fn expired_incremental_snapshots() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));
        for i in 1..=8 {
            scheduler.record_incremental(
                100 + i * 25,
                PathBuf::from(format!("/snap/incr-{}", 100 + i * 25)),
            );
        }
        assert_eq!(scheduler.incremental_count(), 8);

        let expired = scheduler.expired_snapshots();
        assert_eq!(expired.len(), 3); // 8 - 5 max = 3 expired
    }

    #[test]
    fn purge_removes_oldest() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        for i in 1..=5 {
            scheduler.record_full(i * 100, PathBuf::from(format!("/snap/full-{}", i * 100)));
        }
        scheduler.purge_expired();
        assert_eq!(scheduler.full_count(), 3);
        assert_eq!(scheduler.last_full_slot(), Some(500));
    }

    #[test]
    fn disabled_intervals_produce_no_actions() {
        let config = SnapshotConfig::new()
            .with_full_interval(0)
            .with_incremental_interval(0);
        let scheduler = SnapshotScheduler::new(config);
        assert_eq!(scheduler.check_slot(100), SnapshotAction::None);
        assert_eq!(scheduler.check_slot(1000), SnapshotAction::None);
    }

    #[test]
    fn incremental_sequence_after_full() {
        let mut scheduler = SnapshotScheduler::new(test_config());
        scheduler.record_full(100, PathBuf::from("/snap/full-100"));

        assert_eq!(
            scheduler.check_slot(125),
            SnapshotAction::Incremental { base_slot: 100 }
        );
        scheduler.record_incremental(125, PathBuf::from("/snap/incr-125"));

        assert_eq!(
            scheduler.check_slot(150),
            SnapshotAction::Incremental { base_slot: 100 }
        );
        scheduler.record_incremental(150, PathBuf::from("/snap/incr-150"));

        assert_eq!(
            scheduler.check_slot(175),
            SnapshotAction::Incremental { base_slot: 100 }
        );
    }
}
