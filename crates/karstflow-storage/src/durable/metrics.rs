// Lightweight storage metrics using atomic counters.
//
// All counters are bump-only (monotonically increasing) and use relaxed
// ordering — suitable for observability, not synchronization. Metrics
// are accumulated per-store instance, matching the reference implementation's pattern of
// tile-local counters drained to shared memory on housekeeping ticks.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic storage operation counters.
///
/// All fields are `AtomicU64` with relaxed ordering for minimal overhead.
/// Thread-safe for concurrent readers and writers.
pub struct StoreMetrics {
    // Operation counts
    reads: AtomicU64,
    writes: AtomicU64,
    deletes: AtomicU64,
    batches: AtomicU64,
    batch_ops: AtomicU64,

    // Byte counters
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,

    // Compaction counters
    compactions: AtomicU64,
    bytes_compacted: AtomicU64,

    // Error counts
    read_errors: AtomicU64,
    write_errors: AtomicU64,
}

impl StoreMetrics {
    pub fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            deletes: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            batch_ops: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            compactions: AtomicU64::new(0),
            bytes_compacted: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        }
    }

    // --- Increment methods ---

    #[inline]
    pub fn record_read(&self, bytes: u64) {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_write(&self, bytes: u64) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_delete(&self) {
        self.deletes.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_batch(&self, op_count: u64) {
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.batch_ops.fetch_add(op_count, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_compaction(&self, bytes_reclaimed: u64) {
        self.compactions.fetch_add(1, Ordering::Relaxed);
        self.bytes_compacted
            .fetch_add(bytes_reclaimed, Ordering::Relaxed);
    }

    #[inline]
    #[allow(dead_code)]
    pub fn record_read_error(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    #[allow(dead_code)]
    pub fn record_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    // --- Snapshot ---

    /// Capture a point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            reads: self.reads.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            batch_ops: self.batch_ops.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            compactions: self.compactions.load(Ordering::Relaxed),
            bytes_compacted: self.bytes_compacted.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for StoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of storage metrics for reporting.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub batches: u64,
    pub batch_ops: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub compactions: u64,
    pub bytes_compacted: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_are_zero() {
        let m = StoreMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.reads, 0);
        assert_eq!(s.writes, 0);
        assert_eq!(s.deletes, 0);
        assert_eq!(s.batches, 0);
        assert_eq!(s.bytes_read, 0);
        assert_eq!(s.bytes_written, 0);
    }

    #[test]
    fn increments_accumulate() {
        let m = StoreMetrics::new();
        m.record_read(100);
        m.record_read(200);
        m.record_write(50);
        m.record_delete();
        m.record_batch(5);
        m.record_compaction(1000);
        m.record_read_error();

        let s = m.snapshot();
        assert_eq!(s.reads, 2);
        assert_eq!(s.bytes_read, 300);
        assert_eq!(s.writes, 1);
        assert_eq!(s.bytes_written, 50);
        assert_eq!(s.deletes, 1);
        assert_eq!(s.batches, 1);
        assert_eq!(s.batch_ops, 5);
        assert_eq!(s.compactions, 1);
        assert_eq!(s.bytes_compacted, 1000);
        assert_eq!(s.read_errors, 1);
        assert_eq!(s.write_errors, 0);
    }

    #[test]
    fn concurrent_increments() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(StoreMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..8 {
            let m = m.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_read(10);
                    m.record_write(20);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let s = m.snapshot();
        assert_eq!(s.reads, 8000);
        assert_eq!(s.bytes_read, 80000);
        assert_eq!(s.writes, 8000);
        assert_eq!(s.bytes_written, 160000);
    }
}
