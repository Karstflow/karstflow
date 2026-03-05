/// Per-service tick timing and signal bus health monitoring.
///
/// Provides lightweight instrumentation for the tile pipeline:
///
/// - **TickTimer**: Ring buffer of recent tick durations with rolling statistics
///   (min, max, mean, p99). Use `guard()` for RAII timing that records on drop.
///
/// - **SignalBusHealthTracker**: Tracks signal emission success and failures
///   (dropped due to full subscriber channels).
use std::time::Instant;

// ---------------------------------------------------------------------------
// TickTimer — per-service tick timing with rolling window
// ---------------------------------------------------------------------------

/// Tracks tick execution time for a single service.
///
/// Maintains a fixed-size ring buffer of recent tick durations (nanoseconds)
/// and computes rolling statistics. The ring buffer provides O(1) recording
/// in the hot path; snapshot computation is O(n) but only called periodically
/// by the metrics reporter.
pub struct TickTimer {
    /// Service name for identification.
    name: &'static str,
    /// Ring buffer of recent tick durations (nanoseconds).
    durations_ns: Vec<u64>,
    /// Write cursor in the ring buffer.
    cursor: usize,
    /// Number of ticks recorded (up to window size).
    count: usize,
    /// Total ticks recorded (monotonic, never resets).
    total_ticks: u64,
}

impl TickTimer {
    /// Create a new tick timer with the given window size.
    ///
    /// `window_size` determines how many recent tick durations are retained
    /// for rolling statistics. Older entries are overwritten.
    pub fn new(name: &'static str, window_size: usize) -> Self {
        assert!(window_size > 0, "window_size must be > 0");
        Self {
            name,
            durations_ns: vec![0; window_size],
            cursor: 0,
            count: 0,
            total_ticks: 0,
        }
    }

    /// Record a tick duration in nanoseconds.
    #[inline]
    pub fn record(&mut self, duration_ns: u64) {
        self.durations_ns[self.cursor] = duration_ns;
        self.cursor = (self.cursor + 1) % self.durations_ns.len();
        if self.count < self.durations_ns.len() {
            self.count += 1;
        }
        self.total_ticks += 1;
    }

    /// Create an RAII guard that records the elapsed time on drop.
    ///
    /// The `&mut self` borrow ensures only one guard is active at a time,
    /// matching the single-threaded service tick model.
    pub fn guard(&mut self) -> TickGuard<'_> {
        TickGuard {
            timer: self,
            start: Instant::now(),
        }
    }

    /// Compute a snapshot of rolling statistics from the current window.
    ///
    /// Returns zeroed stats if no ticks have been recorded.
    pub fn snapshot(&self) -> TickTimerSnapshot {
        if self.count == 0 {
            return TickTimerSnapshot {
                name: self.name,
                total_ticks: 0,
                window_size: self.count,
                min_ns: 0,
                max_ns: 0,
                mean_ns: 0,
                p99_ns: 0,
            };
        }

        // Collect active entries and sort for percentile computation.
        let mut sorted: Vec<u64> = self.durations_ns[..self.count].to_vec();
        sorted.sort_unstable();

        let min_ns = sorted[0];
        let max_ns = sorted[sorted.len() - 1];
        let sum: u64 = sorted.iter().sum();
        let mean_ns = sum / sorted.len() as u64;

        // P99: the value at index ceil(0.99 * count) - 1.
        let p99_index = ((sorted.len() as f64 * 0.99).ceil() as usize).saturating_sub(1);
        let p99_ns = sorted[p99_index.min(sorted.len() - 1)];

        TickTimerSnapshot {
            name: self.name,
            total_ticks: self.total_ticks,
            window_size: self.count,
            min_ns,
            max_ns,
            mean_ns,
            p99_ns,
        }
    }

    /// Total number of ticks ever recorded (monotonic counter).
    pub fn total_ticks(&self) -> u64 {
        self.total_ticks
    }

    /// Service name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

// ---------------------------------------------------------------------------
// TickGuard — RAII guard for automatic tick timing
// ---------------------------------------------------------------------------

/// RAII guard that records elapsed time to a `TickTimer` on drop.
///
/// Created via `TickTimer::guard()`. The `&mut` borrow on the timer
/// prevents multiple guards from being active simultaneously, which
/// matches the single-threaded service loop model.
pub struct TickGuard<'a> {
    timer: &'a mut TickTimer,
    start: Instant,
}

impl Drop for TickGuard<'_> {
    fn drop(&mut self) {
        let elapsed_ns = self.start.elapsed().as_nanos() as u64;
        self.timer.record(elapsed_ns);
    }
}

// ---------------------------------------------------------------------------
// TickTimerSnapshot — point-in-time statistics
// ---------------------------------------------------------------------------

/// Point-in-time snapshot of tick timing statistics.
#[derive(Debug, Clone)]
pub struct TickTimerSnapshot {
    /// Service name.
    pub name: &'static str,
    /// Total ticks ever recorded.
    pub total_ticks: u64,
    /// Number of samples in the current window.
    pub window_size: usize,
    /// Minimum tick duration in nanoseconds.
    pub min_ns: u64,
    /// Maximum tick duration in nanoseconds.
    pub max_ns: u64,
    /// Mean tick duration in nanoseconds.
    pub mean_ns: u64,
    /// 99th percentile tick duration in nanoseconds.
    pub p99_ns: u64,
}

// ---------------------------------------------------------------------------
// SignalBusHealthTracker — monitors signal emission health
// ---------------------------------------------------------------------------

/// Tracks signal bus emission health.
///
/// Counts total signals emitted, how many were dropped (subscriber channel
/// full), and total emission calls. Used by the metrics reporter to surface
/// signal bus congestion.
#[derive(Debug, Clone, Default)]
pub struct SignalBusHealthTracker {
    /// Total signals successfully delivered to all subscribers.
    pub total_emitted: u64,
    /// Total signals dropped (subscriber channel was full).
    pub total_dropped: u64,
    /// Total emission calls.
    pub emission_count: u64,
}

impl SignalBusHealthTracker {
    /// Create a new health tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an emission result.
    ///
    /// `drops` is the number of subscribers that could not receive the
    /// signal (returned by `SignalBus::emit()`).
    /// `subscriber_count` is the total number of active subscribers.
    pub fn record_emission(&mut self, drops: usize, subscriber_count: usize) {
        self.emission_count += 1;
        self.total_dropped += drops as u64;
        // Delivered = subscribers that received it = total - drops
        self.total_emitted += (subscriber_count.saturating_sub(drops)) as u64;
    }

    /// Drop rate as a fraction (0.0 = no drops, 1.0 = all dropped).
    ///
    /// Returns 0.0 if no signals have been emitted.
    pub fn drop_rate(&self) -> f64 {
        let total = self.total_emitted + self.total_dropped;
        if total == 0 {
            0.0
        } else {
            self.total_dropped as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_timer_basic_recording() {
        let mut timer = TickTimer::new("test-service", 16);

        timer.record(1000);
        timer.record(2000);
        timer.record(3000);

        assert_eq!(timer.total_ticks(), 3);

        let snap = timer.snapshot();
        assert_eq!(snap.name, "test-service");
        assert_eq!(snap.total_ticks, 3);
        assert_eq!(snap.window_size, 3);
        assert_eq!(snap.min_ns, 1000);
        assert_eq!(snap.max_ns, 3000);
        assert_eq!(snap.mean_ns, 2000);
    }

    #[test]
    fn tick_timer_rolling_window() {
        let mut timer = TickTimer::new("rolling", 4);

        // Fill the window.
        timer.record(100);
        timer.record(200);
        timer.record(300);
        timer.record(400);
        assert_eq!(timer.total_ticks(), 4);

        let snap1 = timer.snapshot();
        assert_eq!(snap1.window_size, 4);
        assert_eq!(snap1.min_ns, 100);
        assert_eq!(snap1.max_ns, 400);

        // Overwrite oldest (100).
        timer.record(500);
        assert_eq!(timer.total_ticks(), 5);

        let snap2 = timer.snapshot();
        assert_eq!(snap2.window_size, 4);
        // Window now: [500, 200, 300, 400] → sorted: [200, 300, 400, 500]
        assert_eq!(snap2.min_ns, 200);
        assert_eq!(snap2.max_ns, 500);
    }

    #[test]
    fn tick_guard_records_on_drop() {
        let mut timer = TickTimer::new("guard-test", 8);

        assert_eq!(timer.total_ticks(), 0);

        {
            let _guard = timer.guard();
            // Simulate some work.
            std::hint::black_box(42u64.wrapping_mul(7));
        } // guard drops here, recording elapsed time

        assert_eq!(timer.total_ticks(), 1);

        let snap = timer.snapshot();
        assert_eq!(snap.window_size, 1);
        // Duration recorded (may be 0 on very fast systems, which is fine).
    }

    #[test]
    fn tick_timer_snapshot_stats() {
        let mut timer = TickTimer::new("stats", 8);

        // Known values for deterministic assertions.
        let values = [100, 200, 300, 400, 500, 600, 700, 800];
        for v in &values {
            timer.record(*v);
        }

        let snap = timer.snapshot();
        assert_eq!(snap.min_ns, 100);
        assert_eq!(snap.max_ns, 800);
        assert_eq!(snap.mean_ns, 450); // sum=3600, mean=450

        // P99 of 8 values: ceil(0.99*8) - 1 = ceil(7.92) - 1 = 8 - 1 = 7 → 800
        assert_eq!(snap.p99_ns, 800);
    }

    #[test]
    fn tick_timer_empty_snapshot() {
        let timer = TickTimer::new("empty", 16);

        let snap = timer.snapshot();
        assert_eq!(snap.total_ticks, 0);
        assert_eq!(snap.window_size, 0);
        assert_eq!(snap.min_ns, 0);
        assert_eq!(snap.max_ns, 0);
        assert_eq!(snap.mean_ns, 0);
        assert_eq!(snap.p99_ns, 0);
    }

    #[test]
    fn signal_bus_health_tracker_counts() {
        let mut tracker = SignalBusHealthTracker::new();

        // 5 subscribers, 0 drops.
        tracker.record_emission(0, 5);
        assert_eq!(tracker.emission_count, 1);
        assert_eq!(tracker.total_emitted, 5);
        assert_eq!(tracker.total_dropped, 0);
        assert!((tracker.drop_rate() - 0.0).abs() < f64::EPSILON);

        // 5 subscribers, 2 drops.
        tracker.record_emission(2, 5);
        assert_eq!(tracker.emission_count, 2);
        assert_eq!(tracker.total_emitted, 8); // 5 + 3
        assert_eq!(tracker.total_dropped, 2);

        // drop_rate = 2 / (8+2) = 0.2
        assert!((tracker.drop_rate() - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn emit_returns_drop_count() {
        use crate::replay_stage::{ReplaySignal, SignalBus, SlotDeadInfo, SlotDeadReason};
        use karstflow_constants::replay::SIGNAL_CHANNEL_CAPACITY;

        let mut bus = SignalBus::new();
        let rx = bus.subscribe().unwrap();

        // Fill subscriber's channel to capacity.
        for i in 0..SIGNAL_CHANNEL_CAPACITY {
            let drops = bus.emit(ReplaySignal::SlotDead(SlotDeadInfo {
                slot: i as u64,
                parent_slot: 0,
                reason: SlotDeadReason::InvalidBlock,
            }));
            assert_eq!(drops, 0, "no drops when channel has space");
        }

        // Next emit should drop for this subscriber.
        let drops = bus.emit(ReplaySignal::SlotDead(SlotDeadInfo {
            slot: 9999,
            parent_slot: 0,
            reason: SlotDeadReason::InvalidBlock,
        }));
        assert_eq!(drops, 1, "should drop 1 for the full subscriber");

        // Verify subscriber still has exactly SIGNAL_CHANNEL_CAPACITY signals.
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, SIGNAL_CHANNEL_CAPACITY);
    }
}
