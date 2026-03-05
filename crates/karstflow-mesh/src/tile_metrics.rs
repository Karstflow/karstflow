//! Per-tile metrics for monitoring and observability.
//!
//! Each tile gets a `TileMetrics` instance that tracks gauges, counters,
//! and throughput statistics. The metrics are stored as atomics so they
//! can be read from a monitoring thread without locking.
//!
//! ## Metric Types
//!
//! - **Gauge**: Current value (e.g., queue depth, backpressure level).
//!   Set to an absolute value.
//! - **Counter**: Monotonically increasing count (e.g., fragments published,
//!   bytes processed). Incremented, never decremented.
//! - **Link metrics**: Per-input-link diagnostics (published count/size,
//!   filtered count/size, overrun count/fragment count).
//!
//! ## Usage
//!
//! ```text
//! // In tile initialization:
//! let metrics = TileMetrics::new("verify", 2);  // 2 input links
//!
//! // In service loop:
//! metrics.inc_counter(Counter::FragmentsPublished, 1);
//! metrics.inc_counter(Counter::BytesProcessed, payload.len() as u64);
//! metrics.set_gauge(Gauge::BackpressureCredits, cr_avail);
//! metrics.inc_link_counter(0, LinkCounter::Published, 1);
//! ```

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Maximum number of input links per tile that can have metrics.
pub const MAX_LINK_METRICS: usize = 16;

/// Tile-level gauge indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gauge {
    /// Current lifecycle state (0=Boot, 1=Run, 2=Halt, 3=Error).
    Status = 0,
    /// Current backpressure credits available.
    BackpressureCredits = 1,
    /// Number of input links being polled.
    InLinkCount = 2,
    /// Number of output links.
    OutLinkCount = 3,
    /// Heartbeat counter (mirrors CnC heartbeat).
    Heartbeat = 4,
}

const GAUGE_COUNT: usize = 8;

/// Tile-level counter indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Counter {
    /// Total fragments/messages published to outputs.
    FragmentsPublished = 0,
    /// Total bytes published to outputs.
    BytesPublished = 1,
    /// Total fragments/messages received from inputs.
    FragmentsReceived = 2,
    /// Total bytes received from inputs.
    BytesReceived = 3,
    /// Total fragments filtered (dropped by this tile).
    FragmentsFiltered = 4,
    /// Total service loop iterations.
    ServiceIterations = 5,
    /// Total housekeeping events processed.
    HousekeepingEvents = 6,
    /// Total overrun events detected on any input.
    OverrunEvents = 7,
}

const COUNTER_COUNT: usize = 16;

/// Per-input-link counter indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkCounter {
    /// Fragments published (received on this link).
    Published = 0,
    /// Bytes published on this link.
    PublishedBytes = 1,
    /// Fragments filtered (dropped) from this link.
    Filtered = 2,
    /// Bytes filtered from this link.
    FilteredBytes = 3,
    /// Overrun events on this link.
    Overruns = 4,
    /// Fragments lost to overruns on this link.
    OverrunFragments = 5,
}

const LINK_COUNTER_COUNT: usize = 6;

/// Metrics region for a single input link.
#[repr(C)]
struct LinkMetrics {
    counters: [AtomicU64; LINK_COUNTER_COUNT],
}

impl LinkMetrics {
    fn new() -> Self {
        Self {
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

/// Per-tile metrics store.
///
/// Cache-line aligned to avoid false sharing between tiles.
/// All reads/writes use relaxed ordering since metrics are
/// informational — exact consistency is not required.
#[repr(C, align(128))]
pub struct TileMetrics {
    /// Human-readable tile name.
    name: String,
    /// Tile-level gauges.
    gauges: [AtomicI64; GAUGE_COUNT],
    /// Tile-level counters.
    counters: [AtomicU64; COUNTER_COUNT],
    /// Per-input-link metrics.
    links: Vec<LinkMetrics>,
    /// Number of active input links.
    in_link_count: usize,
}

impl TileMetrics {
    /// Create a new metrics instance for a tile.
    ///
    /// `in_link_count` is the number of input links this tile polls.
    pub fn new(name: &str, in_link_count: usize) -> Self {
        assert!(
            in_link_count <= MAX_LINK_METRICS,
            "too many input links ({in_link_count} > {MAX_LINK_METRICS})"
        );

        let mut links = Vec::with_capacity(in_link_count);
        for _ in 0..in_link_count {
            links.push(LinkMetrics::new());
        }

        Self {
            name: name.to_string(),
            gauges: std::array::from_fn(|_| AtomicI64::new(0)),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            links,
            in_link_count,
        }
    }

    /// Tile name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of input links.
    pub fn in_link_count(&self) -> usize {
        self.in_link_count
    }

    // -----------------------------------------------------------------------
    // Tile-side: write operations (called from the tile's service loop)
    // -----------------------------------------------------------------------

    /// Set a gauge to an absolute value.
    #[inline]
    pub fn set_gauge(&self, gauge: Gauge, value: i64) {
        self.gauges[gauge as usize].store(value, Ordering::Relaxed);
    }

    /// Increment a counter by `delta`.
    #[inline]
    pub fn inc_counter(&self, counter: Counter, delta: u64) {
        self.counters[counter as usize].fetch_add(delta, Ordering::Relaxed);
    }

    /// Increment a per-link counter by `delta`.
    #[inline]
    pub fn inc_link_counter(&self, link_idx: usize, counter: LinkCounter, delta: u64) {
        debug_assert!(link_idx < self.in_link_count);
        self.links[link_idx].counters[counter as usize].fetch_add(delta, Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Monitor-side: read operations (called from monitoring/metrics thread)
    // -----------------------------------------------------------------------

    /// Read a gauge value.
    #[inline]
    pub fn read_gauge(&self, gauge: Gauge) -> i64 {
        self.gauges[gauge as usize].load(Ordering::Relaxed)
    }

    /// Read a counter value.
    #[inline]
    pub fn read_counter(&self, counter: Counter) -> u64 {
        self.counters[counter as usize].load(Ordering::Relaxed)
    }

    /// Read a per-link counter value.
    #[inline]
    pub fn read_link_counter(&self, link_idx: usize, counter: LinkCounter) -> u64 {
        debug_assert!(link_idx < self.in_link_count);
        self.links[link_idx].counters[counter as usize].load(Ordering::Relaxed)
    }

    /// Take a snapshot of all tile-level metrics.
    pub fn snapshot(&self) -> TileMetricsSnapshot {
        TileMetricsSnapshot {
            name: self.name.clone(),
            gauges: std::array::from_fn(|i| self.gauges[i].load(Ordering::Relaxed)),
            counters: std::array::from_fn(|i| self.counters[i].load(Ordering::Relaxed)),
            link_counters: (0..self.in_link_count)
                .map(|li| {
                    std::array::from_fn(|ci| self.links[li].counters[ci].load(Ordering::Relaxed))
                })
                .collect(),
        }
    }
}

// SAFETY: TileMetrics uses only atomics — safe to share across threads.
unsafe impl Send for TileMetrics {}
unsafe impl Sync for TileMetrics {}

/// Point-in-time snapshot of tile metrics (non-atomic copy).
#[derive(Debug, Clone)]
pub struct TileMetricsSnapshot {
    /// Tile name.
    pub name: String,
    /// Gauge values.
    pub gauges: [i64; GAUGE_COUNT],
    /// Counter values.
    pub counters: [u64; COUNTER_COUNT],
    /// Per-link counter values.
    pub link_counters: Vec<[u64; LINK_COUNTER_COUNT]>,
}

impl TileMetricsSnapshot {
    /// Read a gauge from the snapshot.
    pub fn gauge(&self, gauge: Gauge) -> i64 {
        self.gauges[gauge as usize]
    }

    /// Read a counter from the snapshot.
    pub fn counter(&self, counter: Counter) -> u64 {
        self.counters[counter as usize]
    }

    /// Read a per-link counter from the snapshot.
    pub fn link_counter(&self, link_idx: usize, counter: LinkCounter) -> u64 {
        self.link_counters[link_idx][counter as usize]
    }
}

/// Metrics registry that collects metrics from all tiles.
///
/// The monitoring thread reads all registered tile metrics periodically.
pub struct MetricsRegistry {
    tiles: Vec<*const TileMetrics>,
}

impl MetricsRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self { tiles: Vec::new() }
    }

    /// Register a tile's metrics for monitoring.
    ///
    /// # Safety
    ///
    /// The `TileMetrics` must remain valid for the lifetime of the registry.
    pub unsafe fn register(&mut self, metrics: &TileMetrics) {
        self.tiles.push(metrics as *const TileMetrics);
    }

    /// Number of registered tiles.
    pub fn tile_count(&self) -> usize {
        self.tiles.len()
    }

    /// Take a snapshot of all registered tiles' metrics.
    pub fn snapshot_all(&self) -> Vec<TileMetricsSnapshot> {
        self.tiles
            .iter()
            .map(|&ptr| {
                // SAFETY: Pointers valid per register() contract.
                let metrics = unsafe { &*ptr };
                metrics.snapshot()
            })
            .collect()
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: TileMetrics pointers are to atomics — safe across threads.
unsafe impl Send for MetricsRegistry {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_zeroed() {
        let m = TileMetrics::new("test-tile", 2);
        assert_eq!(m.name(), "test-tile");
        assert_eq!(m.in_link_count(), 2);
        assert_eq!(m.read_gauge(Gauge::Status), 0);
        assert_eq!(m.read_counter(Counter::FragmentsPublished), 0);
        assert_eq!(m.read_link_counter(0, LinkCounter::Published), 0);
    }

    #[test]
    fn gauge_set_and_read() {
        let m = TileMetrics::new("gauge-test", 0);
        m.set_gauge(Gauge::Status, 1);
        assert_eq!(m.read_gauge(Gauge::Status), 1);

        m.set_gauge(Gauge::BackpressureCredits, 42);
        assert_eq!(m.read_gauge(Gauge::BackpressureCredits), 42);

        // Overwrite.
        m.set_gauge(Gauge::Status, 2);
        assert_eq!(m.read_gauge(Gauge::Status), 2);
    }

    #[test]
    fn counter_increment() {
        let m = TileMetrics::new("counter-test", 0);
        m.inc_counter(Counter::FragmentsPublished, 5);
        m.inc_counter(Counter::FragmentsPublished, 3);
        assert_eq!(m.read_counter(Counter::FragmentsPublished), 8);

        m.inc_counter(Counter::BytesPublished, 1024);
        assert_eq!(m.read_counter(Counter::BytesPublished), 1024);
    }

    #[test]
    fn link_counter_per_link() {
        let m = TileMetrics::new("link-test", 3);

        m.inc_link_counter(0, LinkCounter::Published, 10);
        m.inc_link_counter(1, LinkCounter::Published, 20);
        m.inc_link_counter(2, LinkCounter::Published, 30);

        assert_eq!(m.read_link_counter(0, LinkCounter::Published), 10);
        assert_eq!(m.read_link_counter(1, LinkCounter::Published), 20);
        assert_eq!(m.read_link_counter(2, LinkCounter::Published), 30);

        m.inc_link_counter(0, LinkCounter::Overruns, 1);
        assert_eq!(m.read_link_counter(0, LinkCounter::Overruns), 1);
    }

    #[test]
    fn snapshot_captures_current_values() {
        let m = TileMetrics::new("snap-test", 2);

        m.set_gauge(Gauge::Status, 1);
        m.inc_counter(Counter::FragmentsPublished, 100);
        m.inc_link_counter(0, LinkCounter::Published, 50);
        m.inc_link_counter(1, LinkCounter::Filtered, 10);

        let snap = m.snapshot();
        assert_eq!(snap.name, "snap-test");
        assert_eq!(snap.gauge(Gauge::Status), 1);
        assert_eq!(snap.counter(Counter::FragmentsPublished), 100);
        assert_eq!(snap.link_counter(0, LinkCounter::Published), 50);
        assert_eq!(snap.link_counter(1, LinkCounter::Filtered), 10);
    }

    #[test]
    fn registry_collects_all_tiles() {
        let m1 = TileMetrics::new("tile-a", 1);
        let m2 = TileMetrics::new("tile-b", 2);

        m1.inc_counter(Counter::ServiceIterations, 100);
        m2.inc_counter(Counter::ServiceIterations, 200);

        let mut registry = MetricsRegistry::new();
        unsafe {
            registry.register(&m1);
            registry.register(&m2);
        }

        assert_eq!(registry.tile_count(), 2);

        let snaps = registry.snapshot_all();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].name, "tile-a");
        assert_eq!(snaps[0].counter(Counter::ServiceIterations), 100);
        assert_eq!(snaps[1].name, "tile-b");
        assert_eq!(snaps[1].counter(Counter::ServiceIterations), 200);
    }

    #[test]
    fn metrics_cross_thread() {
        use std::sync::Arc;

        let m = Arc::new(TileMetrics::new("threaded", 1));
        let m2 = Arc::clone(&m);

        let handle = std::thread::spawn(move || {
            for _ in 0..1000 {
                m2.inc_counter(Counter::FragmentsPublished, 1);
                m2.inc_link_counter(0, LinkCounter::Published, 1);
            }
        });

        handle.join().unwrap();

        assert_eq!(m.read_counter(Counter::FragmentsPublished), 1000);
        assert_eq!(m.read_link_counter(0, LinkCounter::Published), 1000);
    }

    #[test]
    fn negative_gauge_values() {
        let m = TileMetrics::new("neg-gauge", 0);
        m.set_gauge(Gauge::BackpressureCredits, -5);
        assert_eq!(m.read_gauge(Gauge::BackpressureCredits), -5);
    }

    #[test]
    #[should_panic(expected = "too many input links")]
    fn too_many_links_panics() {
        TileMetrics::new("overflow", MAX_LINK_METRICS + 1);
    }
}
