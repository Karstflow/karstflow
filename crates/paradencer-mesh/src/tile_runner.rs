//! Integrated tile runner with CnC lifecycle, housekeeping, and metrics.
//!
//! `run_tile_integrated()` combines all mesh primitives into a single
//! production-ready tile execution loop:
//!
//! - **CnC**: Boot → Run → Halt lifecycle with panic guard
//! - **Heartbeat**: Incremented each service iteration
//! - **Housekeeping**: Jittered timer triggers periodic maintenance
//! - **Metrics**: Gauges and counters updated on each iteration
//!
//! The loop structure mirrors Firedancer's fd_stem run pattern:
//! ```text
//! initialize() → signal_run → loop {
//!     if housekeeping_due { process one housekeeping event }
//!     if halt_requested { break }
//!     service()
//!     heartbeat()
//!     update_metrics()
//! } → signal_halt → shutdown()
//! ```

use crate::cnc::{TileCnc, CNC_STATE_RUN};
use crate::tempo::HousekeepingTimer;
use crate::tile::Tile;
use crate::tile_metrics::{Counter, Gauge, TileMetrics};

/// Configuration for the integrated tile runner.
pub struct TileRunnerConfig {
    /// Power-of-2 minimum housekeeping interval in nanoseconds.
    pub async_min: u64,
    /// RNG seed for housekeeping jitter.
    pub seed: u64,
}

impl Default for TileRunnerConfig {
    fn default() -> Self {
        Self {
            async_min: 1 << 16, // ~65us
            seed: 0,
        }
    }
}

/// Callback for housekeeping events.
///
/// Called periodically during the tile's service loop. Use for:
/// - Flow control credit returns
/// - Metrics flushing
/// - CnC state checks
/// - Any periodic maintenance
pub trait HousekeepingHandler {
    /// Process one housekeeping event.
    ///
    /// `event_idx` is the round-robin event index (0..event_count-1).
    fn on_housekeeping(&mut self, event_idx: usize);

    /// Total number of housekeeping events per cycle.
    fn event_count(&self) -> usize {
        1
    }
}

/// No-op housekeeping handler for tiles that don't need housekeeping.
struct NoopHousekeeping;
impl HousekeepingHandler for NoopHousekeeping {
    fn on_housekeeping(&mut self, _event_idx: usize) {}
    fn event_count(&self) -> usize {
        1
    }
}

/// Run a tile with full CnC + housekeeping + metrics integration.
///
/// This is the production tile execution pattern. It:
/// 1. Initializes the tile
/// 2. Transitions CnC to RUN
/// 3. Runs the service loop with:
///    - Jittered housekeeping timer
///    - CnC halt checking
///    - Heartbeat incrementing
///    - Metrics updates
/// 4. Transitions CnC to HALT on clean shutdown
/// 5. Transitions CnC to ERROR on panic (via drop guard)
///
/// `housekeeping` is called periodically (one event per timer trigger,
/// round-robin across `event_count` events).
pub fn run_tile_integrated(
    tile: &mut dyn Tile,
    cnc: &TileCnc,
    metrics: &TileMetrics,
    config: &TileRunnerConfig,
    housekeeping: &mut dyn HousekeepingHandler,
) {
    // Install panic guard.
    struct PanicGuard<'a>(&'a TileCnc);
    impl Drop for PanicGuard<'_> {
        fn drop(&mut self) {
            if self.0.state() == CNC_STATE_RUN {
                self.0.signal_error(0xDEAD);
            }
        }
    }

    tile.initialize();
    cnc.signal_run();
    metrics.set_gauge(Gauge::Status, 1); // RUN

    let _guard = PanicGuard(cnc);

    let mut timer = HousekeepingTimer::new(config.async_min, config.seed);
    let mut event_seq = 0usize;
    let event_count = housekeeping.event_count().max(1);

    loop {
        // Housekeeping check (jittered timer).
        if timer.should_run() {
            housekeeping.on_housekeeping(event_seq);
            metrics.inc_counter(Counter::HousekeepingEvents, 1);

            event_seq += 1;
            if event_seq >= event_count {
                event_seq = 0;
            }

            timer.reload();
        }

        // CnC halt check.
        if cnc.halt_requested() {
            break;
        }

        // Service iteration.
        let processed = tile.service();
        cnc.heartbeat();
        metrics.inc_counter(Counter::ServiceIterations, 1);

        if processed > 0 {
            metrics.inc_counter(Counter::FragmentsPublished, processed as u64);
        }
    }

    // Clean shutdown.
    cnc.signal_halt();
    metrics.set_gauge(Gauge::Status, 2); // HALT
    tile.shutdown();
}

/// Simplified runner without housekeeping callback.
///
/// Uses a no-op housekeeping handler. Suitable for simple tiles that
/// don't need periodic maintenance beyond CnC and metrics.
pub fn run_tile_simple(
    tile: &mut dyn Tile,
    cnc: &TileCnc,
    metrics: &TileMetrics,
    config: &TileRunnerConfig,
) {
    run_tile_integrated(tile, cnc, metrics, config, &mut NoopHousekeeping);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cnc::TileCnc;
    use crate::tile_metrics::TileMetrics;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct CountTile {
        iterations: usize,
    }

    impl Tile for CountTile {
        fn name(&self) -> &str {
            "count-tile"
        }
        fn service(&mut self) -> usize {
            self.iterations += 1;
            1
        }
    }

    #[test]
    fn integrated_runner_lifecycle() {
        let cnc = Arc::new(TileCnc::new());
        let metrics = Arc::new(TileMetrics::new("test", 0));
        let config = TileRunnerConfig::default();

        let cnc2 = Arc::clone(&cnc);
        let metrics2 = Arc::clone(&metrics);

        let handle = std::thread::spawn(move || {
            let mut tile = CountTile { iterations: 0 };
            run_tile_simple(&mut tile, &cnc2, &metrics2, &config);
            tile.iterations
        });

        // Wait for tile to enter RUN.
        let start = Instant::now();
        loop {
            if cnc.state() == CNC_STATE_RUN {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("tile did not enter RUN");
            }
            std::thread::yield_now();
        }

        // Let it run a bit.
        std::thread::sleep(Duration::from_millis(10));

        // Verify metrics are updating.
        assert!(metrics.read_counter(Counter::ServiceIterations) > 0);
        assert_eq!(metrics.read_gauge(Gauge::Status), 1); // RUN

        // Request halt.
        cnc.request_halt();
        let iterations = handle.join().unwrap();

        assert!(iterations > 0);
        assert_eq!(cnc.state(), 2); // HALT
        assert_eq!(metrics.read_gauge(Gauge::Status), 2); // HALT
        assert!(cnc.read_heartbeat() > 0);
    }

    #[test]
    fn housekeeping_fires() {
        let hk_count = Arc::new(AtomicUsize::new(0));
        let hk_count2 = hk_count.clone();

        struct TestHousekeeping {
            counter: Arc<AtomicUsize>,
        }
        impl HousekeepingHandler for TestHousekeeping {
            fn on_housekeeping(&mut self, _idx: usize) {
                self.counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        let cnc = Arc::new(TileCnc::new());
        let metrics = Arc::new(TileMetrics::new("hk-test", 0));
        let config = TileRunnerConfig {
            async_min: 1 << 10, // very small for fast test
            seed: 42,
        };

        let cnc2 = Arc::clone(&cnc);
        let metrics2 = Arc::clone(&metrics);

        let handle = std::thread::spawn(move || {
            let mut tile = CountTile { iterations: 0 };
            let mut hk = TestHousekeeping { counter: hk_count2 };
            run_tile_integrated(&mut tile, &cnc2, &metrics2, &config, &mut hk);
        });

        // Wait for RUN.
        let start = Instant::now();
        loop {
            if cnc.state() == CNC_STATE_RUN {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("timeout");
            }
            std::thread::yield_now();
        }

        std::thread::sleep(Duration::from_millis(50));
        cnc.request_halt();
        handle.join().unwrap();

        // Housekeeping should have fired at least once.
        assert!(
            hk_count.load(Ordering::Relaxed) > 0,
            "housekeeping never fired"
        );
        assert!(metrics.read_counter(Counter::HousekeepingEvents) > 0);
    }
}
