//! Tile orchestrator for spawning tiles on dedicated pinned threads.
//!
//! Bridges the tile infrastructure (CnC, metrics, tile runner) to actual
//! OS threads with optional CPU core affinity. Handles the complete
//! lifecycle: spawn → wait-for-run → monitor → halt → join.
//!
//! Usage:
//! ```ignore
//! let mut orch = TileOrchestrator::new();
//! orch.add(my_tile, Some(2)); // pin to core 2
//! orch.add(another_tile, None); // floating (no pin)
//! orch.start();
//! // ... monitor via orch.check() ...
//! orch.shutdown();
//! ```

use crate::cnc::{TileCnc, CNC_STATE_HALT, CNC_STATE_RUN};
use crate::tile::Tile;
use crate::tile_metrics::TileMetrics;
use crate::tile_runner::{run_tile_simple, TileRunnerConfig};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A tile slot: tile instance + pinning config, before spawning.
struct TileSlot {
    tile: Box<dyn Tile>,
    core_id: Option<usize>,
}

/// A spawned tile's control handles.
struct SpawnedTile {
    name: String,
    cnc: Arc<TileCnc>,
    metrics: Arc<TileMetrics>,
    handle: JoinHandle<()>,
    core_id: Option<usize>,
}

/// Health report for a single tile.
#[derive(Debug, Clone)]
pub struct TileHealth {
    pub name: String,
    pub state: u64,
    pub heartbeat: u64,
    pub core_id: Option<usize>,
}

/// Orchestrates spawning and lifecycle management of multiple tiles.
///
/// Each tile runs on a dedicated OS thread. When a core ID is specified,
/// the thread sets CPU affinity before entering the tile service loop.
pub struct TileOrchestrator {
    /// Tiles waiting to be spawned.
    pending: Vec<TileSlot>,
    /// Tiles that have been spawned and are running.
    spawned: Vec<SpawnedTile>,
    /// Timeout for waiting for tiles to enter RUN state.
    boot_timeout: Duration,
    /// Tile runner configuration.
    runner_config: TileRunnerConfig,
}

impl TileOrchestrator {
    /// Create a new orchestrator with default settings.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            spawned: Vec::new(),
            boot_timeout: Duration::from_secs(10),
            runner_config: TileRunnerConfig::default(),
        }
    }

    /// Set the boot timeout (how long to wait for tiles to enter RUN).
    pub fn with_boot_timeout(mut self, timeout: Duration) -> Self {
        self.boot_timeout = timeout;
        self
    }

    /// Set the tile runner configuration.
    pub fn with_runner_config(mut self, config: TileRunnerConfig) -> Self {
        self.runner_config = config;
        self
    }

    /// Add a tile to be spawned.
    ///
    /// `core_id` is the CPU core to pin the tile's thread to.
    /// Pass `None` for a floating (unpinned) tile.
    pub fn add(&mut self, tile: Box<dyn Tile>, core_id: Option<usize>) {
        self.pending.push(TileSlot { tile, core_id });
    }

    /// Number of tiles (pending + spawned).
    pub fn tile_count(&self) -> usize {
        self.pending.len() + self.spawned.len()
    }

    /// Spawn all pending tiles on dedicated threads.
    ///
    /// Returns an error if any tile fails to enter RUN state within
    /// the boot timeout.
    pub fn start(&mut self) -> Result<(), OrchestratorError> {
        let slots: Vec<TileSlot> = self.pending.drain(..).collect();

        for (idx, slot) in slots.into_iter().enumerate() {
            let cnc = Arc::new(TileCnc::new());
            let name = slot.tile.name().to_string();
            let metrics = Arc::new(TileMetrics::new(&name, idx));

            let cnc_thread = Arc::clone(&cnc);
            let metrics_thread = Arc::clone(&metrics);
            let core_id = slot.core_id;
            let async_min = self.runner_config.async_min;
            let seed = self.runner_config.seed.wrapping_add(idx as u64);

            let handle = std::thread::Builder::new()
                .name(format!("tile-{name}"))
                .spawn(move || {
                    // Pin to core if requested.
                    if let Some(core) = core_id {
                        set_thread_affinity(core);
                    }

                    let config = TileRunnerConfig { async_min, seed };
                    let mut tile = slot.tile;
                    run_tile_simple(tile.as_mut(), &cnc_thread, &metrics_thread, &config);
                })
                .map_err(|e| OrchestratorError::SpawnFailed {
                    tile: name.clone(),
                    error: e.to_string(),
                })?;

            self.spawned.push(SpawnedTile {
                name,
                cnc,
                metrics,
                handle,
                core_id,
            });
        }

        // Wait for all tiles to enter RUN state.
        self.wait_for_all_running()?;

        Ok(())
    }

    /// Wait for all spawned tiles to reach RUN state.
    fn wait_for_all_running(&self) -> Result<(), OrchestratorError> {
        let deadline = Instant::now() + self.boot_timeout;

        loop {
            let mut all_running = true;
            for tile in &self.spawned {
                let state = tile.cnc.state();
                if state != CNC_STATE_RUN && state != CNC_STATE_HALT {
                    all_running = false;
                    break;
                }
            }

            if all_running {
                return Ok(());
            }

            if Instant::now() >= deadline {
                let stuck: Vec<String> = self
                    .spawned
                    .iter()
                    .filter(|t| t.cnc.state() != CNC_STATE_RUN)
                    .map(|t| t.name.clone())
                    .collect();
                return Err(OrchestratorError::BootTimeout { tiles: stuck });
            }

            std::thread::yield_now();
        }
    }

    /// Check health of all spawned tiles.
    pub fn check(&self) -> Vec<TileHealth> {
        self.spawned
            .iter()
            .map(|t| TileHealth {
                name: t.name.clone(),
                state: t.cnc.state(),
                heartbeat: t.cnc.read_heartbeat(),
                core_id: t.core_id,
            })
            .collect()
    }

    /// Check if all tiles are still in RUN state.
    pub fn all_running(&self) -> bool {
        self.spawned.iter().all(|t| t.cnc.state() == CNC_STATE_RUN)
    }

    /// Request all tiles to halt and join their threads.
    pub fn shutdown(&mut self) {
        // Signal halt to all tiles.
        for tile in &self.spawned {
            tile.cnc.request_halt();
        }

        // Join all threads.
        let tiles: Vec<SpawnedTile> = self.spawned.drain(..).collect();
        for tile in tiles {
            let _ = tile.handle.join();
        }
    }

    /// Get a reference to a tile's CnC by index.
    pub fn cnc(&self, index: usize) -> Option<&Arc<TileCnc>> {
        self.spawned.get(index).map(|t| &t.cnc)
    }

    /// Get a reference to a tile's metrics by index.
    pub fn metrics(&self, index: usize) -> Option<&Arc<TileMetrics>> {
        self.spawned.get(index).map(|t| &t.metrics)
    }
}

impl Default for TileOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from tile orchestration.
#[derive(Debug, Clone)]
pub enum OrchestratorError {
    /// Failed to spawn a tile thread.
    SpawnFailed { tile: String, error: String },
    /// One or more tiles did not enter RUN within the boot timeout.
    BootTimeout { tiles: Vec<String> },
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnFailed { tile, error } => {
                write!(f, "failed to spawn tile '{tile}': {error}")
            }
            Self::BootTimeout { tiles } => {
                write!(f, "tiles did not boot within timeout: {}", tiles.join(", "))
            }
        }
    }
}

impl std::error::Error for OrchestratorError {}

/// Set CPU affinity for the current thread.
///
/// On platforms where `core_affinity` is not available (or the core ID
/// is invalid), this is a best-effort operation — it logs a warning
/// but does not fail.
fn set_thread_affinity(core_id: usize) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED: AtomicBool = AtomicBool::new(false);

        // Use libc sched_setaffinity on Linux.
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(core_id, &mut set);
                let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                if ret != 0 && !WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "[tile] warning: failed to pin to core {core_id}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }

        // macOS doesn't support thread-level affinity; log once.
        #[cfg(target_os = "macos")]
        {
            if !WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[tile] note: CPU pinning not supported on macOS, core_id={core_id} ignored"
                );
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = core_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tile::Tile;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CounterTile {
        name: String,
        counter: Arc<AtomicUsize>,
    }

    impl Tile for CounterTile {
        fn name(&self) -> &str {
            &self.name
        }

        fn service(&mut self) -> usize {
            self.counter.fetch_add(1, Ordering::Relaxed);
            1
        }
    }

    #[test]
    fn orchestrator_spawns_and_halts_tiles() {
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        let tile1 = CounterTile {
            name: "tile-a".to_string(),
            counter: Arc::clone(&counter1),
        };
        let tile2 = CounterTile {
            name: "tile-b".to_string(),
            counter: Arc::clone(&counter2),
        };

        let mut orch = TileOrchestrator::new();
        orch.add(Box::new(tile1), None);
        orch.add(Box::new(tile2), None);
        assert_eq!(orch.tile_count(), 2);

        orch.start().expect("start failed");
        assert!(orch.all_running());

        // Let tiles run briefly.
        std::thread::sleep(Duration::from_millis(20));

        // Both tiles should have made progress.
        assert!(counter1.load(Ordering::Relaxed) > 0);
        assert!(counter2.load(Ordering::Relaxed) > 0);

        // Check health.
        let health = orch.check();
        assert_eq!(health.len(), 2);
        assert_eq!(health[0].state, CNC_STATE_RUN);
        assert_eq!(health[1].state, CNC_STATE_RUN);
        assert!(health[0].heartbeat > 0);

        orch.shutdown();

        // After shutdown, CnC should be HALT.
        assert_eq!(orch.tile_count(), 0); // spawned vec drained
    }

    #[test]
    fn orchestrator_with_core_pinning() {
        let counter = Arc::new(AtomicUsize::new(0));

        let tile = CounterTile {
            name: "pinned".to_string(),
            counter: Arc::clone(&counter),
        };

        let mut orch = TileOrchestrator::new();
        orch.add(Box::new(tile), Some(0)); // pin to core 0

        orch.start().expect("start failed");
        std::thread::sleep(Duration::from_millis(10));

        assert!(counter.load(Ordering::Relaxed) > 0);

        orch.shutdown();
    }

    #[test]
    fn orchestrator_multiple_tiles_parallel() {
        let n = 4;
        let counters: Vec<Arc<AtomicUsize>> =
            (0..n).map(|_| Arc::new(AtomicUsize::new(0))).collect();

        let mut orch = TileOrchestrator::new();
        for (i, counter) in counters.iter().enumerate() {
            let tile = CounterTile {
                name: format!("tile-{i}"),
                counter: Arc::clone(counter),
            };
            orch.add(Box::new(tile), None);
        }

        orch.start().expect("start failed");
        std::thread::sleep(Duration::from_millis(30));

        // All tiles should have made progress.
        for (i, counter) in counters.iter().enumerate() {
            assert!(counter.load(Ordering::Relaxed) > 0, "tile {i} did not run");
        }

        // Verify metrics are available.
        for i in 0..n {
            assert!(orch.metrics(i).is_some());
            assert!(orch.cnc(i).is_some());
        }

        orch.shutdown();
    }

    #[test]
    fn orchestrator_boot_timeout() {
        use std::sync::atomic::AtomicBool;

        struct SlowBootTile {
            stop: Arc<AtomicBool>,
        }
        impl Tile for SlowBootTile {
            fn name(&self) -> &str {
                "slow-boot"
            }
            fn initialize(&mut self) {
                // Busy-wait until signaled — cooperative so shutdown works.
                while !self.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            fn service(&mut self) -> usize {
                0
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let tile = SlowBootTile {
            stop: Arc::clone(&stop),
        };

        let mut orch = TileOrchestrator::new().with_boot_timeout(Duration::from_millis(100));
        orch.add(Box::new(tile), None);

        let result = orch.start();
        assert!(result.is_err());
        match result.unwrap_err() {
            OrchestratorError::BootTimeout { tiles } => {
                assert_eq!(tiles, vec!["slow-boot"]);
            }
            other => panic!("expected BootTimeout, got: {other:?}"),
        }

        // Signal the tile to exit initialize() so the thread can be joined.
        stop.store(true, Ordering::Relaxed);
        orch.shutdown();
    }

    #[test]
    fn empty_orchestrator_starts_ok() {
        let mut orch = TileOrchestrator::new();
        orch.start().expect("empty start should succeed");
        assert!(orch.all_running());
        assert_eq!(orch.tile_count(), 0);
        orch.shutdown();
    }
}
