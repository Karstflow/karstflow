/// Command-and-control state machine for tile lifecycle management.
///
/// Each tile in the pipeline has a CnC handle that tracks its lifecycle
/// state (Boot → Run → Halt) and provides heartbeat monitoring. The
/// supervisor reads tile states to detect stuck or failed tiles.
///
/// All operations are lock-free using atomic u64 — suitable for the
/// poll-driven tile execution model where blocking is not allowed.
///
/// State machine:
/// ```text
///   BOOT ──→ RUN ──→ HALT
///     │               ↑
///     └───→ ERROR ────┘
/// ```
///
/// The `heartbeat` counter is incremented by the tile on each service
/// iteration. The supervisor reads it periodically — if the counter
/// hasn't advanced for a configurable timeout, the tile is presumed stuck.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Tile lifecycle states encoded as u64 for atomic access.
///
/// Low 8 bits: state enum.
/// Bits 8..31: reserved for flags.
/// Bits 32..63: diagnostic code (for ERROR state).
pub const CNC_STATE_BOOT: u64 = 0;
pub const CNC_STATE_RUN: u64 = 1;
pub const CNC_STATE_HALT: u64 = 2;
pub const CNC_STATE_ERROR: u64 = 3;

/// Halt signal sent from supervisor to tile.
const CNC_SIGNAL_HALT: u64 = 0x100;

/// Mask for the state bits (low 8 bits).
const STATE_MASK: u64 = 0xFF;

/// Mask for the signal bits (bits 8..15).
const SIGNAL_MASK: u64 = 0xFF00;

/// Shared command-and-control state for a single tile.
///
/// Allocated once and shared between the tile (writer) and the
/// supervisor (reader). Cache-line aligned to avoid false sharing.
#[repr(C, align(128))]
pub struct TileCnc {
    /// Current lifecycle state + signal bits.
    state: AtomicU64,
    /// Heartbeat counter — incremented by the tile on each service call.
    heartbeat: AtomicU64,
    /// Diagnostic code set when entering ERROR state.
    diagnostic: AtomicU64,
}

impl TileCnc {
    /// Create a new CnC handle in BOOT state.
    pub fn new() -> Self {
        Self {
            state: AtomicU64::new(CNC_STATE_BOOT),
            heartbeat: AtomicU64::new(0),
            diagnostic: AtomicU64::new(0),
        }
    }

    // -----------------------------------------------------------------------
    // Tile-side operations (called from the tile's service loop)
    // -----------------------------------------------------------------------

    /// Transition from BOOT to RUN.
    ///
    /// Called by the tile after initialization completes.
    /// Preserves any pending signals (e.g., halt requested during boot).
    pub fn signal_run(&self) {
        let current = self.state.load(Ordering::Acquire);
        let signals = current & SIGNAL_MASK;
        self.state.store(CNC_STATE_RUN | signals, Ordering::Release);
    }

    /// Transition to HALT.
    ///
    /// Called by the tile during graceful shutdown.
    pub fn signal_halt(&self) {
        self.state.store(CNC_STATE_HALT, Ordering::Release);
    }

    /// Transition to ERROR with a diagnostic code.
    ///
    /// Called by the tile when an unrecoverable error occurs.
    pub fn signal_error(&self, diagnostic_code: u32) {
        self.diagnostic
            .store(diagnostic_code as u64, Ordering::Release);
        self.state.store(CNC_STATE_ERROR, Ordering::Release);
    }

    /// Increment the heartbeat counter.
    ///
    /// Call this on every service iteration to signal liveness.
    #[inline]
    pub fn heartbeat(&self) {
        self.heartbeat.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if the supervisor has requested a halt.
    ///
    /// The tile should check this on each service iteration and begin
    /// shutdown if true.
    #[inline]
    pub fn halt_requested(&self) -> bool {
        let v = self.state.load(Ordering::Acquire);
        (v & SIGNAL_MASK) == CNC_SIGNAL_HALT
    }

    // -----------------------------------------------------------------------
    // Supervisor-side operations (called from the monitoring thread)
    // -----------------------------------------------------------------------

    /// Read the current lifecycle state.
    pub fn state(&self) -> u64 {
        self.state.load(Ordering::Acquire) & STATE_MASK
    }

    /// Read the current heartbeat counter.
    pub fn read_heartbeat(&self) -> u64 {
        self.heartbeat.load(Ordering::Relaxed)
    }

    /// Read the diagnostic code (meaningful only in ERROR state).
    pub fn read_diagnostic(&self) -> u32 {
        self.diagnostic.load(Ordering::Relaxed) as u32
    }

    /// Request the tile to halt.
    ///
    /// Sets the HALT signal bit. The tile will see this on its next
    /// `halt_requested()` check and begin shutdown.
    pub fn request_halt(&self) {
        let current = self.state.load(Ordering::Acquire);
        let state_bits = current & STATE_MASK;
        // Only signal halt to tiles in BOOT or RUN state.
        if state_bits == CNC_STATE_BOOT || state_bits == CNC_STATE_RUN {
            self.state
                .store(state_bits | CNC_SIGNAL_HALT, Ordering::Release);
        }
    }
}

impl Default for TileCnc {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: TileCnc uses only atomics — safe to share across threads.
unsafe impl Send for TileCnc {}
unsafe impl Sync for TileCnc {}

/// Supervisor that monitors a set of tile CnC handles.
///
/// Periodically checks tile heartbeats and states. Reports stuck tiles
/// (heartbeat hasn't advanced within the timeout) and error states.
pub struct TileSupervisor {
    tiles: Vec<TileEntry>,
    heartbeat_timeout: Duration,
}

/// Per-tile tracking state for the supervisor.
struct TileEntry {
    name: String,
    cnc: *const TileCnc,
    last_heartbeat: u64,
    last_check_time: Instant,
    stuck: bool,
}

// SAFETY: TileCnc pointers are to shared atomics — safe across threads.
unsafe impl Send for TileEntry {}

/// Result of a supervisor health check.
#[derive(Debug, Clone)]
pub struct SupervisorReport {
    /// Number of tiles in RUN state.
    pub running: usize,
    /// Number of tiles in BOOT state (still initializing).
    pub booting: usize,
    /// Number of tiles in HALT state.
    pub halted: usize,
    /// Number of tiles in ERROR state.
    pub errored: usize,
    /// Names of tiles whose heartbeat hasn't advanced within the timeout.
    pub stuck_tiles: Vec<String>,
    /// Names of tiles in ERROR state with diagnostic codes.
    pub error_details: Vec<(String, u32)>,
}

impl TileSupervisor {
    /// Create a new supervisor with the given heartbeat timeout.
    ///
    /// Tiles whose heartbeat doesn't advance within `heartbeat_timeout`
    /// are reported as stuck.
    pub fn new(heartbeat_timeout: Duration) -> Self {
        Self {
            tiles: Vec::new(),
            heartbeat_timeout,
        }
    }

    /// Register a tile for monitoring.
    ///
    /// # Safety
    ///
    /// The `TileCnc` must remain valid for the lifetime of the supervisor.
    pub unsafe fn register(&mut self, name: &str, cnc: &TileCnc) {
        self.tiles.push(TileEntry {
            name: name.to_string(),
            cnc: cnc as *const TileCnc,
            last_heartbeat: cnc.read_heartbeat(),
            last_check_time: Instant::now(),
            stuck: false,
        });
    }

    /// Run a health check across all registered tiles.
    ///
    /// Returns a report summarizing tile states and any stuck tiles.
    pub fn check(&mut self) -> SupervisorReport {
        let now = Instant::now();
        let mut running = 0;
        let mut booting = 0;
        let mut halted = 0;
        let mut errored = 0;
        let mut stuck_tiles = Vec::new();
        let mut error_details = Vec::new();

        for entry in &mut self.tiles {
            // SAFETY: TileCnc pointer valid per register() contract.
            let cnc = unsafe { &*entry.cnc };
            let state = cnc.state();

            match state {
                CNC_STATE_BOOT => booting += 1,
                CNC_STATE_RUN => {
                    running += 1;
                    // Check heartbeat liveness.
                    let current_hb = cnc.read_heartbeat();
                    if current_hb == entry.last_heartbeat {
                        // Heartbeat hasn't advanced.
                        if now.duration_since(entry.last_check_time) >= self.heartbeat_timeout {
                            if !entry.stuck {
                                entry.stuck = true;
                            }
                            stuck_tiles.push(entry.name.clone());
                        }
                    } else {
                        // Heartbeat advanced — reset tracking.
                        entry.last_heartbeat = current_hb;
                        entry.last_check_time = now;
                        entry.stuck = false;
                    }
                }
                CNC_STATE_HALT => halted += 1,
                CNC_STATE_ERROR => {
                    errored += 1;
                    error_details.push((entry.name.clone(), cnc.read_diagnostic()));
                }
                _ => {}
            }
        }

        SupervisorReport {
            running,
            booting,
            halted,
            errored,
            stuck_tiles,
            error_details,
        }
    }

    /// Request all tiles to halt.
    pub fn halt_all(&self) {
        for entry in &self.tiles {
            let cnc = unsafe { &*entry.cnc };
            cnc.request_halt();
        }
    }

    /// Number of registered tiles.
    pub fn tile_count(&self) -> usize {
        self.tiles.len()
    }
}

/// Run a tile with CnC lifecycle management.
///
/// Enhanced version of `run_tile` that:
/// 1. Transitions CnC to RUN after initialization
/// 2. Increments heartbeat on each service iteration
/// 3. Checks for halt requests from the supervisor
/// 4. Transitions CnC to HALT on clean shutdown
/// 5. Transitions CnC to ERROR on panic (via drop guard)
pub fn run_tile_with_cnc(tile: &mut dyn super::tile::Tile, cnc: &TileCnc) {
    // Install a drop guard that transitions to ERROR if we panic.
    struct PanicGuard<'a>(&'a TileCnc);
    impl<'a> Drop for PanicGuard<'a> {
        fn drop(&mut self) {
            // If state is still RUN when dropped (panic), transition to ERROR.
            if self.0.state() == CNC_STATE_RUN {
                self.0.signal_error(0xDEAD);
            }
        }
    }

    tile.initialize();
    cnc.signal_run();

    let _guard = PanicGuard(cnc);

    loop {
        if cnc.halt_requested() {
            break;
        }
        tile.service();
        cnc.heartbeat();
    }

    // Clean shutdown — disarm panic guard by setting HALT before drop.
    cnc.signal_halt();
    tile.shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cnc_starts_in_boot() {
        let cnc = TileCnc::new();
        assert_eq!(cnc.state(), CNC_STATE_BOOT);
        assert_eq!(cnc.read_heartbeat(), 0);
    }

    #[test]
    fn lifecycle_boot_run_halt() {
        let cnc = TileCnc::new();
        assert_eq!(cnc.state(), CNC_STATE_BOOT);

        cnc.signal_run();
        assert_eq!(cnc.state(), CNC_STATE_RUN);

        cnc.signal_halt();
        assert_eq!(cnc.state(), CNC_STATE_HALT);
    }

    #[test]
    fn error_with_diagnostic() {
        let cnc = TileCnc::new();
        cnc.signal_run();
        cnc.signal_error(42);
        assert_eq!(cnc.state(), CNC_STATE_ERROR);
        assert_eq!(cnc.read_diagnostic(), 42);
    }

    #[test]
    fn heartbeat_increments() {
        let cnc = TileCnc::new();
        assert_eq!(cnc.read_heartbeat(), 0);
        cnc.heartbeat();
        cnc.heartbeat();
        cnc.heartbeat();
        assert_eq!(cnc.read_heartbeat(), 3);
    }

    #[test]
    fn halt_request_propagates() {
        let cnc = TileCnc::new();
        cnc.signal_run();
        assert!(!cnc.halt_requested());

        cnc.request_halt();
        assert!(cnc.halt_requested());
    }

    #[test]
    fn halt_request_ignored_after_halt() {
        let cnc = TileCnc::new();
        cnc.signal_halt();
        // request_halt should not change state of already-halted tile.
        cnc.request_halt();
        assert_eq!(cnc.state(), CNC_STATE_HALT);
    }

    #[test]
    fn supervisor_tracks_tile_states() {
        let cnc1 = TileCnc::new();
        let cnc2 = TileCnc::new();
        let cnc3 = TileCnc::new();

        cnc1.signal_run();
        cnc2.signal_run();
        // cnc3 stays in BOOT.

        let mut supervisor = TileSupervisor::new(Duration::from_secs(5));
        unsafe {
            supervisor.register("tile-1", &cnc1);
            supervisor.register("tile-2", &cnc2);
            supervisor.register("tile-3", &cnc3);
        }

        let report = supervisor.check();
        assert_eq!(report.running, 2);
        assert_eq!(report.booting, 1);
        assert_eq!(report.halted, 0);
        assert_eq!(report.errored, 0);
        assert!(report.stuck_tiles.is_empty());
    }

    #[test]
    fn supervisor_detects_error_tiles() {
        let cnc = TileCnc::new();
        cnc.signal_run();
        cnc.signal_error(99);

        let mut supervisor = TileSupervisor::new(Duration::from_secs(5));
        unsafe {
            supervisor.register("broken-tile", &cnc);
        }

        let report = supervisor.check();
        assert_eq!(report.errored, 1);
        assert_eq!(report.error_details.len(), 1);
        assert_eq!(report.error_details[0].0, "broken-tile");
        assert_eq!(report.error_details[0].1, 99);
    }

    #[test]
    fn supervisor_halt_all() {
        let cnc1 = TileCnc::new();
        let cnc2 = TileCnc::new();
        cnc1.signal_run();
        cnc2.signal_run();

        let mut supervisor = TileSupervisor::new(Duration::from_secs(5));
        unsafe {
            supervisor.register("t1", &cnc1);
            supervisor.register("t2", &cnc2);
        }

        supervisor.halt_all();
        assert!(cnc1.halt_requested());
        assert!(cnc2.halt_requested());
    }

    #[test]
    fn run_tile_with_cnc_lifecycle() {
        use std::sync::Arc;

        struct StopAfter {
            iterations: usize,
        }
        impl super::super::tile::Tile for StopAfter {
            fn name(&self) -> &str {
                "stop-after"
            }
            fn service(&mut self) -> usize {
                self.iterations += 1;
                1
            }
        }

        // Use Arc for safe cross-thread sharing.
        let cnc = Arc::new(TileCnc::new());
        let cnc_thread = Arc::clone(&cnc);

        let handle = std::thread::spawn(move || {
            let mut tile = StopAfter { iterations: 0 };
            run_tile_with_cnc(&mut tile, &cnc_thread);
            tile.iterations
        });

        // Wait for tile to enter RUN state.
        let start = Instant::now();
        loop {
            if cnc.state() == CNC_STATE_RUN {
                break;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("tile did not enter RUN within 2 seconds");
            }
            std::thread::yield_now();
        }

        // Let it run a few iterations.
        std::thread::sleep(Duration::from_millis(10));

        // Request halt.
        cnc.request_halt();

        let iterations = handle.join().expect("tile thread panicked");
        assert!(iterations > 0, "tile should have run at least once");
        assert_eq!(cnc.state(), CNC_STATE_HALT);
        assert!(cnc.read_heartbeat() > 0);
    }
}
