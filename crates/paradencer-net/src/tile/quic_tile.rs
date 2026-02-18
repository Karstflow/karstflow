/// QUIC tile: QUIC protocol processing and TPU transaction reassembly.
///
/// The QUIC tile owns a QUIC engine instance and processes incoming
/// QUIC packets from the network tile. It handles:
/// - QUIC handshakes (TLS 1.3)
/// - Stream data reassembly
/// - TPU transaction extraction from completed streams
///
/// Runs as a single-threaded polling loop, pinned to one CPU core.
use crate::quic::callbacks::EngineCallbacks;
use crate::quic::config::{EngineConfig, EngineLimits};
use crate::quic::engine::{QuicEngine, ServiceResult};
use crate::tile::reassembly::TpuReassembler;

/// QUIC tile configuration.
#[derive(Debug, Clone)]
pub struct QuicTileConfig {
    /// QUIC engine resource limits.
    pub limits: EngineLimits,
    /// QUIC engine runtime config.
    pub engine_config: EngineConfig,
    /// Maximum concurrent TPU reassembly buffers.
    pub max_reassembly: usize,
    /// Tile CPU affinity (core index, or `None` for no pinning).
    pub cpu_affinity: Option<usize>,
}

impl Default for QuicTileConfig {
    fn default() -> Self {
        Self {
            limits: EngineLimits::default(),
            engine_config: EngineConfig::default(),
            max_reassembly: 1024,
            cpu_affinity: None,
        }
    }
}

/// QUIC tile state.
pub struct QuicTile {
    /// QUIC protocol engine.
    engine: QuicEngine,
    /// TPU transaction reassembler.
    reassembler: TpuReassembler,
    /// Configuration.
    _config: QuicTileConfig,
    /// Whether the tile is running.
    running: bool,
    /// Service loop iteration counter.
    iterations: u64,
    /// Completed transactions counter.
    transactions_completed: u64,
}

impl QuicTile {
    /// Create a new QUIC tile.
    ///
    /// Returns `None` if the engine limits are invalid.
    pub fn new(config: QuicTileConfig) -> Option<Self> {
        let engine = QuicEngine::new(config.limits.clone(), config.engine_config.clone())?;
        let reassembler = TpuReassembler::new(config.max_reassembly);

        Some(Self {
            engine,
            reassembler,
            _config: config,
            running: false,
            iterations: 0,
            transactions_completed: 0,
        })
    }

    /// Get a reference to the QUIC engine.
    pub fn engine(&self) -> &QuicEngine {
        &self.engine
    }

    /// Get a mutable reference to the QUIC engine.
    pub fn engine_mut(&mut self) -> &mut QuicEngine {
        &mut self.engine
    }

    /// Get a reference to the reassembler.
    pub fn reassembler(&self) -> &TpuReassembler {
        &self.reassembler
    }

    /// Get a mutable reference to the reassembler.
    pub fn reassembler_mut(&mut self) -> &mut TpuReassembler {
        &mut self.reassembler
    }

    /// Whether the tile is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Number of service loop iterations.
    pub fn iterations(&self) -> u64 {
        self.iterations
    }

    /// Number of completed TPU transactions.
    pub fn transactions_completed(&self) -> u64 {
        self.transactions_completed
    }

    /// Start the tile.
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the tile.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Execute one service iteration.
    ///
    /// Processes pending QUIC events:
    /// 1. Service the QUIC engine (timers, retransmissions)
    /// 2. Process stream data through the reassembler
    /// 3. Extract completed transactions
    ///
    /// Returns the number of events processed.
    pub fn service(&mut self, now_ns: u64, callbacks: &mut dyn EngineCallbacks) -> usize {
        if !self.running {
            return 0;
        }
        self.iterations += 1;

        // Service the QUIC engine.
        let engine_processed = match self.engine.service(now_ns, callbacks) {
            ServiceResult::Processed => 1,
            ServiceResult::Idle => 0,
        };

        // Check reassembler for completed transactions.
        let completed = self.reassembler.drain_completed();
        self.transactions_completed += completed as u64;

        engine_processed + completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::callbacks::NoopCallbacks;

    #[test]
    fn creation() {
        let tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        assert!(!tile.is_running());
        assert_eq!(tile.iterations(), 0);
        assert_eq!(tile.transactions_completed(), 0);
    }

    #[test]
    fn start_stop() {
        let mut tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        let mut cb = NoopCallbacks;
        tile.start();
        assert!(tile.is_running());

        tile.service(1000, &mut cb);
        assert_eq!(tile.iterations(), 1);

        tile.stop();
        assert!(!tile.is_running());
        assert_eq!(tile.service(2000, &mut cb), 0);
    }

    #[test]
    fn engine_accessible() {
        let tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        assert_eq!(tile.engine().active_connection_count(), 0);
    }

    #[test]
    fn reassembler_accessible() {
        let tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        assert_eq!(tile.reassembler().active_count(), 0);
    }
}
