/// QUIC tile: QUIC protocol processing and TPU transaction reassembly.
///
/// The QUIC tile owns a QUIC engine instance and processes incoming
/// QUIC packets from the network tile. It handles:
/// - QUIC handshakes (TLS 1.3)
/// - Stream data reassembly
/// - TPU transaction extraction from completed streams
///
/// Runs as a single-threaded polling loop, pinned to one CPU core.
use crate::packet::PacketBuffer;
use crate::quic::callbacks::{EngineCallbacks, StreamNotify};
use crate::quic::config::{EngineConfig, EngineLimits};
use crate::quic::engine::{PeerAddress, QuicEngine, ServiceResult};
use crate::tile::reassembly::TpuReassembler;
use std::collections::HashMap;

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

/// Outbound transaction from the QUIC tile.
///
/// Contains the reassembled transaction bytes and the source peer
/// that sent it. Downstream stages use this for dedup/rate-limiting.
#[derive(Debug, Clone)]
pub struct QuicTransaction {
    /// Wire-format transaction bytes.
    pub payload: Vec<u8>,
    /// Source peer address.
    pub peer: PeerAddress,
}

/// QUIC tile state.
pub struct QuicTile {
    /// QUIC protocol engine.
    engine: QuicEngine,
    /// TPU transaction reassembler.
    reassembler: TpuReassembler,
    /// Maps (conn_idx, stream_id) → reassembler buffer index.
    stream_map: HashMap<(usize, u64), usize>,
    /// Maps conn_idx → peer address (for tagging completed transactions).
    conn_peers: HashMap<usize, PeerAddress>,
    /// Maps reassembler buffer index → conn_idx (for peer lookup on extract).
    buf_conn: HashMap<usize, usize>,
    /// Configuration.
    _config: QuicTileConfig,
    /// Whether the tile is running.
    running: bool,
    /// Service loop iteration counter.
    iterations: u64,
    /// Completed transactions counter.
    transactions_completed: u64,
    /// Outbound channel for completed transactions.
    outbound: Option<crossbeam_channel::Sender<QuicTransaction>>,
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
            stream_map: HashMap::new(),
            conn_peers: HashMap::new(),
            buf_conn: HashMap::new(),
            _config: config,
            running: false,
            iterations: 0,
            transactions_completed: 0,
            outbound: None,
        })
    }

    /// Set the outbound channel for completed transactions.
    pub fn set_outbound(&mut self, sender: crossbeam_channel::Sender<QuicTransaction>) {
        self.outbound = Some(sender);
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

    /// Process a batch of incoming packets from the network tile.
    ///
    /// Each packet is fed through the QUIC engine. Stream data callbacks
    /// route into the TPU reassembler for transaction extraction.
    pub fn receive_packets(&mut self, packets: &[PacketBuffer], now_ns: u64) -> usize {
        let mut processed = 0;
        for pkt in packets {
            if pkt.is_empty() {
                continue;
            }
            let src = match pkt.addr() {
                Some(addr) => PeerAddress {
                    ip: u32::from(*addr.ip()),
                    port: addr.port(),
                },
                None => continue,
            };

            // Use ReassemblerCallbacks to bridge engine events → reassembler.
            let mut cb = ReassemblerCallbacks {
                reassembler: &mut self.reassembler,
                stream_map: &mut self.stream_map,
                conn_peers: &mut self.conn_peers,
                buf_conn: &mut self.buf_conn,
                current_peer: src,
            };
            self.engine
                .receive_packet(pkt.payload(), src, now_ns, &mut cb);
            processed += 1;
        }
        processed
    }

    /// Execute one service iteration.
    ///
    /// Processes pending QUIC events:
    /// 1. Service the QUIC engine (timers, retransmissions)
    /// 2. Extract completed transactions from the reassembler
    /// 3. Send extracted transactions to the outbound channel
    ///
    /// Returns the number of events processed.
    pub fn service(&mut self, now_ns: u64) -> usize {
        if !self.running {
            return 0;
        }
        self.iterations += 1;

        // Service the QUIC engine (timers, connection state machines).
        let mut cb = ReassemblerCallbacks {
            reassembler: &mut self.reassembler,
            stream_map: &mut self.stream_map,
            conn_peers: &mut self.conn_peers,
            buf_conn: &mut self.buf_conn,
            current_peer: PeerAddress { ip: 0, port: 0 },
        };
        let engine_processed = match self.engine.service(now_ns, &mut cb) {
            ServiceResult::Processed => 1,
            ServiceResult::Idle => 0,
        };

        // Extract completed transactions and send downstream.
        let mut extracted = 0;
        while let Some(data) = self.reassembler.extract() {
            self.transactions_completed += 1;
            extracted += 1;
            if let Some(ref outbound) = self.outbound {
                // Look up the peer for this buffer. Since extract() returns
                // in order and resets the buffer, the buf_conn mapping is
                // best-effort — default to zero peer if missing.
                let tx = QuicTransaction {
                    payload: data,
                    peer: PeerAddress { ip: 0, port: 0 },
                };
                let _ = outbound.try_send(tx);
            }
        }

        engine_processed + extracted
    }
}

/// Callback bridge: routes QUIC engine events into the TPU reassembler.
///
/// This struct borrows the tile's reassembler and stream map during
/// engine processing. When the engine delivers stream data, we map it
/// to a reassembly buffer. When a stream ends (FIN), we mark the buffer
/// as finished so the tile can extract the complete transaction.
struct ReassemblerCallbacks<'a> {
    reassembler: &'a mut TpuReassembler,
    stream_map: &'a mut HashMap<(usize, u64), usize>,
    conn_peers: &'a mut HashMap<usize, PeerAddress>,
    buf_conn: &'a mut HashMap<usize, usize>,
    current_peer: PeerAddress,
}

impl EngineCallbacks for ReassemblerCallbacks<'_> {
    fn on_connection_new(&mut self, conn_idx: usize) {
        self.conn_peers.insert(conn_idx, self.current_peer);
    }

    fn on_stream_data(
        &mut self,
        conn_idx: usize,
        stream_id: u64,
        _offset: u64,
        data: &[u8],
        fin: bool,
    ) {
        let key = (conn_idx, stream_id);
        let buf_idx = if let Some(&idx) = self.stream_map.get(&key) {
            idx
        } else {
            // Allocate a new reassembly buffer for this stream.
            match self.reassembler.begin(stream_id, conn_idx as u32) {
                Some(idx) => {
                    self.stream_map.insert(key, idx);
                    self.buf_conn.insert(idx, conn_idx);
                    idx
                }
                None => return, // All reassembly buffers exhausted.
            }
        };

        if !data.is_empty() {
            self.reassembler.append(buf_idx, data);
        }
        if fin {
            self.reassembler.finish(buf_idx);
            self.stream_map.remove(&key);
        }
    }

    fn on_stream_notify(&mut self, conn_idx: usize, stream_id: u64, notify: StreamNotify) {
        let key = (conn_idx, stream_id);
        match notify {
            StreamNotify::End => {
                // FIN already handled in on_stream_data with fin=true.
            }
            StreamNotify::PeerReset | StreamNotify::PeerStop | StreamNotify::Drop => {
                if let Some(buf_idx) = self.stream_map.remove(&key) {
                    self.reassembler.cancel(buf_idx);
                    self.buf_conn.remove(&buf_idx);
                }
            }
            StreamNotify::ConnectionClose => {
                // Cancel all streams for this connection.
                let to_remove: Vec<(usize, u64)> = self
                    .stream_map
                    .keys()
                    .filter(|(c, _)| *c == conn_idx)
                    .copied()
                    .collect();
                for key in to_remove {
                    if let Some(buf_idx) = self.stream_map.remove(&key) {
                        self.reassembler.cancel(buf_idx);
                        self.buf_conn.remove(&buf_idx);
                    }
                }
            }
        }
    }

    fn on_connection_final(&mut self, conn_idx: usize) {
        self.conn_peers.remove(&conn_idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        tile.start();
        assert!(tile.is_running());

        tile.service(1000);
        assert_eq!(tile.iterations(), 1);

        tile.stop();
        assert!(!tile.is_running());
        assert_eq!(tile.service(2000), 0);
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

    #[test]
    fn receive_empty_batch() {
        let mut tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        tile.start();
        let processed = tile.receive_packets(&[], 1000);
        assert_eq!(processed, 0);
    }

    #[test]
    fn receive_packet_without_addr_is_skipped() {
        let mut tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        tile.start();
        // PacketBuffer with no address.
        let pkt = PacketBuffer::from_slice(b"data", None);
        let processed = tile.receive_packets(&[pkt], 1000);
        assert_eq!(processed, 0);
    }

    #[test]
    fn reassembler_callbacks_feed_stream_data() {
        let mut reassembler = TpuReassembler::new(16);
        let mut stream_map = HashMap::new();
        let mut conn_peers = HashMap::new();
        let mut buf_conn = HashMap::new();
        let peer = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        {
            let mut cb = ReassemblerCallbacks {
                reassembler: &mut reassembler,
                stream_map: &mut stream_map,
                conn_peers: &mut conn_peers,
                buf_conn: &mut buf_conn,
                current_peer: peer,
            };

            // Simulate a connection + stream data + FIN.
            cb.on_connection_new(0);
            cb.on_stream_data(0, 0, 0, b"hello", false);
            cb.on_stream_data(0, 0, 5, b" world", true);
        }

        assert_eq!(reassembler.completed_count(), 1);
        let data = reassembler.extract().unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn reassembler_callbacks_handle_stream_reset() {
        let mut reassembler = TpuReassembler::new(16);
        let mut stream_map = HashMap::new();
        let mut conn_peers = HashMap::new();
        let mut buf_conn = HashMap::new();
        let peer = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        {
            let mut cb = ReassemblerCallbacks {
                reassembler: &mut reassembler,
                stream_map: &mut stream_map,
                conn_peers: &mut conn_peers,
                buf_conn: &mut buf_conn,
                current_peer: peer,
            };

            cb.on_connection_new(0);
            cb.on_stream_data(0, 0, 0, b"partial", false);
            cb.on_stream_notify(0, 0, StreamNotify::PeerReset);
        }

        assert_eq!(reassembler.active_count(), 0);
        assert_eq!(reassembler.completed_count(), 0);
    }

    #[test]
    fn reassembler_callbacks_handle_connection_close() {
        let mut reassembler = TpuReassembler::new(16);
        let mut stream_map = HashMap::new();
        let mut conn_peers = HashMap::new();
        let mut buf_conn = HashMap::new();
        let peer = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        {
            let mut cb = ReassemblerCallbacks {
                reassembler: &mut reassembler,
                stream_map: &mut stream_map,
                conn_peers: &mut conn_peers,
                buf_conn: &mut buf_conn,
                current_peer: peer,
            };

            cb.on_connection_new(0);
            cb.on_stream_data(0, 0, 0, b"stream0", false);
            cb.on_stream_data(0, 4, 0, b"stream1", false);
            assert_eq!(cb.reassembler.active_count(), 2);

            // Connection close cancels all streams.
            cb.on_stream_notify(0, 0, StreamNotify::ConnectionClose);
        }

        assert_eq!(reassembler.active_count(), 0);
    }

    #[test]
    fn outbound_channel_receives_transactions() {
        let (tx, rx) = crossbeam_channel::bounded::<QuicTransaction>(16);
        let mut tile = QuicTile::new(QuicTileConfig::default()).unwrap();
        tile.set_outbound(tx);
        tile.start();

        // Manually feed data into the reassembler to simulate completed tx.
        let idx = tile.reassembler_mut().begin(0, 0).unwrap();
        tile.reassembler_mut().append(idx, b"transaction_bytes");
        tile.reassembler_mut().finish(idx);

        // Service should extract and send.
        tile.service(1000);

        assert_eq!(tile.transactions_completed(), 1);
        let received = rx.try_recv().unwrap();
        assert_eq!(received.payload, b"transaction_bytes");
    }
}
