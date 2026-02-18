/// QUIC protocol engine: single-threaded, pre-allocated, poll-driven.
///
/// Owns all resources for a QUIC endpoint: connection pool, connection
/// ID map, stream pool, ACK generators, service scheduler, and metrics.
/// All memory is allocated at construction time based on `EngineLimits`;
/// zero heap allocation occurs in the packet processing and service hot
/// paths.
///
/// Usage pattern:
/// 1. Create with `QuicEngine::new(limits, config)`
/// 2. Feed incoming packets via `receive_packet(data, src, now)`
/// 3. Call `service(now)` in a tight loop to process scheduled work
/// 4. Implement `EngineCallbacks` to receive stream data and events
use super::ack::AckGenerator;
use super::callbacks::EngineCallbacks;
use super::config::{EngineConfig, EngineLimits, EngineRole};
use super::conn_id::ConnectionId;
use super::conn_map::ConnectionMap;
use super::connection::{Connection, ConnectionState};
use super::crypto::ConnectionSecrets;
use super::metrics::EngineMetrics;
use super::retry::RetryToken;
use super::service_queue::ServiceQueue;
use super::stream_pool::StreamPool;
use paradencer_constants::network::{
    QUIC_DEFAULT_CONN_ID_SIZE, QUIC_ERR_INTERNAL, QUIC_ERR_NO_ERROR, QUIC_RETRY_IV_SIZE,
    QUIC_RETRY_SECRET_SIZE,
};

/// Network endpoint address for a QUIC peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddress {
    /// IPv4 address in network byte order.
    pub ip: u32,
    /// UDP port in host byte order.
    pub port: u16,
}

/// Result of a single `service()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceResult {
    /// One connection was processed.
    Processed,
    /// No connections needed service at this time.
    Idle,
}

/// Result of receiving a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveResult {
    /// Packet was accepted and processed.
    Accepted,
    /// Packet was dropped (parse error, no matching connection, etc.).
    Dropped,
    /// A new connection was created.
    NewConnection,
    /// A retry packet was sent.
    RetrySent,
}

/// The main QUIC protocol engine.
///
/// Single-threaded, pre-allocated, poll-driven. Designed for one engine
/// per core, matching the tile model.
pub struct QuicEngine {
    // -- Configuration --
    config: EngineConfig,
    limits: EngineLimits,

    // -- Connection pool --
    /// Pre-allocated connections (indexed by pool position).
    connections: Vec<Connection>,
    /// Head of the free connection list (index, or `u32::MAX` if empty).
    free_conn_head: u32,
    /// Number of active connections.
    active_connections: u32,

    // -- Lookup structures --
    /// Connection ID → connection index mapping.
    conn_map: ConnectionMap,

    // -- Stream resources --
    /// Pre-allocated stream pool shared by all connections.
    stream_pool: StreamPool,

    // -- ACK state --
    /// Per-connection ACK generators.
    ack_generators: Vec<AckGenerator>,

    // -- Scheduling --
    /// Service scheduler (instant + timer queues).
    service_queue: ServiceQueue,

    // -- Retry --
    /// Secret key for retry token encryption.
    retry_secret: [u8; QUIC_RETRY_SECRET_SIZE],
    /// IV for retry token encryption.
    retry_iv: [u8; QUIC_RETRY_IV_SIZE],
    /// Monotonic counter for unique retry nonces.
    retry_nonce_counter: u64,

    // -- Metrics --
    /// Comprehensive engine metrics.
    pub metrics: EngineMetrics,
}

impl QuicEngine {
    /// Create a new QUIC engine with the given resource limits and config.
    ///
    /// All memory is allocated here. Returns `None` if limits are invalid.
    pub fn new(limits: EngineLimits, config: EngineConfig) -> Option<Self> {
        limits.validate().ok()?;

        let max_conn = limits.max_connections;

        // Pre-allocate connection pool with free list.
        let mut connections: Vec<Connection> = (0..max_conn)
            .map(|i| {
                let mut conn = Connection::new();
                conn.pool_index = i as u32;
                conn
            })
            .collect();

        // Build free list: chain connections via a "next free" index.
        // We repurpose `close_error_code` as a next-free pointer for
        // invalid connections (it's unused when state == Invalid).
        for (i, conn) in connections.iter_mut().enumerate().take(max_conn) {
            let next = if i + 1 < max_conn {
                (i + 1) as u64
            } else {
                u32::MAX as u64
            };
            conn.close_error_code = next;
        }

        let free_head = if max_conn > 0 { 0u32 } else { u32::MAX };

        // Connection map sized for ~2x connections (good load factor).
        let conn_map_capacity = (max_conn * limits.conn_ids_per_conn * 2).max(16);
        let conn_map = ConnectionMap::new(conn_map_capacity);

        // Stream pool
        let stream_pool = StreamPool::new(limits.stream_pool_size as u32);

        // Per-connection ACK generators
        let ack_generators = (0..max_conn).map(|_| AckGenerator::new()).collect();

        // Service queue
        let service_queue = ServiceQueue::new(max_conn as u32);

        Some(Self {
            config,
            limits,
            connections,
            free_conn_head: free_head,
            active_connections: 0,
            conn_map,
            stream_pool,
            ack_generators,
            service_queue,
            retry_secret: [0; QUIC_RETRY_SECRET_SIZE],
            retry_iv: [0; QUIC_RETRY_IV_SIZE],
            retry_nonce_counter: 0,
            metrics: EngineMetrics::new(),
        })
    }

    /// Set the retry secret and IV for stateless retry tokens.
    ///
    /// Must be called before processing packets when retry is enabled.
    pub fn set_retry_secret(
        &mut self,
        secret: [u8; QUIC_RETRY_SECRET_SIZE],
        iv: [u8; QUIC_RETRY_IV_SIZE],
    ) {
        self.retry_secret = secret;
        self.retry_iv = iv;
    }

    /// Process one scheduled connection.
    ///
    /// Pops the next connection from the service queue, handles its
    /// state (idle timeout, close draining, etc.), and reschedules it
    /// if still alive. Returns whether a connection was processed.
    pub fn service(&mut self, now_ns: u64, callbacks: &mut dyn EngineCallbacks) -> ServiceResult {
        let now_i64 = now_ns as i64;

        // Pop next scheduled connection.
        let (conn_idx, _timeout) = match self.service_queue.pop_next(now_i64) {
            Some(entry) => entry,
            None => return ServiceResult::Idle,
        };

        let conn = &mut self.connections[conn_idx as usize];

        // Handle idle timeout.
        if conn.state.is_alive() && !conn.state.is_closing() && conn.is_idle_timed_out(now_ns) {
            conn.begin_close(QUIC_ERR_NO_ERROR, now_ns);
            self.metrics.conn_timeout += 1;
        }

        // State-based processing.
        match conn.state {
            ConnectionState::Handshaking | ConnectionState::HandshakeComplete => {
                // Check handshake timeout.
                let hs_timeout = self.config.tls_handshake_ttl_ns;
                if now_ns.saturating_sub(conn.state_changed_ns) >= hs_timeout {
                    conn.begin_close(QUIC_ERR_INTERNAL, now_ns);
                }
                // Handshake TX would happen here (send crypto frames).
                self.reschedule_connection(conn_idx, now_ns);
            }

            ConnectionState::Active => {
                // Stream TX would happen here (send data + ACK frames).
                self.reschedule_connection(conn_idx, now_ns);
            }

            ConnectionState::PeerClose | ConnectionState::ClosePending => {
                // Drain period: wait 3x idle timeout then transition to Dead.
                let drain_timeout = conn.idle_timeout_ns.max(100_000_000) * 3;
                if now_ns.saturating_sub(conn.state_changed_ns) >= drain_timeout {
                    conn.mark_dead(now_ns);
                } else {
                    self.reschedule_connection(conn_idx, now_ns);
                }
            }

            ConnectionState::Abort => {
                // Send CONNECTION_CLOSE frame would happen here.
                conn.transition(ConnectionState::ClosePending, now_ns);
                self.reschedule_connection(conn_idx, now_ns);
            }

            ConnectionState::Dead => {
                // Notify application and reclaim resources.
                callbacks.on_connection_final(conn_idx as usize);
                self.release_connection(conn_idx);
            }

            ConnectionState::Invalid => {
                // Should not be scheduled. Ignore.
            }
        }

        self.metrics.conn_state_counts = self.compute_state_counts();
        ServiceResult::Processed
    }

    /// Receive and process an incoming UDP packet.
    ///
    /// This is the main ingress path. The packet should contain the raw
    /// QUIC payload (after UDP header is stripped).
    pub fn receive_packet(
        &mut self,
        data: &[u8],
        src: PeerAddress,
        now_ns: u64,
        callbacks: &mut dyn EngineCallbacks,
    ) -> ReceiveResult {
        self.metrics.rx_packets += 1;
        self.metrics.rx_bytes += data.len() as u64;

        if data.is_empty() {
            self.metrics.pkt_undersized += 1;
            return ReceiveResult::Dropped;
        }

        // Determine if long or short header based on first byte.
        let is_long = data[0] & 0x80 != 0;

        if is_long {
            self.process_long_header_packet(data, src, now_ns, callbacks)
        } else {
            self.process_short_header_packet(data, src, now_ns, callbacks)
        }
    }

    /// Initiate a new outgoing (client) connection.
    ///
    /// Returns the connection index on success, or `None` if no slots
    /// are available or this is a server-only engine.
    pub fn connect(
        &mut self,
        dst: PeerAddress,
        now_ns: u64,
        callbacks: &mut dyn EngineCallbacks,
    ) -> Option<u32> {
        if self.config.role != EngineRole::Client {
            return None;
        }

        let conn_idx = self.allocate_connection()?;

        // Generate connection IDs before borrowing the connection.
        let local_cid = self.generate_connection_id();
        let peer_cid = self.generate_connection_id();

        let conn = &mut self.connections[conn_idx as usize];
        conn.init_client(local_cid, peer_cid, now_ns);
        conn.idle_timeout_ns = self.config.idle_timeout_ns;

        // Derive initial encryption keys from peer's connection ID.
        conn.secrets = ConnectionSecrets::derive_initial(peer_cid.as_bytes(), false);
        conn.keys_available[0] = true; // Initial level

        // Set flow control from config.
        conn.local_max_data = self.config.initial_rx_max_data;
        conn.peer_max_streams_bidi = self.config.initial_max_streams_bidi;
        conn.peer_max_streams_uni = self.config.initial_max_streams_uni;

        // Register our local connection ID.
        self.conn_map.insert(local_cid, conn_idx);

        // Schedule for immediate service (to send ClientHello).
        self.service_queue
            .schedule(conn_idx, now_ns as i64, now_ns as i64);

        callbacks.on_connection_new(conn_idx as usize);
        let _ = dst; // Stored in packet header during TX, not in connection

        self.metrics.conn_created += 1;
        self.active_connections += 1;

        Some(conn_idx)
    }

    /// Close a connection with the given error code.
    pub fn close_connection(&mut self, conn_idx: u32, error_code: u64, now_ns: u64) {
        if (conn_idx as usize) >= self.connections.len() {
            return;
        }
        let conn = &mut self.connections[conn_idx as usize];
        if conn.state.is_alive() && !conn.state.is_closing() {
            conn.begin_close(error_code, now_ns);
            // Schedule immediately to send CONNECTION_CLOSE.
            self.service_queue
                .schedule(conn_idx, now_ns as i64, now_ns as i64);
        }
    }

    /// Get an immutable reference to a connection by index.
    pub fn connection(&self, conn_idx: u32) -> Option<&Connection> {
        let conn = self.connections.get(conn_idx as usize)?;
        if conn.state == ConnectionState::Invalid {
            return None;
        }
        Some(conn)
    }

    /// Get a mutable reference to a connection by index.
    pub fn connection_mut(&mut self, conn_idx: u32) -> Option<&mut Connection> {
        let conn = self.connections.get_mut(conn_idx as usize)?;
        if conn.state == ConnectionState::Invalid {
            return None;
        }
        Some(conn)
    }

    /// Get a reference to the stream pool.
    pub fn stream_pool(&self) -> &StreamPool {
        &self.stream_pool
    }

    /// Get a mutable reference to the stream pool.
    pub fn stream_pool_mut(&mut self) -> &mut StreamPool {
        &mut self.stream_pool
    }

    /// Current number of active connections.
    pub fn active_connection_count(&self) -> u32 {
        self.active_connections
    }

    /// Maximum connections this engine can hold.
    pub fn max_connections(&self) -> usize {
        self.limits.max_connections
    }

    /// Next scheduled service time, or `i64::MAX` if idle.
    pub fn next_service_time(&self) -> i64 {
        self.service_queue.next_timeout()
    }

    /// Engine configuration reference.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Engine limits reference.
    pub fn limits(&self) -> &EngineLimits {
        &self.limits
    }

    // -----------------------------------------------------------------------
    // Internal: connection pool management
    // -----------------------------------------------------------------------

    /// Allocate a connection from the free list.
    fn allocate_connection(&mut self) -> Option<u32> {
        if self.free_conn_head == u32::MAX {
            self.metrics.conn_err_no_slots += 1;
            return None;
        }

        let idx = self.free_conn_head;
        let conn = &self.connections[idx as usize];
        // Next free is stored in close_error_code for invalid connections.
        let next_free = conn.close_error_code as u32;
        self.free_conn_head = next_free;

        Some(idx)
    }

    /// Release a connection back to the free list.
    fn release_connection(&mut self, conn_idx: u32) {
        // Remove connection ID from map.
        let conn = &self.connections[conn_idx as usize];
        let local_cid = conn.local_conn_id;
        self.conn_map.remove(&local_cid);

        // Cancel any pending service.
        self.service_queue.cancel(conn_idx);

        // Reset ACK generator.
        self.ack_generators[conn_idx as usize].reset();

        // Reset connection and add to free list.
        let conn = &mut self.connections[conn_idx as usize];
        conn.reset();
        conn.pool_index = conn_idx;
        conn.close_error_code = self.free_conn_head as u64;
        self.free_conn_head = conn_idx;

        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
        self.metrics.conn_closed += 1;
    }

    /// Reschedule a connection based on its idle timeout.
    fn reschedule_connection(&mut self, conn_idx: u32, now_ns: u64) {
        let conn = &self.connections[conn_idx as usize];
        if !conn.state.is_alive() {
            return;
        }

        // Default: wake up at idle timeout expiry.
        let timeout = if conn.idle_timeout_ns > 0 {
            (conn.last_activity_ns + conn.idle_timeout_ns) as i64
        } else {
            // No idle timeout: check again in 1 second.
            (now_ns + 1_000_000_000) as i64
        };

        self.service_queue
            .schedule(conn_idx, timeout, now_ns as i64);
    }

    /// Generate a random-ish connection ID.
    ///
    /// In production this should use a cryptographic RNG. For now we
    /// use a simple counter-based scheme for deterministic testing.
    fn generate_connection_id(&mut self) -> ConnectionId {
        // Counter-based IDs for determinism (production uses CSPRNG).
        self.retry_nonce_counter += 1;
        let bytes = self.retry_nonce_counter.to_be_bytes();
        ConnectionId::from_bytes(&bytes[..QUIC_DEFAULT_CONN_ID_SIZE]).unwrap_or(ConnectionId::EMPTY)
    }

    // -----------------------------------------------------------------------
    // Internal: packet processing
    // -----------------------------------------------------------------------

    /// Process a long-header (Initial/Handshake/0-RTT) packet.
    fn process_long_header_packet(
        &mut self,
        data: &[u8],
        src: PeerAddress,
        now_ns: u64,
        callbacks: &mut dyn EngineCallbacks,
    ) -> ReceiveResult {
        // Minimum long header: 1 (flags) + 4 (version) + 1 (DCIL) + 1 (SCIL) = 7
        if data.len() < 7 {
            self.metrics.pkt_quic_header_err += 1;
            return ReceiveResult::Dropped;
        }

        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if version != paradencer_constants::network::QUIC_VERSION_1 {
            self.metrics.pkt_version_mismatch += 1;
            return ReceiveResult::Dropped;
        }

        // Extract destination connection ID.
        let dcid_len = data[5] as usize;
        if dcid_len > 20 || data.len() < 6 + dcid_len + 1 {
            self.metrics.pkt_quic_header_err += 1;
            return ReceiveResult::Dropped;
        }
        let dcid = match ConnectionId::from_bytes(&data[6..6 + dcid_len]) {
            Some(cid) => cid,
            None => {
                self.metrics.pkt_quic_header_err += 1;
                return ReceiveResult::Dropped;
            }
        };

        // Extract source connection ID.
        let scid_offset = 6 + dcid_len;
        if scid_offset >= data.len() {
            self.metrics.pkt_quic_header_err += 1;
            return ReceiveResult::Dropped;
        }
        let scid_len = data[scid_offset] as usize;
        if scid_len > 20 || data.len() < scid_offset + 1 + scid_len {
            self.metrics.pkt_quic_header_err += 1;
            return ReceiveResult::Dropped;
        }
        let scid =
            match ConnectionId::from_bytes(&data[scid_offset + 1..scid_offset + 1 + scid_len]) {
                Some(cid) => cid,
                None => {
                    self.metrics.pkt_quic_header_err += 1;
                    return ReceiveResult::Dropped;
                }
            };

        // Determine packet type from first byte.
        let pkt_type = (data[0] & 0x30) >> 4;

        // Look up existing connection.
        if let Some(conn_idx) = self.conn_map.get(&dcid) {
            let conn = &mut self.connections[conn_idx as usize];
            conn.touch(now_ns);

            // Schedule for service.
            self.service_queue
                .schedule(conn_idx, now_ns as i64, now_ns as i64);

            return ReceiveResult::Accepted;
        }

        // No existing connection — must be a new Initial from client (server mode).
        if self.config.role != EngineRole::Server || pkt_type != 0 {
            self.metrics.pkt_no_conn[0] += 1;
            return ReceiveResult::Dropped;
        }

        // Handle retry flow if enabled.
        if self.config.enable_retry {
            // Check for retry token in the Initial packet.
            let token_offset = scid_offset + 1 + scid_len;
            if token_offset >= data.len() {
                self.metrics.pkt_quic_header_err += 1;
                return ReceiveResult::Dropped;
            }

            // Decode token length (varint).
            let (token_len, token_hdr_size) = match super::varint::decode(&data[token_offset..]) {
                Ok((len, consumed)) => (len as usize, consumed),
                Err(_) => {
                    self.metrics.pkt_quic_header_err += 1;
                    return ReceiveResult::Dropped;
                }
            };

            if token_len == 0 {
                // No token: send Retry. Full retry packet construction
                // would happen here; for now just count it.
                self.metrics.retry_tx += 1;
                return ReceiveResult::RetrySent;
            }

            // Validate the retry token.
            let token_data_offset = token_offset + token_hdr_size;
            if token_data_offset + token_len > data.len() {
                self.metrics.pkt_quic_header_err += 1;
                return ReceiveResult::Dropped;
            }
            let token = &data[token_data_offset..token_data_offset + token_len];

            match RetryToken::validate(
                &self.retry_secret,
                &self.retry_iv,
                token,
                src.ip,
                src.port,
                now_ns,
            ) {
                Some(token_data) => {
                    // Token valid. Create connection with original DCID.
                    return self.create_server_connection(
                        token_data.original_dst_conn_id,
                        dcid,
                        scid,
                        now_ns,
                        callbacks,
                    );
                }
                None => {
                    self.metrics.conn_err_retry_fail += 1;
                    return ReceiveResult::Dropped;
                }
            }
        }

        // No retry: accept the connection directly.
        self.create_server_connection(dcid, dcid, scid, now_ns, callbacks)
    }

    /// Process a short-header (1-RTT) packet.
    fn process_short_header_packet(
        &mut self,
        data: &[u8],
        _src: PeerAddress,
        now_ns: u64,
        _callbacks: &mut dyn EngineCallbacks,
    ) -> ReceiveResult {
        // Short header needs at least: 1 (flags) + DCID_LEN bytes.
        if data.len() < 1 + QUIC_DEFAULT_CONN_ID_SIZE {
            self.metrics.pkt_quic_header_err += 1;
            return ReceiveResult::Dropped;
        }

        // Extract destination connection ID (fixed length for short headers).
        let dcid = match ConnectionId::from_bytes(&data[1..1 + QUIC_DEFAULT_CONN_ID_SIZE]) {
            Some(cid) => cid,
            None => {
                self.metrics.pkt_quic_header_err += 1;
                return ReceiveResult::Dropped;
            }
        };

        // Look up connection.
        match self.conn_map.get(&dcid) {
            Some(conn_idx) => {
                let conn = &mut self.connections[conn_idx as usize];
                conn.touch(now_ns);

                // Schedule for immediate service.
                self.service_queue
                    .schedule(conn_idx, now_ns as i64, now_ns as i64);

                // Full packet decryption and frame processing would happen here.
                ReceiveResult::Accepted
            }
            None => {
                self.metrics.pkt_no_conn[3] += 1; // Application level
                ReceiveResult::Dropped
            }
        }
    }

    /// Create a new server-side connection.
    fn create_server_connection(
        &mut self,
        original_dcid: ConnectionId,
        current_dcid: ConnectionId,
        peer_scid: ConnectionId,
        now_ns: u64,
        callbacks: &mut dyn EngineCallbacks,
    ) -> ReceiveResult {
        let conn_idx = match self.allocate_connection() {
            Some(idx) => idx,
            None => return ReceiveResult::Dropped,
        };

        // Generate our new connection ID before borrowing the connection.
        let local_cid = self.generate_connection_id();

        let conn = &mut self.connections[conn_idx as usize];
        conn.init_server(local_cid, peer_scid, original_dcid, now_ns);
        conn.idle_timeout_ns = self.config.idle_timeout_ns;

        // Derive initial keys from the original destination CID.
        conn.secrets = ConnectionSecrets::derive_initial(original_dcid.as_bytes(), true);
        conn.keys_available[0] = true; // Initial level

        // Set flow control from config.
        conn.local_max_data = self.config.initial_rx_max_data;
        conn.peer_max_streams_bidi = self.config.initial_max_streams_bidi;
        conn.peer_max_streams_uni = self.config.initial_max_streams_uni;

        // Register connection IDs.
        self.conn_map.insert(local_cid, conn_idx);
        // Also map the current DCID the client used.
        if current_dcid != local_cid {
            self.conn_map.insert(current_dcid, conn_idx);
        }

        // Schedule for immediate service.
        self.service_queue
            .schedule(conn_idx, now_ns as i64, now_ns as i64);

        callbacks.on_connection_new(conn_idx as usize);

        self.metrics.conn_created += 1;
        self.active_connections += 1;

        ReceiveResult::NewConnection
    }

    /// Compute per-state connection counts for metrics.
    fn compute_state_counts(&self) -> [u64; paradencer_constants::network::CONN_STATE_COUNT] {
        let mut counts = [0u64; paradencer_constants::network::CONN_STATE_COUNT];
        for conn in &self.connections {
            counts[conn.state as usize] += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::callbacks::{NoopCallbacks, RecordingCallbacks};
    use crate::quic::retry::RetryTokenData;

    fn test_limits() -> EngineLimits {
        EngineLimits {
            max_connections: 16,
            max_handshakes: 8,
            conn_ids_per_conn: 4,
            streams_per_conn: 4,
            tx_buf_size: 1024,
            stream_pool_size: 32,
        }
    }

    fn server_config() -> EngineConfig {
        EngineConfig {
            role: EngineRole::Server,
            enable_retry: false, // Simpler for basic tests
            ..Default::default()
        }
    }

    fn client_config() -> EngineConfig {
        EngineConfig {
            role: EngineRole::Client,
            ..Default::default()
        }
    }

    #[test]
    fn engine_creation() {
        let engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        assert_eq!(engine.active_connection_count(), 0);
        assert_eq!(engine.max_connections(), 16);
        assert_eq!(engine.next_service_time(), i64::MAX);
    }

    #[test]
    fn engine_creation_fails_with_invalid_limits() {
        let mut limits = test_limits();
        limits.max_connections = 0;
        assert!(QuicEngine::new(limits, server_config()).is_none());
    }

    #[test]
    fn client_connect() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = RecordingCallbacks::new();

        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };
        let conn_idx = engine.connect(dst, 1000, &mut cb).unwrap();

        assert_eq!(engine.active_connection_count(), 1);
        assert!(engine.connection(conn_idx).is_some());
        assert_eq!(
            engine.connection(conn_idx).unwrap().state,
            ConnectionState::Handshaking
        );
        assert_eq!(cb.events.len(), 1);
        assert!(cb.events[0].starts_with("conn_new:"));
    }

    #[test]
    fn server_cannot_connect() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };
        assert!(engine.connect(dst, 1000, &mut cb).is_none());
    }

    #[test]
    fn connection_pool_exhaustion() {
        let mut limits = test_limits();
        limits.max_connections = 2;
        let mut engine = QuicEngine::new(limits, client_config()).unwrap();
        let mut cb = NoopCallbacks;
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        assert!(engine.connect(dst, 100, &mut cb).is_some());
        assert!(engine.connect(dst, 200, &mut cb).is_some());
        assert!(engine.connect(dst, 300, &mut cb).is_none()); // Pool exhausted
        assert_eq!(engine.active_connection_count(), 2);
    }

    #[test]
    fn service_idle_returns_idle() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        assert_eq!(engine.service(1000, &mut cb), ServiceResult::Idle);
    }

    #[test]
    fn service_processes_connection() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = NoopCallbacks;
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        engine.connect(dst, 1000, &mut cb);
        let result = engine.service(1000, &mut cb);
        assert_eq!(result, ServiceResult::Processed);
    }

    #[test]
    fn close_connection_transitions_to_abort() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = NoopCallbacks;
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        let conn_idx = engine.connect(dst, 1000, &mut cb).unwrap();

        // Activate the connection manually for testing.
        engine.connections[conn_idx as usize].activate(1000);

        engine.close_connection(conn_idx, 0x01, 2000);
        assert_eq!(
            engine.connection(conn_idx).unwrap().state,
            ConnectionState::Abort
        );
    }

    #[test]
    fn idle_timeout_closes_connection() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = RecordingCallbacks::new();
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        let conn_idx = engine.connect(dst, 1000, &mut cb).unwrap();
        engine.connections[conn_idx as usize].activate(1000);

        // Service well past idle timeout (default 1 second).
        let result = engine.service(1000 + 2_000_000_000, &mut cb);
        assert_eq!(result, ServiceResult::Processed);
        assert!(engine.metrics.conn_timeout > 0);
    }

    #[test]
    fn receive_empty_packet_dropped() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        let src = PeerAddress {
            ip: 0x7F000001,
            port: 12345,
        };

        let result = engine.receive_packet(&[], src, 1000, &mut cb);
        assert_eq!(result, ReceiveResult::Dropped);
        assert_eq!(engine.metrics.pkt_undersized, 1);
    }

    #[test]
    fn receive_short_packet_no_connection() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        let src = PeerAddress {
            ip: 0x7F000001,
            port: 12345,
        };

        // Short header with unknown connection ID.
        let mut data = vec![0x40]; // Short header flag
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // 8-byte CID
        data.extend_from_slice(&[0u8; 32]); // payload padding

        let result = engine.receive_packet(&data, src, 1000, &mut cb);
        assert_eq!(result, ReceiveResult::Dropped);
    }

    #[test]
    fn receive_initial_creates_connection() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = RecordingCallbacks::new();
        let src = PeerAddress {
            ip: 0x0A000001,
            port: 12345,
        };

        // Build a minimal Initial packet.
        let mut pkt = Vec::new();
        pkt.push(0xC0); // Long header, Initial type (00 in bits 5-4)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        pkt.push(8); // DCID length
        pkt.extend_from_slice(&[0xAA; 8]); // DCID
        pkt.push(8); // SCID length
        pkt.extend_from_slice(&[0xBB; 8]); // SCID
        pkt.push(0x00); // Token length = 0 (varint)
                        // Padding to reach minimum packet size is not needed for this test
        pkt.extend_from_slice(&[0u8; 32]); // payload

        let result = engine.receive_packet(&pkt, src, 1000, &mut cb);
        assert_eq!(result, ReceiveResult::NewConnection);
        assert_eq!(engine.active_connection_count(), 1);
        assert_eq!(cb.events.len(), 1);
        assert!(cb.events[0].starts_with("conn_new:"));
    }

    #[test]
    fn receive_initial_with_retry_enabled_sends_retry() {
        let mut config = server_config();
        config.enable_retry = true;
        let mut engine = QuicEngine::new(test_limits(), config).unwrap();
        let mut cb = NoopCallbacks;
        let src = PeerAddress {
            ip: 0x0A000001,
            port: 12345,
        };

        // Initial with empty token → should trigger Retry.
        let mut pkt = Vec::new();
        pkt.push(0xC0);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        pkt.push(8); // DCID length
        pkt.extend_from_slice(&[0xAA; 8]);
        pkt.push(8); // SCID length
        pkt.extend_from_slice(&[0xBB; 8]);
        pkt.push(0x00); // Token length = 0
        pkt.extend_from_slice(&[0u8; 32]);

        let result = engine.receive_packet(&pkt, src, 1000, &mut cb);
        assert_eq!(result, ReceiveResult::RetrySent);
        assert_eq!(engine.metrics.retry_tx, 1);
        assert_eq!(engine.active_connection_count(), 0);
    }

    #[test]
    fn receive_version_mismatch_dropped() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        let src = PeerAddress {
            ip: 0x7F000001,
            port: 12345,
        };

        let mut pkt = Vec::new();
        pkt.push(0xC0);
        pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Unknown version
        pkt.push(8);
        pkt.extend_from_slice(&[0xAA; 8]);
        pkt.push(8);
        pkt.extend_from_slice(&[0xBB; 8]);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0u8; 32]);

        let result = engine.receive_packet(&pkt, src, 1000, &mut cb);
        assert_eq!(result, ReceiveResult::Dropped);
        assert_eq!(engine.metrics.pkt_version_mismatch, 1);
    }

    #[test]
    fn metrics_track_rx() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let mut cb = NoopCallbacks;
        let src = PeerAddress {
            ip: 0x7F000001,
            port: 12345,
        };

        engine.receive_packet(&[0x01], src, 1000, &mut cb);
        engine.receive_packet(&[0x02, 0x03], src, 2000, &mut cb);

        assert_eq!(engine.metrics.rx_packets, 2);
        assert_eq!(engine.metrics.rx_bytes, 3);
    }

    #[test]
    fn connection_lifecycle_through_service() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = RecordingCallbacks::new();
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        // Create and immediately close.
        let conn_idx = engine.connect(dst, 1000, &mut cb).unwrap();
        engine.connections[conn_idx as usize].activate(1000);
        engine.close_connection(conn_idx, 0x00, 2000);

        // Service: should process Abort → ClosePending.
        engine.service(2000, &mut cb);
        assert_eq!(
            engine.connections[conn_idx as usize].state,
            ConnectionState::ClosePending
        );

        // Service past drain timeout: ClosePending → Dead → freed.
        engine.service(2000 + 5_000_000_000, &mut cb);
        assert_eq!(
            engine.connections[conn_idx as usize].state,
            ConnectionState::Dead
        );

        // Next service should clean up Dead connection.
        engine
            .service_queue
            .schedule(conn_idx, 2000_i64 + 5_000_000_001, 2000_i64 + 5_000_000_001);
        engine.service(2000 + 5_000_000_001, &mut cb);

        // Connection should be released.
        assert!(engine.connection(conn_idx).is_none());
        assert!(cb.events.iter().any(|e| e.starts_with("conn_final:")));
    }

    #[test]
    fn multiple_connections_service_order() {
        let mut engine = QuicEngine::new(test_limits(), client_config()).unwrap();
        let mut cb = NoopCallbacks;
        let dst = PeerAddress {
            ip: 0x7F000001,
            port: 9000,
        };

        // Create 3 connections at different times.
        let c0 = engine.connect(dst, 100, &mut cb).unwrap();
        let c1 = engine.connect(dst, 200, &mut cb).unwrap();
        let c2 = engine.connect(dst, 300, &mut cb).unwrap();

        assert_eq!(engine.active_connection_count(), 3);

        // Service all three.
        engine.service(300, &mut cb);
        engine.service(300, &mut cb);
        engine.service(300, &mut cb);
        assert_eq!(engine.service(300, &mut cb), ServiceResult::Idle);

        // All three should still be alive.
        assert!(engine.connection(c0).unwrap().state.is_alive());
        assert!(engine.connection(c1).unwrap().state.is_alive());
        assert!(engine.connection(c2).unwrap().state.is_alive());
    }

    #[test]
    fn set_retry_secret() {
        let mut engine = QuicEngine::new(test_limits(), server_config()).unwrap();
        let secret = [0x42; QUIC_RETRY_SECRET_SIZE];
        let iv = [0x13; QUIC_RETRY_IV_SIZE];
        engine.set_retry_secret(secret, iv);
        assert_eq!(engine.retry_secret, secret);
        assert_eq!(engine.retry_iv, iv);
    }

    #[test]
    fn receive_initial_with_valid_retry_token() {
        let mut config = server_config();
        config.enable_retry = true;
        let mut engine = QuicEngine::new(test_limits(), config).unwrap();

        let secret = [0x42; QUIC_RETRY_SECRET_SIZE];
        let iv = [0x13; QUIC_RETRY_IV_SIZE];
        engine.set_retry_secret(secret, iv);

        let src = PeerAddress {
            ip: 0x0A000001,
            port: 12345,
        };

        // Generate a valid retry token.
        let original_dcid = ConnectionId::from_bytes(&[0xAA; 8]).unwrap();
        let token_data = RetryTokenData {
            original_dst_conn_id: original_dcid,
            client_ip: src.ip,
            client_port: src.port,
            expire_at: 2_000_000_000,
        };
        let nonce = [0x01; 12];
        let token = RetryToken::generate(&secret, &iv, &nonce, &token_data).unwrap();

        // Build Initial packet with the token.
        let mut pkt = Vec::new();
        pkt.push(0xC0);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        pkt.push(8);
        pkt.extend_from_slice(&[0xCC; 8]); // New DCID (after retry)
        pkt.push(8);
        pkt.extend_from_slice(&[0xDD; 8]); // SCID

        // Encode token length as varint.
        let token_len = token.len();
        if token_len < 64 {
            pkt.push(token_len as u8);
        } else {
            pkt.push(0x40 | ((token_len >> 8) as u8));
            pkt.push((token_len & 0xFF) as u8);
        }
        pkt.extend_from_slice(&token);
        pkt.extend_from_slice(&[0u8; 32]); // payload

        let mut cb = RecordingCallbacks::new();
        let result = engine.receive_packet(&pkt, src, 1_000_000_000, &mut cb);
        assert_eq!(result, ReceiveResult::NewConnection);
        assert_eq!(engine.active_connection_count(), 1);
    }
}
