/// QUIC connection state machine and per-connection data.
///
/// Models the 8-state connection lifecycle. Each connection stores its
/// cryptographic secrets, packet number state, flow control limits, and
/// connection IDs. Designed for pre-allocated pools with no heap allocation
/// in the hot path.
use super::conn_id::ConnectionId;
use super::crypto::ConnectionSecrets;
use super::pkt_number::{PacketNumberGenerator, PacketNumberSpace, PacketNumberTracker};
use paradencer_constants::network::QUIC_NUM_ENC_LEVELS;

/// Connection lifecycle states (8 states matching the protocol spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// Slot is unused / available for reuse.
    Invalid = 0,
    /// TLS handshake in progress.
    Handshaking = 1,
    /// TLS handshake complete, waiting for HANDSHAKE_DONE.
    HandshakeComplete = 2,
    /// Fully established, data transfer active.
    Active = 3,
    /// Peer sent CONNECTION_CLOSE, draining.
    PeerClose = 4,
    /// Local error, sending CONNECTION_CLOSE.
    Abort = 5,
    /// CONNECTION_CLOSE sent, waiting for drain timeout.
    ClosePending = 6,
    /// Connection fully terminated, slot ready for cleanup.
    Dead = 7,
}

impl ConnectionState {
    /// Whether data frames can be sent in this state.
    pub fn can_send_data(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the connection is still alive (not dead or invalid).
    pub fn is_alive(self) -> bool {
        !matches!(self, Self::Invalid | Self::Dead)
    }

    /// Whether the connection is in a closing state.
    pub fn is_closing(self) -> bool {
        matches!(self, Self::PeerClose | Self::Abort | Self::ClosePending)
    }
}

/// Role of this endpoint in the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Client = 1,
    Server = 2,
}

/// Per-connection data for a QUIC connection.
///
/// Stores all state needed for a single connection. Designed to live in
/// a pre-allocated pool (`ConnectionPool`).
pub struct Connection {
    /// Current connection state.
    pub state: ConnectionState,
    /// Our role (client or server).
    pub role: Role,
    /// Our connection ID that the peer addresses us by.
    pub local_conn_id: ConnectionId,
    /// Peer's connection ID.
    pub peer_conn_id: ConnectionId,
    /// Original destination connection ID (from Initial packet).
    pub original_dst_conn_id: ConnectionId,
    /// Index in the connection pool (for reverse lookups).
    pub pool_index: u32,
    /// Cryptographic secrets and key material per encryption level.
    pub secrets: ConnectionSecrets,
    /// Per-space packet number generator (for sending).
    pub pn_generators: [PacketNumberGenerator; PacketNumberSpace::COUNT],
    /// Per-space packet number tracker (for receiving).
    pub pn_trackers: [PacketNumberTracker; PacketNumberSpace::COUNT],
    /// Whether keys exist for each encryption level.
    pub keys_available: [bool; QUIC_NUM_ENC_LEVELS],
    /// Connection-level flow control: max bytes we can send.
    pub peer_max_data: u64,
    /// Connection-level flow control: bytes we've sent.
    pub tx_data_sent: u64,
    /// Connection-level flow control: max bytes peer can send.
    pub local_max_data: u64,
    /// Connection-level flow control: bytes peer has sent.
    pub rx_data_received: u64,
    /// Maximum number of bidirectional streams the peer allows.
    pub peer_max_streams_bidi: u64,
    /// Maximum number of unidirectional streams the peer allows.
    pub peer_max_streams_uni: u64,
    /// Number of bidirectional streams we've opened.
    pub local_streams_bidi: u64,
    /// Number of unidirectional streams we've opened.
    pub local_streams_uni: u64,
    /// Idle timeout in nanoseconds (0 = disabled).
    pub idle_timeout_ns: u64,
    /// Last activity timestamp in nanoseconds.
    pub last_activity_ns: u64,
    /// Timestamp when this connection entered its current state.
    pub state_changed_ns: u64,
    /// Closing error code (when in Abort/ClosePending state).
    pub close_error_code: u64,
    /// Whether this is the server side of the connection.
    pub is_server: bool,
    /// Whether peer has completed the handshake (server sees client Finished).
    pub peer_handshake_complete: bool,
    /// Spin bit state for latency measurement.
    pub spin_bit: bool,
    /// Key phase for key update tracking.
    pub key_phase: bool,
}

impl Connection {
    /// Create a new connection in the Invalid state (ready for pool allocation).
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Invalid,
            role: Role::Client,
            local_conn_id: ConnectionId::EMPTY,
            peer_conn_id: ConnectionId::EMPTY,
            original_dst_conn_id: ConnectionId::EMPTY,
            pool_index: 0,
            secrets: ConnectionSecrets::new(),
            pn_generators: [
                PacketNumberGenerator::new(),
                PacketNumberGenerator::new(),
                PacketNumberGenerator::new(),
            ],
            pn_trackers: [
                PacketNumberTracker::new(),
                PacketNumberTracker::new(),
                PacketNumberTracker::new(),
            ],
            keys_available: [false; QUIC_NUM_ENC_LEVELS],
            peer_max_data: 0,
            tx_data_sent: 0,
            local_max_data: 0,
            rx_data_received: 0,
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            local_streams_bidi: 0,
            local_streams_uni: 0,
            idle_timeout_ns: 0,
            last_activity_ns: 0,
            state_changed_ns: 0,
            close_error_code: 0,
            is_server: false,
            peer_handshake_complete: false,
            spin_bit: false,
            key_phase: false,
        }
    }

    /// Initialize a connection for a new incoming (server-side) connection.
    pub fn init_server(
        &mut self,
        local_conn_id: ConnectionId,
        peer_conn_id: ConnectionId,
        original_dst_conn_id: ConnectionId,
        now_ns: u64,
    ) {
        self.state = ConnectionState::Handshaking;
        self.role = Role::Server;
        self.is_server = true;
        self.local_conn_id = local_conn_id;
        self.peer_conn_id = peer_conn_id;
        self.original_dst_conn_id = original_dst_conn_id;
        self.last_activity_ns = now_ns;
        self.state_changed_ns = now_ns;
    }

    /// Initialize a connection for a new outgoing (client-side) connection.
    pub fn init_client(
        &mut self,
        local_conn_id: ConnectionId,
        peer_conn_id: ConnectionId,
        now_ns: u64,
    ) {
        self.state = ConnectionState::Handshaking;
        self.role = Role::Client;
        self.is_server = false;
        self.local_conn_id = local_conn_id;
        self.peer_conn_id = peer_conn_id;
        self.original_dst_conn_id = peer_conn_id;
        self.last_activity_ns = now_ns;
        self.state_changed_ns = now_ns;
    }

    /// Transition to the given state.
    pub fn transition(&mut self, new_state: ConnectionState, now_ns: u64) {
        self.state = new_state;
        self.state_changed_ns = now_ns;
    }

    /// Mark the connection as fully established (handshake done).
    pub fn activate(&mut self, now_ns: u64) {
        self.state = ConnectionState::Active;
        self.state_changed_ns = now_ns;
    }

    /// Begin connection close with a transport error.
    pub fn begin_close(&mut self, error_code: u64, now_ns: u64) {
        if !self.state.is_closing() && self.state.is_alive() {
            self.close_error_code = error_code;
            self.state = ConnectionState::Abort;
            self.state_changed_ns = now_ns;
        }
    }

    /// Mark connection as dead (ready for pool reclamation).
    pub fn mark_dead(&mut self, now_ns: u64) {
        self.state = ConnectionState::Dead;
        self.state_changed_ns = now_ns;
    }

    /// Reset all fields for pool reuse.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Whether the connection has flow control capacity to send `bytes` more.
    pub fn can_send_bytes(&self, bytes: u64) -> bool {
        self.tx_data_sent + bytes <= self.peer_max_data
    }

    /// Record that we sent `bytes` of stream data.
    pub fn record_tx_data(&mut self, bytes: u64) {
        self.tx_data_sent += bytes;
    }

    /// Whether the peer can still send us data.
    pub fn can_receive_bytes(&self, bytes: u64) -> bool {
        self.rx_data_received + bytes <= self.local_max_data
    }

    /// Record that we received `bytes` of stream data from the peer.
    pub fn record_rx_data(&mut self, bytes: u64) {
        self.rx_data_received += bytes;
    }

    /// Touch the activity timestamp.
    pub fn touch(&mut self, now_ns: u64) {
        self.last_activity_ns = now_ns;
    }

    /// Check if the connection has timed out due to idleness.
    pub fn is_idle_timed_out(&self, now_ns: u64) -> bool {
        self.idle_timeout_ns > 0
            && now_ns.saturating_sub(self.last_activity_ns) >= self.idle_timeout_ns
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connection_is_invalid() {
        let conn = Connection::new();
        assert_eq!(conn.state, ConnectionState::Invalid);
        assert!(!conn.state.is_alive());
    }

    #[test]
    fn server_init() {
        let mut conn = Connection::new();
        let local = ConnectionId::from_bytes(&[0x01, 0x02]).unwrap();
        let peer = ConnectionId::from_bytes(&[0x03, 0x04]).unwrap();
        let orig = ConnectionId::from_bytes(&[0x05, 0x06]).unwrap();

        conn.init_server(local, peer, orig, 1000);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Server);
        assert!(conn.is_server);
        assert_eq!(conn.local_conn_id, local);
        assert_eq!(conn.peer_conn_id, peer);
        assert_eq!(conn.original_dst_conn_id, orig);
    }

    #[test]
    fn client_init() {
        let mut conn = Connection::new();
        let local = ConnectionId::from_bytes(&[0xAA]).unwrap();
        let peer = ConnectionId::from_bytes(&[0xBB]).unwrap();

        conn.init_client(local, peer, 2000);
        assert_eq!(conn.state, ConnectionState::Handshaking);
        assert_eq!(conn.role, Role::Client);
        assert!(!conn.is_server);
    }

    #[test]
    fn state_transitions() {
        let mut conn = Connection::new();
        let local = ConnectionId::from_bytes(&[0x01]).unwrap();
        let peer = ConnectionId::from_bytes(&[0x02]).unwrap();
        conn.init_server(local, peer, peer, 100);

        assert!(conn.state.is_alive());
        assert!(!conn.state.can_send_data());

        conn.transition(ConnectionState::HandshakeComplete, 200);
        assert_eq!(conn.state, ConnectionState::HandshakeComplete);

        conn.activate(300);
        assert_eq!(conn.state, ConnectionState::Active);
        assert!(conn.state.can_send_data());

        conn.begin_close(0x01, 400);
        assert_eq!(conn.state, ConnectionState::Abort);
        assert!(conn.state.is_closing());
        assert!(!conn.state.can_send_data());

        conn.mark_dead(500);
        assert_eq!(conn.state, ConnectionState::Dead);
        assert!(!conn.state.is_alive());
    }

    #[test]
    fn flow_control() {
        let mut conn = Connection::new();
        conn.peer_max_data = 1000;
        conn.local_max_data = 500;

        assert!(conn.can_send_bytes(500));
        conn.record_tx_data(500);
        assert!(conn.can_send_bytes(500));
        assert!(!conn.can_send_bytes(501));

        assert!(conn.can_receive_bytes(500));
        conn.record_rx_data(400);
        assert!(conn.can_receive_bytes(100));
        assert!(!conn.can_receive_bytes(101));
    }

    #[test]
    fn idle_timeout() {
        let mut conn = Connection::new();
        conn.idle_timeout_ns = 1_000_000_000; // 1 second
        conn.last_activity_ns = 100;

        assert!(!conn.is_idle_timed_out(500));
        assert!(!conn.is_idle_timed_out(1_000_000_099));
        assert!(conn.is_idle_timed_out(1_000_000_100));
    }

    #[test]
    fn idle_timeout_disabled() {
        let mut conn = Connection::new();
        conn.idle_timeout_ns = 0; // disabled
        conn.last_activity_ns = 0;
        assert!(!conn.is_idle_timed_out(u64::MAX));
    }

    #[test]
    fn reset_clears_state() {
        let mut conn = Connection::new();
        let local = ConnectionId::from_bytes(&[0x01]).unwrap();
        let peer = ConnectionId::from_bytes(&[0x02]).unwrap();
        conn.init_server(local, peer, peer, 100);
        conn.activate(200);
        conn.peer_max_data = 5000;

        conn.reset();
        assert_eq!(conn.state, ConnectionState::Invalid);
        assert_eq!(conn.peer_max_data, 0);
    }

    #[test]
    fn connection_state_properties() {
        assert!(!ConnectionState::Invalid.is_alive());
        assert!(ConnectionState::Handshaking.is_alive());
        assert!(ConnectionState::Active.is_alive());
        assert!(ConnectionState::PeerClose.is_alive());
        assert!(!ConnectionState::Dead.is_alive());

        assert!(ConnectionState::PeerClose.is_closing());
        assert!(ConnectionState::Abort.is_closing());
        assert!(ConnectionState::ClosePending.is_closing());
        assert!(!ConnectionState::Active.is_closing());

        assert!(ConnectionState::Active.can_send_data());
        assert!(!ConnectionState::Handshaking.can_send_data());
    }

    #[test]
    fn double_close_is_idempotent() {
        let mut conn = Connection::new();
        let local = ConnectionId::from_bytes(&[0x01]).unwrap();
        let peer = ConnectionId::from_bytes(&[0x02]).unwrap();
        conn.init_server(local, peer, peer, 100);
        conn.activate(200);

        conn.begin_close(0x01, 300);
        assert_eq!(conn.state, ConnectionState::Abort);
        assert_eq!(conn.close_error_code, 0x01);

        // Second close attempt doesn't change state
        conn.begin_close(0x02, 400);
        assert_eq!(conn.state, ConnectionState::Abort);
        assert_eq!(conn.close_error_code, 0x01); // Unchanged
    }
}
