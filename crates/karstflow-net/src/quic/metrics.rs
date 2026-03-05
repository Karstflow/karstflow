/// QUIC engine metrics counters.
///
/// Tracks packet, connection, stream, and handshake statistics for
/// monitoring and debugging. All counters are u64 and can be atomically
/// read from a monitoring thread.
use karstflow_constants::network::{CONN_STATE_COUNT, FRAME_TYPE_COUNT};

/// Comprehensive QUIC engine metrics.
#[derive(Debug, Clone)]
pub struct EngineMetrics {
    // --- Network ---
    /// Total packets received.
    pub rx_packets: u64,
    /// Total bytes received (including headers).
    pub rx_bytes: u64,
    /// Total packets transmitted.
    pub tx_packets: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Retry packets sent.
    pub retry_tx: u64,

    // --- Connections ---
    /// Currently allocated connections.
    pub conn_active: u64,
    /// Total connections created.
    pub conn_created: u64,
    /// Connections closed gracefully.
    pub conn_closed: u64,
    /// Connections aborted.
    pub conn_aborted: u64,
    /// Connections timed out (idle).
    pub conn_timeout: u64,
    /// Connections established via retry.
    pub conn_retry: u64,
    /// Connection creation failed (no free slots).
    pub conn_err_no_slots: u64,
    /// Retry token validation failed.
    pub conn_err_retry_fail: u64,
    /// Per-state connection counts.
    pub conn_state_counts: [u64; CONN_STATE_COUNT],

    // --- Packets ---
    /// IP/UDP header parse errors.
    pub pkt_net_header_err: u64,
    /// QUIC header parse errors.
    pub pkt_quic_header_err: u64,
    /// Packets too small.
    pub pkt_undersized: u64,
    /// Packets too large.
    pub pkt_oversized: u64,
    /// Decryption failures per encryption level.
    pub pkt_decrypt_fail: [u64; 4],
    /// Missing keys per encryption level.
    pub pkt_no_key: [u64; 4],
    /// Unknown connection ID per encryption level.
    pub pkt_no_conn: [u64; 4],
    /// Version mismatch.
    pub pkt_version_mismatch: u64,

    // --- Frames ---
    /// RX frame counts by type.
    pub frame_rx: [u64; FRAME_TYPE_COUNT],
    /// Frame processing errors.
    pub frame_rx_err: u64,

    // --- Streams ---
    /// Streams opened.
    pub stream_opened: u64,
    /// Streams closed.
    pub stream_closed: u64,
    /// Currently active streams.
    pub stream_active: u64,
    /// Stream RX data events.
    pub stream_rx_events: u64,
    /// Total stream RX bytes.
    pub stream_rx_bytes: u64,

    // --- Handshakes ---
    /// TLS handshakes started.
    pub hs_started: u64,
    /// TLS handshakes completed.
    pub hs_completed: u64,
    /// Handshake allocation failures.
    pub hs_alloc_fail: u64,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineMetrics {
    /// Create zeroed metrics.
    pub fn new() -> Self {
        Self {
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            retry_tx: 0,
            conn_active: 0,
            conn_created: 0,
            conn_closed: 0,
            conn_aborted: 0,
            conn_timeout: 0,
            conn_retry: 0,
            conn_err_no_slots: 0,
            conn_err_retry_fail: 0,
            conn_state_counts: [0; CONN_STATE_COUNT],
            pkt_net_header_err: 0,
            pkt_quic_header_err: 0,
            pkt_undersized: 0,
            pkt_oversized: 0,
            pkt_decrypt_fail: [0; 4],
            pkt_no_key: [0; 4],
            pkt_no_conn: [0; 4],
            pkt_version_mismatch: 0,
            frame_rx: [0; FRAME_TYPE_COUNT],
            frame_rx_err: 0,
            stream_opened: 0,
            stream_closed: 0,
            stream_active: 0,
            stream_rx_events: 0,
            stream_rx_bytes: 0,
            hs_started: 0,
            hs_completed: 0,
            hs_alloc_fail: 0,
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_default_all_zero() {
        let m = EngineMetrics::new();
        assert_eq!(m.rx_packets, 0);
        assert_eq!(m.tx_packets, 0);
        assert_eq!(m.conn_active, 0);
        assert_eq!(m.conn_created, 0);
        assert_eq!(m.stream_opened, 0);
        assert_eq!(m.hs_started, 0);
    }

    #[test]
    fn metrics_increment_and_reset() {
        let mut m = EngineMetrics::new();
        m.rx_packets = 100;
        m.conn_created = 50;
        m.stream_opened = 200;

        assert_eq!(m.rx_packets, 100);
        assert_eq!(m.conn_created, 50);

        m.reset();
        assert_eq!(m.rx_packets, 0);
        assert_eq!(m.conn_created, 0);
        assert_eq!(m.stream_opened, 0);
    }

    #[test]
    fn per_enc_level_counters() {
        let mut m = EngineMetrics::new();
        m.pkt_decrypt_fail[0] = 5; // Initial
        m.pkt_decrypt_fail[2] = 3; // Handshake
        m.pkt_no_key[3] = 1; // Application

        assert_eq!(m.pkt_decrypt_fail[0], 5);
        assert_eq!(m.pkt_decrypt_fail[2], 3);
        assert_eq!(m.pkt_no_key[3], 1);
    }

    #[test]
    fn frame_rx_counters() {
        let mut m = EngineMetrics::new();
        m.frame_rx[0x02] = 100; // ACK frames
        m.frame_rx[0x06] = 50; // CRYPTO frames
        assert_eq!(m.frame_rx[0x02], 100);
        assert_eq!(m.frame_rx[0x06], 50);
    }
}
