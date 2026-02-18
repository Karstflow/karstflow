/// Transport backend abstraction.
///
/// Provides a unified interface over different packet transport mechanisms:
/// - UDP socket (portable, uses sendmmsg/recvmmsg on Linux)
/// - AF_XDP (Linux kernel bypass, zero-copy)
///
/// The backend is selected at initialization time and presents the same
/// API for sending and receiving packet batches.
use crate::io::IoHandle;

/// Transport backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// Standard UDP socket (portable).
    Udp,
    /// AF_XDP kernel bypass (Linux only).
    Xdp,
}

impl BackendType {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Xdp => "xdp",
        }
    }

    /// Whether this backend requires root/CAP_NET_ADMIN.
    pub fn requires_privileges(self) -> bool {
        matches!(self, Self::Xdp)
    }

    /// Whether this backend is available on the current platform.
    pub fn is_available(self) -> bool {
        match self {
            Self::Udp => true,
            Self::Xdp => cfg!(target_os = "linux"),
        }
    }
}

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Backend type to use.
    pub backend: BackendType,
    /// Bind address (IPv4, host byte order).
    pub bind_addr: u32,
    /// Bind port.
    pub bind_port: u16,
    /// Network interface name (for XDP).
    pub interface: String,
    /// NIC queue index (for XDP).
    pub queue_id: u32,
    /// UDP receive buffer size.
    pub recv_buf_size: usize,
    /// UDP send buffer size.
    pub send_buf_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::Udp,
            bind_addr: 0, // INADDR_ANY
            bind_port: 0,
            interface: String::new(),
            queue_id: 0,
            recv_buf_size: 2 * 1024 * 1024,
            send_buf_size: 2 * 1024 * 1024,
        }
    }
}

/// Transport statistics.
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    /// Total packets received.
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total packets sent.
    pub tx_packets: u64,
    /// Total bytes sent.
    pub tx_bytes: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Send errors.
    pub tx_errors: u64,
}

impl TransportStats {
    /// Record a received batch.
    pub fn record_rx(&mut self, packets: usize, bytes: usize) {
        self.rx_packets += packets as u64;
        self.rx_bytes += bytes as u64;
    }

    /// Record a sent batch.
    pub fn record_tx(&mut self, packets: usize, bytes: usize) {
        self.tx_packets += packets as u64;
        self.tx_bytes += bytes as u64;
    }

    /// Record a receive error.
    pub fn record_rx_error(&mut self) {
        self.rx_errors += 1;
    }

    /// Record a send error.
    pub fn record_tx_error(&mut self) {
        self.tx_errors += 1;
    }
}

/// Unified transport handle.
///
/// Wraps the selected backend and provides batch send/receive operations.
/// This is the main entry point for packet I/O in the networking stack.
pub struct Transport {
    /// Backend type.
    backend_type: BackendType,
    /// Transport configuration.
    config: TransportConfig,
    /// Cumulative statistics.
    stats: TransportStats,
    /// Optional IO callback for received packets.
    rx_callback: Option<IoHandle>,
}

impl Transport {
    /// Create a new transport with the given configuration.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            backend_type: config.backend,
            config,
            stats: TransportStats::default(),
            rx_callback: None,
        }
    }

    /// Set the callback for received packets.
    pub fn set_rx_callback(&mut self, callback: IoHandle) {
        self.rx_callback = Some(callback);
    }

    /// Backend type in use.
    pub fn backend_type(&self) -> BackendType {
        self.backend_type
    }

    /// Transport configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Current statistics.
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Mutable statistics (for recording events).
    pub fn stats_mut(&mut self) -> &mut TransportStats {
        &mut self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = TransportStats::default();
    }

    /// Whether the transport has an RX callback set.
    pub fn has_rx_callback(&self) -> bool {
        self.rx_callback.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_type_properties() {
        assert_eq!(BackendType::Udp.name(), "udp");
        assert_eq!(BackendType::Xdp.name(), "xdp");
        assert!(!BackendType::Udp.requires_privileges());
        assert!(BackendType::Xdp.requires_privileges());
        assert!(BackendType::Udp.is_available());
    }

    #[test]
    fn transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.backend, BackendType::Udp);
        assert_eq!(config.bind_port, 0);
    }

    #[test]
    fn transport_creation() {
        let config = TransportConfig {
            bind_port: 8000,
            ..Default::default()
        };
        let transport = Transport::new(config);
        assert_eq!(transport.backend_type(), BackendType::Udp);
        assert_eq!(transport.config().bind_port, 8000);
    }

    #[test]
    fn transport_stats() {
        let mut stats = TransportStats::default();
        stats.record_rx(10, 1500);
        stats.record_tx(5, 750);
        stats.record_rx_error();

        assert_eq!(stats.rx_packets, 10);
        assert_eq!(stats.rx_bytes, 1500);
        assert_eq!(stats.tx_packets, 5);
        assert_eq!(stats.tx_bytes, 750);
        assert_eq!(stats.rx_errors, 1);
    }
}
