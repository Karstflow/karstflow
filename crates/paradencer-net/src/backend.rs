/// Transport backend abstraction with actual packet I/O.
///
/// Provides a unified interface over different packet transport mechanisms:
/// - UDP socket (portable, uses sendto/recvfrom, non-blocking)
/// - AF_XDP (Linux kernel bypass, zero-copy) — future integration
///
/// The backend is selected at initialization time. Both backends expose
/// the same batch receive/send API through the `Transport` struct.
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::packet::PacketBatch;
use crate::socket::{SocketConfig, UdpSocket};

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
    /// Bind address (IPv4).
    pub bind_addr: Ipv4Addr,
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
            bind_addr: Ipv4Addr::UNSPECIFIED,
            bind_port: 0,
            interface: String::new(),
            queue_id: 0,
            recv_buf_size: 4 * 1024 * 1024,
            send_buf_size: 4 * 1024 * 1024,
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

/// Active backend resource.
enum Backend {
    /// UDP socket backend.
    Udp(UdpSocket),
    /// Not yet bound (initial state before `bind()`).
    Unbound,
}

/// Unified transport handle with actual packet I/O.
///
/// Wraps the selected backend and provides batch send/receive operations.
/// Must be explicitly opened via `open()` before I/O operations.
pub struct Transport {
    /// Active backend.
    backend: Backend,
    /// Backend type.
    backend_type: BackendType,
    /// Transport configuration.
    config: TransportConfig,
    /// Cumulative statistics.
    stats: TransportStats,
}

impl Transport {
    /// Create a new transport (not yet bound).
    ///
    /// Call `open()` to bind the socket and start I/O.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            backend: Backend::Unbound,
            backend_type: config.backend,
            config,
            stats: TransportStats::default(),
        }
    }

    /// Open the transport: create and bind the underlying socket.
    pub fn open(&mut self) -> io::Result<()> {
        match self.backend_type {
            BackendType::Udp => {
                let socket_config = SocketConfig {
                    bind_addr: SocketAddrV4::new(self.config.bind_addr, self.config.bind_port),
                    recv_buf_size: self.config.recv_buf_size,
                    send_buf_size: self.config.send_buf_size,
                    reuse_port: false,
                    non_blocking: true,
                };
                let socket = UdpSocket::bind(&socket_config)?;
                self.backend = Backend::Udp(socket);
                Ok(())
            }
            BackendType::Xdp => {
                // TODO: XDP backend integration with LiveXdpSocket.
                // Requires Linux, root privileges, and interface configuration.
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "XDP backend requires Linux and is not yet integrated into Transport",
                ))
            }
        }
    }

    /// Whether the transport is open and ready for I/O.
    pub fn is_open(&self) -> bool {
        !matches!(self.backend, Backend::Unbound)
    }

    /// Receive packets into a batch.
    ///
    /// Returns the number of packets received. Non-blocking: returns 0
    /// immediately if no packets are available.
    pub fn receive_batch<const N: usize>(&mut self, batch: &mut PacketBatch<N>) -> usize {
        let count = match &self.backend {
            Backend::Udp(socket) => socket.recv_batch(batch),
            Backend::Unbound => 0,
        };

        if count > 0 {
            let bytes: usize = batch
                .as_slice()
                .iter()
                .take(count)
                .map(|p| p.len() as usize)
                .sum();
            self.stats.record_rx(count, bytes);
        }

        count
    }

    /// Send a batch of packets.
    ///
    /// Returns the number of packets successfully sent.
    pub fn send_batch<const N: usize>(&mut self, batch: &PacketBatch<N>) -> usize {
        let count = match &self.backend {
            Backend::Udp(socket) => socket.send_batch_to(batch),
            Backend::Unbound => 0,
        };

        if count > 0 {
            let bytes: usize = batch
                .as_slice()
                .iter()
                .take(count)
                .map(|p| p.len() as usize)
                .sum();
            self.stats.record_tx(count, bytes);
        }

        count
    }

    /// Send a single packet to a specific address.
    pub fn send_to(&mut self, data: &[u8], addr: &SocketAddrV4) -> io::Result<usize> {
        match &self.backend {
            Backend::Udp(socket) => {
                let n = socket.send_to(data, addr)?;
                self.stats.record_tx(1, n);
                Ok(n)
            }
            Backend::Unbound => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport not open",
            )),
        }
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

    /// Get the local bind address (only valid after `open()`).
    pub fn local_addr(&self) -> Option<SocketAddrV4> {
        match &self.backend {
            Backend::Udp(socket) => Some(socket.local_addr()),
            Backend::Unbound => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketBuffer;
    use paradencer_constants::network::PACKET_BATCH_DEFAULT;

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
    fn transport_creation_not_open() {
        let config = TransportConfig {
            bind_port: 8000,
            ..Default::default()
        };
        let transport = Transport::new(config);
        assert_eq!(transport.backend_type(), BackendType::Udp);
        assert_eq!(transport.config().bind_port, 8000);
        assert!(!transport.is_open());
    }

    #[test]
    fn transport_open_udp() {
        let config = TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        };
        let mut transport = Transport::new(config);
        transport.open().expect("open failed");
        assert!(transport.is_open());
        assert!(transport.local_addr().is_some());
    }

    #[test]
    fn transport_receive_when_unbound_returns_zero() {
        let mut transport = Transport::new(TransportConfig::default());
        let mut batch = PacketBatch::<PACKET_BATCH_DEFAULT>::new();
        assert_eq!(transport.receive_batch(&mut batch), 0);
    }

    #[test]
    fn transport_send_receive_udp() {
        // Create sender and receiver transports.
        let mut rx_transport = Transport::new(TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        });
        rx_transport.open().expect("rx open");
        let rx_addr = rx_transport.local_addr().unwrap();

        let mut tx_transport = Transport::new(TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        });
        tx_transport.open().expect("tx open");

        // Send a packet.
        tx_transport
            .send_to(b"hello transport", &rx_addr)
            .expect("send_to");

        // Poll with retries for loopback delivery.
        let mut batch = PacketBatch::<4>::new();
        let mut received = 0;
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            received = rx_transport.receive_batch(&mut batch);
            if received > 0 {
                break;
            }
        }
        assert_eq!(received, 1);
        assert_eq!(batch.get(0).payload(), b"hello transport");

        // Check stats.
        assert_eq!(tx_transport.stats().tx_packets, 1);
        assert_eq!(rx_transport.stats().rx_packets, 1);
    }

    #[test]
    fn transport_batch_send() {
        let mut rx_transport = Transport::new(TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        });
        rx_transport.open().expect("rx open");
        let rx_addr = rx_transport.local_addr().unwrap();

        let mut tx_transport = Transport::new(TransportConfig {
            bind_addr: Ipv4Addr::LOCALHOST,
            ..Default::default()
        });
        tx_transport.open().expect("tx open");

        // Send batch.
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"pkt0", Some(rx_addr)));
        batch.push(PacketBuffer::from_slice(b"pkt1", Some(rx_addr)));
        batch.push(PacketBuffer::from_slice(b"pkt2", Some(rx_addr)));

        let sent = tx_transport.send_batch(&batch);
        assert_eq!(sent, 3);
        assert_eq!(tx_transport.stats().tx_packets, 3);
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
