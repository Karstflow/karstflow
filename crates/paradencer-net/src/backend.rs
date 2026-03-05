/// Transport backend abstraction with actual packet I/O.
///
/// Provides a unified interface over different packet transport mechanisms:
/// - UDP socket (portable, uses sendto/recvfrom, non-blocking)
/// - AF_XDP (Linux kernel bypass, zero-copy, requires root/CAP_NET_ADMIN)
///
/// The backend is selected at initialization time. Both backends expose
/// the same batch receive/send API through the `Transport` struct.
///
/// For XDP, received packets contain raw ethernet frames (L2+L3+L4+payload).
/// The caller is responsible for header parsing. For UDP, packets contain
/// only the UDP payload with the source address metadata.
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::packet::PacketBatch;
use crate::socket::{SocketConfig, UdpSocket};

#[cfg(target_os = "linux")]
use crate::xdp::socket::XdpSocketConfig;
#[cfg(target_os = "linux")]
use crate::xdp::sys::XdpDesc;
#[cfg(target_os = "linux")]
use crate::xdp::{LiveXdpSocket, LiveXdpStats, XdpProgram, XskMap};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use paradencer_constants::network::PACKET_BUFFER_SIZE;

/// Maximum XDP descriptors to process per receive call.
#[cfg(target_os = "linux")]
const XDP_RX_BATCH_SIZE: usize = 64;

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

/// XDP backend state holding the live socket and pre-allocated receive buffer.
#[cfg(target_os = "linux")]
struct XdpBackendState {
    /// Live AF_XDP socket with kernel ring integration.
    socket: LiveXdpSocket,
    /// Pre-allocated descriptor buffer for batch receive operations.
    rx_descs: Vec<XdpDesc>,
}

/// Active backend resource.
enum Backend {
    /// UDP socket backend.
    Udp(UdpSocket),
    /// AF_XDP kernel bypass backend (Linux only).
    #[cfg(target_os = "linux")]
    Xdp(Box<XdpBackendState>),
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
                // XDP requires shared eBPF program and XSKMAP resources that are
                // created externally (typically by install_xdp). Use open_xdp()
                // with those shared resources instead of open().
                #[cfg(target_os = "linux")]
                {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "XDP backend requires open_xdp() with shared XSKMAP and eBPF program",
                    ))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "XDP backend is only available on Linux",
                    ))
                }
            }
        }
    }

    /// Open the transport with an AF_XDP kernel-bypass socket.
    ///
    /// Requires a pre-configured `XdpSocketConfig`, a shared XSKMAP, and
    /// a shared eBPF program (typically obtained from `install_xdp()`).
    /// The eBPF program steers matching packets to the XSK socket.
    ///
    /// This method is Linux-only. On other platforms, use UDP.
    #[cfg(target_os = "linux")]
    pub fn open_xdp(
        &mut self,
        xdp_config: &XdpSocketConfig,
        xsk_map: Arc<XskMap>,
        program: Arc<XdpProgram>,
    ) -> io::Result<()> {
        let socket = LiveXdpSocket::open(xdp_config, xsk_map, program)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let rx_descs = vec![XdpDesc::default(); XDP_RX_BATCH_SIZE];
        self.backend = Backend::Xdp(Box::new(XdpBackendState { socket, rx_descs }));
        self.backend_type = BackendType::Xdp;
        Ok(())
    }

    /// Whether the transport is open and ready for I/O.
    pub fn is_open(&self) -> bool {
        !matches!(self.backend, Backend::Unbound)
    }

    /// Receive packets into a batch.
    ///
    /// Returns the number of packets received. Non-blocking: returns 0
    /// immediately if no packets are available.
    ///
    /// For the UDP backend, each packet contains the UDP payload with source
    /// address metadata. For the XDP backend, each packet contains the raw
    /// ethernet frame (L2 headers included); the caller must parse headers.
    pub fn receive_batch<const N: usize>(&mut self, batch: &mut PacketBatch<N>) -> usize {
        let count = match &mut self.backend {
            Backend::Udp(socket) => socket.recv_batch(batch),
            #[cfg(target_os = "linux")]
            Backend::Xdp(state) => Self::receive_xdp(state, batch),
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

    /// XDP receive: service the kernel rings and copy frame data into the batch.
    #[cfg(target_os = "linux")]
    fn receive_xdp<const N: usize>(
        state: &mut XdpBackendState,
        batch: &mut PacketBatch<N>,
    ) -> usize {
        let received = state.socket.service(&mut state.rx_descs);
        let mut count = 0;

        for i in 0..received {
            let desc = state.rx_descs[i];

            if !batch.is_full() {
                // SAFETY: desc is from a valid RX ring entry. The frame has not
                // been released yet (we release below after copying).
                let frame_data = unsafe { state.socket.frame_data(&desc) };
                let copy_len = frame_data.len().min(PACKET_BUFFER_SIZE);

                if let Some(slot) = batch.reserve_slot() {
                    slot.data_mut()[..copy_len].copy_from_slice(&frame_data[..copy_len]);
                    slot.set_len(copy_len as u16);
                    count += 1;
                }
            }

            // Always release the frame, even if the batch was full.
            state.socket.release_rx_frame(desc.addr);
        }

        count
    }

    /// Send a batch of packets.
    ///
    /// Returns the number of packets successfully sent.
    ///
    /// For the XDP backend, packet data is copied into UMEM frames and
    /// submitted to the kernel TX ring. The caller must provide complete
    /// ethernet frames (L2 headers included) for XDP.
    pub fn send_batch<const N: usize>(&mut self, batch: &PacketBatch<N>) -> usize {
        let count = match &mut self.backend {
            Backend::Udp(socket) => socket.send_batch_to(batch),
            #[cfg(target_os = "linux")]
            Backend::Xdp(state) => Self::send_batch_xdp(state, batch),
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

    /// XDP send: allocate frames, copy data, submit to TX ring, and flush.
    #[cfg(target_os = "linux")]
    fn send_batch_xdp<const N: usize>(
        state: &mut XdpBackendState,
        batch: &PacketBatch<N>,
    ) -> usize {
        let mut sent = 0;

        for pkt in batch.as_slice() {
            if pkt.is_empty() {
                sent += 1;
                continue;
            }

            let payload = pkt.payload();
            let frame_addr = match state.socket.allocate_tx_frame() {
                Some(addr) => addr,
                None => break, // No frames available.
            };

            // SAFETY: frame_addr is from a freshly allocated frame. We have
            // exclusive ownership until we submit it to the TX ring.
            unsafe {
                let frame = state
                    .socket
                    .frame_data_mut(frame_addr, payload.len() as u32);
                frame.copy_from_slice(payload);
            }

            let desc = XdpDesc {
                addr: frame_addr,
                len: payload.len() as u32,
                options: 0,
            };

            if !state.socket.transmit(&desc) {
                // TX ring full — release the allocated frame.
                state.socket.release_rx_frame(frame_addr);
                break;
            }
            sent += 1;
        }

        if sent > 0 {
            let _ = state.socket.flush_tx();
        }

        sent
    }

    /// Send a single packet to a specific address.
    ///
    /// For the XDP backend, the destination address is ignored — XDP operates
    /// at the L2 level and the packet data must include all headers. The
    /// `addr` parameter is only used by the UDP backend.
    pub fn send_to(&mut self, data: &[u8], addr: &SocketAddrV4) -> io::Result<usize> {
        match &mut self.backend {
            Backend::Udp(socket) => {
                let n = socket.send_to(data, addr)?;
                self.stats.record_tx(1, n);
                Ok(n)
            }
            #[cfg(target_os = "linux")]
            Backend::Xdp(state) => {
                let frame_addr = state
                    .socket
                    .allocate_tx_frame()
                    .ok_or_else(|| io::Error::other("no UMEM frames available for TX"))?;

                // SAFETY: frame_addr is from a freshly allocated frame.
                unsafe {
                    let frame = state.socket.frame_data_mut(frame_addr, data.len() as u32);
                    frame.copy_from_slice(data);
                }

                let desc = XdpDesc {
                    addr: frame_addr,
                    len: data.len() as u32,
                    options: 0,
                };

                if state.socket.transmit(&desc) {
                    let _ = state.socket.flush_tx();
                    self.stats.record_tx(1, data.len());
                    Ok(data.len())
                } else {
                    state.socket.release_rx_frame(frame_addr);
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "XDP TX ring full",
                    ))
                }
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
    ///
    /// Returns `None` for XDP backends, which bind to NIC interface + queue
    /// rather than an IP:port pair.
    pub fn local_addr(&self) -> Option<SocketAddrV4> {
        match &self.backend {
            Backend::Udp(socket) => Some(socket.local_addr()),
            #[cfg(target_os = "linux")]
            Backend::Xdp(_) => None,
            Backend::Unbound => None,
        }
    }

    /// Get AF_XDP-specific runtime statistics.
    ///
    /// Returns `None` if the backend is not XDP.
    #[cfg(target_os = "linux")]
    pub fn xdp_stats(&self) -> Option<&LiveXdpStats> {
        match &self.backend {
            Backend::Xdp(state) => Some(state.socket.stats()),
            _ => None,
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

    #[test]
    fn transport_xdp_open_requires_explicit_setup() {
        let config = TransportConfig {
            backend: BackendType::Xdp,
            ..Default::default()
        };
        let mut transport = Transport::new(config);
        // open() should fail for XDP — must use open_xdp() with shared resources.
        let result = transport.open();
        assert!(result.is_err());
        assert!(!transport.is_open());
    }
}
