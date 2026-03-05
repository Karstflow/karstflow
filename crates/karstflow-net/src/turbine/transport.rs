use std::net::SocketAddr;

/// Trait for sending raw data to a network peer.
///
/// This abstracts the transport layer (UDP, QUIC, etc.) so that
/// turbine broadcast and retransmit logic can operate independently
/// of the specific networking implementation.
pub trait ShredTransport: Send + Sync {
    /// Send data to a specific peer address.
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), TransportError>;
}

/// Transport-level error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TransportError {
    #[error("send failed: {detail}")]
    SendFailed { detail: String },
    #[error("connection closed")]
    ConnectionClosed,
    #[error("address unreachable: {addr}")]
    Unreachable { addr: SocketAddr },
}

/// UDP transport for sending shreds over the network.
///
/// Binds a non-blocking UDP socket and sends raw bytes to peer
/// addresses. Used by the retransmit and broadcast services for
/// turbine tree propagation.
pub struct UdpShredTransport {
    socket: std::net::UdpSocket,
}

impl UdpShredTransport {
    /// Create a new UDP transport bound to the given address.
    pub fn new(bind_addr: SocketAddr) -> std::io::Result<Self> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Return the local address of the bound socket.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl ShredTransport for UdpShredTransport {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), TransportError> {
        self.socket
            .send_to(data, addr)
            .map_err(|e| TransportError::SendFailed {
                detail: e.to_string(),
            })?;
        Ok(())
    }
}

/// XDP kernel-bypass transport for sending shreds via AF_XDP.
///
/// On Linux, wraps a `LiveXdpSocket` and constructs raw UDP packets using
/// the wire module. Requires a pre-configured source IP/port and destination
/// MAC address (resolved at creation time or via ARP).
///
/// On non-Linux platforms this type does not exist — callers should fall back
/// to `UdpShredTransport`.
#[cfg(target_os = "linux")]
pub struct XdpShredTransport {
    socket: std::sync::Mutex<crate::xdp::LiveXdpSocket>,
    src_addr: u32,
    src_port: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

#[cfg(target_os = "linux")]
impl XdpShredTransport {
    /// Create a new XDP shred transport.
    ///
    /// - `socket`: a configured `LiveXdpSocket` with UMEM + rings ready
    /// - `src_addr`: source IPv4 address in host byte order
    /// - `src_port`: source UDP port
    /// - `src_mac`, `dst_mac`: Ethernet addresses (dst_mac is typically the gateway)
    pub fn new(
        socket: crate::xdp::LiveXdpSocket,
        src_addr: u32,
        src_port: u16,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Self {
        Self {
            socket: std::sync::Mutex::new(socket),
            src_addr,
            src_port,
            src_mac,
            dst_mac,
        }
    }
}

#[cfg(target_os = "linux")]
impl ShredTransport for XdpShredTransport {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<(), TransportError> {
        use crate::wire::{build_udp_packet, EthernetHeader, Ipv4Header, UdpHeader};
        use crate::xdp::sys::XdpDesc;

        let dst_addr = match addr.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4),
            std::net::IpAddr::V6(_) => {
                return Err(TransportError::SendFailed {
                    detail: "XDP transport does not support IPv6".to_string(),
                });
            }
        };
        let dst_port = addr.port();

        let eth = EthernetHeader {
            dst_mac: self.dst_mac,
            src_mac: self.src_mac,
            ether_type: 0x0800, // IPv4
        };
        let udp_payload_len = (UdpHeader::WIRE_SIZE + data.len()) as u16;
        let mut ip = Ipv4Header::new(
            karstflow_constants::network::IPV4_PROTO_UDP,
            self.src_addr,
            dst_addr,
            udp_payload_len,
        );
        let udp = UdpHeader::new(self.src_port, dst_port, data.len() as u16);

        // Build packet into a stack buffer first, then copy into UMEM frame.
        let mut pkt_buf = [0u8; 4096];
        let total_len = build_udp_packet(&mut pkt_buf, &eth, &mut ip, &udp, data).ok_or(
            TransportError::SendFailed {
                detail: "packet too large for XDP frame".to_string(),
            },
        )?;

        let mut sock = self.socket.lock().map_err(|_| TransportError::SendFailed {
            detail: "XDP socket lock poisoned".to_string(),
        })?;

        // Process completions to reclaim frames before allocating.
        sock.process_completions();

        let frame_addr = sock.allocate_tx_frame().ok_or(TransportError::SendFailed {
            detail: "no free UMEM frames for TX".to_string(),
        })?;

        // SAFETY: frame_addr was just allocated via allocate_tx_frame and
        // total_len fits within the frame size (max ~1500 bytes shred + headers).
        unsafe {
            let frame = sock.frame_data_mut(frame_addr, total_len as u32);
            frame.copy_from_slice(&pkt_buf[..total_len]);
        }

        let desc = XdpDesc {
            addr: frame_addr,
            len: total_len as u32,
            options: 0,
        };
        if !sock.transmit(&desc) {
            return Err(TransportError::SendFailed {
                detail: "XDP TX ring full".to_string(),
            });
        }
        sock.flush_tx().map_err(|e| TransportError::SendFailed {
            detail: format!("XDP flush_tx failed: {e}"),
        })?;
        Ok(())
    }
}

/// No-op transport for testing and development.
pub struct NullTransport;

impl ShredTransport for NullTransport {
    fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Counting transport for tests — tracks how many sends occurred.
#[cfg(test)]
pub(crate) struct CountingTransport {
    pub send_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub byte_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(test)]
impl CountingTransport {
    pub fn new() -> Self {
        Self {
            send_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            byte_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

#[cfg(test)]
impl ShredTransport for CountingTransport {
    fn send_to(&self, data: &[u8], _addr: SocketAddr) -> Result<(), TransportError> {
        self.send_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.byte_count
            .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_null_transport() {
        let transport = NullTransport;
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        assert!(transport.send_to(b"test data", addr).is_ok());
    }

    #[test]
    fn test_counting_transport() {
        let transport = CountingTransport::new();
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        transport.send_to(b"hello", addr).unwrap();
        transport.send_to(b"world!", addr).unwrap();

        assert_eq!(transport.send_count.load(Ordering::Relaxed), 2);
        assert_eq!(transport.byte_count.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn test_udp_transport_bind_and_send() {
        let transport = UdpShredTransport::new("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = transport.local_addr().unwrap();
        assert_ne!(local.port(), 0);

        // Send to self — non-blocking send should succeed even if nobody reads.
        let result = transport.send_to(b"test-shred", local);
        assert!(result.is_ok());
    }
}
