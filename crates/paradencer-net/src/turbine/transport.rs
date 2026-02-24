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
