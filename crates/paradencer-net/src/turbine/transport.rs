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

/// No-op transport for testing and development.
pub struct NullTransport;

impl ShredTransport for NullTransport {
    fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// Counting transport for tests — tracks how many sends occurred.
    pub struct CountingTransport {
        pub send_count: Arc<AtomicU64>,
        pub byte_count: Arc<AtomicU64>,
    }

    impl CountingTransport {
        pub fn new() -> Self {
            Self {
                send_count: Arc::new(AtomicU64::new(0)),
                byte_count: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    impl ShredTransport for CountingTransport {
        fn send_to(&self, data: &[u8], _addr: SocketAddr) -> Result<(), TransportError> {
            self.send_count.fetch_add(1, Ordering::Relaxed);
            self.byte_count
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

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
}
