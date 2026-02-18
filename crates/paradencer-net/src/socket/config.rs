/// UDP socket configuration.
use std::net::SocketAddrV4;

/// Configuration for a UDP socket.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Local address to bind to.
    pub bind_addr: SocketAddrV4,
    /// Receive buffer size in bytes (SO_RCVBUF).
    pub recv_buf_size: usize,
    /// Send buffer size in bytes (SO_SNDBUF).
    pub send_buf_size: usize,
    /// Enable SO_REUSEPORT for load balancing across threads.
    pub reuse_port: bool,
    /// Non-blocking mode.
    pub non_blocking: bool,
}

impl SocketConfig {
    /// Default config for a given bind address.
    pub fn new(bind_addr: SocketAddrV4) -> Self {
        Self {
            bind_addr,
            recv_buf_size: 4 * 1024 * 1024, // 4 MB
            send_buf_size: 4 * 1024 * 1024, // 4 MB
            reuse_port: false,
            non_blocking: true,
        }
    }
}
