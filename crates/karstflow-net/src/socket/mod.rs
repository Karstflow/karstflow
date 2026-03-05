mod config;
/// UDP socket backend with batch I/O support.
///
/// Uses sendmmsg/recvmmsg on Linux for batched operations.
/// Falls back to standard sendto/recvfrom on other platforms.
mod udp;

pub use config::SocketConfig;
pub use udp::UdpSocket;
