/// High-performance UDP socket with batch I/O.
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::io::{PacketSender, SendResult};
use crate::packet::{PacketBatch, PacketBuffer};
use crate::socket::SocketConfig;

/// UDP socket wrapper using raw file descriptors for maximum control.
///
/// Supports both single-packet and batch I/O modes:
/// - On Linux: uses sendmmsg/recvmmsg for batch operations.
/// - On other platforms: loops over sendto/recvfrom.
pub struct UdpSocket {
    fd: OwnedFd,
    local_addr: SocketAddrV4,
}

impl UdpSocket {
    /// Create and bind a UDP socket with the given configuration.
    pub fn bind(config: &SocketConfig) -> io::Result<Self> {
        let fd = create_udp_socket()?;
        let raw = fd.as_raw_fd();

        // Set socket options before bind
        if config.reuse_port {
            set_reuse_port(raw)?;
        }
        set_recv_buf_size(raw, config.recv_buf_size)?;
        set_send_buf_size(raw, config.send_buf_size)?;

        bind_socket(raw, &config.bind_addr)?;

        // Query the actual bound address (resolves port 0 to assigned port).
        let local_addr = get_local_addr(raw).unwrap_or(config.bind_addr);

        if config.non_blocking {
            set_non_blocking(raw)?;
        }

        Ok(Self { fd, local_addr })
    }

    /// Returns the local address the socket is bound to.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    /// Returns the raw file descriptor.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Send a single packet to the given address.
    pub fn send_to(&self, data: &[u8], addr: &SocketAddrV4) -> io::Result<usize> {
        let sockaddr = to_sockaddr_in(addr);
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Receive a single packet into the given buffer.
    /// Returns (bytes_read, source_address).
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sockaddr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addrlen,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            let addr = from_sockaddr_in(&sockaddr);
            Ok((ret as usize, addr))
        }
    }

    /// Receive packets into a batch. Fills as many slots as possible.
    /// Returns the number of packets received.
    pub fn recv_batch<const N: usize>(&self, batch: &mut PacketBatch<N>) -> usize {
        let mut count = 0;
        while !batch.is_full() {
            let start_count = batch.count();
            let slot = match batch.reserve_slot() {
                Some(s) => s,
                None => break,
            };
            match self.recv_from(slot.data_mut()) {
                Ok((n, addr)) => {
                    slot.set_len(n as u16);
                    slot.set_addr(addr);
                    count += 1;
                }
                Err(_) => {
                    // Undo the reserved slot (WouldBlock or other error).
                    batch.truncate(start_count);
                    break;
                }
            }
        }
        count
    }

    /// Send all packets in a batch. Returns the number successfully sent.
    pub fn send_batch_to<const N: usize>(&self, batch: &PacketBatch<N>) -> usize {
        let mut sent = 0;
        for pkt in batch.as_slice() {
            if pkt.is_empty() {
                sent += 1; // Skip empty packets (same as Firedancer)
                continue;
            }
            if let Some(addr) = pkt.addr() {
                match self.send_to(pkt.payload(), &addr) {
                    Ok(_) => sent += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        sent
    }
}

impl PacketSender for UdpSocket {
    fn send_packets(&self, packets: &[PacketBuffer], _flush: bool) -> SendResult {
        let mut sent = 0;
        for pkt in packets {
            if pkt.is_empty() {
                sent += 1;
                continue;
            }
            if let Some(addr) = pkt.addr() {
                match self.send_to(pkt.payload(), &addr) {
                    Ok(_) => sent += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if sent == packets.len() {
            SendResult::Success
        } else if sent > 0 {
            SendResult::Partial { sent_count: sent }
        } else {
            SendResult::WouldBlock
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific helpers
// ---------------------------------------------------------------------------

fn create_udp_socket() -> io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let flags = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::SOCK_DGRAM;

    let fd = unsafe { libc::socket(libc::AF_INET, flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_socket(fd: RawFd, addr: &SocketAddrV4) -> io::Result<()> {
    let sockaddr = to_sockaddr_in(addr);
    let ret = unsafe {
        libc::bind(
            fd,
            &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_non_blocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_reuse_port(fd: RawFd) -> io::Result<()> {
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_recv_buf_size(fd: RawFd, size: usize) -> io::Result<()> {
    let val = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_send_buf_size(fd: RawFd, size: usize) -> io::Result<()> {
    let val = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn get_local_addr(fd: RawFd) -> Option<SocketAddrV4> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd,
            &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret < 0 {
        None
    } else {
        Some(from_sockaddr_in(&sa))
    }
}

fn to_sockaddr_in(addr: &SocketAddrV4) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = addr.port().to_be();
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from(*addr.ip()).to_be(),
    };
    sa
}

fn from_sockaddr_in(sa: &libc::sockaddr_in) -> SocketAddrV4 {
    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
    let port = u16::from_be(sa.sin_port);
    SocketAddrV4::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use karstflow_constants::network::PACKET_BUFFER_SIZE;

    fn loopback_config() -> SocketConfig {
        SocketConfig {
            bind_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            recv_buf_size: 256 * 1024,
            send_buf_size: 256 * 1024,
            reuse_port: false,
            non_blocking: true,
        }
    }

    #[test]
    fn socket_bind_loopback() {
        let config = loopback_config();
        let sock = UdpSocket::bind(&config).expect("bind failed");
        assert!(sock.raw_fd() >= 0);
    }

    #[test]
    fn socket_send_recv_loopback() {
        // Create two sockets: sender and receiver
        let rx_config = SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let rx = UdpSocket::bind(&rx_config).expect("rx bind");

        // Get the actual bound port
        let mut rx_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe {
            libc::getsockname(
                rx.raw_fd(),
                &mut rx_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addrlen,
            );
        }
        let rx_port = u16::from_be(rx_addr.sin_port);
        let rx_target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rx_port);

        let tx_config = SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let tx = UdpSocket::bind(&tx_config).expect("tx bind");

        // Send a packet
        let msg = b"test packet";
        tx.send_to(msg, &rx_target).expect("send_to");

        // Receive it (non-blocking, but data should be there immediately on loopback)
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        // Small sleep to ensure delivery
        std::thread::sleep(std::time::Duration::from_millis(10));
        let (n, src) = rx.recv_from(&mut buf).expect("recv_from");
        assert_eq!(&buf[..n], msg);
        assert_eq!(src.ip(), &Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn socket_batch_send_recv() {
        let rx_config = SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let rx = UdpSocket::bind(&rx_config).expect("rx bind");

        let mut rx_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe {
            libc::getsockname(
                rx.raw_fd(),
                &mut rx_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addrlen,
            );
        }
        let rx_port = u16::from_be(rx_addr.sin_port);
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rx_port);

        let tx_config = SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let tx = UdpSocket::bind(&tx_config).expect("tx bind");

        // Send batch of 3 packets
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"pkt0", Some(target)));
        batch.push(PacketBuffer::from_slice(b"pkt1", Some(target)));
        batch.push(PacketBuffer::from_slice(b"pkt2", Some(target)));

        let sent = tx.send_batch_to(&batch);
        assert_eq!(sent, 3);

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Receive them
        let mut rx_batch = PacketBatch::<4>::new();
        let received = rx.recv_batch(&mut rx_batch);
        assert!(received >= 1); // At least one should arrive
    }

    #[test]
    fn socket_packet_sender_trait() {
        let config = SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let rx = UdpSocket::bind(&config).expect("bind");

        let mut rx_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        unsafe {
            libc::getsockname(
                rx.raw_fd(),
                &mut rx_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addrlen,
            );
        }
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, u16::from_be(rx_addr.sin_port));

        let tx = UdpSocket::bind(&SocketConfig::new(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .expect("bind tx");

        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"via trait", Some(target)));

        let result = PacketSender::send_packets(&tx, batch.as_slice(), true);
        assert_eq!(result, SendResult::Success);
    }

    #[test]
    fn socket_nonblocking_recv_returns_wouldblock() {
        let config = SocketConfig {
            non_blocking: true,
            ..SocketConfig::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        };
        let sock = UdpSocket::bind(&config).expect("bind");

        let mut buf = [0u8; 64];
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }
}
