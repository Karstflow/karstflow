// Linux AF_XDP kernel ABI: constants, structures, and syscall wrappers.
//
// All types match the Linux kernel UAPI headers for AF_XDP sockets.
// Every struct is `#[repr(C)]` with exact kernel ABI layout.
//
// This module is Linux-only (`#[cfg(target_os = "linux")]`).

// ---------------------------------------------------------------------------
// Socket family and protocol
// ---------------------------------------------------------------------------

/// AF_XDP socket address family.
pub const AF_XDP: i32 = 44;
/// Protocol family for `sockaddr_xdp`.
pub const PF_XDP: u16 = AF_XDP as u16;

// ---------------------------------------------------------------------------
// SOL_XDP socket options (setsockopt / getsockopt)
// ---------------------------------------------------------------------------

/// Socket option level for XDP options.
pub const SOL_XDP: i32 = 283;

/// Register a UMEM region with the kernel.
pub const XDP_UMEM_REG: i32 = 1;
/// Set the RX ring depth.
pub const XDP_RX_RING: i32 = 2;
/// Set the TX ring depth.
pub const XDP_TX_RING: i32 = 3;
/// Set the UMEM FILL ring depth.
pub const XDP_UMEM_FILL_RING: i32 = 5;
/// Set the UMEM COMPLETION ring depth.
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
/// Query ring memory layout offsets from kernel.
pub const XDP_MMAP_OFFSETS: i32 = 1;
/// Query XDP statistics from the kernel.
pub const XDP_STATISTICS: i32 = 7;

// ---------------------------------------------------------------------------
// mmap page offsets for ring regions
// ---------------------------------------------------------------------------

/// mmap offset for the RX descriptor ring.
pub const XDP_PGOFF_RX_RING: i64 = 0;
/// mmap offset for the TX descriptor ring.
pub const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
/// mmap offset for the UMEM FILL ring.
pub const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
/// mmap offset for the UMEM COMPLETION ring.
pub const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

// ---------------------------------------------------------------------------
// XDP bind flags (sockaddr_xdp.sxdp_flags)
// ---------------------------------------------------------------------------

/// Enable wakeup notification via ring flags.
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
/// Request zero-copy mode (requires driver support).
pub const XDP_ZEROCOPY: u16 = 1 << 2;
/// Use copy mode (fallback when zero-copy unsupported).
pub const XDP_COPY: u16 = 1 << 1;

// ---------------------------------------------------------------------------
// XDP ring flags
// ---------------------------------------------------------------------------

/// Kernel sets this flag when it needs a wakeup from userspace.
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// XDP action codes
// ---------------------------------------------------------------------------

/// Drop the packet.
pub const XDP_DROP: u32 = 1;
/// Pass packet to kernel networking stack.
pub const XDP_PASS: u32 = 2;
/// Transmit packet back out the same interface.
pub const XDP_TX: u32 = 3;
/// Redirect packet to another target (AF_XDP socket via XSKMAP).
pub const XDP_REDIRECT: u32 = 4;

// ---------------------------------------------------------------------------
// XDP attachment mode flags
// ---------------------------------------------------------------------------

/// Software-based XDP (uses sk_buff, slowest but most compatible).
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
/// Driver-based XDP (direct NIC, requires driver support).
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
/// Hardware-offloaded XDP (NIC processes eBPF, requires NIC support).
pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// BPF syscall commands
// ---------------------------------------------------------------------------

/// Create a BPF map.
pub const BPF_MAP_CREATE: u32 = 0;
/// Look up a BPF map element.
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
/// Update a BPF map element.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// Delete a BPF map element.
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
/// Load a BPF program into the kernel.
pub const BPF_PROG_LOAD: u32 = 5;
/// Create a BPF link (attach program to target).
pub const BPF_LINK_CREATE: u32 = 28;

// ---------------------------------------------------------------------------
// BPF map and program types
// ---------------------------------------------------------------------------

/// BPF map type for XSK socket dispatch.
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
/// BPF program type for XDP packet processing.
pub const BPF_PROG_TYPE_XDP: u32 = 6;
/// BPF attach type for XDP programs.
pub const BPF_XDP: u32 = 37;

// ---------------------------------------------------------------------------
// BPF map update flags
// ---------------------------------------------------------------------------

/// Create or update element (no existence check).
pub const BPF_ANY: u64 = 0;

// ---------------------------------------------------------------------------
// Kernel ABI structures
// ---------------------------------------------------------------------------

/// UMEM region registration parameters.
///
/// Passed to `setsockopt(fd, SOL_XDP, XDP_UMEM_REG, ...)` to register
/// a contiguous userspace memory region as UMEM for AF_XDP.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XdpUmemReg {
    /// Userspace address of the UMEM buffer.
    pub addr: u64,
    /// Total size of the UMEM region in bytes.
    pub len: u64,
    /// Frame (chunk) size in bytes. Must be a power of 2.
    pub chunk_size: u32,
    /// Headroom reserved before packet data in each frame.
    pub headroom: u32,
    /// Flags (currently unused, set to 0).
    pub flags: u32,
    /// Padding for alignment.
    pub _pad: u32,
}

/// AF_XDP socket address for `bind()`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockaddrXdp {
    /// Address family (`PF_XDP`).
    pub sxdp_family: u16,
    /// Bind flags (e.g., `XDP_USE_NEED_WAKEUP`, `XDP_ZEROCOPY`).
    pub sxdp_flags: u16,
    /// Network interface index.
    pub sxdp_ifindex: u32,
    /// NIC queue index to bind to.
    pub sxdp_queue_id: u32,
    /// File descriptor for shared UMEM (0 if not sharing).
    pub sxdp_shared_umem_fd: u32,
}

/// Per-ring memory layout offsets, populated by kernel via `getsockopt`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XdpRingOffset {
    /// Byte offset to the producer sequence counter.
    pub producer: u64,
    /// Byte offset to the consumer sequence counter.
    pub consumer: u64,
    /// Byte offset to the start of the descriptor/frame array.
    pub desc: u64,
    /// Byte offset to the flags field.
    pub flags: u64,
}

/// Ring memory layout offsets for all four XDP rings.
///
/// Retrieved via `getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, ...)`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XdpMmapOffsets {
    /// RX descriptor ring offsets.
    pub rx: XdpRingOffset,
    /// TX descriptor ring offsets.
    pub tx: XdpRingOffset,
    /// FILL ring offsets.
    pub fr: XdpRingOffset,
    /// COMPLETION ring offsets.
    pub cr: XdpRingOffset,
}

/// Kernel XDP statistics counters.
///
/// Retrieved via `getsockopt(fd, SOL_XDP, XDP_STATISTICS, ...)`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XdpStatistics {
    /// Packets dropped due to invalid descriptor.
    pub rx_dropped: u64,
    /// Packets dropped due to invalid FILL address.
    pub rx_invalid_descs: u64,
    /// TX packets dropped due to invalid descriptor.
    pub tx_invalid_descs: u64,
    /// Packets dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Packets dropped due to FILL ring being empty.
    pub rx_fill_ring_empty_descs: u64,
    /// TX packets that could not be completed.
    pub tx_ring_empty_descs: u64,
}

/// Packet descriptor for RX/TX rings.
///
/// Identical layout to the kernel `xdp_desc`. This matches our
/// `PacketDescriptor` in `ring.rs` — both are 16 bytes with the same
/// field layout, ensuring zero-copy compatibility.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XdpDesc {
    /// Frame address within UMEM (byte offset from UMEM base).
    pub addr: u64,
    /// Packet data length in bytes.
    pub len: u32,
    /// Options flags.
    pub options: u32,
}

// ---------------------------------------------------------------------------
// BPF syscall attribute structures
// ---------------------------------------------------------------------------

/// Parameters for `BPF_MAP_CREATE` command.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BpfMapCreateAttr {
    /// Map type (e.g., `BPF_MAP_TYPE_XSKMAP`).
    pub map_type: u32,
    /// Size of map keys in bytes.
    pub key_size: u32,
    /// Size of map values in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Map flags.
    pub map_flags: u32,
    /// Inner map fd (for map-in-map types).
    pub inner_map_fd: u32,
    /// NUMA node (0 for default).
    pub numa_node: u32,
    /// Map name (null-terminated, up to 15 chars + NUL).
    pub map_name: [u8; 16],
}

/// Parameters for `BPF_PROG_LOAD` command.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BpfProgLoadAttr {
    /// Program type (e.g., `BPF_PROG_TYPE_XDP`).
    pub prog_type: u32,
    /// Number of eBPF instructions.
    pub insn_cnt: u32,
    /// Pointer to instruction array.
    pub insns: u64,
    /// Pointer to license string (must be GPL-compatible).
    pub license: u64,
    /// Kernel verifier log verbosity (0 = off, 6 = max).
    pub log_level: u32,
    /// Size of the log buffer.
    pub log_size: u32,
    /// Pointer to the log buffer.
    pub log_buf: u64,
    /// Minimum kernel version (0 for any).
    pub kern_version: u32,
    /// Program flags.
    pub prog_flags: u32,
    /// Program name (null-terminated, up to 15 chars + NUL).
    pub prog_name: [u8; 16],
    /// Expected attach type.
    pub expected_attach_type: u32,
    /// Padding.
    pub _pad: u32,
}

/// Parameters for `BPF_LINK_CREATE` command.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BpfLinkCreateAttr {
    /// Program file descriptor.
    pub prog_fd: u32,
    /// Target interface index.
    pub target_fd: u32,
    /// Attach type (e.g., `BPF_XDP`).
    pub attach_type: u32,
    /// Flags (e.g., `XDP_FLAGS_DRV_MODE`).
    pub flags: u32,
}

/// Parameters for `BPF_MAP_UPDATE_ELEM` command.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BpfMapUpdateAttr {
    /// Map file descriptor.
    pub map_fd: u32,
    /// Padding.
    pub _pad0: u32,
    /// Pointer to key.
    pub key: u64,
    /// Pointer to value (or next map fd).
    pub value: u64,
    /// Update flags (e.g., `BPF_ANY`).
    pub flags: u64,
}

/// Parameters for `BPF_MAP_DELETE_ELEM` command.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BpfMapDeleteAttr {
    /// Map file descriptor.
    pub map_fd: u32,
    /// Padding.
    pub _pad0: u32,
    /// Pointer to key.
    pub key: u64,
}

// ---------------------------------------------------------------------------
// Syscall wrappers
// ---------------------------------------------------------------------------

use std::os::unix::io::RawFd;

/// Create an AF_XDP socket.
///
/// # Safety
///
/// Caller must ensure the returned file descriptor is properly closed
/// when no longer needed.
#[inline]
pub unsafe fn xdp_socket() -> Result<RawFd, i32> {
    // SAFETY: socket() is a standard POSIX syscall. AF_XDP + SOCK_RAW + 0
    // creates a new AF_XDP socket. The fd must be closed by the caller.
    let fd = libc::socket(AF_XDP, libc::SOCK_RAW, 0);
    if fd < 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(fd)
    }
}

/// Register a UMEM region with an AF_XDP socket.
///
/// # Safety
///
/// - `fd` must be a valid AF_XDP socket file descriptor.
/// - `reg` must point to a valid, initialized `XdpUmemReg`.
/// - The UMEM memory region described by `reg.addr` and `reg.len` must
///   remain valid and mapped for the lifetime of the socket.
#[inline]
pub unsafe fn xdp_umem_reg(fd: RawFd, reg: &XdpUmemReg) -> Result<(), i32> {
    // SAFETY: setsockopt with SOL_XDP/XDP_UMEM_REG registers the UMEM
    // region with the kernel. The reg pointer is valid for the call duration.
    let ret = libc::setsockopt(
        fd,
        SOL_XDP,
        XDP_UMEM_REG,
        reg as *const XdpUmemReg as *const libc::c_void,
        std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
    );
    if ret != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(())
    }
}

/// Set the depth of an XDP ring.
///
/// # Safety
///
/// `fd` must be a valid AF_XDP socket file descriptor.
/// `optname` must be one of `XDP_RX_RING`, `XDP_TX_RING`,
/// `XDP_UMEM_FILL_RING`, or `XDP_UMEM_COMPLETION_RING`.
#[inline]
pub unsafe fn xdp_set_ring_depth(fd: RawFd, optname: i32, depth: u32) -> Result<(), i32> {
    // SAFETY: setsockopt with the given ring option sets the ring depth.
    // depth is passed as a 4-byte value. The kernel validates the value.
    let ret = libc::setsockopt(
        fd,
        SOL_XDP,
        optname,
        &depth as *const u32 as *const libc::c_void,
        std::mem::size_of::<u32>() as libc::socklen_t,
    );
    if ret != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(())
    }
}

/// Query the mmap offsets for all XDP rings from the kernel.
///
/// # Safety
///
/// `fd` must be a valid AF_XDP socket file descriptor with rings
/// already configured via `xdp_set_ring_depth`.
#[inline]
pub unsafe fn xdp_mmap_offsets(fd: RawFd) -> Result<XdpMmapOffsets, i32> {
    // SAFETY: getsockopt with SOL_XDP/XDP_MMAP_OFFSETS writes ring layout
    // information into the provided buffer. The kernel validates the fd.
    let mut offsets = XdpMmapOffsets::default();
    let mut len = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        SOL_XDP,
        XDP_MMAP_OFFSETS,
        &mut offsets as *mut XdpMmapOffsets as *mut libc::c_void,
        &mut len,
    );
    if ret != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(offsets)
    }
}

/// Query XDP statistics from the kernel.
///
/// # Safety
///
/// `fd` must be a valid AF_XDP socket file descriptor.
#[inline]
pub unsafe fn xdp_statistics(fd: RawFd) -> Result<XdpStatistics, i32> {
    // SAFETY: getsockopt with SOL_XDP/XDP_STATISTICS reads kernel counters.
    let mut stats = XdpStatistics::default();
    let mut len = std::mem::size_of::<XdpStatistics>() as libc::socklen_t;
    let ret = libc::getsockopt(
        fd,
        SOL_XDP,
        XDP_STATISTICS,
        &mut stats as *mut XdpStatistics as *mut libc::c_void,
        &mut len,
    );
    if ret != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(stats)
    }
}

/// Memory-map a ring region from an AF_XDP socket.
///
/// # Safety
///
/// - `fd` must be a valid AF_XDP socket file descriptor.
/// - `size` must be the correct map size for the ring (desc offset + depth * element_size).
/// - `pgoff` must be one of the `XDP_PGOFF_*` / `XDP_UMEM_PGOFF_*` constants.
/// - The returned pointer must be unmapped via `libc::munmap` when no longer needed.
#[inline]
pub unsafe fn xdp_mmap_ring(fd: RawFd, size: usize, pgoff: i64) -> Result<*mut u8, i32> {
    // SAFETY: mmap with MAP_SHARED | MAP_POPULATE creates a shared mapping
    // of the kernel ring region. The pgoff selects which ring to map.
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_POPULATE,
        fd,
        pgoff,
    );
    if ptr == libc::MAP_FAILED {
        Err(*libc::__errno_location())
    } else {
        Ok(ptr as *mut u8)
    }
}

/// Bind an AF_XDP socket to a network interface queue.
///
/// # Safety
///
/// - `fd` must be a valid AF_XDP socket with UMEM registered and rings configured.
/// - `addr` must point to a valid, initialized `SockaddrXdp`.
#[inline]
pub unsafe fn xdp_bind(fd: RawFd, addr: &SockaddrXdp) -> Result<(), i32> {
    // SAFETY: bind() attaches the socket to the specified interface/queue.
    // The addr pointer is valid for the call duration.
    let ret = libc::bind(
        fd,
        addr as *const SockaddrXdp as *const libc::sockaddr,
        std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
    );
    if ret != 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(())
    }
}

/// Wake up the kernel for TX processing.
///
/// Call when `XDP_RING_NEED_WAKEUP` is set in the TX ring flags.
///
/// # Safety
///
/// `fd` must be a valid AF_XDP socket file descriptor.
#[inline]
pub unsafe fn xdp_wakeup_tx(fd: RawFd) -> Result<(), i32> {
    // SAFETY: sendto with NULL buffer and MSG_DONTWAIT wakes the kernel
    // to process pending TX descriptors without blocking.
    let ret = libc::sendto(
        fd,
        std::ptr::null(),
        0,
        libc::MSG_DONTWAIT,
        std::ptr::null(),
        0,
    );
    if ret < 0 {
        let errno = *libc::__errno_location();
        // EAGAIN/EWOULDBLOCK are expected in non-blocking mode.
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            Ok(())
        } else {
            Err(errno)
        }
    } else {
        Ok(())
    }
}

/// Wake up the kernel for RX processing.
///
/// Call when `XDP_RING_NEED_WAKEUP` is set in the FILL ring flags.
///
/// # Safety
///
/// `fd` must be a valid AF_XDP socket file descriptor.
#[inline]
pub unsafe fn xdp_wakeup_rx(fd: RawFd) -> Result<(), i32> {
    // SAFETY: recvmsg with NULL buffer and MSG_DONTWAIT wakes the kernel
    // to check for new packets without blocking.
    let mut msg: libc::msghdr = std::mem::zeroed();
    let ret = libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT);
    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            Ok(())
        } else {
            Err(errno)
        }
    } else {
        Ok(())
    }
}

/// Invoke the `bpf()` syscall with the given command and attribute buffer.
///
/// # Safety
///
/// - `cmd` must be a valid BPF command.
/// - `attr` must point to a properly initialized attribute struct
///   of the correct type for the given command.
/// - `attr_size` must be the exact size of the attribute struct.
#[inline]
pub unsafe fn bpf_syscall(cmd: u32, attr: *const u8, attr_size: u32) -> Result<RawFd, i32> {
    // SAFETY: SYS_bpf is the BPF syscall number. The attr pointer must be
    // valid and correctly sized for the given command. Returns an fd or
    // result code on success, -1 on error.
    let ret = libc::syscall(
        libc::SYS_bpf,
        cmd as libc::c_ulong,
        attr as libc::c_ulong,
        attr_size as libc::c_ulong,
    );
    if ret < 0 {
        Err(*libc::__errno_location())
    } else {
        Ok(ret as RawFd)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn xdp_umem_reg_layout() {
        assert_eq!(size_of::<XdpUmemReg>(), 32);
        assert_eq!(align_of::<XdpUmemReg>(), 8);
    }

    #[test]
    fn sockaddr_xdp_layout() {
        assert_eq!(size_of::<SockaddrXdp>(), 16);
        assert_eq!(align_of::<SockaddrXdp>(), 4);
    }

    #[test]
    fn xdp_ring_offset_layout() {
        assert_eq!(size_of::<XdpRingOffset>(), 32);
        assert_eq!(align_of::<XdpRingOffset>(), 8);
    }

    #[test]
    fn xdp_mmap_offsets_layout() {
        assert_eq!(size_of::<XdpMmapOffsets>(), 128);
        assert_eq!(align_of::<XdpMmapOffsets>(), 8);
    }

    #[test]
    fn xdp_statistics_layout() {
        assert_eq!(size_of::<XdpStatistics>(), 48);
        assert_eq!(align_of::<XdpStatistics>(), 8);
    }

    #[test]
    fn xdp_desc_layout() {
        // Must be exactly 16 bytes to match kernel ABI and our PacketDescriptor.
        assert_eq!(size_of::<XdpDesc>(), 16);
        assert_eq!(align_of::<XdpDesc>(), 8);
    }

    #[test]
    fn xdp_desc_matches_packet_descriptor() {
        use crate::xdp::ring::PacketDescriptor;
        assert_eq!(size_of::<XdpDesc>(), size_of::<PacketDescriptor>());
        assert_eq!(align_of::<XdpDesc>(), align_of::<PacketDescriptor>());
    }

    #[test]
    fn bpf_map_create_attr_layout() {
        // Verify the struct is at least large enough for kernel expectations.
        assert!(size_of::<BpfMapCreateAttr>() >= 44);
    }

    #[test]
    fn bpf_prog_load_attr_layout() {
        assert!(size_of::<BpfProgLoadAttr>() >= 64);
    }

    #[test]
    fn bpf_link_create_attr_layout() {
        assert_eq!(size_of::<BpfLinkCreateAttr>(), 16);
    }

    #[test]
    fn constant_values() {
        // Verify critical constants match kernel UAPI.
        assert_eq!(AF_XDP, 44);
        assert_eq!(SOL_XDP, 283);
        assert_eq!(XDP_PASS, 2);
        assert_eq!(XDP_REDIRECT, 4);
        assert_eq!(BPF_MAP_TYPE_XSKMAP, 17);
        assert_eq!(BPF_PROG_TYPE_XDP, 6);
    }

    #[test]
    fn mmap_page_offsets() {
        // Verify mmap offsets are distinct and non-overlapping.
        assert_eq!(XDP_PGOFF_RX_RING, 0);
        const { assert!(XDP_PGOFF_TX_RING > XDP_PGOFF_RX_RING) };
        const { assert!(XDP_UMEM_PGOFF_FILL_RING > XDP_PGOFF_TX_RING) };
        const { assert!(XDP_UMEM_PGOFF_COMPLETION_RING > XDP_UMEM_PGOFF_FILL_RING) };
    }
}
