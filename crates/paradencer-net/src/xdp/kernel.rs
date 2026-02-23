/// Kernel-mapped AF_XDP ring buffers and socket initialization.
///
/// Bridges userspace ring logic to Linux kernel shared memory via mmap.
/// Each ring has producer/consumer counters shared with the kernel and
/// locally cached copies to minimize volatile memory traffic.
///
/// The caching strategy: userspace caches both indices locally and only
/// refreshes from shared memory when the cached state indicates the ring
/// might be empty (consumer) or full (producer). This avoids cache-line
/// bouncing on every operation.
///
/// This module is Linux-only (`#[cfg(target_os = "linux")]`).
use std::os::unix::io::RawFd;
use std::ptr;

use super::socket::XdpSocketConfig;
use super::sys::*;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from AF_XDP kernel operations.
#[derive(Debug, thiserror::Error)]
pub enum XdpError {
    /// Failed to create AF_XDP socket.
    #[error("failed to create AF_XDP socket: errno {0}")]
    SocketCreate(i32),

    /// Failed to register UMEM region with kernel.
    #[error("failed to register UMEM: errno {0}")]
    UmemRegister(i32),

    /// Failed to configure ring depth.
    #[error("failed to set ring depth (option {option}): errno {errno}")]
    RingSetup { option: i32, errno: i32 },

    /// Failed to query mmap offsets from kernel.
    #[error("failed to query mmap offsets: errno {0}")]
    MmapOffsets(i32),

    /// Failed to mmap a ring region.
    #[error("failed to mmap ring region (offset 0x{pgoff:x}): errno {errno}")]
    MmapFailed { pgoff: i64, errno: i32 },

    /// Failed to bind socket to interface/queue.
    #[error("failed to bind to if_index={if_index} queue={queue_id}: errno {errno}")]
    BindFailed {
        if_index: u32,
        queue_id: u32,
        errno: i32,
    },

    /// Failed to wake up the kernel.
    #[error("kernel wakeup failed: errno {0}")]
    WakeupFailed(i32),

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    /// BPF syscall error.
    #[error("bpf syscall failed (cmd={cmd}): errno {errno}")]
    BpfSyscall { cmd: u32, errno: i32 },
}

// ---------------------------------------------------------------------------
// KernelRing — volatile shared-memory ring buffer
// ---------------------------------------------------------------------------

/// A kernel-mapped ring buffer with locally cached producer/consumer indices.
///
/// Type parameter `T` is:
/// - `u64` for FILL and COMPLETION rings (frame offsets)
/// - `XdpDesc` for RX and TX rings (packet descriptors)
///
/// The ring memory is mmap'd from the kernel and shared between userspace
/// and the kernel. Producer and consumer counters are `u32` and wrap at 2^32.
pub struct KernelRing<T: Copy> {
    /// Volatile pointer to the producer counter (shared with kernel).
    prod: *const u32,
    /// Volatile pointer to the consumer counter (shared with kernel).
    cons: *const u32,
    /// Pointer to the ring flags (contains `XDP_RING_NEED_WAKEUP`).
    flags: *const u32,
    /// Pointer to the start of the descriptor/frame array.
    ring: *mut T,
    /// Base address of the mmap'd region (for munmap).
    map_base: *mut u8,
    /// Size of the mmap'd region (for munmap).
    map_size: usize,
    /// Ring capacity (power of 2).
    depth: u32,
    /// Bitmask: `depth - 1`.
    mask: u32,
    /// Locally cached producer index.
    cached_prod: u32,
    /// Locally cached consumer index.
    cached_cons: u32,
}

// SAFETY: KernelRing pointers are to mmap'd shared memory that is
// valid for the lifetime of the ring. The ring is used from a single
// thread (tile model — one ring per core, no sharing).
unsafe impl<T: Copy + Send> Send for KernelRing<T> {}

impl<T: Copy> KernelRing<T> {
    /// Initialize a kernel ring from mmap'd memory and kernel-provided offsets.
    ///
    /// # Safety
    ///
    /// - `map_base` must point to a valid mmap'd region of at least `map_size` bytes.
    /// - `offsets` must contain valid byte offsets within the mapped region.
    /// - `depth` must match the ring depth configured with the kernel.
    /// - The mapped memory must remain valid for the lifetime of this ring.
    pub unsafe fn from_mmap(
        map_base: *mut u8,
        map_size: usize,
        offsets: &XdpRingOffset,
        depth: u32,
    ) -> Self {
        // SAFETY: All pointer arithmetic is within the mmap'd region.
        // The offsets are provided by the kernel and describe the layout.
        let prod = map_base.add(offsets.producer as usize) as *const u32;
        let cons = map_base.add(offsets.consumer as usize) as *const u32;
        let flags = map_base.add(offsets.flags as usize) as *const u32;
        let ring = map_base.add(offsets.desc as usize) as *mut T;

        Self {
            prod,
            cons,
            flags,
            ring,
            map_base,
            map_size,
            depth,
            mask: depth - 1,
            cached_prod: 0,
            cached_cons: 0,
        }
    }

    /// Number of entries available based on cached indices.
    #[inline(always)]
    pub fn cached_available(&self) -> u32 {
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Remaining capacity based on cached indices.
    #[inline(always)]
    pub fn cached_remaining(&self) -> u32 {
        self.depth - self.cached_available()
    }

    /// Refresh the cached producer index from kernel shared memory.
    #[inline(always)]
    pub fn refresh_producer(&mut self) {
        // SAFETY: prod points to a valid u32 in mmap'd shared memory.
        // Volatile read ensures we see the kernel's latest update.
        self.cached_prod = unsafe { ptr::read_volatile(self.prod) };
    }

    /// Refresh the cached consumer index from kernel shared memory.
    #[inline(always)]
    pub fn refresh_consumer(&mut self) {
        // SAFETY: cons points to a valid u32 in mmap'd shared memory.
        self.cached_cons = unsafe { ptr::read_volatile(self.cons) };
    }

    /// Publish the cached producer index to kernel shared memory.
    #[inline(always)]
    pub fn publish_producer(&mut self) {
        // SAFETY: prod points to mmap'd shared memory. Volatile write
        // ensures the kernel sees the update.
        unsafe { ptr::write_volatile(self.prod as *mut u32, self.cached_prod) };
    }

    /// Publish the cached consumer index to kernel shared memory.
    #[inline(always)]
    pub fn publish_consumer(&mut self) {
        // SAFETY: cons points to mmap'd shared memory.
        unsafe { ptr::write_volatile(self.cons as *mut u32, self.cached_cons) };
    }

    /// Check if the kernel has set the `NEED_WAKEUP` flag on this ring.
    #[inline(always)]
    pub fn need_wakeup(&self) -> bool {
        // SAFETY: flags points to a valid u32 in mmap'd shared memory.
        let f = unsafe { ptr::read_volatile(self.flags) };
        (f & XDP_RING_NEED_WAKEUP) != 0
    }

    /// Write entries to the ring as producer (FILL / TX side).
    ///
    /// Writes up to `items.len()` entries starting at `cached_prod`.
    /// Updates `cached_prod` but does NOT publish to kernel — caller
    /// must call `publish_producer()` after batching writes.
    ///
    /// Returns the number of entries written.
    #[inline]
    pub fn produce_batch(&mut self, items: &[T]) -> u32 {
        let remaining = self.cached_remaining();
        let count = (items.len() as u32).min(remaining);
        for i in 0..count {
            let idx = (self.cached_prod.wrapping_add(i) & self.mask) as usize;
            // SAFETY: idx is masked to [0, depth), so it's within the ring array.
            // The ring pointer is valid mmap'd memory.
            unsafe {
                ptr::write(self.ring.add(idx), items[i as usize]);
            }
        }
        self.cached_prod = self.cached_prod.wrapping_add(count);
        count
    }

    /// Read entries from the ring as consumer (RX / COMPLETION side).
    ///
    /// Reads up to `buf.len()` entries starting at `cached_cons`.
    /// Updates `cached_cons` but does NOT publish to kernel — caller
    /// must call `publish_consumer()` after processing.
    ///
    /// Returns the number of entries read.
    #[inline]
    pub fn consume_batch(&mut self, buf: &mut [T]) -> u32 {
        let available = self.cached_available();
        let count = (buf.len() as u32).min(available);
        for i in 0..count {
            let idx = (self.cached_cons.wrapping_add(i) & self.mask) as usize;
            // SAFETY: idx is masked to [0, depth), within the ring array.
            unsafe {
                buf[i as usize] = ptr::read(self.ring.add(idx));
            }
        }
        self.cached_cons = self.cached_cons.wrapping_add(count);
        count
    }

    /// Ring capacity.
    #[inline]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Current cached producer sequence.
    #[inline]
    pub fn cached_prod_seq(&self) -> u32 {
        self.cached_prod
    }

    /// Current cached consumer sequence.
    #[inline]
    pub fn cached_cons_seq(&self) -> u32 {
        self.cached_cons
    }
}

impl<T: Copy> Drop for KernelRing<T> {
    fn drop(&mut self) {
        if !self.map_base.is_null() && self.map_size > 0 {
            // SAFETY: map_base and map_size were set during from_mmap
            // and describe the exact region that was mmap'd.
            unsafe {
                libc::munmap(self.map_base as *mut libc::c_void, self.map_size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KernelXsk — complete AF_XDP socket with all kernel-mapped resources
// ---------------------------------------------------------------------------

/// Owns all kernel-mapped resources for one AF_XDP socket.
///
/// Manages the socket fd, four ring buffers (FILL, RX, TX, COMPLETION),
/// and the UMEM mmap'd region. Implements `Drop` to clean up all resources.
pub struct KernelXsk {
    /// AF_XDP socket file descriptor.
    xsk_fd: RawFd,
    /// FILL ring: userspace provides free frames to kernel.
    pub fill: KernelRing<u64>,
    /// RX ring: kernel delivers received packet descriptors.
    pub rx: KernelRing<XdpDesc>,
    /// TX ring: userspace submits packet descriptors for transmission.
    pub tx: KernelRing<XdpDesc>,
    /// COMPLETION ring: kernel returns transmitted frame offsets.
    pub completion: KernelRing<u64>,
    /// UMEM mmap'd base address.
    umem_area: *mut u8,
    /// UMEM total size in bytes.
    umem_size: usize,
    /// Network interface index.
    if_index: u32,
    /// NIC queue index.
    queue_id: u32,
}

// SAFETY: All resources are owned and the socket is used from a single
// tile/thread. The raw pointers are to mmap'd memory valid for the
// lifetime of this struct.
unsafe impl Send for KernelXsk {}

impl KernelXsk {
    /// Create and fully initialize an AF_XDP socket.
    ///
    /// Performs the complete initialization sequence:
    /// 1. Create AF_XDP socket
    /// 2. Allocate and mmap UMEM region
    /// 3. Register UMEM with kernel
    /// 4. Configure ring depths
    /// 5. Query ring mmap offsets
    /// 6. mmap all four ring regions
    /// 7. Bind to interface/queue
    pub fn create(config: &XdpSocketConfig) -> Result<Self, XdpError> {
        config.validate().map_err(XdpError::InvalidConfig)?;

        let umem_size = config.umem.total_size();
        let ring_depth = config.ring_depth;

        // Step 1: Create AF_XDP socket.
        let xsk_fd = unsafe { xdp_socket() }.map_err(XdpError::SocketCreate)?;

        // From here on, if anything fails we need to close the fd.
        let result = Self::init_socket(xsk_fd, config, umem_size, ring_depth);
        if result.is_err() {
            unsafe { libc::close(xsk_fd) };
        }
        result
    }

    /// Internal initialization after socket creation.
    fn init_socket(
        xsk_fd: RawFd,
        config: &XdpSocketConfig,
        umem_size: usize,
        ring_depth: u32,
    ) -> Result<Self, XdpError> {
        // Step 2: Allocate UMEM via anonymous mmap.
        let umem_area = unsafe {
            let ptr = libc::mmap(
                ptr::null_mut(),
                umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(XdpError::MmapFailed {
                    pgoff: -1,
                    errno: *libc::__errno_location(),
                });
            }
            ptr as *mut u8
        };

        // Step 3: Register UMEM with kernel.
        let umem_reg = XdpUmemReg {
            addr: umem_area as u64,
            len: umem_size as u64,
            chunk_size: config.umem.frame_size as u32,
            headroom: config.umem.headroom as u32,
            flags: 0,
            _pad: 0,
        };
        unsafe { xdp_umem_reg(xsk_fd, &umem_reg) }.map_err(XdpError::UmemRegister)?;

        // Step 4: Configure ring depths.
        let ring_opts = [
            (XDP_UMEM_FILL_RING, ring_depth),
            (XDP_UMEM_COMPLETION_RING, ring_depth),
            (XDP_RX_RING, ring_depth),
            (XDP_TX_RING, ring_depth),
        ];
        for &(opt, depth) in &ring_opts {
            unsafe { xdp_set_ring_depth(xsk_fd, opt, depth) }
                .map_err(|errno| XdpError::RingSetup { option: opt, errno })?;
        }

        // Step 5: Query ring mmap offsets from kernel.
        let offsets = unsafe { xdp_mmap_offsets(xsk_fd) }.map_err(XdpError::MmapOffsets)?;

        // Step 6: mmap all four ring regions.
        let fill =
            Self::mmap_ring::<u64>(xsk_fd, &offsets.fr, ring_depth, XDP_UMEM_PGOFF_FILL_RING)?;
        let completion = Self::mmap_ring::<u64>(
            xsk_fd,
            &offsets.cr,
            ring_depth,
            XDP_UMEM_PGOFF_COMPLETION_RING,
        )?;
        let rx = Self::mmap_ring::<XdpDesc>(xsk_fd, &offsets.rx, ring_depth, XDP_PGOFF_RX_RING)?;
        let tx = Self::mmap_ring::<XdpDesc>(xsk_fd, &offsets.tx, ring_depth, XDP_PGOFF_TX_RING)?;

        // Step 7: Bind to interface/queue.
        let mut bind_flags: u16 = XDP_USE_NEED_WAKEUP;
        if config.zero_copy {
            bind_flags |= XDP_ZEROCOPY;
        }

        let sa = SockaddrXdp {
            sxdp_family: PF_XDP,
            sxdp_flags: bind_flags,
            sxdp_ifindex: config.if_index,
            sxdp_queue_id: config.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        unsafe { xdp_bind(xsk_fd, &sa) }.map_err(|errno| XdpError::BindFailed {
            if_index: config.if_index,
            queue_id: config.queue_id,
            errno,
        })?;

        // Post-bind: diagnostic wakeup to detect driver issues.
        let _ = unsafe { xdp_wakeup_tx(xsk_fd) };

        Ok(Self {
            xsk_fd,
            fill,
            rx,
            tx,
            completion,
            umem_area,
            umem_size,
            if_index: config.if_index,
            queue_id: config.queue_id,
        })
    }

    /// mmap a single ring region and construct a `KernelRing`.
    fn mmap_ring<T: Copy>(
        fd: RawFd,
        offsets: &XdpRingOffset,
        depth: u32,
        pgoff: i64,
    ) -> Result<KernelRing<T>, XdpError> {
        let map_size = offsets.desc as usize + (depth as usize) * std::mem::size_of::<T>();
        let base = unsafe { xdp_mmap_ring(fd, map_size, pgoff) }
            .map_err(|errno| XdpError::MmapFailed { pgoff, errno })?;

        // Lock pages and exclude from core dumps.
        unsafe {
            libc::mlock(base as *const libc::c_void, map_size);
            libc::madvise(base as *mut libc::c_void, map_size, libc::MADV_DONTDUMP);
        }

        // SAFETY: base points to a freshly mmap'd region of map_size bytes.
        // offsets are kernel-provided and describe the layout within the region.
        Ok(unsafe { KernelRing::from_mmap(base, map_size, offsets, depth) })
    }

    /// Wake up the kernel for TX processing if needed.
    pub fn wakeup_tx(&self) -> Result<(), XdpError> {
        if self.tx.need_wakeup() {
            unsafe { xdp_wakeup_tx(self.xsk_fd) }.map_err(XdpError::WakeupFailed)
        } else {
            Ok(())
        }
    }

    /// Wake up the kernel for RX processing if needed.
    pub fn wakeup_rx(&self) -> Result<(), XdpError> {
        if self.fill.need_wakeup() {
            unsafe { xdp_wakeup_rx(self.xsk_fd) }.map_err(XdpError::WakeupFailed)
        } else {
            Ok(())
        }
    }

    /// Query XDP statistics from the kernel.
    pub fn statistics(&self) -> Result<XdpStatistics, XdpError> {
        unsafe { xdp_statistics(self.xsk_fd) }.map_err(XdpError::WakeupFailed)
    }

    /// Get the socket file descriptor.
    pub fn fd(&self) -> RawFd {
        self.xsk_fd
    }

    /// Get a raw pointer to the UMEM region base.
    pub fn umem_area(&self) -> *mut u8 {
        self.umem_area
    }

    /// Get the UMEM total size.
    pub fn umem_size(&self) -> usize {
        self.umem_size
    }

    /// Get the network interface index.
    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Get the NIC queue index.
    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Get zero-copy access to packet data within a UMEM frame.
    ///
    /// # Safety
    ///
    /// - `addr` must be a valid UMEM offset returned from an RX descriptor.
    /// - `len` must not exceed the frame boundary.
    /// - The returned slice is only valid until the frame is returned to
    ///   the FILL ring.
    #[inline]
    pub unsafe fn frame_data(&self, addr: u64, len: u32) -> &[u8] {
        // SAFETY: addr is within the UMEM region and len is bounded
        // by the frame size. Caller guarantees validity.
        std::slice::from_raw_parts(self.umem_area.add(addr as usize), len as usize)
    }

    /// Get mutable zero-copy access to packet data within a UMEM frame.
    ///
    /// # Safety
    ///
    /// - `addr` must be a valid UMEM offset (e.g., for TX frame writing).
    /// - `len` must not exceed the frame boundary.
    /// - No other references to this frame data may exist.
    #[inline]
    pub unsafe fn frame_data_mut(&mut self, addr: u64, len: u32) -> &mut [u8] {
        // SAFETY: addr is within UMEM, len is bounded, and caller
        // guarantees exclusive access.
        std::slice::from_raw_parts_mut(self.umem_area.add(addr as usize), len as usize)
    }
}

impl Drop for KernelXsk {
    fn drop(&mut self) {
        // Close the socket fd. Ring mmaps are cleaned up by KernelRing::drop.
        if self.xsk_fd >= 0 {
            unsafe { libc::close(self.xsk_fd) };
        }

        // Unmap UMEM.
        if !self.umem_area.is_null() && self.umem_size > 0 {
            unsafe {
                libc::munmap(self.umem_area as *mut libc::c_void, self.umem_size);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc, Layout};

    /// Helper: allocate a mock ring region and construct a KernelRing.
    ///
    /// Layout: [producer: u32][consumer: u32][flags: u32][pad: u32][entries: T * depth]
    /// This mimics the kernel's ring layout with known offsets.
    fn mock_ring<T: Copy + Default>(depth: u32) -> (KernelRing<T>, *mut u8) {
        let header_size = 16usize; // prod(4) + cons(4) + flags(4) + pad(4)
        let entries_size = depth as usize * std::mem::size_of::<T>();
        let total = header_size + entries_size;

        let layout = Layout::from_size_align(total, 8).unwrap();
        // SAFETY: layout is valid with non-zero size and alignment.
        let base = unsafe { alloc_zeroed(layout) };
        assert!(!base.is_null());

        let offsets = XdpRingOffset {
            producer: 0,
            consumer: 4,
            flags: 8,
            desc: header_size as u64,
        };

        // SAFETY: base points to valid zeroed memory of sufficient size.
        // We set map_size to 0 to prevent munmap in Drop (we manage memory ourselves).
        let ring = unsafe {
            let mut r = KernelRing::<T>::from_mmap(base, 0, &offsets, depth);
            // Zero map_size so Drop doesn't try to munmap our alloc'd memory.
            r.map_size = 0;
            r
        };

        (ring, base)
    }

    fn free_mock<T: Copy>(ring: KernelRing<T>, base: *mut u8, depth: u32) {
        let header_size = 16usize;
        let entries_size = depth as usize * std::mem::size_of::<T>();
        let total = header_size + entries_size;
        let layout = Layout::from_size_align(total, 8).unwrap();

        drop(ring);
        // SAFETY: base was allocated with this exact layout.
        unsafe { dealloc(base, layout) };
    }

    #[test]
    fn kernel_ring_produce_consume_u64() {
        let depth = 8u32;
        let (mut ring, base) = mock_ring::<u64>(depth);

        // Produce 4 frame offsets.
        let frames = [0u64, 4096, 8192, 12288];
        let produced = ring.produce_batch(&frames);
        assert_eq!(produced, 4);
        assert_eq!(ring.cached_prod_seq(), 4);
        assert_eq!(ring.cached_remaining(), 4);

        // Publish producer so consumer can see.
        ring.publish_producer();

        // Refresh consumer's view of producer (simulates kernel reading).
        ring.refresh_producer();
        assert_eq!(ring.cached_available(), 4);

        // Consume 3 entries.
        let mut buf = [0u64; 3];
        let consumed = ring.consume_batch(&mut buf);
        assert_eq!(consumed, 3);
        assert_eq!(buf, [0, 4096, 8192]);
        assert_eq!(ring.cached_cons_seq(), 3);

        ring.publish_consumer();

        free_mock(ring, base, depth);
    }

    #[test]
    fn kernel_ring_produce_consume_desc() {
        let depth = 4u32;
        let (mut ring, base) = mock_ring::<XdpDesc>(depth);

        let descs = [
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            XdpDesc {
                addr: 4096,
                len: 128,
                options: 0,
            },
        ];
        let produced = ring.produce_batch(&descs);
        assert_eq!(produced, 2);

        ring.publish_producer();
        ring.refresh_producer();

        let mut buf = [XdpDesc::default(); 4];
        let consumed = ring.consume_batch(&mut buf);
        assert_eq!(consumed, 2);
        assert_eq!(buf[0].addr, 0);
        assert_eq!(buf[0].len, 64);
        assert_eq!(buf[1].addr, 4096);
        assert_eq!(buf[1].len, 128);

        free_mock(ring, base, depth);
    }

    #[test]
    fn kernel_ring_wraparound() {
        let depth = 4u32;
        let (mut ring, base) = mock_ring::<u64>(depth);

        // Fill and drain multiple rounds to exercise index wrapping.
        for round in 0..10u64 {
            let items: Vec<u64> = (0..4).map(|i| round * 100 + i).collect();
            let produced = ring.produce_batch(&items);
            assert_eq!(produced, 4);
            ring.publish_producer();
            ring.refresh_producer();

            let mut buf = [0u64; 4];
            let consumed = ring.consume_batch(&mut buf);
            assert_eq!(consumed, 4);
            for (i, &val) in buf.iter().enumerate() {
                assert_eq!(val, round * 100 + i as u64);
            }
            ring.publish_consumer();
            ring.refresh_consumer();
        }

        free_mock(ring, base, depth);
    }

    #[test]
    fn kernel_ring_full_empty() {
        let depth = 4u32;
        let (mut ring, base) = mock_ring::<u64>(depth);

        // Ring starts empty.
        assert_eq!(ring.cached_available(), 0);
        assert_eq!(ring.cached_remaining(), 4);

        // Fill completely.
        let items = [1u64, 2, 3, 4];
        let produced = ring.produce_batch(&items);
        assert_eq!(produced, 4);
        assert_eq!(ring.cached_remaining(), 0);

        // Attempt to produce more — should return 0.
        let more = [5u64, 6];
        let produced = ring.produce_batch(&more);
        assert_eq!(produced, 0);

        free_mock(ring, base, depth);
    }

    #[test]
    fn kernel_ring_need_wakeup() {
        let depth = 4u32;
        let (ring, base) = mock_ring::<u64>(depth);

        // Initially flags are 0 — no wakeup needed.
        assert!(!ring.need_wakeup());

        // Set the NEED_WAKEUP flag in shared memory.
        unsafe {
            std::ptr::write_volatile(ring.flags as *mut u32, XDP_RING_NEED_WAKEUP);
        }
        assert!(ring.need_wakeup());

        // Clear it.
        unsafe {
            std::ptr::write_volatile(ring.flags as *mut u32, 0);
        }
        assert!(!ring.need_wakeup());

        free_mock(ring, base, depth);
    }

    #[test]
    fn xdp_error_display() {
        let err = XdpError::SocketCreate(13);
        assert!(err.to_string().contains("errno 13"));

        let err = XdpError::BindFailed {
            if_index: 2,
            queue_id: 0,
            errno: 19,
        };
        assert!(err.to_string().contains("if_index=2"));
    }
}
