/// Production-ready AF_XDP socket combining kernel integration with
/// userspace frame management.
///
/// `LiveXdpSocket` is the primary entry point for AF_XDP packet I/O.
/// It owns a kernel-mapped socket (`KernelXsk`), a frame allocator
/// (`FrameAllocator`), and references to the shared eBPF program and
/// XSKMAP. All operations are zero-copy via UMEM shared memory.
///
/// Typical usage in a network tile's service loop:
/// ```text
/// loop {
///     socket.process_completions();  // Reclaim TX frames
///     socket.refill();               // Provide free frames for RX
///     let n = socket.receive(&mut rx_buf);
///     for desc in &rx_buf[..n] {
///         let data = socket.frame_data(desc);
///         // Process packet...
///         socket.release_rx_frame(desc.addr);
///     }
///     // TX: write data, submit, flush
///     socket.flush_tx();
/// }
/// ```
///
/// This module is Linux-only (`#[cfg(target_os = "linux")]`).
use std::sync::Arc;

use super::kernel::{KernelXsk, XdpError};
use super::loader::{XdpProgram, XskMap};
use super::socket::XdpSocketConfig;
use super::sys::XdpDesc;
use super::umem::FrameAllocator;

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Runtime statistics for a live XDP socket.
#[derive(Debug, Clone, Default)]
pub struct LiveXdpStats {
    /// Total packets received from the RX ring.
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Total packets submitted to the TX ring.
    pub tx_packets: u64,
    /// Total bytes submitted for transmission.
    pub tx_bytes: u64,
    /// Number of frames reclaimed from the COMPLETION ring.
    pub completions: u64,
    /// Number of frames pushed to the FILL ring.
    pub fill_count: u64,
    /// Times the FILL ring refill was blocked (no free frames).
    pub fill_blocked: u64,
    /// Times the kernel was woken for RX.
    pub rx_wakeups: u64,
    /// Times the kernel was woken for TX.
    pub tx_wakeups: u64,
    /// Frame allocation failures (allocator exhausted).
    pub allocation_failures: u64,
}

// ---------------------------------------------------------------------------
// LiveXdpSocket
// ---------------------------------------------------------------------------

/// Complete AF_XDP socket for production packet I/O.
///
/// Combines the kernel-mapped socket, userspace frame allocator,
/// XSKMAP registration, and eBPF program into a single operational unit.
pub struct LiveXdpSocket {
    /// Kernel-mapped AF_XDP socket with ring buffers.
    kernel: KernelXsk,
    /// Userspace frame allocator tracking UMEM frame ownership.
    allocator: FrameAllocator,
    /// Shared XSKMAP reference (socket registered at our queue index).
    xsk_map: Arc<XskMap>,
    /// Shared eBPF program reference (attached to our interface).
    program: Arc<XdpProgram>,
    /// Runtime statistics.
    stats: LiveXdpStats,
    /// Number of pending TX descriptors not yet flushed.
    tx_pending: u32,
}

impl LiveXdpSocket {
    /// Open a new AF_XDP socket with full kernel integration.
    ///
    /// Performs the complete setup:
    /// 1. Create kernel socket (UMEM, rings, bind)
    /// 2. Register socket in the XSKMAP
    /// 3. Bootstrap the FILL ring with free frames
    ///
    /// The `xsk_map` and `program` should be obtained from `install_xdp()`.
    pub fn open(
        config: &XdpSocketConfig,
        xsk_map: Arc<XskMap>,
        program: Arc<XdpProgram>,
    ) -> Result<Self, XdpError> {
        // Create kernel socket with UMEM + rings + bind.
        let kernel = KernelXsk::create(config)?;

        // Create userspace frame allocator.
        let allocator = FrameAllocator::new(&config.umem).ok_or(XdpError::InvalidConfig(
            "invalid UMEM configuration for frame allocator",
        ))?;

        // Register this socket in the XSKMAP for packet dispatch.
        xsk_map.insert(config.queue_id, kernel.fd())?;

        let mut socket = Self {
            kernel,
            allocator,
            xsk_map,
            program,
            stats: LiveXdpStats::default(),
            tx_pending: 0,
        };

        // Bootstrap: fill the FILL ring with free frames so the kernel
        // has buffers for receiving packets immediately.
        socket.bootstrap_fill_ring();

        Ok(socket)
    }

    /// Fill the FILL ring with all available free frames.
    fn bootstrap_fill_ring(&mut self) {
        let depth = self.kernel.fill.depth();
        let mut batch = Vec::with_capacity(depth as usize);

        // Allocate frames from the freelist.
        for _ in 0..depth {
            match self.allocator.allocate() {
                Some(offset) => batch.push(offset),
                None => break,
            }
        }

        if !batch.is_empty() {
            let produced = self.kernel.fill.produce_batch(&batch);
            self.kernel.fill.publish_producer();
            self.stats.fill_count += produced as u64;

            // Return any frames we couldn't push (shouldn't happen if
            // ring depth <= frame count, but defensive).
            for &offset in &batch[produced as usize..] {
                self.allocator.release(offset);
            }
        }
    }

    /// Receive packets from the kernel RX ring.
    ///
    /// Reads up to `buf.len()` packet descriptors. Each descriptor contains
    /// the UMEM address and length of the received packet data.
    ///
    /// After processing each packet, call `release_rx_frame()` to return
    /// the frame to the free pool.
    pub fn receive(&mut self, buf: &mut [XdpDesc]) -> usize {
        // Refresh producer to see kernel's latest writes.
        self.kernel.rx.refresh_producer();

        let count = self.kernel.rx.consume_batch(buf);
        if count > 0 {
            self.kernel.rx.publish_consumer();

            // Update statistics.
            self.stats.rx_packets += count as u64;
            for desc in &buf[..count as usize] {
                self.stats.rx_bytes += desc.len as u64;
            }
        }

        count as usize
    }

    /// Submit a packet descriptor for transmission.
    ///
    /// The caller must have already written packet data to the UMEM frame.
    /// Returns `true` if the descriptor was enqueued, `false` if the TX
    /// ring is full.
    ///
    /// Call `flush_tx()` after submitting a batch to notify the kernel.
    pub fn transmit(&mut self, desc: &XdpDesc) -> bool {
        // Refresh consumer to see kernel's latest completions.
        if self.kernel.tx.cached_remaining() == 0 {
            self.kernel.tx.refresh_consumer();
        }

        let items = [*desc];
        let produced = self.kernel.tx.produce_batch(&items);
        if produced > 0 {
            self.tx_pending += 1;
            self.stats.tx_packets += 1;
            self.stats.tx_bytes += desc.len as u64;
            true
        } else {
            false
        }
    }

    /// Flush pending TX descriptors to the kernel.
    ///
    /// Publishes the TX ring producer index and wakes the kernel if
    /// the `NEED_WAKEUP` flag is set.
    pub fn flush_tx(&mut self) -> Result<(), XdpError> {
        if self.tx_pending > 0 {
            self.kernel.tx.publish_producer();
            self.tx_pending = 0;

            if self.kernel.tx.need_wakeup() {
                self.stats.tx_wakeups += 1;
                self.kernel.wakeup_tx()?;
            }
        }
        Ok(())
    }

    /// Refill the FILL ring with free frames from the allocator.
    ///
    /// Returns the number of frames pushed to the FILL ring.
    pub fn refill(&mut self) -> u32 {
        // Refresh consumer to see how many frames the kernel has consumed.
        self.kernel.fill.refresh_consumer();

        let remaining = self.kernel.fill.cached_remaining();
        if remaining == 0 {
            return 0;
        }

        let mut batch = Vec::with_capacity(remaining as usize);
        for _ in 0..remaining {
            match self.allocator.allocate() {
                Some(offset) => batch.push(offset),
                None => {
                    self.stats.fill_blocked += 1;
                    break;
                }
            }
        }

        if batch.is_empty() {
            self.stats.allocation_failures += 1;
            return 0;
        }

        let produced = self.kernel.fill.produce_batch(&batch);
        self.kernel.fill.publish_producer();
        self.stats.fill_count += produced as u64;

        // Return unpushed frames (defensive).
        for &offset in &batch[produced as usize..] {
            self.allocator.release(offset);
        }

        // Wake kernel if it's waiting for FILL frames.
        if self.kernel.fill.need_wakeup() {
            self.stats.rx_wakeups += 1;
            let _ = self.kernel.wakeup_rx();
        }

        produced
    }

    /// Process the COMPLETION ring, reclaiming transmitted frames.
    ///
    /// Returns the number of frames reclaimed.
    pub fn process_completions(&mut self) -> u32 {
        self.kernel.completion.refresh_producer();

        let available = self.kernel.completion.cached_available();
        if available == 0 {
            return 0;
        }

        let mut batch = vec![0u64; available as usize];
        let count = self.kernel.completion.consume_batch(&mut batch);
        if count > 0 {
            self.kernel.completion.publish_consumer();

            // Return frames to the allocator.
            for &offset in &batch[..count as usize] {
                self.allocator.release(offset);
            }

            self.stats.completions += count as u64;
        }

        count
    }

    /// Release an RX frame back to the allocator.
    ///
    /// Call this after processing a received packet to make the frame
    /// available for refilling the FILL ring.
    #[inline]
    pub fn release_rx_frame(&mut self, addr: u64) {
        self.allocator.release(addr);
    }

    /// Release multiple RX frames back to the allocator.
    #[inline]
    pub fn release_rx_frames(&mut self, addrs: &[u64]) {
        self.allocator.release_batch(addrs);
    }

    /// Allocate a UMEM frame for TX data writing.
    ///
    /// Returns the frame's UMEM byte offset, or `None` if the allocator
    /// is exhausted.
    #[inline]
    pub fn allocate_tx_frame(&mut self) -> Option<u64> {
        self.allocator.allocate()
    }

    /// Get zero-copy read access to packet data in a UMEM frame.
    ///
    /// # Safety
    ///
    /// The descriptor must be from a valid RX ring entry that has not
    /// been released back to the allocator.
    #[inline]
    pub unsafe fn frame_data(&self, desc: &XdpDesc) -> &[u8] {
        // SAFETY: Caller guarantees the descriptor is valid and the
        // frame has not been released. Delegates to KernelXsk.
        self.kernel.frame_data(desc.addr, desc.len)
    }

    /// Get zero-copy mutable access to a UMEM frame for TX data writing.
    ///
    /// # Safety
    ///
    /// The `addr` must be from a frame allocated via `allocate_tx_frame()`.
    /// `len` must not exceed the frame size minus headroom.
    #[inline]
    pub unsafe fn frame_data_mut(&mut self, addr: u64, len: u32) -> &mut [u8] {
        // SAFETY: Caller guarantees the addr is from an allocated frame
        // and len is within bounds.
        self.kernel.frame_data_mut(addr, len)
    }

    /// Run one service iteration: completions -> refill -> receive.
    ///
    /// This is the recommended call for the main poll loop. Returns the
    /// number of packets received.
    pub fn service(&mut self, rx_buf: &mut [XdpDesc]) -> usize {
        self.process_completions();
        self.refill();
        self.receive(rx_buf)
    }

    /// Get the UMEM headroom per frame.
    #[inline]
    pub fn headroom(&self) -> usize {
        self.allocator.headroom()
    }

    /// Get the frame size.
    #[inline]
    pub fn frame_size(&self) -> usize {
        self.allocator.frame_size()
    }

    /// Get runtime statistics.
    pub fn stats(&self) -> &LiveXdpStats {
        &self.stats
    }

    /// Get the underlying socket file descriptor.
    pub fn fd(&self) -> std::os::unix::io::RawFd {
        self.kernel.fd()
    }

    /// Get the interface index.
    pub fn if_index(&self) -> u32 {
        self.kernel.if_index()
    }

    /// Get the queue index.
    pub fn queue_id(&self) -> u32 {
        self.kernel.queue_id()
    }
}

impl Drop for LiveXdpSocket {
    fn drop(&mut self) {
        // Deregister from XSKMAP before closing the socket.
        let _ = self.xsk_map.remove(self.kernel.queue_id());
        // KernelXsk::drop handles fd close and munmap.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_xdp_stats_default() {
        let stats = LiveXdpStats::default();
        assert_eq!(stats.rx_packets, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.completions, 0);
        assert_eq!(stats.fill_count, 0);
        assert_eq!(stats.rx_wakeups, 0);
        assert_eq!(stats.tx_wakeups, 0);
    }

    #[test]
    fn xdp_desc_zero_copy_layout() {
        // Verify XdpDesc matches the kernel ABI expectation.
        assert_eq!(std::mem::size_of::<XdpDesc>(), 16);
        assert_eq!(std::mem::align_of::<XdpDesc>(), 8);

        let desc = XdpDesc {
            addr: 0x1000,
            len: 1500,
            options: 0,
        };
        assert_eq!(desc.addr, 0x1000);
        assert_eq!(desc.len, 1500);
    }
}
