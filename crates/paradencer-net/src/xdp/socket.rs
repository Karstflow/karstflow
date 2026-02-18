/// AF_XDP socket with four rings for kernel-bypass packet I/O.
///
/// Combines a UMEM frame allocator with four XDP rings:
/// - **FILL ring**: userspace provides free frames to kernel for RX
/// - **RX ring**: kernel returns received packets to userspace
/// - **TX ring**: userspace submits packets for kernel to transmit
/// - **COMPLETION ring**: kernel returns transmitted frames to userspace
///
/// This module provides the high-level socket abstraction. The actual
/// Linux AF_XDP syscalls (socket, bind, mmap) are behind
/// `#[cfg(target_os = "linux")]`. The ring and UMEM logic is
/// platform-independent and fully testable.
use super::ring::{DescriptorRing, FrameRing, PacketDescriptor};
use super::umem::{FrameAllocator, UmemConfig};
use paradencer_constants::network::{XDP_DEFAULT_RING_DEPTH, XDP_MIN_RING_DEPTH};

/// Configuration for an XDP socket.
#[derive(Debug, Clone)]
pub struct XdpSocketConfig {
    /// UMEM configuration.
    pub umem: UmemConfig,
    /// Depth of each ring (FILL, RX, TX, COMPLETION).
    pub ring_depth: u32,
    /// Network interface index (Linux only).
    pub if_index: u32,
    /// Queue index on the network interface (Linux only).
    pub queue_id: u32,
    /// Whether to use zero-copy mode (Linux only).
    pub zero_copy: bool,
}

impl Default for XdpSocketConfig {
    fn default() -> Self {
        Self {
            umem: UmemConfig::default(),
            ring_depth: XDP_DEFAULT_RING_DEPTH,
            if_index: 0,
            queue_id: 0,
            zero_copy: false,
        }
    }
}

impl XdpSocketConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.umem.validate()?;
        if self.ring_depth < XDP_MIN_RING_DEPTH {
            return Err("ring_depth must be >= XDP_MIN_RING_DEPTH");
        }
        if !self.ring_depth.is_power_of_two() {
            return Err("ring_depth must be a power of 2");
        }
        Ok(())
    }
}

/// XDP socket state (platform-independent ring management).
///
/// On Linux, the actual AF_XDP socket fd and mmap'd regions are
/// managed separately. This struct owns the userspace-side ring
/// buffers and frame allocator.
pub struct XdpSocket {
    /// Frame allocator for UMEM regions.
    allocator: FrameAllocator,

    /// FILL ring: free frames provided to kernel.
    fill_ring: FrameRing,
    /// RX ring: received packet descriptors from kernel.
    rx_ring: DescriptorRing,
    /// TX ring: packet descriptors submitted for transmission.
    tx_ring: DescriptorRing,
    /// COMPLETION ring: frame offsets returned after TX.
    completion_ring: FrameRing,

    /// Packets received counter.
    rx_count: u64,
    /// Packets transmitted counter.
    tx_count: u64,
    /// Frames returned via completion counter.
    completion_count: u64,
}

impl XdpSocket {
    /// Create a new XDP socket from configuration.
    ///
    /// Allocates rings and UMEM frames. Does NOT create the actual
    /// Linux AF_XDP socket (see `bind()` for Linux-specific setup).
    pub fn new(config: &XdpSocketConfig) -> Option<Self> {
        config.validate().ok()?;

        let allocator = FrameAllocator::new(&config.umem)?;
        let depth = config.ring_depth;

        Some(Self {
            allocator,
            fill_ring: FrameRing::new(depth),
            rx_ring: DescriptorRing::new(depth),
            tx_ring: DescriptorRing::new(depth),
            completion_ring: FrameRing::new(depth),
            rx_count: 0,
            tx_count: 0,
            completion_count: 0,
        })
    }

    /// Pre-fill the FILL ring with free UMEM frames.
    ///
    /// Should be called during initialization to give the kernel
    /// frames for writing received packets. Returns the number of
    /// frames submitted.
    pub fn fill_initial_frames(&mut self) -> u32 {
        let mut count = 0u32;
        while !self.fill_ring.is_full() {
            match self.allocator.allocate() {
                Some(offset) => {
                    self.fill_ring.push(offset);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Refill the FILL ring from the frame allocator.
    ///
    /// Call this after processing received packets to maintain
    /// available frames for the kernel. Returns number of frames added.
    pub fn refill(&mut self) -> u32 {
        let mut count = 0u32;
        while !self.fill_ring.is_full() {
            match self.allocator.allocate() {
                Some(offset) => {
                    self.fill_ring.push(offset);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Receive packets from the RX ring.
    ///
    /// Pops up to `max_packets` descriptors from the RX ring into the
    /// provided buffer. Returns the number of packets received.
    pub fn receive(&mut self, buf: &mut [PacketDescriptor]) -> usize {
        let count = self.rx_ring.pop_batch(buf);
        self.rx_count += count as u64;
        count
    }

    /// Return a received frame to the free pool.
    ///
    /// Call this after processing a received packet to make the frame
    /// available for reuse.
    pub fn return_rx_frame(&mut self, frame_offset: u64) {
        self.allocator.release(frame_offset);
    }

    /// Return multiple received frames to the free pool.
    pub fn return_rx_frames(&mut self, offsets: &[u64]) {
        self.allocator.release_batch(offsets);
    }

    /// Submit a packet for transmission via the TX ring.
    ///
    /// The caller must have written packet data to the UMEM frame
    /// at `frame_offset` before calling this.
    pub fn transmit(&mut self, frame_offset: u64, len: u32) -> bool {
        let desc = PacketDescriptor::new(frame_offset, len);
        if self.tx_ring.push(desc) {
            self.tx_count += 1;
            true
        } else {
            false
        }
    }

    /// Process the COMPLETION ring, reclaiming transmitted frames.
    ///
    /// Returns the number of frames reclaimed.
    pub fn process_completions(&mut self) -> u32 {
        let mut count = 0u32;
        while let Some(offset) = self.completion_ring.pop() {
            self.allocator.release(offset);
            count += 1;
        }
        self.completion_count += count as u64;
        count
    }

    /// Allocate a frame for TX data.
    ///
    /// Returns a UMEM frame offset where the caller should write
    /// packet data starting at `offset + headroom`.
    pub fn allocate_tx_frame(&mut self) -> Option<u64> {
        self.allocator.allocate()
    }

    // -- Accessors --

    /// Reference to the FILL ring.
    pub fn fill_ring(&self) -> &FrameRing {
        &self.fill_ring
    }

    /// Mutable reference to the FILL ring.
    pub fn fill_ring_mut(&mut self) -> &mut FrameRing {
        &mut self.fill_ring
    }

    /// Reference to the RX ring.
    pub fn rx_ring(&self) -> &DescriptorRing {
        &self.rx_ring
    }

    /// Mutable reference to the RX ring (for kernel simulation in tests).
    pub fn rx_ring_mut(&mut self) -> &mut DescriptorRing {
        &mut self.rx_ring
    }

    /// Reference to the TX ring.
    pub fn tx_ring(&self) -> &DescriptorRing {
        &self.tx_ring
    }

    /// Reference to the COMPLETION ring.
    pub fn completion_ring(&self) -> &FrameRing {
        &self.completion_ring
    }

    /// Mutable reference to the COMPLETION ring (for kernel simulation).
    pub fn completion_ring_mut(&mut self) -> &mut FrameRing {
        &mut self.completion_ring
    }

    /// Frame allocator reference.
    pub fn allocator(&self) -> &FrameAllocator {
        &self.allocator
    }

    /// Total packets received.
    pub fn rx_count(&self) -> u64 {
        self.rx_count
    }

    /// Total packets transmitted.
    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }

    /// Total completion events processed.
    pub fn completion_count(&self) -> u64 {
        self.completion_count
    }

    /// UMEM headroom per frame.
    pub fn headroom(&self) -> usize {
        self.allocator.headroom()
    }

    /// Frame size.
    pub fn frame_size(&self) -> usize {
        self.allocator.frame_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> XdpSocketConfig {
        XdpSocketConfig {
            umem: UmemConfig {
                frame_count: 128,
                frame_size: 4096,
                headroom: 256,
            },
            ring_depth: 64,
            ..Default::default()
        }
    }

    #[test]
    fn socket_creation() {
        let sock = XdpSocket::new(&test_config()).unwrap();
        assert_eq!(sock.rx_count(), 0);
        assert_eq!(sock.tx_count(), 0);
        assert_eq!(sock.completion_count(), 0);
        assert_eq!(sock.frame_size(), 4096);
        assert_eq!(sock.headroom(), 256);
    }

    #[test]
    fn socket_creation_invalid_config() {
        let bad = XdpSocketConfig {
            ring_depth: 3, // not power of 2
            ..test_config()
        };
        assert!(XdpSocket::new(&bad).is_none());
    }

    #[test]
    fn fill_initial_frames() {
        let mut sock = XdpSocket::new(&test_config()).unwrap();
        let filled = sock.fill_initial_frames();
        // Should fill ring depth (64) or available frames, whichever is smaller.
        assert_eq!(filled, 64);
        assert_eq!(sock.fill_ring().available(), 64);
        assert_eq!(sock.allocator().allocated_count(), 64);
    }

    #[test]
    fn rx_simulation() {
        let mut sock = XdpSocket::new(&test_config()).unwrap();
        sock.fill_initial_frames();

        // Simulate kernel putting packets in RX ring.
        let rx_ring = sock.rx_ring_mut();
        rx_ring.push(PacketDescriptor::new(0, 64));
        rx_ring.push(PacketDescriptor::new(4096, 128));

        // Receive packets.
        let mut buf = [PacketDescriptor::new(0, 0); 4];
        let count = sock.receive(&mut buf);
        assert_eq!(count, 2);
        assert_eq!(buf[0].addr, 0);
        assert_eq!(buf[0].len, 64);
        assert_eq!(buf[1].addr, 4096);
        assert_eq!(buf[1].len, 128);
        assert_eq!(sock.rx_count(), 2);

        // Return frames.
        sock.return_rx_frame(0);
        sock.return_rx_frame(4096);
    }

    #[test]
    fn tx_flow() {
        let mut sock = XdpSocket::new(&test_config()).unwrap();

        // Allocate a TX frame.
        let frame = sock.allocate_tx_frame().unwrap();
        assert_eq!(frame, 0); // First frame

        // Submit for transmission.
        assert!(sock.transmit(frame, 100));
        assert_eq!(sock.tx_count(), 1);
        assert_eq!(sock.tx_ring().available(), 1);

        // Simulate kernel completing TX.
        sock.completion_ring_mut().push(frame);

        // Process completions.
        let reclaimed = sock.process_completions();
        assert_eq!(reclaimed, 1);
        assert_eq!(sock.completion_count(), 1);
    }

    #[test]
    fn full_rx_tx_cycle() {
        let mut sock = XdpSocket::new(&test_config()).unwrap();

        // Phase 1: Fill FILL ring.
        sock.fill_initial_frames();
        assert_eq!(sock.fill_ring().available(), 64);

        // Phase 2: Simulate kernel consuming FILL frames and producing RX.
        // Pop frames from FILL ring (kernel side).
        let mut fill_buf = [0u64; 4];
        sock.fill_ring_mut().pop_batch(&mut fill_buf);

        // Kernel puts received packets in RX ring.
        for &frame_offset in &fill_buf {
            sock.rx_ring_mut()
                .push(PacketDescriptor::new(frame_offset, 1500));
        }

        // Phase 3: Userspace receives packets.
        let mut rx_buf = [PacketDescriptor::new(0, 0); 4];
        let received = sock.receive(&mut rx_buf);
        assert_eq!(received, 4);

        // Phase 4: Return frames and refill.
        for desc in &rx_buf[..received] {
            sock.return_rx_frame(desc.addr);
        }
        let refilled = sock.refill();
        assert!(refilled > 0);
    }

    #[test]
    fn tx_ring_full() {
        let config = XdpSocketConfig {
            ring_depth: 64, // minimum valid
            umem: UmemConfig {
                frame_count: 128,
                frame_size: 4096,
                headroom: 256,
            },
            ..Default::default()
        };
        let mut sock = XdpSocket::new(&config).unwrap();

        // Fill up TX ring.
        for i in 0..64 {
            let frame = sock.allocate_tx_frame().unwrap();
            assert!(sock.transmit(frame, (i * 10) as u32));
        }
        assert!(sock.tx_ring().is_full());

        // Next transmit should fail.
        let frame = sock.allocate_tx_frame().unwrap();
        assert!(!sock.transmit(frame, 100));
    }

    #[test]
    fn config_validation() {
        let valid = test_config();
        assert!(valid.validate().is_ok());

        let bad_depth = XdpSocketConfig {
            ring_depth: 30, // not power of 2
            ..test_config()
        };
        assert!(bad_depth.validate().is_err());

        let too_small = XdpSocketConfig {
            ring_depth: 32, // less than minimum
            ..test_config()
        };
        // 32 < 64 (XDP_MIN_RING_DEPTH)
        assert!(too_small.validate().is_err());
    }

    #[test]
    fn completion_reclamation() {
        let mut sock = XdpSocket::new(&test_config()).unwrap();

        // Allocate and transmit several frames.
        let mut frames = Vec::new();
        for _ in 0..5 {
            let f = sock.allocate_tx_frame().unwrap();
            sock.transmit(f, 100);
            frames.push(f);
        }
        assert_eq!(sock.allocator().allocated_count(), 5);

        // Simulate kernel completing all.
        for &f in &frames {
            sock.completion_ring_mut().push(f);
        }

        let reclaimed = sock.process_completions();
        assert_eq!(reclaimed, 5);
        assert_eq!(sock.allocator().allocated_count(), 0);
    }
}
