/// XDP ring buffer: single-producer/single-consumer with cached indices.
///
/// Implements the kernel AF_XDP ring protocol where producer and consumer
/// maintain 32-bit sequence numbers that wrap at 2^32. The ring capacity
/// must be a power of 2 for efficient masking.
///
/// Two ring flavors exist:
/// - **Frame rings** (FILL/COMPLETION): entries are `u64` UMEM frame offsets
/// - **Descriptor rings** (RX/TX): entries are `(offset, len)` packet descriptors
///
/// This module provides the platform-independent ring logic. Actual mmap'd
/// shared memory with the kernel is handled in `socket.rs` (Linux only).
use paradencer_constants::network::XDP_FRAME_INVALID;

/// A packet descriptor in RX/TX rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PacketDescriptor {
    /// UMEM frame offset (byte offset from UMEM base).
    pub addr: u64,
    /// Packet data length in bytes.
    pub len: u32,
    /// Options (currently unused, set to 0).
    pub options: u32,
}

impl PacketDescriptor {
    /// Create a new descriptor.
    pub fn new(addr: u64, len: u32) -> Self {
        Self {
            addr,
            len,
            options: 0,
        }
    }
}

/// Ring buffer for UMEM frame offsets (FILL and COMPLETION rings).
///
/// Single-producer/single-consumer. Capacity must be a power of 2.
/// Producer and consumer indices are 32-bit and wrap naturally.
pub struct FrameRing {
    /// Ring entries (UMEM frame offsets).
    entries: Vec<u64>,
    /// Ring capacity (power of 2).
    depth: u32,
    /// Bitmask for wrapping: `depth - 1`.
    mask: u32,
    /// Producer sequence number (monotonically increasing).
    producer: u32,
    /// Consumer sequence number (monotonically increasing).
    consumer: u32,
}

impl FrameRing {
    /// Create a new frame ring with the given depth (rounded up to power of 2).
    pub fn new(min_depth: u32) -> Self {
        let depth = min_depth.next_power_of_two().max(2);
        Self {
            entries: vec![XDP_FRAME_INVALID; depth as usize],
            depth,
            mask: depth - 1,
            producer: 0,
            consumer: 0,
        }
    }

    /// Number of entries available for consumption.
    #[inline]
    pub fn available(&self) -> u32 {
        self.producer.wrapping_sub(self.consumer)
    }

    /// Remaining capacity for production.
    #[inline]
    pub fn remaining(&self) -> u32 {
        self.depth - self.available()
    }

    /// Whether the ring is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.producer == self.consumer
    }

    /// Whether the ring is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.available() >= self.depth
    }

    /// Push a frame offset onto the ring (producer side).
    ///
    /// Returns `true` if pushed, `false` if full.
    pub fn push(&mut self, frame_offset: u64) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.producer & self.mask) as usize;
        self.entries[idx] = frame_offset;
        self.producer = self.producer.wrapping_add(1);
        true
    }

    /// Push multiple frame offsets. Returns the number actually pushed.
    pub fn push_batch(&mut self, offsets: &[u64]) -> usize {
        let space = self.remaining() as usize;
        let count = offsets.len().min(space);
        for &offset in &offsets[..count] {
            let idx = (self.producer & self.mask) as usize;
            self.entries[idx] = offset;
            self.producer = self.producer.wrapping_add(1);
        }
        count
    }

    /// Pop a frame offset from the ring (consumer side).
    ///
    /// Returns `None` if the ring is empty.
    pub fn pop(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.consumer & self.mask) as usize;
        let offset = self.entries[idx];
        self.consumer = self.consumer.wrapping_add(1);
        Some(offset)
    }

    /// Pop up to `max` frame offsets into the provided buffer.
    /// Returns the number of offsets popped.
    pub fn pop_batch(&mut self, buf: &mut [u64]) -> usize {
        let avail = self.available() as usize;
        let count = buf.len().min(avail);
        for entry in buf.iter_mut().take(count) {
            let idx = (self.consumer & self.mask) as usize;
            *entry = self.entries[idx];
            self.consumer = self.consumer.wrapping_add(1);
        }
        count
    }

    /// Peek at the next entry without consuming it.
    pub fn peek(&self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        Some(self.entries[(self.consumer & self.mask) as usize])
    }

    /// Ring depth (capacity).
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Current producer sequence.
    pub fn producer_seq(&self) -> u32 {
        self.producer
    }

    /// Current consumer sequence.
    pub fn consumer_seq(&self) -> u32 {
        self.consumer
    }
}

/// Ring buffer for packet descriptors (RX and TX rings).
///
/// Same SPSC protocol as `FrameRing` but entries are `PacketDescriptor`.
pub struct DescriptorRing {
    /// Ring entries.
    entries: Vec<PacketDescriptor>,
    /// Ring capacity (power of 2).
    depth: u32,
    /// Bitmask for wrapping.
    mask: u32,
    /// Producer sequence number.
    producer: u32,
    /// Consumer sequence number.
    consumer: u32,
}

impl DescriptorRing {
    /// Create a new descriptor ring.
    pub fn new(min_depth: u32) -> Self {
        let depth = min_depth.next_power_of_two().max(2);
        Self {
            entries: vec![PacketDescriptor::new(0, 0); depth as usize],
            depth,
            mask: depth - 1,
            producer: 0,
            consumer: 0,
        }
    }

    /// Number of entries available for consumption.
    #[inline]
    pub fn available(&self) -> u32 {
        self.producer.wrapping_sub(self.consumer)
    }

    /// Remaining capacity for production.
    #[inline]
    pub fn remaining(&self) -> u32 {
        self.depth - self.available()
    }

    /// Whether the ring is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.producer == self.consumer
    }

    /// Whether the ring is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.available() >= self.depth
    }

    /// Push a descriptor onto the ring.
    pub fn push(&mut self, desc: PacketDescriptor) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.producer & self.mask) as usize;
        self.entries[idx] = desc;
        self.producer = self.producer.wrapping_add(1);
        true
    }

    /// Pop a descriptor from the ring.
    pub fn pop(&mut self) -> Option<PacketDescriptor> {
        if self.is_empty() {
            return None;
        }
        let idx = (self.consumer & self.mask) as usize;
        let desc = self.entries[idx];
        self.consumer = self.consumer.wrapping_add(1);
        Some(desc)
    }

    /// Pop up to `max` descriptors into the provided buffer.
    pub fn pop_batch(&mut self, buf: &mut [PacketDescriptor]) -> usize {
        let avail = self.available() as usize;
        let count = buf.len().min(avail);
        for entry in buf.iter_mut().take(count) {
            let idx = (self.consumer & self.mask) as usize;
            *entry = self.entries[idx];
            self.consumer = self.consumer.wrapping_add(1);
        }
        count
    }

    /// Peek at the next descriptor without consuming it.
    pub fn peek(&self) -> Option<&PacketDescriptor> {
        if self.is_empty() {
            return None;
        }
        Some(&self.entries[(self.consumer & self.mask) as usize])
    }

    /// Ring depth (capacity).
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- FrameRing tests ---

    #[test]
    fn frame_ring_empty() {
        let ring = FrameRing::new(16);
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.remaining(), 16);
        assert_eq!(ring.depth(), 16);
    }

    #[test]
    fn frame_ring_push_pop() {
        let mut ring = FrameRing::new(4);
        assert!(ring.push(100));
        assert!(ring.push(200));
        assert_eq!(ring.available(), 2);

        assert_eq!(ring.pop(), Some(100));
        assert_eq!(ring.pop(), Some(200));
        assert!(ring.is_empty());
    }

    #[test]
    fn frame_ring_full() {
        let mut ring = FrameRing::new(4);
        assert!(ring.push(0));
        assert!(ring.push(1));
        assert!(ring.push(2));
        assert!(ring.push(3));
        assert!(ring.is_full());
        assert!(!ring.push(4)); // Should fail
    }

    #[test]
    fn frame_ring_wraparound() {
        let mut ring = FrameRing::new(4);

        // Fill and drain multiple times to exercise wraparound.
        for round in 0..10u64 {
            for i in 0..4 {
                assert!(ring.push(round * 4 + i));
            }
            assert!(ring.is_full());

            for i in 0..4 {
                assert_eq!(ring.pop(), Some(round * 4 + i));
            }
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn frame_ring_batch_push() {
        let mut ring = FrameRing::new(8);
        let offsets = [10, 20, 30, 40, 50];
        assert_eq!(ring.push_batch(&offsets), 5);
        assert_eq!(ring.available(), 5);

        assert_eq!(ring.pop(), Some(10));
        assert_eq!(ring.pop(), Some(20));
    }

    #[test]
    fn frame_ring_batch_push_partial() {
        let mut ring = FrameRing::new(4);
        ring.push(0);
        ring.push(1);
        // 2 remaining
        let offsets = [10, 20, 30, 40];
        assert_eq!(ring.push_batch(&offsets), 2);
        assert_eq!(ring.available(), 4);
    }

    #[test]
    fn frame_ring_batch_pop() {
        let mut ring = FrameRing::new(8);
        for i in 0..5 {
            ring.push(i * 100);
        }

        let mut buf = [0u64; 3];
        assert_eq!(ring.pop_batch(&mut buf), 3);
        assert_eq!(buf, [0, 100, 200]);
        assert_eq!(ring.available(), 2);
    }

    #[test]
    fn frame_ring_peek() {
        let mut ring = FrameRing::new(4);
        assert!(ring.peek().is_none());

        ring.push(42);
        assert_eq!(ring.peek(), Some(42));
        assert_eq!(ring.available(), 1); // Peek doesn't consume
    }

    #[test]
    fn frame_ring_depth_rounds_up() {
        let ring = FrameRing::new(3);
        assert_eq!(ring.depth(), 4); // Rounded up to power of 2

        let ring = FrameRing::new(1);
        assert_eq!(ring.depth(), 2); // Minimum depth 2
    }

    #[test]
    fn frame_ring_sequence_wraparound() {
        let mut ring = FrameRing::new(4);

        // Simulate near-u32::MAX sequences by manually setting state.
        ring.producer = u32::MAX - 1;
        ring.consumer = u32::MAX - 1;

        assert!(ring.push(100));
        assert!(ring.push(200));
        // producer is now u32::MAX + 1 = 0 (wrapped)
        assert_eq!(ring.available(), 2);

        assert_eq!(ring.pop(), Some(100));
        assert_eq!(ring.pop(), Some(200));
        assert!(ring.is_empty());
    }

    // --- DescriptorRing tests ---

    #[test]
    fn desc_ring_empty() {
        let ring = DescriptorRing::new(8);
        assert!(ring.is_empty());
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.depth(), 8);
    }

    #[test]
    fn desc_ring_push_pop() {
        let mut ring = DescriptorRing::new(4);
        let d1 = PacketDescriptor::new(0x1000, 64);
        let d2 = PacketDescriptor::new(0x2000, 128);

        assert!(ring.push(d1));
        assert!(ring.push(d2));

        let popped1 = ring.pop().unwrap();
        assert_eq!(popped1.addr, 0x1000);
        assert_eq!(popped1.len, 64);

        let popped2 = ring.pop().unwrap();
        assert_eq!(popped2.addr, 0x2000);
        assert_eq!(popped2.len, 128);

        assert!(ring.is_empty());
    }

    #[test]
    fn desc_ring_full() {
        let mut ring = DescriptorRing::new(2);
        assert!(ring.push(PacketDescriptor::new(1, 10)));
        assert!(ring.push(PacketDescriptor::new(2, 20)));
        assert!(ring.is_full());
        assert!(!ring.push(PacketDescriptor::new(3, 30)));
    }

    #[test]
    fn desc_ring_batch_pop() {
        let mut ring = DescriptorRing::new(8);
        for i in 0..5 {
            ring.push(PacketDescriptor::new(i * 0x1000, (i * 10) as u32));
        }

        let mut buf = [PacketDescriptor::new(0, 0); 3];
        assert_eq!(ring.pop_batch(&mut buf), 3);
        assert_eq!(buf[0].addr, 0);
        assert_eq!(buf[1].addr, 0x1000);
        assert_eq!(buf[2].addr, 0x2000);
    }

    #[test]
    fn desc_ring_peek() {
        let mut ring = DescriptorRing::new(4);
        assert!(ring.peek().is_none());

        ring.push(PacketDescriptor::new(0xABCD, 42));
        let peeked = ring.peek().unwrap();
        assert_eq!(peeked.addr, 0xABCD);
        assert_eq!(peeked.len, 42);
        assert_eq!(ring.available(), 1);
    }

    #[test]
    fn desc_ring_wraparound() {
        let mut ring = DescriptorRing::new(4);
        for round in 0..8u64 {
            for i in 0..4 {
                assert!(ring.push(PacketDescriptor::new(round * 4 + i, 64)));
            }
            for i in 0..4 {
                let d = ring.pop().unwrap();
                assert_eq!(d.addr, round * 4 + i);
            }
        }
    }

    // --- PacketDescriptor tests ---

    #[test]
    fn descriptor_fields() {
        let d = PacketDescriptor::new(0x1234_5678, 1500);
        assert_eq!(d.addr, 0x1234_5678);
        assert_eq!(d.len, 1500);
        assert_eq!(d.options, 0);
    }

    #[test]
    fn descriptor_size() {
        // Descriptor must be 16 bytes (matching kernel xdp_desc).
        assert_eq!(std::mem::size_of::<PacketDescriptor>(), 16);
    }
}
