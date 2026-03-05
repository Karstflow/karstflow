/// Core packet buffer and batch types for zero-allocation I/O.
///
/// `PacketBuffer` holds a single network packet with inline storage.
/// `PacketBatch` groups packets for batch send/receive operations.
use std::net::SocketAddrV4;

use karstflow_constants::network::{PACKET_BATCH_DEFAULT, PACKET_BUFFER_SIZE};

/// A single network packet with inline storage and metadata.
///
/// The buffer is cache-line aligned and large enough for any MTU-sized packet.
/// Metadata (address, length) is stored alongside the data for locality.
#[repr(C, align(64))]
pub struct PacketBuffer {
    data: [u8; PACKET_BUFFER_SIZE],
    len: u16,
    /// Source or destination address.
    addr: Option<SocketAddrV4>,
}

impl PacketBuffer {
    /// Create an empty packet buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; PACKET_BUFFER_SIZE],
            len: 0,
            addr: None,
        }
    }

    /// Create a packet buffer from a slice.
    ///
    /// Panics if `data.len() > PACKET_BUFFER_SIZE`.
    pub fn from_slice(data: &[u8], addr: Option<SocketAddrV4>) -> Self {
        assert!(data.len() <= PACKET_BUFFER_SIZE);
        let mut buf = Self::new();
        buf.data[..data.len()].copy_from_slice(data);
        buf.len = data.len() as u16;
        buf.addr = addr;
        buf
    }

    /// Returns the packet payload as a byte slice.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    /// Returns a mutable reference to the full data buffer.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8; PACKET_BUFFER_SIZE] {
        &mut self.data
    }

    /// Set the payload length after writing into `data_mut()`.
    #[inline]
    pub fn set_len(&mut self, len: u16) {
        debug_assert!((len as usize) <= PACKET_BUFFER_SIZE);
        self.len = len;
    }

    /// Returns the payload length in bytes.
    #[inline]
    pub fn len(&self) -> u16 {
        self.len
    }

    /// Returns true if the payload is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the associated address.
    #[inline]
    pub fn addr(&self) -> Option<SocketAddrV4> {
        self.addr
    }

    /// Set the associated address.
    #[inline]
    pub fn set_addr(&mut self, addr: SocketAddrV4) {
        self.addr = Some(addr);
    }

    /// Clear the buffer (reset length and address).
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
        self.addr = None;
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed-capacity batch of packets for batch I/O operations.
///
/// Avoids heap allocation — packets are stored inline in a fixed-size array.
/// The default capacity is `PACKET_BATCH_DEFAULT` (64).
pub struct PacketBatch<const N: usize = PACKET_BATCH_DEFAULT> {
    packets: [PacketBuffer; N],
    count: usize,
}

impl<const N: usize> PacketBatch<N> {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self {
            packets: std::array::from_fn(|_| PacketBuffer::new()),
            count: 0,
        }
    }

    /// Number of packets currently in the batch.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Maximum number of packets the batch can hold.
    #[inline]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Returns true if no packets are in the batch.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns true if the batch is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Get a reference to the packet at index `idx`.
    ///
    /// Panics if `idx >= count`.
    #[inline]
    pub fn get(&self, idx: usize) -> &PacketBuffer {
        assert!(idx < self.count);
        &self.packets[idx]
    }

    /// Get a mutable reference to the packet at index `idx`.
    ///
    /// Panics if `idx >= count`.
    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> &mut PacketBuffer {
        assert!(idx < self.count);
        &mut self.packets[idx]
    }

    /// Returns a slice of all active packets.
    #[inline]
    pub fn as_slice(&self) -> &[PacketBuffer] {
        &self.packets[..self.count]
    }

    /// Returns a mutable slice of all active packets.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [PacketBuffer] {
        &mut self.packets[..self.count]
    }

    /// Push a packet into the batch. Returns false if full.
    pub fn push(&mut self, pkt: PacketBuffer) -> bool {
        if self.count >= N {
            return false;
        }
        self.packets[self.count] = pkt;
        self.count += 1;
        true
    }

    /// Reserve a slot for writing. Returns `None` if full.
    ///
    /// The returned mutable reference can be filled in-place, avoiding a copy.
    pub fn reserve_slot(&mut self) -> Option<&mut PacketBuffer> {
        if self.count >= N {
            return None;
        }
        let idx = self.count;
        self.count += 1;
        self.packets[idx].clear();
        Some(&mut self.packets[idx])
    }

    /// Truncate the batch to `n` packets (discard the rest).
    #[inline]
    pub fn truncate(&mut self, n: usize) {
        self.count = n.min(self.count);
    }

    /// Reset the batch to empty (does not zero packet data).
    #[inline]
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Consume the first `n` packets by shifting the remaining left.
    ///
    /// This is used for partial-send semantics: if only some packets
    /// in the batch were sent, consume them and keep the rest.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.count);
        if n == 0 {
            return;
        }
        if n == self.count {
            self.count = 0;
            return;
        }
        // Shift remaining packets left
        let remaining = self.count - n;
        for i in 0..remaining {
            // Use raw pointer swap to avoid borrow checker issues with overlapping slices
            let src = n + i;
            let dst = i;
            self.packets.swap(dst, src);
        }
        self.count = remaining;
    }
}

impl<const N: usize> Default for PacketBatch<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn packet_buffer_new_is_empty() {
        let pkt = PacketBuffer::new();
        assert!(pkt.is_empty());
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.payload(), &[]);
        assert!(pkt.addr().is_none());
    }

    #[test]
    fn packet_buffer_from_slice() {
        let data = b"hello QUIC";
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8000);
        let pkt = PacketBuffer::from_slice(data, Some(addr));
        assert_eq!(pkt.len(), 10);
        assert_eq!(pkt.payload(), data);
        assert_eq!(pkt.addr(), Some(addr));
    }

    #[test]
    fn packet_buffer_write_in_place() {
        let mut pkt = PacketBuffer::new();
        let msg = b"test data";
        pkt.data_mut()[..msg.len()].copy_from_slice(msg);
        pkt.set_len(msg.len() as u16);
        assert_eq!(pkt.payload(), msg);
    }

    #[test]
    fn packet_buffer_clear() {
        let mut pkt = PacketBuffer::from_slice(b"data", None);
        assert!(!pkt.is_empty());
        pkt.clear();
        assert!(pkt.is_empty());
    }

    #[test]
    #[should_panic]
    fn packet_buffer_from_oversized_slice_panics() {
        let big = vec![0u8; PACKET_BUFFER_SIZE + 1];
        PacketBuffer::from_slice(&big, None);
    }

    #[test]
    fn packet_buffer_max_size() {
        let data = vec![0xAB; PACKET_BUFFER_SIZE];
        let pkt = PacketBuffer::from_slice(&data, None);
        assert_eq!(pkt.len() as usize, PACKET_BUFFER_SIZE);
        assert_eq!(pkt.payload().len(), PACKET_BUFFER_SIZE);
    }

    #[test]
    fn packet_batch_push_and_access() {
        let mut batch = PacketBatch::<4>::new();
        assert!(batch.is_empty());
        assert_eq!(batch.capacity(), 4);

        batch.push(PacketBuffer::from_slice(b"pkt0", None));
        batch.push(PacketBuffer::from_slice(b"pkt1", None));
        assert_eq!(batch.count(), 2);
        assert_eq!(batch.get(0).payload(), b"pkt0");
        assert_eq!(batch.get(1).payload(), b"pkt1");
    }

    #[test]
    fn packet_batch_full() {
        let mut batch = PacketBatch::<2>::new();
        assert!(batch.push(PacketBuffer::from_slice(b"a", None)));
        assert!(batch.push(PacketBuffer::from_slice(b"b", None)));
        assert!(batch.is_full());
        assert!(!batch.push(PacketBuffer::from_slice(b"c", None)));
    }

    #[test]
    fn packet_batch_reserve_slot() {
        let mut batch = PacketBatch::<4>::new();
        let slot = batch.reserve_slot().unwrap();
        slot.data_mut()[..3].copy_from_slice(b"abc");
        slot.set_len(3);
        assert_eq!(batch.count(), 1);
        assert_eq!(batch.get(0).payload(), b"abc");
    }

    #[test]
    fn packet_batch_clear() {
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"data", None));
        batch.push(PacketBuffer::from_slice(b"more", None));
        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.count(), 0);
    }

    #[test]
    fn packet_batch_consume_partial() {
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"a", None));
        batch.push(PacketBuffer::from_slice(b"b", None));
        batch.push(PacketBuffer::from_slice(b"c", None));

        batch.consume(1);
        assert_eq!(batch.count(), 2);
        assert_eq!(batch.get(0).payload(), b"b");
        assert_eq!(batch.get(1).payload(), b"c");
    }

    #[test]
    fn packet_batch_consume_all() {
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"a", None));
        batch.push(PacketBuffer::from_slice(b"b", None));
        batch.consume(2);
        assert!(batch.is_empty());
    }

    #[test]
    fn packet_batch_consume_more_than_count() {
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"a", None));
        batch.consume(10);
        assert!(batch.is_empty());
    }

    #[test]
    fn packet_batch_as_slice() {
        let mut batch = PacketBatch::<4>::new();
        batch.push(PacketBuffer::from_slice(b"x", None));
        batch.push(PacketBuffer::from_slice(b"y", None));
        let slc = batch.as_slice();
        assert_eq!(slc.len(), 2);
        assert_eq!(slc[0].payload(), b"x");
        assert_eq!(slc[1].payload(), b"y");
    }

    #[test]
    fn packet_buffer_alignment() {
        assert_eq!(std::mem::align_of::<PacketBuffer>(), 64);
    }

    #[test]
    fn packet_batch_default_capacity() {
        let batch = PacketBatch::<PACKET_BATCH_DEFAULT>::new();
        assert_eq!(batch.capacity(), 64);
    }
}
