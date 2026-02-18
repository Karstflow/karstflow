/// UMEM (User Memory) frame allocator for AF_XDP.
///
/// UMEM is a contiguous region of memory divided into fixed-size frames.
/// Frames are exchanged between userspace and the kernel via XDP rings:
///
/// - Userspace → FILL ring: free frames available for kernel to write RX data
/// - Kernel → RX ring: frames containing received packets
/// - Userspace → TX ring: frames containing packets to transmit
/// - Kernel → COMPLETION ring: TX frames returned after transmission
///
/// The allocator tracks frame ownership with a freelist. All memory is
/// pre-allocated; zero heap allocation during operation.
use paradencer_constants::network::{XDP_FRAME_SIZE, XDP_UMEM_ALIGN};

/// Configuration for UMEM allocation.
#[derive(Debug, Clone)]
pub struct UmemConfig {
    /// Number of frames to allocate.
    pub frame_count: u32,
    /// Size of each frame in bytes (must be power of 2).
    pub frame_size: usize,
    /// Headroom reserved before packet data in each frame.
    pub headroom: usize,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_count: paradencer_constants::network::XDP_DEFAULT_FRAME_COUNT,
            frame_size: XDP_FRAME_SIZE,
            headroom: paradencer_constants::network::XDP_HEADROOM,
        }
    }
}

impl UmemConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.frame_count == 0 {
            return Err("frame_count must be > 0");
        }
        if !self.frame_size.is_power_of_two() {
            return Err("frame_size must be a power of 2");
        }
        if self.frame_size < 2048 {
            return Err("frame_size must be >= 2048");
        }
        if self.headroom >= self.frame_size {
            return Err("headroom must be < frame_size");
        }
        Ok(())
    }

    /// Total UMEM size in bytes.
    pub fn total_size(&self) -> usize {
        self.frame_count as usize * self.frame_size
    }

    /// Required alignment for the UMEM region.
    pub fn alignment(&self) -> usize {
        XDP_UMEM_ALIGN
    }
}

/// Frame allocator backed by a UMEM region.
///
/// Manages frame ownership through a singly-linked freelist stored
/// inline in the frame offset array. All operations are O(1).
pub struct FrameAllocator {
    /// Frame size in bytes.
    frame_size: usize,
    /// Total number of frames.
    frame_count: u32,
    /// Headroom per frame.
    headroom: usize,
    /// Freelist: each entry is the offset of a free frame, linked via
    /// array indexing. `free_head` points to the first free frame index.
    free_offsets: Vec<u64>,
    /// Head of freelist (index into `free_offsets`, or `u32::MAX`).
    free_head: u32,
    /// Number of allocated (in-use) frames.
    allocated: u32,
}

impl FrameAllocator {
    /// Create a new frame allocator from configuration.
    ///
    /// Returns `None` if the configuration is invalid.
    pub fn new(config: &UmemConfig) -> Option<Self> {
        config.validate().ok()?;

        let frame_count = config.frame_count;
        let frame_size = config.frame_size;

        // Build freelist: each entry holds its frame offset and is
        // chained via implicit next = index + 1.
        let free_offsets: Vec<u64> = (0..frame_count)
            .map(|i| (i as usize * frame_size) as u64)
            .collect();

        Some(Self {
            frame_size,
            frame_count,
            headroom: config.headroom,
            free_offsets,
            free_head: 0,
            allocated: 0,
        })
    }

    /// Allocate a free frame. Returns the UMEM byte offset.
    ///
    /// Returns `None` if all frames are in use.
    pub fn allocate(&mut self) -> Option<u64> {
        if self.free_head >= self.frame_count {
            return None;
        }

        let idx = self.free_head as usize;
        let offset = self.free_offsets[idx];
        self.free_head += 1;
        self.allocated += 1;
        Some(offset)
    }

    /// Allocate up to `count` frames into the provided buffer.
    /// Returns the number of frames allocated.
    pub fn allocate_batch(&mut self, buf: &mut [u64]) -> usize {
        let available = self.available_count() as usize;
        let count = buf.len().min(available);
        for entry in buf.iter_mut().take(count) {
            let idx = self.free_head as usize;
            *entry = self.free_offsets[idx];
            self.free_head += 1;
            self.allocated += 1;
        }
        count
    }

    /// Return a frame to the free pool by its UMEM offset.
    ///
    /// The frame is placed at the end of the freelist for simple
    /// FIFO reuse. In the pre-allocated model, frames are always
    /// returned in bulk from COMPLETION ring processing.
    pub fn release(&mut self, frame_offset: u64) {
        if self.allocated == 0 {
            return;
        }
        // Validate that this is a valid frame offset.
        if !frame_offset.is_multiple_of(self.frame_size as u64) {
            return;
        }
        let frame_idx = (frame_offset / self.frame_size as u64) as u32;
        if frame_idx >= self.frame_count {
            return;
        }

        // Compact strategy: decrement free_head and place offset there.
        if self.free_head > 0 {
            self.free_head -= 1;
            self.free_offsets[self.free_head as usize] = frame_offset;
            self.allocated -= 1;
        }
    }

    /// Release multiple frames at once.
    pub fn release_batch(&mut self, offsets: &[u64]) {
        for &offset in offsets {
            self.release(offset);
        }
    }

    /// Number of allocated (in-use) frames.
    pub fn allocated_count(&self) -> u32 {
        self.allocated
    }

    /// Number of free frames available.
    pub fn available_count(&self) -> u32 {
        self.frame_count - self.allocated
    }

    /// Total frame count.
    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Frame size in bytes.
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Headroom per frame.
    pub fn headroom(&self) -> usize {
        self.headroom
    }

    /// Whether all frames are allocated.
    pub fn is_exhausted(&self) -> bool {
        self.free_head >= self.frame_count
    }

    /// Compute the packet data start offset within a frame.
    ///
    /// Returns the UMEM byte offset where packet data begins
    /// (frame offset + headroom).
    pub fn packet_data_offset(&self, frame_offset: u64) -> u64 {
        frame_offset + self.headroom as u64
    }

    /// Total UMEM size needed.
    pub fn total_size(&self) -> usize {
        self.frame_count as usize * self.frame_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> UmemConfig {
        UmemConfig {
            frame_count: 16,
            frame_size: 4096,
            headroom: 256,
        }
    }

    #[test]
    fn config_validation() {
        assert!(test_config().validate().is_ok());

        let bad = UmemConfig {
            frame_count: 0,
            ..test_config()
        };
        assert!(bad.validate().is_err());

        let bad = UmemConfig {
            frame_size: 3000, // not power of 2
            ..test_config()
        };
        assert!(bad.validate().is_err());

        let bad = UmemConfig {
            frame_size: 1024, // too small
            ..test_config()
        };
        assert!(bad.validate().is_err());

        let bad = UmemConfig {
            headroom: 4096, // >= frame_size
            ..test_config()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn config_total_size() {
        let cfg = test_config();
        assert_eq!(cfg.total_size(), 16 * 4096);
    }

    #[test]
    fn allocator_creation() {
        let alloc = FrameAllocator::new(&test_config()).unwrap();
        assert_eq!(alloc.frame_count(), 16);
        assert_eq!(alloc.available_count(), 16);
        assert_eq!(alloc.allocated_count(), 0);
        assert!(!alloc.is_exhausted());
    }

    #[test]
    fn allocate_single() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();
        let offset = alloc.allocate().unwrap();
        assert_eq!(offset, 0); // First frame at offset 0
        assert_eq!(alloc.allocated_count(), 1);
        assert_eq!(alloc.available_count(), 15);
    }

    #[test]
    fn allocate_sequential() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();
        for i in 0..16u64 {
            let offset = alloc.allocate().unwrap();
            assert_eq!(offset, i * 4096);
        }
        assert!(alloc.is_exhausted());
        assert!(alloc.allocate().is_none());
    }

    #[test]
    fn allocate_and_release() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();

        let o1 = alloc.allocate().unwrap();
        let _o2 = alloc.allocate().unwrap();
        assert_eq!(alloc.allocated_count(), 2);

        alloc.release(o1);
        assert_eq!(alloc.allocated_count(), 1);
        assert_eq!(alloc.available_count(), 15);

        // Reallocate should return the released frame.
        let o3 = alloc.allocate().unwrap();
        assert_eq!(o3, o1);
    }

    #[test]
    fn release_invalid_offset_ignored() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();
        alloc.allocate();

        // Invalid offset (not aligned to frame size).
        alloc.release(100);
        assert_eq!(alloc.allocated_count(), 1);

        // Out of range.
        alloc.release(16 * 4096);
        assert_eq!(alloc.allocated_count(), 1);
    }

    #[test]
    fn allocate_batch() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();
        let mut buf = [0u64; 5];
        assert_eq!(alloc.allocate_batch(&mut buf), 5);
        assert_eq!(alloc.allocated_count(), 5);

        for (i, &offset) in buf.iter().enumerate() {
            assert_eq!(offset, (i * 4096) as u64);
        }
    }

    #[test]
    fn allocate_batch_partial() {
        let cfg = UmemConfig {
            frame_count: 3,
            ..test_config()
        };
        let mut alloc = FrameAllocator::new(&cfg).unwrap();
        let mut buf = [0u64; 5];
        assert_eq!(alloc.allocate_batch(&mut buf), 3);
        assert!(alloc.is_exhausted());
    }

    #[test]
    fn release_batch() {
        let mut alloc = FrameAllocator::new(&test_config()).unwrap();
        let mut frames = [0u64; 4];
        alloc.allocate_batch(&mut frames);
        assert_eq!(alloc.allocated_count(), 4);

        alloc.release_batch(&frames);
        assert_eq!(alloc.allocated_count(), 0);
    }

    #[test]
    fn packet_data_offset() {
        let alloc = FrameAllocator::new(&test_config()).unwrap();
        assert_eq!(alloc.packet_data_offset(0), 256);
        assert_eq!(alloc.packet_data_offset(4096), 4096 + 256);
    }

    #[test]
    fn default_config() {
        let cfg = UmemConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.frame_size, 4096);
    }

    #[test]
    fn exhaustion_and_recovery() {
        let cfg = UmemConfig {
            frame_count: 4,
            ..test_config()
        };
        let mut alloc = FrameAllocator::new(&cfg).unwrap();

        // Exhaust all frames.
        let mut frames = [0u64; 4];
        alloc.allocate_batch(&mut frames);
        assert!(alloc.is_exhausted());

        // Release all.
        alloc.release_batch(&frames);
        assert_eq!(alloc.available_count(), 4);
        assert!(!alloc.is_exhausted());

        // Can allocate again.
        assert!(alloc.allocate().is_some());
    }
}
