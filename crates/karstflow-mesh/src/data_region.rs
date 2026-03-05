/// Pre-allocated data region for zero-copy fragment payloads.
///
/// Provides chunk-indexed storage where producers write payload data
/// and consumers read it via chunk offsets stored in fragment metadata.
/// The region supports a compact ring mode where the producer writes
/// contiguously and wraps around, ensuring consumers never see partial
/// data across region boundaries.
use std::alloc::{self, Layout};

use karstflow_constants::ipc::{
    CHUNK_LG_SIZE, CHUNK_SIZE, DATA_REGION_ALIGN, DATA_REGION_GUARD_SIZE, DATA_REGION_SLOT_ALIGN,
};

// ---------------------------------------------------------------------------
// DataRegion
// ---------------------------------------------------------------------------

/// Pre-allocated region for fragment payload storage.
///
/// Memory layout (all regions properly aligned):
/// - Header (128 bytes): data_sz, app_sz
/// - Guard region (3968 bytes): alignment flexibility for producers
/// - Data region (data_sz bytes): payload storage
/// - App region (app_sz bytes): application-specific metadata
///
/// Producers write payload data at chunk-aligned positions within the
/// data region. The chunk index stored in FragmentMeta points into this
/// region, enabling zero-copy reads by consumers.
pub struct DataRegion {
    /// Pointer to the start of the data region (after guard).
    data_ptr: *mut u8,
    /// Size of the data region in bytes.
    data_sz: usize,
    /// Pointer to the start of the app region (after data).
    _app_ptr: *mut u8,
    /// Size of the app region in bytes.
    _app_sz: usize,
    /// Backing allocation pointer and layout.
    alloc_ptr: *mut u8,
    alloc_layout: Layout,
}

// SAFETY: DataRegion is designed for SPSC use where the producer writes
// and consumers read from different positions. Payloads are only read
// after the corresponding fragment metadata is published.
unsafe impl Send for DataRegion {}
unsafe impl Sync for DataRegion {}

impl DataRegion {
    /// Create a new DataRegion with the given data and app sizes.
    ///
    /// # Panics
    ///
    /// Panics if the sizes would produce an invalid layout.
    pub fn new(data_sz: usize, app_sz: usize) -> Self {
        let header_size = DATA_REGION_SLOT_ALIGN; // 128 bytes
        let guard_size = DATA_REGION_GUARD_SIZE;
        let data_aligned = align_up(data_sz, DATA_REGION_ALIGN);
        let app_aligned = align_up(app_sz, DATA_REGION_ALIGN);

        let total_size = header_size + guard_size + data_aligned + app_aligned;
        let layout = Layout::from_size_align(total_size, DATA_REGION_ALIGN)
            .expect("invalid layout for DataRegion");

        // SAFETY: Layout is valid.
        let alloc_ptr = unsafe { alloc::alloc_zeroed(layout) };
        if alloc_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }

        let data_ptr = unsafe { alloc_ptr.add(header_size + guard_size) };
        let app_ptr = unsafe { data_ptr.add(data_aligned) };

        Self {
            data_ptr,
            data_sz: data_aligned,
            _app_ptr: app_ptr,
            _app_sz: app_aligned,
            alloc_ptr,
            alloc_layout: layout,
        }
    }

    /// Create a DataRegion sized for the given parameters.
    ///
    /// Computes the required data size based on MTU, depth (number of
    /// in-flight fragments), burst (number of fragments being prepared),
    /// and whether compact ring mode is used.
    pub fn for_link(mtu: usize, depth: usize, burst: usize, compact: bool) -> Self {
        let data_sz = required_data_size(mtu, depth, burst, compact);
        Self::new(data_sz, 0)
    }

    /// Size of the data region in bytes.
    #[inline]
    pub fn data_size(&self) -> usize {
        self.data_sz
    }

    /// Base pointer for chunk index arithmetic.
    ///
    /// Chunk index 0 corresponds to `base()`. The byte offset for a given
    /// chunk is `chunk * CHUNK_SIZE` from this base.
    #[inline]
    pub fn base(&self) -> *const u8 {
        self.data_ptr as *const u8
    }

    /// Mutable base pointer.
    #[inline]
    pub fn base_mut(&mut self) -> *mut u8 {
        self.data_ptr
    }

    /// Convert a chunk index to a pointer within the data region.
    ///
    /// # Safety
    ///
    /// Caller must ensure the resulting pointer is within the data region.
    #[inline]
    pub unsafe fn chunk_to_ptr(&self, chunk: u32) -> *const u8 {
        self.data_ptr.add((chunk as usize) << CHUNK_LG_SIZE) as *const u8
    }

    /// Convert a chunk index to a mutable pointer within the data region.
    ///
    /// # Safety
    ///
    /// Caller must ensure the resulting pointer is within the data region.
    #[inline]
    pub unsafe fn chunk_to_ptr_mut(&mut self, chunk: u32) -> *mut u8 {
        self.data_ptr.add((chunk as usize) << CHUNK_LG_SIZE)
    }

    /// Convert a pointer within the data region to a chunk index.
    ///
    /// # Safety
    ///
    /// Caller must ensure `ptr` is chunk-aligned and within the data region.
    #[inline]
    pub unsafe fn ptr_to_chunk(&self, ptr: *const u8) -> u32 {
        let offset = ptr as usize - self.data_ptr as usize;
        (offset >> CHUNK_LG_SIZE) as u32
    }

    /// First valid chunk index in the data region.
    #[inline]
    pub fn chunk0(&self) -> u32 {
        0
    }

    /// One-past-the-last valid chunk index.
    #[inline]
    pub fn chunk1(&self) -> u32 {
        (self.data_sz >> CHUNK_LG_SIZE) as u32
    }

    /// High water mark for compact ring mode.
    ///
    /// The first chunk of any fragment must be at or before this index
    /// to guarantee the full payload fits without wrapping.
    #[inline]
    pub fn watermark(&self, mtu: usize) -> u32 {
        let chunk_mtu = slot_chunks(mtu);
        self.chunk1() - chunk_mtu
    }

    /// Read a fragment payload as a byte slice.
    ///
    /// # Safety
    ///
    /// Caller must ensure the chunk+sz range is within the data region
    /// and the producer is not concurrently writing to this range.
    #[inline]
    pub unsafe fn read_payload(&self, chunk: u32, sz: u16) -> &[u8] {
        let ptr = self.chunk_to_ptr(chunk);
        std::slice::from_raw_parts(ptr, sz as usize)
    }

    /// Get a mutable slice for writing a payload.
    ///
    /// # Safety
    ///
    /// Caller must ensure the chunk+mtu range is within the data region.
    #[inline]
    pub unsafe fn write_slice(&mut self, chunk: u32, len: usize) -> &mut [u8] {
        let ptr = self.chunk_to_ptr_mut(chunk);
        std::slice::from_raw_parts_mut(ptr, len)
    }
}

impl Drop for DataRegion {
    fn drop(&mut self) {
        // SAFETY: alloc_ptr was allocated with alloc_layout.
        unsafe {
            alloc::dealloc(self.alloc_ptr, self.alloc_layout);
        }
    }
}

// ---------------------------------------------------------------------------
// Compact ring advancement
// ---------------------------------------------------------------------------

/// Advance to the next chunk position in compact ring mode.
///
/// After writing a fragment of `frag_sz` bytes starting at `chunk`,
/// this returns the next chunk position. If the next position would
/// exceed the watermark, it wraps back to `chunk0`.
///
/// The advancement rounds up to `DATA_REGION_SLOT_ALIGN` boundaries
/// (128 bytes = 2 chunks) to maintain alignment.
#[inline]
pub fn compact_next(chunk: u32, frag_sz: usize, chunk0: u32, wmark: u32) -> u32 {
    let advance = slot_chunks(frag_sz);
    let next = chunk + advance;
    if next > wmark {
        chunk0
    } else {
        next
    }
}

/// Number of chunks needed for a slot of the given MTU.
/// Rounds up to `DATA_REGION_SLOT_ALIGN / CHUNK_SIZE` chunks (= 2).
#[inline]
pub fn slot_chunks(mtu: usize) -> u32 {
    let slot_align_chunks = DATA_REGION_SLOT_ALIGN / CHUNK_SIZE; // 2
    let raw_chunks = mtu.div_ceil(CHUNK_SIZE);
    let aligned = raw_chunks.div_ceil(slot_align_chunks) * slot_align_chunks;
    aligned as u32
}

/// Compute the footprint of a slot large enough for the given MTU.
#[inline]
pub fn slot_footprint(mtu: usize) -> usize {
    align_up(mtu, DATA_REGION_SLOT_ALIGN)
}

/// Compute the required data region size for the given parameters.
///
/// - `mtu`: maximum fragment payload size in bytes
/// - `depth`: number of in-flight fragments visible to consumers
/// - `burst`: number of fragments the producer may be preparing concurrently
/// - `compact`: whether compact ring mode is used (adds one extra slot)
pub fn required_data_size(mtu: usize, depth: usize, burst: usize, compact: bool) -> usize {
    let slot_size = slot_footprint(mtu);
    slot_size * (depth + burst + usize::from(compact))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_data_region() {
        let region = DataRegion::new(4096, 0);
        assert!(region.data_size() >= 4096);
        assert_eq!(region.chunk0(), 0);
        assert!(region.chunk1() > 0);
    }

    #[test]
    fn create_for_link() {
        let region = DataRegion::for_link(1280, 64, 1, true);
        assert!(region.data_size() > 0);
        // Should have room for at least (64 + 1 + 1) slots of 1280 bytes.
        let expected_min = slot_footprint(1280) * (64 + 1 + 1);
        assert!(region.data_size() >= expected_min);
    }

    #[test]
    fn chunk_indexing() {
        let region = DataRegion::new(8192, 0);
        let chunk0 = region.chunk0();

        // chunk 0 should point to the data region base.
        // SAFETY: chunk0 is within the data region.
        let ptr = unsafe { region.chunk_to_ptr(chunk0) };
        assert_eq!(ptr, region.base());
    }

    #[test]
    fn chunk_roundtrip() {
        let region = DataRegion::new(8192, 0);

        for chunk in [0u32, 1, 5, 10, 50] {
            if chunk < region.chunk1() {
                // SAFETY: chunk is within data region.
                unsafe {
                    let ptr = region.chunk_to_ptr(chunk);
                    let back = region.ptr_to_chunk(ptr);
                    assert_eq!(back, chunk, "chunk roundtrip failed for {}", chunk);
                }
            }
        }
    }

    #[test]
    fn watermark_calculation() {
        let region = DataRegion::new(8192, 0);
        let wmark = region.watermark(1280);
        // Watermark should be less than chunk1.
        assert!(wmark < region.chunk1());
        // Watermark + slot_chunks(mtu) should not exceed chunk1.
        assert!(wmark + slot_chunks(1280) <= region.chunk1());
    }

    #[test]
    fn compact_next_advance() {
        let chunk0 = 0u32;
        let wmark = 100u32;

        // Advance from 0 with a small payload.
        let next = compact_next(0, 64, chunk0, wmark);
        assert!(next > 0);
        assert!(next <= wmark);

        // Advance past watermark should wrap to chunk0.
        let next = compact_next(wmark, 64, chunk0, wmark);
        assert_eq!(next, chunk0);
    }

    #[test]
    fn compact_next_wrapping() {
        let chunk0 = 0u32;
        let region = DataRegion::for_link(1280, 8, 1, true);
        let wmark = region.watermark(1280);
        let _slot = slot_chunks(1280);

        // Walk through the ring and verify wrapping.
        let mut chunk = chunk0;
        let mut wrapped = false;
        for _ in 0..20 {
            let next = compact_next(chunk, 1280, chunk0, wmark);
            if next == chunk0 && chunk != chunk0 {
                wrapped = true;
            }
            chunk = next;
        }
        assert!(wrapped, "compact_next should wrap around");
    }

    #[test]
    fn slot_footprint_alignment() {
        // slot_footprint should always be a multiple of DATA_REGION_SLOT_ALIGN.
        for mtu in [64, 128, 500, 1280, 2048] {
            let fp = slot_footprint(mtu);
            assert_eq!(fp % DATA_REGION_SLOT_ALIGN, 0, "mtu={}", mtu);
            assert!(fp >= mtu, "mtu={}", mtu);
        }
    }

    #[test]
    fn slot_chunks_values() {
        // 64 bytes = 1 chunk, but rounds up to 2 (slot_align_chunks).
        assert_eq!(slot_chunks(64), 2);
        // 128 bytes = 2 chunks = 2 (already aligned).
        assert_eq!(slot_chunks(128), 2);
        // 129 bytes = 3 chunks, rounds up to 4.
        assert_eq!(slot_chunks(129), 4);
        // 1280 bytes = 20 chunks, already aligned to 2.
        assert_eq!(slot_chunks(1280), 20);
    }

    #[test]
    fn required_data_size_calculation() {
        let sz = required_data_size(1280, 64, 1, true);
        // Should be slot_footprint(1280) * (64 + 1 + 1) = 1280 * 66 = 84480
        // But slot_footprint rounds up: 1280 is already 128-aligned.
        assert_eq!(sz, slot_footprint(1280) * 66);
    }

    #[test]
    fn write_and_read_payload() {
        let mut region = DataRegion::new(8192, 0);
        let payload = b"hello zero-copy IPC";

        // Write at chunk 0.
        // SAFETY: chunk 0 is within the data region, len fits in one chunk.
        unsafe {
            let slice = region.write_slice(0, payload.len());
            slice.copy_from_slice(payload);
        }

        // Read back.
        // SAFETY: same region, same range.
        let read = unsafe { region.read_payload(0, payload.len() as u16) };
        assert_eq!(read, payload);
    }
}
