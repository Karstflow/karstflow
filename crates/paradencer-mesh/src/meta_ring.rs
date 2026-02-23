/// Lock-free SPSC ring buffer for fragment metadata.
///
/// Stores recently published fragment descriptors in a fixed-depth ring.
/// The producer writes metadata entries sequentially; consumers poll for
/// specific sequence numbers. The ring depth determines how many fragments
/// can be "in flight" before the oldest is overwritten.
///
/// All operations use compiler memory fences (not hardware fences) since
/// x86-64 Total Store Order guarantees sufficient ordering. Non-x86
/// targets may require stronger fencing.
use std::alloc::{self, Layout};
use std::ptr;

use paradencer_constants::ipc::{META_RING_ALIGN, META_RING_SEQ_COUNT};

use crate::fragment::{seq_dec, seq_diff, FragmentMeta};

// ---------------------------------------------------------------------------
// Poll result
// ---------------------------------------------------------------------------

/// Result of polling the MetaRing for a fragment.
#[derive(Debug)]
pub enum PollResult {
    /// Successfully read the requested fragment metadata.
    Ready(FragmentMeta),
    /// Consumer has been overrun: the requested sequence was evicted.
    /// Contains the sequence number currently at the expected slot,
    /// which is a lower bound of where the producer currently is.
    Overrun { found_seq: u64 },
    /// Timed out: the producer hasn't published the requested sequence yet.
    Timeout,
}

// ---------------------------------------------------------------------------
// MetaRing
// ---------------------------------------------------------------------------

/// A ring buffer of `FragmentMeta` entries for zero-copy message passing.
///
/// Memory layout (all regions `META_RING_ALIGN` aligned):
/// - Header (128 bytes): depth, initial seq, app_sz
/// - Seq region (128 bytes): `META_RING_SEQ_COUNT` u64 values.
///   `seq[0]` is the producer watermark (non-strictly updated).
/// - Meta entries: `depth * size_of::<FragmentMeta>()` bytes
pub struct MetaRing {
    /// Pointer to the seq region (META_RING_SEQ_COUNT u64 values).
    seq_region: *mut u64,
    /// Pointer to the metadata entries array.
    entries: *mut FragmentMeta,
    /// Ring depth (number of entries, must be power of 2).
    depth: usize,
    /// Mask for index calculation: `depth - 1`.
    mask: usize,
    /// Backing allocation pointer and layout.
    alloc_ptr: *mut u8,
    alloc_layout: Layout,
}

// SAFETY: MetaRing is designed for SPSC use where the producer and consumer
// may be on different threads. All shared access uses volatile operations
// with compiler fences. The backing memory is owned by this struct.
unsafe impl Send for MetaRing {}
unsafe impl Sync for MetaRing {}

impl MetaRing {
    /// Create a new MetaRing with the given depth and initial sequence number.
    ///
    /// # Panics
    ///
    /// Panics if `depth` is zero or not a power of 2.
    pub fn new(depth: usize, initial_seq: u64) -> Self {
        assert!(
            depth > 0 && depth.is_power_of_two(),
            "depth must be a power of 2"
        );

        let header_size = META_RING_ALIGN; // 128 bytes
        let seq_size = META_RING_SEQ_COUNT * std::mem::size_of::<u64>();
        let seq_padded = align_up(seq_size, META_RING_ALIGN);
        let entries_size = depth * std::mem::size_of::<FragmentMeta>();

        let total_size = header_size + seq_padded + entries_size;
        let layout = Layout::from_size_align(total_size, META_RING_ALIGN)
            .expect("invalid layout for MetaRing");

        // SAFETY: We just computed a valid layout.
        let alloc_ptr = unsafe { alloc::alloc_zeroed(layout) };
        if alloc_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }

        let seq_region = unsafe { alloc_ptr.add(header_size) } as *mut u64;
        let entries = unsafe { alloc_ptr.add(header_size + seq_padded) } as *mut FragmentMeta;

        // Initialize seq[0] to the initial sequence.
        // SAFETY: seq_region points to zeroed, properly aligned memory.
        unsafe {
            ptr::write_volatile(seq_region, initial_seq);
        }

        // Initialize all meta entries as invalid with sequence numbers
        // that will make any consumer think it's ahead of the producer.
        // Each entry gets seq = initial_seq - depth + i (with SOM+EOM+ERR set).
        for i in 0..depth {
            let entry_seq = seq_dec(initial_seq, (depth - i) as u64);
            // SAFETY: entries[i] is within our allocation.
            unsafe {
                ptr::write(entries.add(i), FragmentMeta::invalid(entry_seq));
            }
        }

        Self {
            seq_region,
            entries,
            depth,
            mask: depth - 1,
            alloc_ptr,
            alloc_layout: layout,
        }
    }

    /// Ring depth (number of entries).
    #[inline]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Map a sequence number to a ring index.
    #[inline]
    fn line_idx(&self, seq: u64) -> usize {
        (seq as usize) & self.mask
    }

    // -----------------------------------------------------------------------
    // Producer operations
    // -----------------------------------------------------------------------

    /// Publish a fragment's metadata to the ring.
    ///
    /// This atomically makes the fragment available to consumers.
    /// The publish protocol ensures consumers see consistent data:
    /// 1. Write `seq-1` to the entry's seq field (mark as being written)
    /// 2. Write all other fields
    /// 3. Write the real `seq` (mark as published)
    ///
    /// Compiler fences between steps prevent reordering.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        seq: u64,
        sig: u64,
        chunk: u32,
        sz: u16,
        ctl: u16,
        tsorig: u32,
        tspub: u32,
    ) {
        let idx = self.line_idx(seq);
        // SAFETY: idx is within [0, depth) since mask = depth - 1.
        let meta = unsafe { &mut *self.entries.add(idx) };

        // Step 1: Mark entry as being written (seq - 1).
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: meta.seq is naturally aligned u64, atomic on x86-64.
        unsafe { ptr::write_volatile(&mut meta.seq, seq_dec(seq, 1)) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        // Step 2: Write body fields.
        meta.sig = sig;
        meta.chunk = chunk;
        meta.sz = sz;
        meta.ctl = ctl;
        meta.tsorig = tsorig;
        meta.tspub = tspub;
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        // Step 3: Mark as published (real seq).
        // SAFETY: same as step 1.
        unsafe { ptr::write_volatile(&mut meta.seq, seq) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// Update the producer watermark (seq[0]).
    ///
    /// This is a lower bound of the most recently published sequence number.
    /// Should be called periodically by the producer during housekeeping.
    pub fn update_watermark(&self, seq: u64) {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: seq_region[0] is within our allocation, naturally aligned.
        unsafe { ptr::write_volatile(self.seq_region, seq) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    // -----------------------------------------------------------------------
    // Consumer operations
    // -----------------------------------------------------------------------

    /// Read the producer watermark (seq[0]).
    ///
    /// Returns a lower bound of the most recently published sequence number.
    /// Use sparingly to avoid cache-line ping-ponging with the producer.
    pub fn query_watermark(&self) -> u64 {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: seq_region[0] is within our allocation, naturally aligned.
        let seq = unsafe { ptr::read_volatile(self.seq_region) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        seq
    }

    /// Poll for a specific sequence number with bounded waiting.
    ///
    /// Polls up to `max_polls` times for the fragment with `expected_seq`.
    /// Returns `PollResult::Ready` with the metadata on success,
    /// `PollResult::Overrun` if the consumer has fallen behind, or
    /// `PollResult::Timeout` if the producer hasn't published yet.
    pub fn poll(&self, expected_seq: u64, max_polls: usize) -> PollResult {
        let idx = self.line_idx(expected_seq);
        // SAFETY: idx is within [0, depth).
        let mline = unsafe { &*self.entries.add(idx) };

        for _ in 0..max_polls {
            // Read seq (first read).
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            let seq_found = unsafe { ptr::read_volatile(&mline.seq) };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

            // Read the full metadata (may be non-atomic as a whole).
            let meta_copy = FragmentMeta {
                seq: seq_found,
                sig: mline.sig,
                chunk: mline.chunk,
                sz: mline.sz,
                ctl: mline.ctl,
                tsorig: mline.tsorig,
                tspub: mline.tspub,
            };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

            // Read seq again (verify no torn read).
            let seq_test = unsafe { ptr::read_volatile(&mline.seq) };
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

            let diff = seq_diff(seq_found, expected_seq);

            // Check: seq stable AND at-or-past expected
            if seq_found == seq_test && diff >= 0 {
                if diff == 0 {
                    return PollResult::Ready(meta_copy);
                } else {
                    // Consumer has been overrun.
                    return PollResult::Overrun {
                        found_seq: seq_found,
                    };
                }
            }

            // Spin pause hint for the CPU.
            std::hint::spin_loop();
        }

        PollResult::Timeout
    }

    /// Point query: check if a sequence number is currently in the ring.
    ///
    /// Returns the sequence number found at the expected slot.
    /// If it matches `seq_query`, the fragment is still available.
    pub fn query(&self, seq_query: u64) -> u64 {
        let idx = self.line_idx(seq_query);
        // SAFETY: idx is within [0, depth).
        let mline = unsafe { &*self.entries.add(idx) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let seq = unsafe { ptr::read_volatile(&mline.seq) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        seq
    }

    /// Read the fragment metadata at a specific index (no validation).
    ///
    /// # Safety
    ///
    /// Caller must ensure `idx < depth`. The returned metadata may be
    /// inconsistent if the producer is concurrently writing to this slot.
    pub unsafe fn read_entry_unchecked(&self, idx: usize) -> FragmentMeta {
        debug_assert!(idx < self.depth);
        ptr::read(self.entries.add(idx))
    }
}

impl Drop for MetaRing {
    fn drop(&mut self) {
        // SAFETY: alloc_ptr was allocated with alloc_layout via alloc::alloc_zeroed.
        unsafe {
            alloc::dealloc(self.alloc_ptr, self.alloc_layout);
        }
    }
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
    use crate::fragment::{ctl_eom, ctl_err, ctl_pack, ctl_som, seq_eq};

    #[test]
    fn create_ring() {
        let ring = MetaRing::new(64, 0);
        assert_eq!(ring.depth(), 64);
    }

    #[test]
    #[should_panic(expected = "depth must be a power of 2")]
    fn create_ring_non_power_of_two() {
        let _ring = MetaRing::new(63, 0);
    }

    #[test]
    fn initial_watermark() {
        let ring = MetaRing::new(16, 42);
        assert_eq!(ring.query_watermark(), 42);
    }

    #[test]
    fn publish_and_poll() {
        let ring = MetaRing::new(16, 0);
        let ctl = ctl_pack(0, true, true, false);

        ring.publish(0, 0xDEAD, 10, 100, ctl, 1000, 2000);

        match ring.poll(0, 1) {
            PollResult::Ready(meta) => {
                assert_eq!(meta.seq, 0);
                assert_eq!(meta.sig, 0xDEAD);
                assert_eq!(meta.chunk, 10);
                assert_eq!(meta.sz, 100);
                assert!(ctl_som(meta.ctl));
                assert!(ctl_eom(meta.ctl));
                assert!(!ctl_err(meta.ctl));
                assert_eq!(meta.tsorig, 1000);
                assert_eq!(meta.tspub, 2000);
            }
            other => panic!("expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn poll_timeout() {
        let ring = MetaRing::new(16, 0);
        // Nothing published yet, so polling for seq 0 should timeout
        // (the initial entries have seq values before 0).
        match ring.poll(0, 10) {
            PollResult::Timeout => {} // expected
            other => panic!("expected Timeout, got {:?}", other),
        }
    }

    #[test]
    fn sequential_publish_and_poll() {
        let ring = MetaRing::new(8, 0);

        for i in 0..8u64 {
            ring.publish(i, i * 100, i as u32, i as u16, 0, 0, 0);
        }

        for i in 0..8u64 {
            match ring.poll(i, 1) {
                PollResult::Ready(meta) => {
                    assert_eq!(meta.seq, i);
                    assert_eq!(meta.sig, i * 100);
                    assert_eq!(meta.chunk, i as u32);
                    assert_eq!(meta.sz, i as u16);
                }
                other => panic!("seq {} expected Ready, got {:?}", i, other),
            }
        }
    }

    #[test]
    fn overrun_detection() {
        let ring = MetaRing::new(4, 0);

        // Publish 8 entries (depth is 4, so first 4 are overwritten).
        for i in 0..8u64 {
            ring.publish(i, 0, 0, 0, 0, 0, 0);
        }

        // Trying to read seq 0 should detect overrun (seq 4 is at that slot).
        match ring.poll(0, 1) {
            PollResult::Overrun { found_seq } => {
                assert_eq!(found_seq, 4);
            }
            other => panic!("expected Overrun, got {:?}", other),
        }

        // seq 4-7 should still be readable.
        for i in 4..8u64 {
            match ring.poll(i, 1) {
                PollResult::Ready(meta) => assert_eq!(meta.seq, i),
                other => panic!("seq {} expected Ready, got {:?}", i, other),
            }
        }
    }

    #[test]
    fn watermark_update() {
        let ring = MetaRing::new(16, 0);
        assert_eq!(ring.query_watermark(), 0);

        ring.update_watermark(42);
        assert_eq!(ring.query_watermark(), 42);

        ring.update_watermark(100);
        assert_eq!(ring.query_watermark(), 100);
    }

    #[test]
    fn point_query() {
        let ring = MetaRing::new(8, 0);
        ring.publish(5, 0, 0, 0, 0, 0, 0);

        assert!(seq_eq(ring.query(5), 5));
    }

    #[test]
    fn wrapping_sequence_numbers() {
        let start = u64::MAX - 3;
        let ring = MetaRing::new(8, start);

        // Publish across the u64 boundary.
        for i in 0..8u64 {
            let seq = start.wrapping_add(i);
            ring.publish(seq, i, 0, 0, 0, 0, 0);
        }

        // Read back.
        for i in 0..8u64 {
            let seq = start.wrapping_add(i);
            match ring.poll(seq, 1) {
                PollResult::Ready(meta) => {
                    assert_eq!(meta.seq, seq);
                    assert_eq!(meta.sig, i);
                }
                other => panic!("seq {} expected Ready, got {:?}", seq, other),
            }
        }
    }
}
