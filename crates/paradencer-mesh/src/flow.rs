/// Flow control sequence for inter-tile backpressure.
///
/// A single atomic sequence number shared between producer and consumer.
/// The consumer updates the flow sequence to indicate how far it has
/// processed, allowing the producer to throttle when the consumer falls
/// behind. Aligned to double cache line (128 bytes) to avoid false sharing.
use std::alloc::{self, Layout};
use std::ptr;

use paradencer_constants::ipc::FLOW_SEQ_ALIGN;

/// Flow control sequence number.
///
/// Wraps a cache-line-aligned atomic u64 for cross-thread communication.
/// The consumer periodically writes its progress here; the producer reads
/// it to determine available credits (how many more fragments it can send).
pub struct FlowSequence {
    /// Pointer to the sequence value (u64, cache-line aligned).
    seq_ptr: *mut u64,
    /// Backing allocation.
    alloc_ptr: *mut u8,
    alloc_layout: Layout,
}

// SAFETY: FlowSequence is designed for shared access between exactly
// one producer thread (reads) and one consumer thread (writes).
// All access uses volatile operations with compiler fences.
unsafe impl Send for FlowSequence {}
unsafe impl Sync for FlowSequence {}

impl FlowSequence {
    /// Create a new FlowSequence initialized to `initial_seq`.
    pub fn new(initial_seq: u64) -> Self {
        let layout = Layout::from_size_align(FLOW_SEQ_ALIGN, FLOW_SEQ_ALIGN)
            .expect("invalid FlowSequence layout");

        // SAFETY: Layout is valid.
        let alloc_ptr = unsafe { alloc::alloc_zeroed(layout) };
        if alloc_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }

        // The first 8 bytes after an 8-byte reserved header store the seq.
        // Layout: [8-byte reserved (seq0 backup)] [8-byte seq value] [app region...]
        // We put seq at offset 0 for simplicity (matching the reference where
        // fseq[0] is the active value, fseq[-1] is seq0).
        let seq_ptr = alloc_ptr as *mut u64;

        // SAFETY: seq_ptr is within our allocation, properly aligned.
        unsafe {
            ptr::write_volatile(seq_ptr, initial_seq);
        }

        Self {
            seq_ptr,
            alloc_ptr,
            alloc_layout: layout,
        }
    }

    /// Read the current sequence number.
    ///
    /// The value was observed at some point between call start and return.
    /// Acts as a compiler memory fence.
    #[inline]
    pub fn query(&self) -> u64 {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: seq_ptr is properly aligned and within our allocation.
        let seq = unsafe { ptr::read_volatile(self.seq_ptr) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        seq
    }

    /// Update the sequence number.
    ///
    /// The value is written at some point between call start and return.
    /// Acts as a compiler memory fence.
    #[inline]
    pub fn update(&self, seq: u64) {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        // SAFETY: seq_ptr is properly aligned and within our allocation.
        unsafe { ptr::write_volatile(self.seq_ptr, seq) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for FlowSequence {
    fn drop(&mut self) {
        // SAFETY: alloc_ptr was allocated with alloc_layout.
        unsafe {
            alloc::dealloc(self.alloc_ptr, self.alloc_layout);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_query() {
        let fseq = FlowSequence::new(42);
        assert_eq!(fseq.query(), 42);
    }

    #[test]
    fn update_and_query() {
        let fseq = FlowSequence::new(0);
        fseq.update(100);
        assert_eq!(fseq.query(), 100);
        fseq.update(200);
        assert_eq!(fseq.query(), 200);
    }

    #[test]
    fn alignment() {
        let fseq = FlowSequence::new(0);
        let ptr = fseq.seq_ptr as usize;
        assert_eq!(
            ptr % FLOW_SEQ_ALIGN,
            0,
            "FlowSequence must be 128-byte aligned"
        );
    }

    #[test]
    fn wrapping_values() {
        let fseq = FlowSequence::new(u64::MAX);
        assert_eq!(fseq.query(), u64::MAX);
        fseq.update(0);
        assert_eq!(fseq.query(), 0);
    }
}
