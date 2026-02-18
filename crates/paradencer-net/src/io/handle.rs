/// Type-erased I/O handle using raw function pointers.
///
/// Context pointer + send function pointer, stored inline. No Box/dyn,
/// suitable for embedding in pre-allocated structs.
use crate::io::SendResult;
use crate::packet::PacketBuffer;

/// Raw function pointer type for sending packet slices.
///
/// # Safety
///
/// Must only be called with the corresponding `ctx` pointer.
pub type SendFn = unsafe fn(ctx: *mut (), packets: &[PacketBuffer], flush: bool) -> SendResult;

/// Type-erased packet I/O handle.
///
/// Designed for single-threaded tile use.
pub struct IoHandle {
    ctx: *mut (),
    send_fn: SendFn,
}

impl IoHandle {
    /// Create a new IoHandle.
    ///
    /// # Safety
    ///
    /// `ctx` must remain valid for the lifetime of this handle.
    pub unsafe fn new(ctx: *mut (), send_fn: SendFn) -> Self {
        Self { ctx, send_fn }
    }

    /// Create a no-op handle that drops all packets.
    pub fn noop() -> Self {
        unsafe fn noop_send(_ctx: *mut (), _packets: &[PacketBuffer], _flush: bool) -> SendResult {
            SendResult::Success
        }
        Self {
            ctx: std::ptr::null_mut(),
            send_fn: noop_send,
        }
    }

    /// Send packets through this handle.
    #[inline]
    pub fn send(&self, packets: &[PacketBuffer], flush: bool) -> SendResult {
        unsafe { (self.send_fn)(self.ctx, packets, flush) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn noop_handle_accepts_everything() {
        let handle = IoHandle::noop();
        let pkts = [PacketBuffer::from_slice(b"test", None)];
        assert_eq!(handle.send(&pkts, true), SendResult::Success);
    }

    #[test]
    fn handle_with_context() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        unsafe fn counting_send(
            _ctx: *mut (),
            packets: &[PacketBuffer],
            _flush: bool,
        ) -> SendResult {
            COUNTER.fetch_add(packets.len(), Ordering::Relaxed);
            SendResult::Success
        }

        COUNTER.store(0, Ordering::Relaxed);

        let handle = unsafe { IoHandle::new(std::ptr::null_mut(), counting_send) };
        let pkts = [
            PacketBuffer::from_slice(b"a", None),
            PacketBuffer::from_slice(b"b", None),
            PacketBuffer::from_slice(b"c", None),
        ];

        handle.send(&pkts, false);
        assert_eq!(COUNTER.load(Ordering::Relaxed), 3);

        handle.send(&pkts, true);
        assert_eq!(COUNTER.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn handle_partial_send() {
        unsafe fn partial_send(
            _ctx: *mut (),
            _packets: &[PacketBuffer],
            _flush: bool,
        ) -> SendResult {
            SendResult::Partial { sent_count: 1 }
        }

        let handle = unsafe { IoHandle::new(std::ptr::null_mut(), partial_send) };
        let pkts = [
            PacketBuffer::from_slice(b"a", None),
            PacketBuffer::from_slice(b"b", None),
        ];

        let result = handle.send(&pkts, true);
        assert_eq!(result, SendResult::Partial { sent_count: 1 });
    }
}
