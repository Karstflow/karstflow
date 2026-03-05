use crate::ChannelSnapshot;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub struct ChannelStats {
    enqueued_messages: Arc<AtomicU64>,
    dequeued_messages: Arc<AtomicU64>,
    blocked_sends: Arc<AtomicU64>,
    closed_sends: Arc<AtomicU64>,
    empty_receives: Arc<AtomicU64>,
    closed_receives: Arc<AtomicU64>,
}

impl ChannelStats {
    pub(crate) fn record_enqueue(&self) {
        self.enqueued_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dequeue(&self) {
        self.dequeued_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_blocked_send(&self) {
        self.blocked_sends.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_closed_send(&self) {
        self.closed_sends.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_empty_receive(&self) {
        self.empty_receives.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_closed_receive(&self) {
        self.closed_receives.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, current_len: usize, capacity: Option<usize>) -> ChannelSnapshot {
        ChannelSnapshot {
            queue_depth: current_len,
            queue_capacity: capacity,
            enqueued_messages: self.enqueued_messages.load(Ordering::Relaxed),
            dequeued_messages: self.dequeued_messages.load(Ordering::Relaxed),
            blocked_sends: self.blocked_sends.load(Ordering::Relaxed),
            closed_sends: self.closed_sends.load(Ordering::Relaxed),
            empty_receives: self.empty_receives.load(Ordering::Relaxed),
            closed_receives: self.closed_receives.load(Ordering::Relaxed),
        }
    }
}
