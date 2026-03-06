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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stats_are_zero() {
        let stats = ChannelStats::default();
        let snap = stats.snapshot(0, None);
        assert_eq!(snap.enqueued_messages, 0);
        assert_eq!(snap.dequeued_messages, 0);
        assert_eq!(snap.blocked_sends, 0);
        assert_eq!(snap.closed_sends, 0);
        assert_eq!(snap.empty_receives, 0);
        assert_eq!(snap.closed_receives, 0);
    }

    #[test]
    fn record_operations_increment() {
        let stats = ChannelStats::default();
        stats.record_enqueue();
        stats.record_enqueue();
        stats.record_dequeue();
        stats.record_blocked_send();
        stats.record_closed_send();
        stats.record_empty_receive();
        stats.record_closed_receive();

        let snap = stats.snapshot(5, Some(64));
        assert_eq!(snap.enqueued_messages, 2);
        assert_eq!(snap.dequeued_messages, 1);
        assert_eq!(snap.blocked_sends, 1);
        assert_eq!(snap.closed_sends, 1);
        assert_eq!(snap.empty_receives, 1);
        assert_eq!(snap.closed_receives, 1);
        assert_eq!(snap.queue_depth, 5);
        assert_eq!(snap.queue_capacity, Some(64));
    }

    #[test]
    fn clone_shares_counters() {
        let stats = ChannelStats::default();
        let clone = stats.clone();
        stats.record_enqueue();
        clone.record_enqueue();
        let snap = stats.snapshot(0, None);
        assert_eq!(snap.enqueued_messages, 2);
    }

    #[test]
    fn snapshot_without_capacity() {
        let stats = ChannelStats::default();
        let snap = stats.snapshot(10, None);
        assert_eq!(snap.queue_depth, 10);
        assert!(snap.queue_capacity.is_none());
    }
}
