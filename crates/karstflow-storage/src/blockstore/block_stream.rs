//! Block streaming — publish slot lifecycle events to subscribers.
//!
//! Provides a lightweight publish-subscribe mechanism for blockstore events.
//! Subscribers receive notifications when slots complete, become rooted, or
//! when block data is available for consumption. This is the equivalent of
//! the reference implementation's `bstream` tile for streaming block data to downstream
//! consumers (RPC, Geyser plugins, archivers).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A slot lifecycle event published by the blockstore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotEvent {
    /// All data shreds for this slot have been received and assembled.
    Completed {
        slot: u64,
        parent_slot: Option<u64>,
        num_shreds: u32,
        num_transactions: u32,
    },
    /// This slot has been set as a root (finalized).
    Rooted { slot: u64 },
    /// This slot was marked dead (unrecoverable).
    Dead { slot: u64 },
    /// This slot was marked as a duplicate.
    Duplicate { slot: u64 },
}

impl SlotEvent {
    /// Get the slot number for this event.
    pub fn slot(&self) -> u64 {
        match self {
            Self::Completed { slot, .. }
            | Self::Rooted { slot }
            | Self::Dead { slot }
            | Self::Duplicate { slot } => *slot,
        }
    }
}

/// Sender side of the block stream.
///
/// Attached to a [`Blockstore`] to publish events when slot state changes.
/// Internally uses a bounded broadcast channel to avoid unbounded memory
/// growth if subscribers fall behind.
pub struct BlockStreamPublisher {
    sender: crossbeam_channel::Sender<SlotEvent>,
    stats: Arc<BlockStreamStats>,
}

/// Receiver side of the block stream.
///
/// Each subscriber gets its own receiver. Events are delivered in order.
/// If the subscriber falls behind the channel capacity, older events are
/// dropped (the receiver will see a disconnect error).
pub struct BlockStreamSubscriber {
    receiver: crossbeam_channel::Receiver<SlotEvent>,
    stats: Arc<BlockStreamStats>,
}

/// Statistics for the block stream.
#[derive(Debug, Default)]
pub struct BlockStreamStats {
    /// Total events published.
    pub events_published: AtomicU64,
    /// Total events that could not be sent (channel full or disconnected).
    pub events_dropped: AtomicU64,
    /// Total completed slot events.
    pub slots_completed: AtomicU64,
    /// Total rooted slot events.
    pub slots_rooted: AtomicU64,
}

/// Create a block stream publisher/subscriber pair with the given channel capacity.
pub fn block_stream(capacity: usize) -> (BlockStreamPublisher, BlockStreamSubscriber) {
    let (sender, receiver) = crossbeam_channel::bounded(capacity);
    let stats = Arc::new(BlockStreamStats::default());
    (
        BlockStreamPublisher {
            sender,
            stats: stats.clone(),
        },
        BlockStreamSubscriber { receiver, stats },
    )
}

impl BlockStreamPublisher {
    /// Publish a slot event to all subscribers.
    ///
    /// Non-blocking: if the channel is full, the event is dropped and
    /// counted in `events_dropped`.
    pub fn publish(&self, event: SlotEvent) {
        match &event {
            SlotEvent::Completed { .. } => {
                self.stats.slots_completed.fetch_add(1, Ordering::Relaxed);
            }
            SlotEvent::Rooted { .. } => {
                self.stats.slots_rooted.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        match self.sender.try_send(event) {
            Ok(()) => {
                self.stats.events_published.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get the stream statistics.
    pub fn stats(&self) -> &BlockStreamStats {
        &self.stats
    }
}

impl BlockStreamSubscriber {
    /// Try to receive the next event without blocking.
    pub fn try_recv(&self) -> Option<SlotEvent> {
        self.receiver.try_recv().ok()
    }

    /// Block until the next event is available.
    pub fn recv(&self) -> Option<SlotEvent> {
        self.receiver.recv().ok()
    }

    /// Receive with a timeout.
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<SlotEvent> {
        self.receiver.recv_timeout(timeout).ok()
    }

    /// Drain all currently available events into a vec.
    pub fn drain(&self) -> Vec<SlotEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        events
    }

    /// Get the stream statistics.
    pub fn stats(&self) -> &BlockStreamStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn publish_completed_event() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Completed {
            slot: 42,
            parent_slot: Some(41),
            num_shreds: 100,
            num_transactions: 50,
        });
        let event = sub.recv_timeout(Duration::from_millis(100)).unwrap();
        assert_eq!(event.slot(), 42);
        assert!(matches!(event, SlotEvent::Completed { slot: 42, .. }));
    }

    #[test]
    fn publish_rooted_event() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Rooted { slot: 10 });
        let event = sub.try_recv().unwrap();
        assert_eq!(event, SlotEvent::Rooted { slot: 10 });
    }

    #[test]
    fn publish_dead_event() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Dead { slot: 5 });
        let event = sub.try_recv().unwrap();
        assert_eq!(event, SlotEvent::Dead { slot: 5 });
    }

    #[test]
    fn publish_duplicate_event() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Duplicate { slot: 7 });
        let event = sub.try_recv().unwrap();
        assert_eq!(event, SlotEvent::Duplicate { slot: 7 });
    }

    #[test]
    fn stats_track_published_events() {
        let (pub_, _sub) = block_stream(16);
        pub_.publish(SlotEvent::Completed {
            slot: 1,
            parent_slot: None,
            num_shreds: 10,
            num_transactions: 5,
        });
        pub_.publish(SlotEvent::Rooted { slot: 1 });
        pub_.publish(SlotEvent::Dead { slot: 2 });

        assert_eq!(pub_.stats().events_published.load(Ordering::Relaxed), 3);
        assert_eq!(pub_.stats().slots_completed.load(Ordering::Relaxed), 1);
        assert_eq!(pub_.stats().slots_rooted.load(Ordering::Relaxed), 1);
        assert_eq!(pub_.stats().events_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dropped_events_counted_when_channel_full() {
        let (pub_, _sub) = block_stream(2);
        pub_.publish(SlotEvent::Rooted { slot: 1 });
        pub_.publish(SlotEvent::Rooted { slot: 2 });
        // Channel is now full (capacity=2), next publish should drop.
        pub_.publish(SlotEvent::Rooted { slot: 3 });

        assert_eq!(pub_.stats().events_published.load(Ordering::Relaxed), 2);
        assert_eq!(pub_.stats().events_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn drain_returns_all_available_events() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Rooted { slot: 1 });
        pub_.publish(SlotEvent::Rooted { slot: 2 });
        pub_.publish(SlotEvent::Rooted { slot: 3 });

        let events = sub.drain();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].slot(), 1);
        assert_eq!(events[2].slot(), 3);
    }

    #[test]
    fn try_recv_returns_none_when_empty() {
        let (_pub, sub) = block_stream(16);
        assert!(sub.try_recv().is_none());
    }

    #[test]
    fn recv_timeout_returns_none_on_timeout() {
        let (_pub, sub) = block_stream(16);
        let result = sub.recv_timeout(Duration::from_millis(10));
        assert!(result.is_none());
    }

    #[test]
    fn event_ordering_preserved() {
        let (pub_, sub) = block_stream(16);
        for i in 0..10 {
            pub_.publish(SlotEvent::Rooted { slot: i });
        }
        for i in 0..10 {
            let event = sub.try_recv().unwrap();
            assert_eq!(event.slot(), i);
        }
    }

    #[test]
    fn subscriber_stats_shared_with_publisher() {
        let (pub_, sub) = block_stream(16);
        pub_.publish(SlotEvent::Rooted { slot: 1 });
        assert_eq!(sub.stats().events_published.load(Ordering::Relaxed), 1);
    }
}
