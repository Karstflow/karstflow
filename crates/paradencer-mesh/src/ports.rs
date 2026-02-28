use crate::{ChannelSnapshot, ChannelStats, ReceiveError, SendError};
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};

pub struct OutPort<MessageType> {
    sender: Sender<MessageType>,
    stats: ChannelStats,
}

impl<MessageType> Clone for OutPort<MessageType> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            stats: self.stats.clone(),
        }
    }
}

pub struct InPort<MessageType> {
    receiver: Receiver<MessageType>,
    stats: ChannelStats,
}

impl<MessageType> Clone for InPort<MessageType> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
            stats: self.stats.clone(),
        }
    }
}

impl<MessageType> OutPort<MessageType> {
    pub fn try_send(&self, message: MessageType) -> Result<(), SendError<MessageType>> {
        match self.sender.try_send(message) {
            Ok(()) => {
                self.stats.record_enqueue();
                Ok(())
            }
            Err(TrySendError::Full(returned_message)) => {
                self.stats.record_blocked_send();
                Err(SendError::QueueFull(returned_message))
            }
            Err(TrySendError::Disconnected(returned_message)) => {
                self.stats.record_closed_send();
                Err(SendError::QueueClosed(returned_message))
            }
        }
    }

    pub fn snapshot(&self) -> ChannelSnapshot {
        self.stats
            .snapshot(self.sender.len(), self.sender.capacity())
    }

    pub fn stats(&self) -> ChannelStats {
        self.stats.clone()
    }
}

impl<MessageType> InPort<MessageType> {
    /// Blocking receive — waits until a message is available or the channel closes.
    pub fn recv(&self) -> Result<MessageType, ReceiveError> {
        match self.receiver.recv() {
            Ok(message) => {
                self.stats.record_dequeue();
                Ok(message)
            }
            Err(_) => {
                self.stats.record_closed_receive();
                Err(ReceiveError::QueueClosed)
            }
        }
    }

    pub fn try_recv(&self) -> Result<Option<MessageType>, ReceiveError> {
        match self.receiver.try_recv() {
            Ok(message) => {
                self.stats.record_dequeue();
                Ok(Some(message))
            }
            Err(TryRecvError::Empty) => {
                self.stats.record_empty_receive();
                Ok(None)
            }
            Err(TryRecvError::Disconnected) => {
                self.stats.record_closed_receive();
                Err(ReceiveError::QueueClosed)
            }
        }
    }

    pub fn snapshot(&self) -> ChannelSnapshot {
        self.stats
            .snapshot(self.receiver.len(), self.receiver.capacity())
    }

    pub fn stats(&self) -> ChannelStats {
        self.stats.clone()
    }
}

pub fn bounded_link<MessageType>(capacity: usize) -> (OutPort<MessageType>, InPort<MessageType>) {
    let bounded_capacity = capacity.max(1);
    let (sender, receiver) = bounded(bounded_capacity);
    let shared_stats = ChannelStats::default();

    (
        OutPort {
            sender,
            stats: shared_stats.clone(),
        },
        InPort {
            receiver,
            stats: shared_stats,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_link_sends_and_receives() {
        let (tx, rx) = bounded_link::<u64>(4);
        tx.try_send(42).unwrap();
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg, Some(42));
    }

    #[test]
    fn bounded_link_empty_receive_returns_none() {
        let (_tx, rx) = bounded_link::<u64>(4);
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg, None);
    }

    #[test]
    fn bounded_link_full_returns_error() {
        let (tx, _rx) = bounded_link::<u64>(2);
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        let result = tx.try_send(3);
        assert!(matches!(result, Err(SendError::QueueFull(3))));
    }

    #[test]
    fn bounded_link_dropped_receiver_returns_closed() {
        let (tx, rx) = bounded_link::<u64>(4);
        drop(rx);
        let result = tx.try_send(1);
        assert!(matches!(result, Err(SendError::QueueClosed(1))));
    }

    #[test]
    fn bounded_link_dropped_sender_returns_closed() {
        let (tx, rx) = bounded_link::<u64>(4);
        tx.try_send(1).unwrap();
        drop(tx);
        // First read succeeds (buffered message)
        assert_eq!(rx.try_recv().unwrap(), Some(1));
        // Next read sees closed
        let result = rx.try_recv();
        assert!(matches!(result, Err(ReceiveError::QueueClosed)));
    }

    #[test]
    fn bounded_link_stats_track_enqueue_dequeue() {
        let (tx, rx) = bounded_link::<u64>(4);
        tx.try_send(10).unwrap();
        tx.try_send(20).unwrap();
        rx.try_recv().unwrap();

        let snap = tx.snapshot();
        assert_eq!(snap.enqueued_messages, 2);
        // Dequeue tracked on receiver side
        let snap_rx = rx.snapshot();
        assert_eq!(snap_rx.dequeued_messages, 1);
    }

    #[test]
    fn bounded_link_stats_track_blocked_sends() {
        let (tx, _rx) = bounded_link::<u64>(1);
        tx.try_send(1).unwrap();
        let _ = tx.try_send(2); // blocked

        let snap = tx.snapshot();
        assert_eq!(snap.blocked_sends, 1);
    }

    #[test]
    fn bounded_link_stats_track_empty_receives() {
        let (_tx, rx) = bounded_link::<u64>(4);
        rx.try_recv().unwrap(); // empty
        rx.try_recv().unwrap(); // empty again

        let snap = rx.snapshot();
        assert_eq!(snap.empty_receives, 2);
    }

    #[test]
    fn bounded_link_zero_capacity_becomes_one() {
        let (tx, rx) = bounded_link::<u64>(0);
        tx.try_send(99).unwrap();
        assert_eq!(rx.try_recv().unwrap(), Some(99));
    }

    #[test]
    fn bounded_link_fifo_order() {
        let (tx, rx) = bounded_link::<u64>(8);
        for i in 0..5 {
            tx.try_send(i).unwrap();
        }
        for i in 0..5 {
            assert_eq!(rx.try_recv().unwrap(), Some(i));
        }
    }

    #[test]
    fn bounded_link_snapshot_reports_depth() {
        let (tx, _rx) = bounded_link::<u64>(8);
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();
        tx.try_send(3).unwrap();

        let snap = tx.snapshot();
        assert_eq!(snap.queue_depth, 3);
        assert_eq!(snap.queue_capacity, Some(8));
    }
}
