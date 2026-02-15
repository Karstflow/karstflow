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
