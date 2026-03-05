#[derive(Debug, Clone)]
pub struct ChannelSnapshot {
    pub queue_depth: usize,
    pub queue_capacity: Option<usize>,
    pub enqueued_messages: u64,
    pub dequeued_messages: u64,
    pub blocked_sends: u64,
    pub closed_sends: u64,
    pub empty_receives: u64,
    pub closed_receives: u64,
}

#[derive(Debug)]
pub enum SendError<MessageType> {
    QueueFull(MessageType),
    QueueClosed(MessageType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    QueueClosed,
}
