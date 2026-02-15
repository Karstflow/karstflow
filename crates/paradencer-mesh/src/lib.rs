mod ports;
mod stats;
#[cfg(test)]
mod tests;
mod types;

pub use ports::{bounded_link, InPort, OutPort};
pub use stats::ChannelStats;
pub use types::{ChannelSnapshot, ReceiveError, SendError};

// Type aliases for convenience
pub type Sender<T> = OutPort<T>;
pub type Receiver<T> = InPort<T>;
