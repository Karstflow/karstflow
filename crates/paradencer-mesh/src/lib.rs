mod ports;
mod stats;
#[cfg(test)]
mod tests;
mod types;

pub use ports::{bounded_link, InPort, OutPort};
pub use stats::ChannelStats;
pub use types::{ChannelSnapshot, ReceiveError, SendError};
