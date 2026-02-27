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

// ---------------------------------------------------------------------------
// Zero-copy inter-tile IPC (Tango-equivalent)
// ---------------------------------------------------------------------------

pub mod cnc;
pub mod data_region;
pub mod flow;
pub mod flow_control;
pub mod fragment;
pub mod meta_ring;
pub mod stem;
pub mod tag_cache;
pub mod tempo;
pub mod tile;
pub mod tile_link;
