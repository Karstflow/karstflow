mod handle;
/// Packet I/O abstraction layer.
mod traits;

pub use handle::IoHandle;
pub use traits::{PacketReceiver, PacketSender, SendResult};
