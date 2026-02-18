/// AF_XDP kernel-bypass packet I/O.
///
/// Provides UMEM frame management, SPSC ring buffers, and a high-level
/// XDP socket abstraction for zero-copy packet send/receive. The ring
/// and UMEM logic is platform-independent; actual Linux AF_XDP syscalls
/// are behind `#[cfg(target_os = "linux")]`.
pub mod ring;
pub mod socket;
pub mod umem;

pub use ring::{DescriptorRing, FrameRing, PacketDescriptor};
pub use socket::{XdpSocket, XdpSocketConfig};
pub use umem::{FrameAllocator, UmemConfig};
