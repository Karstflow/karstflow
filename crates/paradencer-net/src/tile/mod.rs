/// Tile-based network processing.
///
/// Tiles are single-threaded processing units that can be pinned to CPU
/// cores. Each tile owns its resources and communicates via lock-free
/// channels, matching Firedancer's tile architecture.
pub mod net_tile;
pub mod quic_tile;
pub mod reassembly;

pub use net_tile::NetworkTile;
pub use quic_tile::{QuicTile, QuicTransaction};
pub use reassembly::TpuReassembler;
