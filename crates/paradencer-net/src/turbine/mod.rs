mod broadcaster;
mod config;
mod neighborhood;
mod retransmit;
mod stats;
mod transport;
mod tree;

#[cfg(test)]
mod tests;

pub use broadcaster::{BroadcastManager, BroadcastShred, ShredBroadcaster};
pub use config::{TurbineConfig, DEFAULT_FANOUT, DEFAULT_NEIGHBORHOOD_SIZE};
pub use neighborhood::{Neighborhood, NetworkProximity, ProximityEstimator, ProximityScore};
pub use retransmit::{RetransmitRequest, RetransmitService, RetransmitShred};
pub use stats::{BroadcastStats, PropagationMetrics, RetransmitStats, TurbineStats};
pub use transport::{NullTransport, ShredTransport, TransportError, UdpShredTransport};
pub use tree::{TurbineNode, TurbineTree, TurbineTreeBuilder};

use crate::IngressError;

pub type TurbineResult<T> = Result<T, IngressError>;
