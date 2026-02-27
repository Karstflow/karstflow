mod coordinator;
mod forest;
mod nonce;
mod policy;
mod protocol;
mod request;
mod server;
mod service;
pub mod wire;

#[cfg(test)]
mod tests;

pub use coordinator::{
    OutboundRepair, RepairCoordinator, RepairCoordinatorConfig, RepairCoordinatorStats,
    ResponseOutcome,
};
pub use forest::{InsertOutcome, RepairForest, RepairTarget, ShredSource, SlotRepairState};
pub use nonce::{current_time_ns, RepairNonceGenerator};
pub use policy::{InflightEntry, InflightTracker, PeerId, PeerMetrics, PeerSelector, RequestDedup};
pub use protocol::{RepairRequest, RepairRequestType, RepairResponse, ShredData};
pub use request::{RepairRequester, RepairRequesterStats};
pub use server::{
    InMemoryShredStore, RepairServer, RepairServerConfig, RepairServerStats, ShredProvider,
};
pub use service::{RepairService, RepairServiceConfig};
pub use wire::{WireRepairProtocol, WireRepairRequestHeader};

use crate::IngressError;

pub type RepairResult<T> = Result<T, IngressError>;

/// Slot number
pub type Slot = u64;

/// Shred index within a slot
pub type ShredIndex = u32;
