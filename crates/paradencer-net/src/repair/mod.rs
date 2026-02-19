mod protocol;
mod request;
mod server;
mod service;

#[cfg(test)]
mod tests;

pub use protocol::{
    RepairMessage, RepairProtocol, RepairRequest, RepairRequestType, RepairResponse, ShredData,
    REPAIR_PROTOCOL_VERSION,
};
pub use request::{RepairRequester, RepairRequesterStats};
pub use server::{
    InMemoryShredStore, RepairServer, RepairServerConfig, RepairServerStats, ShredProvider,
};
pub use service::{RepairService, RepairServiceConfig};

use crate::IngressError;

pub type RepairResult<T> = Result<T, IngressError>;

/// Slot number
pub type Slot = u64;

/// Shred index within a slot
pub type ShredIndex = u32;
