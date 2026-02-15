mod cluster_info;
mod protocol;
mod service;

#[cfg(test)]
mod tests;

pub use cluster_info::{
    ClusterInfo, ContactInfo, GossipNode, NodeId, ValidatorInfo, CRDT_UPDATE_INTERVAL_MS,
    GOSSIP_PRUNE_TIMEOUT_MS, MAX_CLUSTER_SIZE,
};
pub use protocol::{
    GossipMessage, GossipMessageType, GossipPullRequest, GossipPullResponse, GossipPushMessage,
    GossipVersion, GOSSIP_PROTOCOL_VERSION,
};
pub use service::{GossipConfig, GossipService, GossipServiceStats};

use crate::IngressError;
use std::sync::Arc;

pub type GossipResult<T> = Result<T, IngressError>;
