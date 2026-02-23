mod cluster_info;
pub mod crds;
mod protocol;
mod service;
pub mod wire;

#[cfg(test)]
mod tests;

pub use cluster_info::{
    ClusterInfo, ContactInfo, GossipNode, NodeId, ValidatorInfo, CRDT_UPDATE_INTERVAL_MS,
    GOSSIP_PRUNE_TIMEOUT_MS, MAX_CLUSTER_SIZE,
};
pub use crds::{
    CrdsContactInfo, CrdsEntry, CrdsKey, CrdsTable, CrdsValue, CrdsValueData, GossipBloomFilter,
    InsertOutcome, WeightedPeerSampler,
};
pub use protocol::{
    GossipMessage, GossipMessageType, GossipPullRequest, GossipPullResponse, GossipPushMessage,
    GossipVersion, PullRequestFilter, GOSSIP_PROTOCOL_VERSION,
};
pub use service::{GossipConfig, GossipService, GossipServiceStats};

use crate::IngressError;

pub type GossipResult<T> = Result<T, IngressError>;
