//! High-performance networking stack for Paradencer validator.
//!
//! Combines custom QUIC/TLS/XDP transport with gossip, repair,
//! turbine, and ingress filter pipeline modules.

pub mod backend;
pub mod io;
pub mod neighbor;
pub mod packet;
pub mod quic;
pub mod routing;
pub mod socket;
pub mod tile;
pub mod tls;
pub mod wire;
pub mod xdp;

mod errors;
pub mod filter;
pub mod gossip;
pub mod repair;
pub mod snapshot_download;
pub mod turbine;

pub use errors::IngressError;

pub use filter::{
    DecodeOutcome, DedupDecision, DropReason, InboundFrame, IngressMode, IngressPolicy,
    IngressSource, PacketDecoder, PreparedShred, PreparedTransaction, ShredDecodeOutcome,
    ShredDecoder, SignatureDeduplicator, SignatureVerifier, SourceCostBudgetLimiter,
    SourceRateLimiter, VerificationError, VerificationResult, VerificationStats,
};

pub use gossip::{
    ClusterInfo, ContactInfo, CrdsContactInfo, CrdsEntry, CrdsKey, CrdsTable, CrdsValue,
    CrdsValueData, GossipBloomFilter, GossipConfig, GossipMessage, GossipNode, GossipService,
    GossipServiceStats, InsertOutcome, NodeId, PullRequestFilter, ValidatorInfo, VoteGossip,
    WeightedPeerSampler,
};

pub use repair::{
    InMemoryShredStore, OutboundRepair, PeerId, RepairCoordinator, RepairCoordinatorConfig,
    RepairCoordinatorStats, RepairRequest, RepairRequester, RepairResponse, RepairServer,
    RepairServerConfig, RepairService, RepairServiceConfig, RepairTarget, ShredData, ShredIndex,
    ShredProvider, Slot, WireRepairProtocol, WireRepairRequestHeader,
};

pub use turbine::{
    BroadcastManager, BroadcastShred, BroadcastStats, Neighborhood, NetworkProximity,
    PropagationMetrics, ProximityEstimator, ProximityScore, RetransmitRequest, RetransmitService,
    RetransmitShred, RetransmitStats, ShredBroadcaster, TurbineConfig, TurbineNode, TurbineResult,
    TurbineStats, TurbineTree, TurbineTreeBuilder, UdpShredTransport, DEFAULT_FANOUT,
    DEFAULT_NEIGHBORHOOD_SIZE,
};
