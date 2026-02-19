//! High-performance networking stack for Paradencer validator.
//!
//! Combines custom QUIC/TLS/XDP transport with gossip, repair,
//! turbine, and ingress filter pipeline modules.

// --- Transport layer (custom, Firedancer-aligned) ---
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

// --- Protocol layer (gossip, repair, turbine) ---
mod errors;
pub mod gossip;
pub mod repair;
pub mod turbine;

// --- Ingress filter pipeline (decode, dedup, verify, rate-limit) ---
pub mod filter;

// --- Re-exports: error types ---
pub use errors::IngressError;

// --- Re-exports: gossip ---
pub use gossip::{
    ClusterInfo, ContactInfo, GossipConfig, GossipMessage, GossipNode, GossipService,
    GossipServiceStats, NodeId, ValidatorInfo,
};

// --- Re-exports: ingress filter pipeline ---
pub use filter::{
    DecodeOutcome, DedupDecision, DropReason, InboundFrame, IngressMode, IngressPolicy,
    IngressSource, PacketDecoder, PreparedShred, PreparedTransaction, ShredDecodeOutcome,
    ShredDecoder, SignatureDeduplicator, SignatureVerifier, SourceCostBudgetLimiter,
    SourceRateLimiter, VerificationError, VerificationResult, VerificationStats,
};

// --- Re-exports: repair ---
pub use repair::{
    InMemoryShredStore, RepairMessage, RepairRequest, RepairRequester, RepairResponse,
    RepairServer, RepairServerConfig, RepairService, RepairServiceConfig, ShredData, ShredIndex,
    ShredProvider, Slot,
};

// --- Re-exports: turbine ---
pub use turbine::{
    BroadcastManager, BroadcastShred, BroadcastStats, Neighborhood, NetworkProximity,
    PropagationMetrics, ProximityEstimator, ProximityScore, RetransmitRequest, RetransmitService,
    RetransmitShred, RetransmitStats, ShredBroadcaster, TurbineConfig, TurbineNode, TurbineResult,
    TurbineStats, TurbineTree, TurbineTreeBuilder, DEFAULT_FANOUT, DEFAULT_NEIGHBORHOOD_SIZE,
};
