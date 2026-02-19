//! Cluster Replicated Data Store (CRDS).
//!
//! The CRDS is the core gossip data structure that holds all values
//! exchanged between validators in the cluster. It supports 14 value
//! types and uses a multi-index architecture for efficient lookup,
//! eviction, expiration, and bloom filter queries.

mod bloom;
mod entry;
mod key;
mod sampler;
mod table;
mod value;

pub use bloom::{GossipBloomFilter, PullRequestMask};
pub use entry::{CrdsEntry, EntryOrigin};
pub use key::CrdsKey;
pub use sampler::WeightedPeerSampler;
pub use table::{CrdsTable, InsertOutcome};
pub use value::{
    CrdsContactInfo, CrdsValue, CrdsValueData, DuplicateShredProof, EpochSlots,
    IncrementalSnapshotHashes, NodeInstanceToken, RestartHeaviestFork, RestartLastVotedForkSlots,
    SnapshotHashes, VersionInfo, VoteGossip,
};
