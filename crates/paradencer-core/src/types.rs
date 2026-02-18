use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Tokio,
    Pinned,
}

impl ExecutionMode {
    pub fn from_env(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tokio" => Some(Self::Tokio),
            "pinned" => Some(Self::Pinned),
            _ => None,
        }
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tokio => write!(f, "tokio"),
            Self::Pinned => write!(f, "pinned"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedCorePolicy {
    Strict,
    Shared,
    Adaptive,
}

impl PinnedCorePolicy {
    pub fn from_env(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "shared" => Some(Self::Shared),
            "adaptive" => Some(Self::Adaptive),
            _ => None,
        }
    }
}

impl fmt::Display for PinnedCorePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Shared => write!(f, "shared"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeSpec {
    pub mode: ExecutionMode,
    pub workers: usize,
    pub run_for_seconds: Option<u64>,
    pub pinned_allow_core_sharing: bool,
    pub pinned_core_policy: PinnedCorePolicy,
    pub pinned_service_core_ids: Option<Vec<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    IngressGateway,
    TransactionSanitizer,
    ShredSanitizer,
    BlockBuilder,
    Telemetry,
    NetworkTile,
    QuicTile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    PacketStream,
    ShredStream,
    TransactionStream,
    QuicStream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageSpec {
    pub stage_id: String,
    pub stage_kind: StageKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSpec {
    pub link_id: String,
    pub link_kind: LinkKind,
    pub source_stage_id: String,
    pub destination_stage_id: String,
    pub capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySpec {
    pub topology_name: String,
    pub stages: Vec<StageSpec>,
    pub links: Vec<LinkSpec>,
}
