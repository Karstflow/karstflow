use serde::{Deserialize, Serialize};
use std::fmt;

/// Inter-tile IPC transport mode.
///
/// Selects the communication backend for inter-stage data links.
/// Both modes are always compiled — selection happens at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcMode {
    /// Crossbeam bounded channels (typed, copies message).
    Channel,
    /// Zero-copy SPSC tile links (raw bytes via FragmentCodec).
    SharedMemory,
}

impl IpcMode {
    pub fn from_env(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "channel" | "channels" => Some(Self::Channel),
            "shared_memory" | "shm" => Some(Self::SharedMemory),
            _ => None,
        }
    }
}

impl fmt::Display for IpcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel => write!(f, "channel"),
            Self::SharedMemory => write!(f, "shared_memory"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Tokio,
    Pinned,
    /// Tile execution: poll-driven spin-loop with CnC lifecycle,
    /// heartbeat monitoring, and metrics — Firedancer-style.
    Tile,
}

impl ExecutionMode {
    pub fn from_env(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tokio" => Some(Self::Tokio),
            "pinned" => Some(Self::Pinned),
            "tile" => Some(Self::Tile),
            _ => None,
        }
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tokio => write!(f, "tokio"),
            Self::Pinned => write!(f, "pinned"),
            Self::Tile => write!(f, "tile"),
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
    SignatureVerifier,
    BlockhashResolver,
    ShredSanitizer,
    BlockBuilder,
    ReplayEngine,
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
    VerifiedStream,
    BlockStream,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_mode_from_env() {
        assert_eq!(IpcMode::from_env("channel"), Some(IpcMode::Channel));
        assert_eq!(IpcMode::from_env("channels"), Some(IpcMode::Channel));
        assert_eq!(IpcMode::from_env("CHANNEL"), Some(IpcMode::Channel));
        assert_eq!(
            IpcMode::from_env("shared_memory"),
            Some(IpcMode::SharedMemory)
        );
        assert_eq!(IpcMode::from_env("shm"), Some(IpcMode::SharedMemory));
        assert_eq!(IpcMode::from_env("SHM"), Some(IpcMode::SharedMemory));
        assert_eq!(IpcMode::from_env("unknown"), None);
    }

    #[test]
    fn ipc_mode_display() {
        assert_eq!(IpcMode::Channel.to_string(), "channel");
        assert_eq!(IpcMode::SharedMemory.to_string(), "shared_memory");
    }

    #[test]
    fn execution_mode_from_env() {
        assert_eq!(ExecutionMode::from_env("tokio"), Some(ExecutionMode::Tokio));
        assert_eq!(ExecutionMode::from_env("TOKIO"), Some(ExecutionMode::Tokio));
        assert_eq!(
            ExecutionMode::from_env("pinned"),
            Some(ExecutionMode::Pinned)
        );
        assert_eq!(ExecutionMode::from_env("tile"), Some(ExecutionMode::Tile));
        assert_eq!(ExecutionMode::from_env("invalid"), None);
    }

    #[test]
    fn execution_mode_display() {
        assert_eq!(ExecutionMode::Tokio.to_string(), "tokio");
        assert_eq!(ExecutionMode::Pinned.to_string(), "pinned");
        assert_eq!(ExecutionMode::Tile.to_string(), "tile");
    }

    #[test]
    fn pinned_core_policy_from_env() {
        assert_eq!(
            PinnedCorePolicy::from_env("strict"),
            Some(PinnedCorePolicy::Strict)
        );
        assert_eq!(
            PinnedCorePolicy::from_env("SHARED"),
            Some(PinnedCorePolicy::Shared)
        );
        assert_eq!(
            PinnedCorePolicy::from_env("adaptive"),
            Some(PinnedCorePolicy::Adaptive)
        );
        assert_eq!(PinnedCorePolicy::from_env("none"), None);
    }

    #[test]
    fn pinned_core_policy_display() {
        assert_eq!(PinnedCorePolicy::Strict.to_string(), "strict");
        assert_eq!(PinnedCorePolicy::Shared.to_string(), "shared");
        assert_eq!(PinnedCorePolicy::Adaptive.to_string(), "adaptive");
    }

    #[test]
    fn from_env_display_roundtrip() {
        for mode in [IpcMode::Channel, IpcMode::SharedMemory] {
            let s = mode.to_string();
            assert_eq!(IpcMode::from_env(&s), Some(mode));
        }
        for mode in [
            ExecutionMode::Tokio,
            ExecutionMode::Pinned,
            ExecutionMode::Tile,
        ] {
            let s = mode.to_string();
            assert_eq!(ExecutionMode::from_env(&s), Some(mode));
        }
        for policy in [
            PinnedCorePolicy::Strict,
            PinnedCorePolicy::Shared,
            PinnedCorePolicy::Adaptive,
        ] {
            let s = policy.to_string();
            assert_eq!(PinnedCorePolicy::from_env(&s), Some(policy));
        }
    }
}
