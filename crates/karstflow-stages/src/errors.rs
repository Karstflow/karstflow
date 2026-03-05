use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StageError {
    #[error("failed to serialize metrics payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to open metrics output file '{path}': {source}")]
    FileOpen {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write metrics output file '{path}': {source}")]
    FileWrite {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to bind UDP metrics socket: {0}")]
    UdpBind(std::io::Error),
    #[error("failed to send metrics datagram to {target}: {source}")]
    UdpSend {
        target: SocketAddr,
        source: std::io::Error,
    },
    #[error("failed to load snapshot catalog from '{path}': {message}")]
    StorageCatalogLoad { path: PathBuf, message: String },
    #[error("failed to persist snapshot catalog to '{path}': {message}")]
    StorageCatalogPersist { path: PathBuf, message: String },
    #[error(
        "startup strict-restore requires snapshot catalog path for startup policy '{startup_policy}'"
    )]
    StorageStartupStrictRestoreRequiresCatalogPath { startup_policy: &'static str },
    #[error("startup restore_latest is strict but no snapshot is available")]
    StorageStartupMissingLatestSnapshot,
    #[error(
        "startup restore_specific is strict but requested snapshot {fragment_id} is unavailable"
    )]
    StorageStartupMissingSpecificSnapshot { fragment_id: u64 },
    #[error("invalid storage runtime policy: {0}")]
    InvalidStoragePolicy(String),
    #[error("replay stage error: {0}")]
    ReplayError(String),
}
