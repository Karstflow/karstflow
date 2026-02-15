use std::net::SocketAddr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RpcError>;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("failed to bind RPC HTTP listener on {bind_addr}: {source}")]
    RpcHttpBind {
        bind_addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("failed to spawn RPC HTTP thread: {0}")]
    RpcHttpThreadSpawn(std::io::Error),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("preflight failed: {0}")]
    PreflightFailed(String),
    #[error("min context slot not reached: slot={slot}, min={min_slot}")]
    MinContextSlotNotReached { slot: u64, min_slot: u64 },
    #[error("batch too large: size={size}, max={max}")]
    BatchTooLarge { size: usize, max: usize },
}
