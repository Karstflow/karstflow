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
}
