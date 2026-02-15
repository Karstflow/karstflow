use thiserror::Error;

pub type Result<T> = std::result::Result<T, ObservabilityError>;

#[derive(Debug, Error)]
pub enum ObservabilityError {
    #[error("failed to bind metrics HTTP bridge on {bind_addr}: {source}")]
    MetricsHttpBind {
        bind_addr: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error("failed to spawn metrics HTTP bridge thread: {0}")]
    MetricsHttpThreadSpawn(std::io::Error),
}
