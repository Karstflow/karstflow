use paradencer_config::ConfigError;
use paradencer_observability::ObservabilityError;
use paradencer_rpc::RpcError;
use paradencer_runtime::RuntimeError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ControlPlaneError>;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("config failed: {0}")]
    Config(#[from] ConfigError),
    #[error("runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("topology failed: {0}")]
    Topology(#[from] paradencer_topology::TopologyError),
    #[error("observability failed: {0}")]
    Observability(#[from] ObservabilityError),
    #[error("rpc failed: {0}")]
    Rpc(#[from] RpcError),
    #[error(
        "metrics HTTP bridge requires metrics target 'file' so it can serve a stable snapshot"
    )]
    MetricsHttpRequiresFileTarget,
    #[error("live preflight failed to bind ingress UDP socket on {bind_addr}: {source}")]
    IngressUdpBindPreflight {
        bind_addr: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error(
        "live preflight failed to bind UDP probe socket for entrypoint {entrypoint}: {source}"
    )]
    LiveEntrypointProbeBind {
        entrypoint: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error(
        "live preflight failed to connect UDP probe socket to entrypoint {entrypoint}: {source}"
    )]
    LiveEntrypointProbeConnect {
        entrypoint: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error("live preflight failed to send UDP probe packet to entrypoint {entrypoint}: {source}")]
    LiveEntrypointProbeSend {
        entrypoint: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error(
        "service startup preflight failed during {phase} for service '{service_name}': {source}"
    )]
    ServiceStartupPreflight {
        service_name: String,
        phase: &'static str,
        source: RuntimeError,
    },
    #[error("invalid command '{command}', expected one of: run, preflight, diagnostics, config, keys, version")]
    InvalidCommand { command: String },
    #[error("identity keypair path is required for 'keys' command (set PARADENCER_IDENTITY_KEYPAIR_PATH)")]
    KeysCommandRequiresIdentityPath,
    #[error("mainnet readiness checks failed: {reasons}")]
    MainnetReadinessFailed { reasons: String },
}
