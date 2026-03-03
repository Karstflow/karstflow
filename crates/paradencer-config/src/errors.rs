use paradencer_core::StageKind;
use std::num::ParseIntError;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {kind} file '{path}': {source}")]
    FileRead {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {kind} TOML '{path}': {message}")]
    FileTomlParse {
        kind: &'static str,
        path: PathBuf,
        message: String,
    },
    #[error("invalid {kind} TOML: {message}")]
    InlineTomlParse { kind: &'static str, message: String },
    #[error("unsupported node config schema_version {found}, expected {expected}")]
    UnsupportedNodeConfigSchemaVersion { found: u32, expected: u32 },
    #[error("unsupported ingress policy schema_version {found}, expected {expected}")]
    UnsupportedIngressPolicySchemaVersion { found: u32, expected: u32 },
    #[error("invalid {scope}: {message}")]
    InvalidScope {
        scope: &'static str,
        message: String,
    },
    #[error("{name} must be greater than zero")]
    NonPositiveValue { name: String },
    #[error("failed to parse {name} as {ty}: {source}")]
    EnvParseInt {
        name: String,
        ty: &'static str,
        source: ParseIntError,
    },
    #[error("invalid boolean value for {name}: '{value}'")]
    InvalidBooleanValue { name: String, value: String },
    #[error("invalid socket address for {name} '{value}': {source}")]
    InvalidSocketAddr {
        name: String,
        value: String,
        source: std::net::AddrParseError,
    },
    #[error("invalid cluster mode '{value}', expected one of: dev, live")]
    InvalidClusterMode { value: String },
    #[error("metrics.output_target='file' requires metrics.file_path")]
    MetricsFileTargetRequiresPath,
    #[error("metrics.output_target='udp' requires metrics.udp_addr")]
    MetricsUdpTargetRequiresAddress,
    #[error("PARADENCER_METRICS_TARGET=file requires PARADENCER_METRICS_FILE_PATH")]
    MetricsEnvFileTargetRequiresPath,
    #[error("PARADENCER_METRICS_TARGET=udp requires PARADENCER_METRICS_UDP_ADDR")]
    MetricsEnvUdpTargetRequiresAddress,
    #[error("rpc.enabled=true requires rpc.bind (or PARADENCER_RPC_BIND)")]
    RpcEnabledRequiresBindAddr,
    #[error("storage startup policy 'restore_specific' requires restore_fragment_id")]
    StorageStartupPolicyRequiresRestoreFragmentId,
    #[error(
        "storage startup strict-restore policy requires storage.catalog_path when startup_policy is '{startup_policy}'"
    )]
    StorageStartupStrictRestoreRequiresCatalogPath { startup_policy: &'static str },
    #[error("required stage kind is missing from topology: {stage_kind:?}")]
    MissingRequiredStageKind { stage_kind: StageKind },
    #[error("live mode requires ingress_mode='udp'")]
    LiveModeRequiresUdpIngressMode,
    #[error("live mode requires PARADENCER_IDENTITY_KEYPAIR_PATH")]
    LiveModeRequiresIdentityKeypairPath,
    #[error("live mode identity keypair path does not exist: '{path}'")]
    LiveModeIdentityKeypairPathMissing { path: PathBuf },
    #[error("live mode identity keypair file has invalid JSON format at '{path}': {message}")]
    LiveModeIdentityKeypairInvalidFormat { path: PathBuf, message: String },
    #[error(
        "live mode identity keypair file must contain exactly {expected} bytes at '{path}', found {found}"
    )]
    LiveModeIdentityKeypairInvalidLength {
        path: PathBuf,
        found: usize,
        expected: usize,
    },
    #[error("live mode requires PARADENCER_EXPECTED_GENESIS_HASH")]
    LiveModeRequiresExpectedGenesisHash,
    #[error("live mode requires PARADENCER_EXPECTED_SHRED_VERSION")]
    LiveModeRequiresExpectedShredVersion,
    #[error("live mode requires PARADENCER_EXPECTED_SHRED_VERSION to be greater than zero")]
    LiveModeRequiresPositiveShredVersion,
    #[error(
        "live mode requires PARADENCER_EXPECTED_GENESIS_HASH to be a 64-char lowercase hex string"
    )]
    LiveModeInvalidExpectedGenesisHash,
    #[error("live mode requires PARADENCER_LIVE_ENTRYPOINTS")]
    LiveModeRequiresEntryPoints,
    #[error("failed to parse entrypoint '{value}': {source}")]
    InvalidEntryPointAddr {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error("failed to resolve entrypoint hostname '{value}': {message}")]
    EntryPointDnsResolutionFailed { value: String, message: String },
    #[error("entrypoint hostname '{value}' resolved to no addresses")]
    EntryPointDnsNoAddresses { value: String },
    #[error("live mode entrypoint is not routable: {entrypoint}")]
    LiveModeUnroutableEntryPoint { entrypoint: std::net::SocketAddr },
    #[error("live mode ingress UDP bind address is not routable: {bind_addr}")]
    LiveModeUnroutableIngressBindAddr { bind_addr: std::net::SocketAddr },
    #[error("live mode rejects metrics.output_target='stdout'")]
    LiveModeRejectsStdoutMetricsTarget,
    #[error("live mode rejects runtime.run_for_seconds (dev-only knob)")]
    LiveModeRejectsRunForSeconds,
    #[error("metrics file target parent directory does not exist: '{path}'")]
    MetricsFileTargetParentMissing { path: PathBuf },
    #[error("metrics UDP target is not routable: {addr}")]
    MetricsUdpTargetUnroutable { addr: std::net::SocketAddr },
    #[error("storage catalog parent directory does not exist: '{path}'")]
    StorageCatalogParentMissing { path: PathBuf },
    #[error("storage snapshot catalog file is invalid at '{path}': {message}")]
    StorageCatalogInvalid { path: PathBuf, message: String },
    #[error(
        "storage strict-restore requires existing snapshot catalog file '{path}' for startup_policy '{startup_policy}'"
    )]
    StorageStrictRestoreCatalogMissing {
        path: PathBuf,
        startup_policy: &'static str,
    },
    #[error("live mode rejects default topology '{topology_name}'")]
    LiveModeRejectsDefaultTopologyName { topology_name: String },
    #[error("invalid gossip bind address '{value}': {source}")]
    InvalidGossipBindAddr {
        value: String,
        source: std::net::AddrParseError,
    },
    #[error(
        "test-validator mode cannot be used with {cluster} genesis hash — \
         use cluster.mode = \"live\" for production networks"
    )]
    DevModeRejectsProductionGenesisHash { cluster: &'static str },
    #[error(
        "test-validator mode cannot be used with {cluster} entrypoints — \
         use cluster.mode = \"live\" for production networks"
    )]
    DevModeRejectsProductionEntrypoints { cluster: &'static str },
}
