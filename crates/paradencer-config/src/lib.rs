mod errors;
mod ingress;
mod metrics;
pub mod network;
mod parts;
mod profile_loader;
mod profile_schema;
mod profile_types;
mod readiness;
mod rpc;
mod runtime;
mod storage;
mod topology;

pub use crate::errors::{ConfigError, Result};
use crate::network::NetworkConfig;
use crate::parts::{
    build_ingress_policy, build_mainnet_readiness_policy, build_metrics_http_bind,
    build_metrics_output_format, build_metrics_output_target, build_network_config, build_rpc_bind,
    build_rpc_enabled, build_rpc_full_api, build_rpc_private, build_runtime_spec,
    build_storage_runtime_policy, build_topology_spec, load_node_profile_from_env,
    validate_rpc_preflight,
};
use crate::profile_loader::load_node_profile_from_file;
use crate::profile_types::NodeProfileToml;
use paradencer_core::{RuntimeSpec, TopologySpec};
use paradencer_net::{IngressMode, IngressPolicy};
use paradencer_stages::{
    MetricsOutputFormat, MetricsOutputTarget, StorageRuntimePolicy, StorageStartupPolicy,
};
use paradencer_storage::SnapshotCatalog;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMode {
    Dev,
    Live,
}

pub fn parse_cluster_mode(value: Option<String>) -> Result<ClusterMode> {
    match value {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "dev" => Ok(ClusterMode::Dev),
            "live" => Ok(ClusterMode::Live),
            _ => Err(ConfigError::InvalidClusterMode { value: raw }),
        },
        None => Ok(ClusterMode::Dev),
    }
}

pub struct NodeConfig {
    pub cluster_mode: ClusterMode,
    pub identity_keypair_path: Option<PathBuf>,
    pub expected_genesis_hash: Option<String>,
    pub expected_shred_version: Option<u16>,
    pub live_entrypoints: Vec<SocketAddr>,
    pub gossip_bind_addr: SocketAddr,
    pub runtime_spec: RuntimeSpec,
    pub topology_spec: TopologySpec,
    pub ingress_policy: IngressPolicy,
    pub metrics_output_format: MetricsOutputFormat,
    pub metrics_output_target: MetricsOutputTarget,
    pub metrics_http_bind: Option<SocketAddr>,
    pub rpc_enabled: bool,
    pub rpc_bind: Option<SocketAddr>,
    pub rpc_private: bool,
    pub rpc_full_api: bool,
    pub storage_runtime_policy: StorageRuntimePolicy,
    pub mainnet_readiness_policy: MainnetReadinessPolicy,
    pub network_config: NetworkConfig,
    /// Base directory for persistent storage (accounts, blockstore, snapshots).
    /// When `None`, the node runs in-memory only (no persistence across restarts).
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct MainnetReadinessPolicy {
    pub min_runtime_workers: usize,
    pub min_live_entrypoints: usize,
    pub min_transaction_sanitizer_stages: usize,
    pub min_shred_sanitizer_stages: usize,
    pub min_packet_stream_capacity: usize,
    pub min_shred_stream_capacity: usize,
    pub min_transaction_stream_capacity: usize,
    pub min_replay_candidate_confirmation_threshold: u32,
    pub min_replay_failed_ratio_penalty_weight: u64,
    pub require_pinned_runtime_mode: bool,
    pub require_udp_ingress_mode: bool,
    pub require_non_stdout_metrics_target: bool,
    pub require_metrics_http_bind: bool,
    pub require_fork_choice_runtime_enabled: bool,
    pub require_fail_fast_execution_errors: bool,
    pub require_fail_open_execution_error_circuit_breaker: bool,
}

impl Default for MainnetReadinessPolicy {
    fn default() -> Self {
        Self {
            min_runtime_workers: 4,
            min_live_entrypoints: 1,
            min_transaction_sanitizer_stages: 2,
            min_shred_sanitizer_stages: 2,
            min_packet_stream_capacity: 4096,
            min_shred_stream_capacity: 4096,
            min_transaction_stream_capacity: 8192,
            min_replay_candidate_confirmation_threshold: 2,
            min_replay_failed_ratio_penalty_weight: 50,
            require_pinned_runtime_mode: true,
            require_udp_ingress_mode: true,
            require_non_stdout_metrics_target: true,
            require_metrics_http_bind: false,
            require_fork_choice_runtime_enabled: false,
            require_fail_fast_execution_errors: false,
            require_fail_open_execution_error_circuit_breaker: false,
        }
    }
}

impl NodeConfig {
    pub fn from_env() -> Result<Self> {
        let profile = load_node_profile_from_env()?;
        Self::from_profile(profile.as_ref())
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let profile = load_node_profile_from_file(path)?;
        Self::from_profile(Some(&profile))
    }

    pub fn from_profile(profile: Option<&NodeProfileToml>) -> Result<Self> {
        let config = Self::build(profile)?;
        config.validate_preflight()?;
        Ok(config)
    }

    fn build(profile: Option<&NodeProfileToml>) -> Result<Self> {
        let cluster_mode = parse_cluster_mode(std::env::var("PARADENCER_CLUSTER_MODE").ok())?;
        let identity_keypair_path = std::env::var("PARADENCER_IDENTITY_KEYPAIR_PATH")
            .ok()
            .map(PathBuf::from);
        let expected_genesis_hash = std::env::var("PARADENCER_EXPECTED_GENESIS_HASH").ok();
        let expected_shred_version = parse_expected_shred_version_from_env()?;
        let live_entrypoints =
            parse_live_entrypoints(std::env::var("PARADENCER_LIVE_ENTRYPOINTS").ok())?;
        let gossip_bind_addr = parse_gossip_bind_addr_from_env()?;
        let data_dir = std::env::var("PARADENCER_DATA_DIR").ok().map(PathBuf::from);

        Ok(Self {
            cluster_mode,
            identity_keypair_path,
            expected_genesis_hash,
            expected_shred_version,
            live_entrypoints,
            gossip_bind_addr,
            runtime_spec: build_runtime_spec(profile)?,
            topology_spec: build_topology_spec(profile)?,
            ingress_policy: build_ingress_policy(profile)?,
            metrics_output_format: build_metrics_output_format(profile)?,
            metrics_output_target: build_metrics_output_target(profile)?,
            metrics_http_bind: build_metrics_http_bind(profile)?,
            rpc_enabled: build_rpc_enabled(profile)?,
            rpc_bind: build_rpc_bind(profile)?,
            rpc_private: build_rpc_private(profile)?,
            rpc_full_api: build_rpc_full_api(profile)?,
            storage_runtime_policy: build_storage_runtime_policy(profile)?,
            mainnet_readiness_policy: build_mainnet_readiness_policy(profile)?,
            network_config: build_network_config(profile.and_then(|p| p.network.as_ref())),
            data_dir,
        })
    }

    /// TPU (transaction processing unit) bind address.
    ///
    /// Defaults to gossip port + 2, following Solana port conventions.
    pub fn tpu_bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.gossip_bind_addr.ip(),
            self.gossip_bind_addr.port().wrapping_add(2),
        )
    }

    /// TPU QUIC bind address for client connections.
    ///
    /// Defaults to gossip port + 4, following Solana port conventions.
    pub fn tpu_quic_bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.gossip_bind_addr.ip(),
            self.gossip_bind_addr.port().wrapping_add(4),
        )
    }

    /// Repair protocol bind address.
    ///
    /// Defaults to gossip port + 6, following Solana port conventions.
    pub fn repair_bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.gossip_bind_addr.ip(),
            self.gossip_bind_addr.port().wrapping_add(6),
        )
    }

    fn validate_preflight(&self) -> Result<()> {
        validate_metrics_target_preflight(&self.metrics_output_target)?;
        validate_storage_startup_preflight(&self.storage_runtime_policy)?;
        validate_rpc_preflight(self.rpc_enabled, self.rpc_bind)?;

        if self.cluster_mode != ClusterMode::Live {
            return Ok(());
        }

        if self.ingress_policy.ingress_mode != IngressMode::Udp {
            return Err(ConfigError::LiveModeRequiresUdpIngressMode);
        }
        let identity_path = self
            .identity_keypair_path
            .as_ref()
            .ok_or(ConfigError::LiveModeRequiresIdentityKeypairPath)?;
        if !identity_path.exists() {
            return Err(ConfigError::LiveModeIdentityKeypairPathMissing {
                path: identity_path.clone(),
            });
        }
        validate_identity_keypair_file(identity_path)?;
        if self
            .expected_genesis_hash
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            return Err(ConfigError::LiveModeRequiresExpectedGenesisHash);
        }
        let expected_genesis_hash = self.expected_genesis_hash.as_deref().unwrap_or_default();
        if !is_valid_genesis_hash(expected_genesis_hash) {
            return Err(ConfigError::LiveModeInvalidExpectedGenesisHash);
        }
        let expected_shred_version = self
            .expected_shred_version
            .ok_or(ConfigError::LiveModeRequiresExpectedShredVersion)?;
        if expected_shred_version == 0 {
            return Err(ConfigError::LiveModeRequiresPositiveShredVersion);
        }
        if self.live_entrypoints.is_empty() {
            return Err(ConfigError::LiveModeRequiresEntryPoints);
        }
        for entrypoint in &self.live_entrypoints {
            if !is_routable_socket_addr(entrypoint) {
                return Err(ConfigError::LiveModeUnroutableEntryPoint {
                    entrypoint: *entrypoint,
                });
            }
        }
        let bind_addr = self
            .ingress_policy
            .udp_bind_address
            .ok_or(ConfigError::LiveModeRequiresUdpIngressMode)?;
        if !is_routable_bind_addr(&bind_addr) {
            return Err(ConfigError::LiveModeUnroutableIngressBindAddr { bind_addr });
        }
        validate_live_runtime_spec(&self.runtime_spec)?;
        if matches!(self.metrics_output_target, MetricsOutputTarget::Stdout) {
            return Err(ConfigError::LiveModeRejectsStdoutMetricsTarget);
        }
        if self.topology_spec.topology_name == "default-pipeline" {
            return Err(ConfigError::LiveModeRejectsDefaultTopologyName {
                topology_name: self.topology_spec.topology_name.clone(),
            });
        }

        Ok(())
    }
}

fn parse_gossip_bind_addr_from_env() -> Result<SocketAddr> {
    match std::env::var("PARADENCER_GOSSIP_BIND_ADDR").ok() {
        Some(raw) => raw
            .parse::<SocketAddr>()
            .map_err(|source| ConfigError::InvalidGossipBindAddr { value: raw, source }),
        None => Ok("0.0.0.0:8001".parse().unwrap()),
    }
}

fn parse_expected_shred_version_from_env() -> Result<Option<u16>> {
    match std::env::var("PARADENCER_EXPECTED_SHRED_VERSION").ok() {
        Some(raw) => raw
            .parse::<u16>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: "PARADENCER_EXPECTED_SHRED_VERSION".to_string(),
                ty: "u16",
                source,
            }),
        None => Ok(None),
    }
}

pub fn parse_live_entrypoints(value: Option<String>) -> Result<Vec<SocketAddr>> {
    let Some(raw) = value else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<SocketAddr>()
                .map_err(|source| ConfigError::InvalidEntryPointAddr {
                    value: entry.to_string(),
                    source,
                })
        })
        .collect()
}

pub fn is_valid_genesis_hash(value: &str) -> bool {
    value.len() == 64
        && value.chars().all(|character| {
            character.is_ascii_digit() || matches!(character, 'a' | 'b' | 'c' | 'd' | 'e' | 'f')
        })
}

pub fn is_routable_socket_addr(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    let ip = addr.ip();
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast())
}

pub fn is_routable_bind_addr(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    let ip = addr.ip();
    !(ip.is_loopback() || ip.is_multicast())
}

pub fn validate_identity_keypair_file(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::FileRead {
        kind: "identity keypair",
        path: path.to_path_buf(),
        source,
    })?;

    let bytes: Vec<u8> = serde_json::from_str(&raw).map_err(|source| {
        ConfigError::LiveModeIdentityKeypairInvalidFormat {
            path: path.to_path_buf(),
            message: source.to_string(),
        }
    })?;
    if bytes.len() != 64 {
        return Err(ConfigError::LiveModeIdentityKeypairInvalidLength {
            path: path.to_path_buf(),
            found: bytes.len(),
            expected: 64,
        });
    }

    Ok(())
}

/// Validator identity holding the Ed25519 secret key and derived public key.
///
/// The 64-byte Solana keypair format stores `[secret_key(32) || public_key(32)]`.
/// The secret key is the Ed25519 seed; the public key is derived from it.
#[derive(Clone)]
pub struct ValidatorIdentity {
    /// Ed25519 secret key (32-byte seed).
    secret_key: [u8; 32],
    /// Ed25519 public key (derived from secret key).
    pubkey: [u8; 32],
}

impl ValidatorIdentity {
    /// Create an identity from raw key components.
    pub fn new(secret_key: [u8; 32], pubkey: [u8; 32]) -> Self {
        Self { secret_key, pubkey }
    }

    /// The 32-byte Ed25519 secret key (seed).
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }

    /// The 32-byte Ed25519 public key.
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }
}

impl std::fmt::Debug for ValidatorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret key.
        write!(
            f,
            "ValidatorIdentity({:02x}{:02x}{:02x}{:02x}..)",
            self.pubkey[0], self.pubkey[1], self.pubkey[2], self.pubkey[3]
        )
    }
}

/// Load a validator identity keypair from a Solana-format JSON file.
///
/// The file contains a JSON array of 64 bytes: `[secret_key(32), public_key(32)]`.
/// Returns the parsed identity with both secret and public key components.
pub fn load_identity_keypair(path: &Path) -> Result<ValidatorIdentity> {
    let raw = fs::read_to_string(path).map_err(|source| ConfigError::FileRead {
        kind: "identity keypair",
        path: path.to_path_buf(),
        source,
    })?;

    let bytes: Vec<u8> = serde_json::from_str(&raw).map_err(|source| {
        ConfigError::LiveModeIdentityKeypairInvalidFormat {
            path: path.to_path_buf(),
            message: source.to_string(),
        }
    })?;
    if bytes.len() != 64 {
        return Err(ConfigError::LiveModeIdentityKeypairInvalidLength {
            path: path.to_path_buf(),
            found: bytes.len(),
            expected: 64,
        });
    }

    let mut secret_key = [0u8; 32];
    let mut pubkey = [0u8; 32];
    secret_key.copy_from_slice(&bytes[..32]);
    pubkey.copy_from_slice(&bytes[32..]);

    Ok(ValidatorIdentity::new(secret_key, pubkey))
}

pub fn validate_live_runtime_spec(runtime_spec: &RuntimeSpec) -> Result<()> {
    if runtime_spec.run_for_seconds.is_some() {
        return Err(ConfigError::LiveModeRejectsRunForSeconds);
    }
    Ok(())
}

pub fn validate_storage_startup_preflight(
    storage_runtime_policy: &StorageRuntimePolicy,
) -> Result<()> {
    if let Some(catalog_path) = storage_runtime_policy.snapshot_catalog_path.as_ref() {
        if let Some(parent) = catalog_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(ConfigError::StorageCatalogParentMissing {
                    path: parent.to_path_buf(),
                });
            }
        }
        if catalog_path.exists() {
            SnapshotCatalog::load_from_file(catalog_path).map_err(|error| {
                ConfigError::StorageCatalogInvalid {
                    path: catalog_path.clone(),
                    message: error.to_string(),
                }
            })?;
        }
    }

    let strict_restore_required = match storage_runtime_policy.startup_policy {
        StorageStartupPolicy::RestoreLatestIfAvailable
            if storage_runtime_policy
                .startup_strict_restore_policy
                .restore_latest_requires_snapshot =>
        {
            Some("restore_latest_if_available")
        }
        StorageStartupPolicy::RestoreSpecificIfAvailable { .. }
            if storage_runtime_policy
                .startup_strict_restore_policy
                .restore_specific_requires_snapshot =>
        {
            Some("restore_specific_if_available")
        }
        _ => None,
    };

    if let Some(startup_policy) = strict_restore_required {
        let catalog_path = storage_runtime_policy
            .snapshot_catalog_path
            .as_ref()
            .ok_or(
                ConfigError::StorageStartupStrictRestoreRequiresCatalogPath { startup_policy },
            )?;
        if !catalog_path.exists() {
            return Err(ConfigError::StorageStrictRestoreCatalogMissing {
                path: catalog_path.clone(),
                startup_policy,
            });
        }
    }

    Ok(())
}

pub fn validate_metrics_target_preflight(
    metrics_output_target: &MetricsOutputTarget,
) -> Result<()> {
    match metrics_output_target {
        MetricsOutputTarget::Stdout => Ok(()),
        MetricsOutputTarget::File(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return Err(ConfigError::MetricsFileTargetParentMissing {
                        path: parent.to_path_buf(),
                    });
                }
            }
            Ok(())
        }
        MetricsOutputTarget::Udp(addr) => {
            if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
                return Err(ConfigError::MetricsUdpTargetUnroutable { addr: *addr });
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
