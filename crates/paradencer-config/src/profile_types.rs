use crate::ingress::IngressPolicyToml;
use crate::metrics::MetricsProfileToml;
use crate::network::NetworkProfileToml;
use crate::readiness::MainnetReadinessProfileToml;
use crate::rpc::RpcProfileToml;
use crate::runtime::RuntimeProfileToml;
use crate::storage::StorageProfileToml;
use crate::topology::TopologyProfileToml;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct NodeProfileToml {
    pub schema_version: Option<u32>,
    pub cluster: Option<ClusterProfileToml>,
    pub runtime: Option<RuntimeProfileToml>,
    pub topology: Option<TopologyProfileToml>,
    pub ingress_policy: Option<IngressPolicyToml>,
    pub metrics: Option<MetricsProfileToml>,
    pub rpc: Option<RpcProfileToml>,
    pub storage: Option<StorageProfileToml>,
    pub readiness: Option<MainnetReadinessProfileToml>,
    pub network: Option<NetworkProfileToml>,
    pub logging: Option<LoggingProfileToml>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ClusterProfileToml {
    pub mode: Option<String>,
    pub expected_genesis_hash: Option<String>,
    pub expected_shred_version: Option<u16>,
    pub entrypoints: Option<Vec<String>>,
    pub gossip_bind_addr: Option<String>,
    pub gossip_allow_private_addresses: Option<bool>,
    pub identity_keypair_path: Option<String>,
    pub genesis_path: Option<String>,
    pub snapshot_download: Option<bool>,
    pub data_dir: Option<String>,
    pub ipc_mode: Option<String>,
    pub quic_enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct LoggingProfileToml {
    pub stderr_level: Option<String>,
    pub file_path: Option<String>,
    pub file_level: Option<String>,
    pub colorize: Option<bool>,
    pub json_file: Option<bool>,
}
