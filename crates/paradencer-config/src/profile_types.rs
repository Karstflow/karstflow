use crate::ingress::IngressPolicyToml;
use crate::metrics::MetricsProfileToml;
use crate::readiness::MainnetReadinessProfileToml;
use crate::rpc::RpcProfileToml;
use crate::runtime::RuntimeProfileToml;
use crate::storage::StorageProfileToml;
use crate::topology::TopologyProfileToml;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct NodeProfileToml {
    pub schema_version: Option<u32>,
    pub runtime: Option<RuntimeProfileToml>,
    pub topology: Option<TopologyProfileToml>,
    pub ingress_policy: Option<IngressPolicyToml>,
    pub metrics: Option<MetricsProfileToml>,
    pub rpc: Option<RpcProfileToml>,
    pub storage: Option<StorageProfileToml>,
    pub readiness: Option<MainnetReadinessProfileToml>,
}
