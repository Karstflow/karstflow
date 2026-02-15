use super::types::RpcProfileToml;
use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use std::net::SocketAddr;

pub(super) fn profile_rpc_toml(profile: Option<&NodeProfileToml>) -> Option<&RpcProfileToml> {
    profile.and_then(|node_profile| node_profile.rpc.as_ref())
}

pub(super) fn resolve_rpc_bind(profile: Option<&NodeProfileToml>) -> Result<Option<SocketAddr>> {
    profile_rpc_toml(profile)
        .and_then(|rpc| rpc.bind.as_ref())
        .map(|bind| {
            bind.parse::<SocketAddr>()
                .map_err(|source| ConfigError::InvalidSocketAddr {
                    name: "rpc.bind".to_string(),
                    value: bind.to_string(),
                    source,
                })
        })
        .transpose()
}
