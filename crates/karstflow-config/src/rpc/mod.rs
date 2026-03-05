mod env;
mod profile;
mod types;

pub use types::RpcProfileToml;

use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use env::{parse_optional_bool_env, parse_optional_socket_addr_env};
use profile::{profile_rpc_toml, resolve_rpc_bind};
use std::net::SocketAddr;

pub fn build_rpc_enabled(profile: Option<&NodeProfileToml>) -> Result<bool> {
    let mut enabled = profile_rpc_toml(profile)
        .and_then(|rpc| rpc.enabled)
        .unwrap_or(false);
    if let Some(value) = parse_optional_bool_env("KARSTFLOW_RPC_ENABLED")? {
        enabled = value;
    }
    Ok(enabled)
}

pub fn build_rpc_bind(profile: Option<&NodeProfileToml>) -> Result<Option<SocketAddr>> {
    let mut bind = resolve_rpc_bind(profile)?;
    if let Some(value) = parse_optional_socket_addr_env("KARSTFLOW_RPC_BIND")? {
        bind = Some(value);
    }
    Ok(bind)
}

pub fn build_rpc_private(profile: Option<&NodeProfileToml>) -> Result<bool> {
    let mut private = profile_rpc_toml(profile)
        .and_then(|rpc| rpc.private)
        .unwrap_or(true);
    if let Some(value) = parse_optional_bool_env("KARSTFLOW_RPC_PRIVATE")? {
        private = value;
    }
    Ok(private)
}

pub fn build_rpc_full_api(profile: Option<&NodeProfileToml>) -> Result<bool> {
    let mut full_api = profile_rpc_toml(profile)
        .and_then(|rpc| rpc.full_api)
        .unwrap_or(false);
    if let Some(value) = parse_optional_bool_env("KARSTFLOW_RPC_FULL_API")? {
        full_api = value;
    }
    Ok(full_api)
}

pub fn validate_rpc_preflight(enabled: bool, bind: Option<SocketAddr>) -> Result<()> {
    if enabled && bind.is_none() {
        return Err(ConfigError::RpcEnabledRequiresBindAddr);
    }
    Ok(())
}
