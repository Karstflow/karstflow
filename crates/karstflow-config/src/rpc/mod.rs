mod env;
mod profile;
mod types;

pub use types::RpcProfileToml;

use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use env::{parse_optional_bool_env, parse_optional_socket_addr_env};
use profile::{profile_rpc_toml, resolve_rpc_bind, resolve_rpc_ws_bind};
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

pub fn build_rpc_ws_bind(
    profile: Option<&NodeProfileToml>,
    rpc_bind: Option<SocketAddr>,
) -> Result<Option<SocketAddr>> {
    // Explicit env var takes highest priority.
    if let Some(value) = parse_optional_socket_addr_env("KARSTFLOW_RPC_WS_BIND")? {
        return Ok(Some(value));
    }
    // TOML config next.
    if let Some(value) = resolve_rpc_ws_bind(profile)? {
        return Ok(Some(value));
    }
    // Default: RPC port + 1 (e.g. 8899 → 8900, matching Solana convention).
    Ok(rpc_bind.map(|addr| SocketAddr::new(addr.ip(), addr.port() + 1)))
}

pub fn validate_rpc_preflight(enabled: bool, bind: Option<SocketAddr>) -> Result<()> {
    if enabled && bind.is_none() {
        return Err(ConfigError::RpcEnabledRequiresBindAddr);
    }
    Ok(())
}
