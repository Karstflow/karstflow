use crate::{ConfigError, Result};
use std::net::SocketAddr;

pub(super) fn parse_optional_bool_env(name: &'static str) -> Result<Option<bool>> {
    match std::env::var(name).ok() {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            _ => Err(ConfigError::InvalidBooleanValue {
                name: name.to_string(),
                value: raw,
            }),
        },
        None => Ok(None),
    }
}

pub(super) fn parse_optional_socket_addr_env(name: &'static str) -> Result<Option<SocketAddr>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            raw.parse::<SocketAddr>()
                .map(Some)
                .map_err(|source| ConfigError::InvalidSocketAddr {
                    name: name.to_string(),
                    value: raw,
                    source,
                })
        }
        None => Ok(None),
    }
}
