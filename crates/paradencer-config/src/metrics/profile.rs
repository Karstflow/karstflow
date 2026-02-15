use super::types::MetricsProfileToml;
use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use paradencer_stages::MetricsOutputTarget;
use std::net::SocketAddr;
use std::path::PathBuf;

pub(super) fn profile_metrics_toml(
    profile: Option<&NodeProfileToml>,
) -> Option<&MetricsProfileToml> {
    profile.and_then(|node_profile| node_profile.metrics.as_ref())
}

pub(super) fn resolve_output_target(
    profile: Option<&NodeProfileToml>,
) -> Result<MetricsOutputTarget> {
    match profile_metrics_toml(profile) {
        Some(metrics_profile) => match metrics_profile.output_target.as_deref() {
            Some("file") => {
                let path = metrics_profile
                    .file_path
                    .as_ref()
                    .ok_or(ConfigError::MetricsFileTargetRequiresPath)?;
                Ok(MetricsOutputTarget::File(PathBuf::from(path)))
            }
            Some("udp") => {
                let udp_addr = metrics_profile
                    .udp_addr
                    .as_ref()
                    .ok_or(ConfigError::MetricsUdpTargetRequiresAddress)?;
                Ok(MetricsOutputTarget::Udp(udp_addr.parse().map_err(
                    |source| ConfigError::InvalidSocketAddr {
                        name: "metrics.udp_addr".to_string(),
                        value: udp_addr.clone(),
                        source,
                    },
                )?))
            }
            Some("stdout") | None => Ok(MetricsOutputTarget::Stdout),
            Some(other) => Err(ConfigError::InvalidScope {
                scope: "metrics.output_target",
                message: format!("'{other}'"),
            }),
        },
        None => Ok(MetricsOutputTarget::Stdout),
    }
}

pub(super) fn resolve_http_bind(profile: Option<&NodeProfileToml>) -> Result<Option<SocketAddr>> {
    profile_metrics_toml(profile)
        .and_then(|metrics| metrics.http_bind.as_ref())
        .map(|bind| {
            bind.parse::<SocketAddr>()
                .map_err(|source| ConfigError::InvalidSocketAddr {
                    name: "metrics.http_bind".to_string(),
                    value: bind.to_string(),
                    source,
                })
        })
        .transpose()
}
