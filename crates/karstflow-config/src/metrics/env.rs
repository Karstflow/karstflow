use crate::{ConfigError, Result};
use karstflow_stages::MetricsOutputTarget;
use std::net::SocketAddr;
use std::path::PathBuf;

pub(super) fn apply_output_target_override(output_target: &mut MetricsOutputTarget) -> Result<()> {
    if let Ok(target_value) = std::env::var("KARSTFLOW_METRICS_TARGET") {
        match target_value.to_ascii_lowercase().as_str() {
            "stdout" => *output_target = MetricsOutputTarget::Stdout,
            "file" => {
                let file_path = std::env::var("KARSTFLOW_METRICS_FILE_PATH")
                    .map_err(|_| ConfigError::MetricsEnvFileTargetRequiresPath)?;
                *output_target = MetricsOutputTarget::File(PathBuf::from(file_path));
            }
            "udp" => {
                let udp_addr = std::env::var("KARSTFLOW_METRICS_UDP_ADDR")
                    .map_err(|_| ConfigError::MetricsEnvUdpTargetRequiresAddress)?;
                *output_target = MetricsOutputTarget::Udp(udp_addr.parse().map_err(|source| {
                    ConfigError::InvalidSocketAddr {
                        name: "KARSTFLOW_METRICS_UDP_ADDR".to_string(),
                        value: udp_addr,
                        source,
                    }
                })?);
            }
            _ => {
                return Err(ConfigError::InvalidScope {
                    scope: "KARSTFLOW_METRICS_TARGET",
                    message: format!("'{target_value}'"),
                });
            }
        }
    }

    Ok(())
}

pub(super) fn apply_http_bind_override(metrics_http_bind: &mut Option<SocketAddr>) -> Result<()> {
    if let Ok(bind_value) = std::env::var("KARSTFLOW_METRICS_HTTP_BIND") {
        *metrics_http_bind = Some(bind_value.parse::<SocketAddr>().map_err(|source| {
            ConfigError::InvalidSocketAddr {
                name: "KARSTFLOW_METRICS_HTTP_BIND".to_string(),
                value: bind_value,
                source,
            }
        })?);
    }

    Ok(())
}
