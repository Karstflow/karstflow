mod env;
mod profile;
mod types;

pub use types::MetricsProfileToml;

use crate::profile_types::NodeProfileToml;
use crate::{ConfigError, Result};
use env::{apply_http_bind_override, apply_output_target_override};
use karstflow_stages::{MetricsOutputFormat, MetricsOutputTarget};
use profile::{profile_metrics_toml, resolve_http_bind, resolve_output_target};
use std::net::SocketAddr;

pub fn build_metrics_output_format(
    profile: Option<&NodeProfileToml>,
) -> Result<MetricsOutputFormat> {
    let mut output_format = MetricsOutputFormat::JsonLines;

    if let Some(metrics_profile) = profile_metrics_toml(profile) {
        if let Some(format_value) = metrics_profile.output_format.as_deref() {
            output_format = parse_metrics_output_format(Some(format_value.to_string()))?;
        }
    }

    if let Ok(format_value) = std::env::var("KARSTFLOW_METRICS_FORMAT") {
        output_format = parse_metrics_output_format(Some(format_value))?;
    }

    Ok(output_format)
}

pub fn build_metrics_output_target(
    profile: Option<&NodeProfileToml>,
) -> Result<MetricsOutputTarget> {
    let mut output_target = resolve_output_target(profile)?;
    apply_output_target_override(&mut output_target)?;
    Ok(output_target)
}

pub fn build_metrics_http_bind(profile: Option<&NodeProfileToml>) -> Result<Option<SocketAddr>> {
    let mut metrics_http_bind = resolve_http_bind(profile)?;
    apply_http_bind_override(&mut metrics_http_bind)?;
    Ok(metrics_http_bind)
}

pub fn parse_metrics_output_format(raw: Option<String>) -> Result<MetricsOutputFormat> {
    match raw {
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "json" | "json_lines" | "jsonl" => Ok(MetricsOutputFormat::JsonLines),
            "prometheus" | "prometheus_text" | "prom" => Ok(MetricsOutputFormat::PrometheusText),
            _ => Err(ConfigError::InvalidScope {
                scope: "KARSTFLOW_METRICS_FORMAT",
                message: format!("'{value}'"),
            }),
        },
        None => Ok(MetricsOutputFormat::JsonLines),
    }
}
