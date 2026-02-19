use super::types::IngressPolicyToml;
use crate::{ConfigError, Result};
use paradencer_net::{IngressMode, IngressPolicy};
use std::fs;
use std::path::Path;

pub(super) fn load_ingress_policy_from_file(path: &Path) -> Result<IngressPolicyToml> {
    let policy_toml = fs::read_to_string(path).map_err(|source| ConfigError::FileRead {
        kind: "ingress policy",
        path: path.to_path_buf(),
        source,
    })?;
    let profile = toml::from_str::<IngressPolicyToml>(&policy_toml).map_err(|source| {
        ConfigError::FileTomlParse {
            kind: "ingress policy",
            path: path.to_path_buf(),
            message: source.to_string(),
        }
    })?;
    super::migrate_ingress_policy_schema(profile)
}

pub(super) fn apply_profile(
    ingress_policy: &mut IngressPolicy,
    profile: &IngressPolicyToml,
) -> Result<()> {
    if let Some(value) = profile.ingress_mode.as_deref() {
        ingress_policy.ingress_mode =
            IngressMode::parse(value).ok_or_else(|| ConfigError::InvalidScope {
                scope: "ingress policy",
                message: format!("invalid ingress_mode '{value}', expected one of: synthetic, udp"),
            })?;
    }
    if let Some(value) = profile.udp_bind_address.as_deref() {
        ingress_policy.udp_bind_address =
            Some(value.parse::<std::net::SocketAddr>().map_err(|source| {
                ConfigError::InvalidSocketAddr {
                    name: "ingress.udp_bind_address".to_string(),
                    value: value.to_string(),
                    source,
                }
            })?);
    }
    if let Some(value) = profile.udp_quic_source_port {
        ingress_policy.udp_quic_source_port = Some(value);
    }
    if let Some(value) = profile.udp_gossip_source_port {
        ingress_policy.udp_gossip_source_port = Some(value);
    }
    if let Some(value) = profile.udp_bundle_source_port {
        ingress_policy.udp_bundle_source_port = Some(value);
    }
    if let Some(value) = profile.udp_rpc_source_port {
        ingress_policy.udp_rpc_source_port = Some(value);
    }
    if let Some(value) = profile.udp_max_packets_per_tick {
        ingress_policy.udp_max_packets_per_tick = value.max(1);
    }
    if let Some(value) = profile.max_payload_bytes {
        ingress_policy.max_payload_bytes = value;
    }
    if let Some(value) = profile.allow_quic_source {
        ingress_policy.allow_quic_source = value;
    }
    if let Some(value) = profile.allow_gossip_source {
        ingress_policy.allow_gossip_source = value;
    }
    if let Some(value) = profile.allow_bundle_source {
        ingress_policy.allow_bundle_source = value;
    }
    if let Some(value) = profile.allow_rpc_source {
        ingress_policy.allow_rpc_source = value;
    }
    if let Some(value) = profile.dedup_window_capacity {
        ingress_policy.dedup_window_capacity = value;
    }
    if let Some(value) = profile.quic_min_gap_ticks {
        ingress_policy.quic_min_gap_ticks = value;
    }
    if let Some(value) = profile.gossip_min_gap_ticks {
        ingress_policy.gossip_min_gap_ticks = value;
    }
    if let Some(value) = profile.bundle_min_gap_ticks {
        ingress_policy.bundle_min_gap_ticks = value;
    }
    if let Some(value) = profile.rpc_min_gap_ticks {
        ingress_policy.rpc_min_gap_ticks = value;
    }
    if let Some(value) = profile.quic_burst_capacity {
        ingress_policy.quic_burst_capacity = value;
    }
    if let Some(value) = profile.gossip_burst_capacity {
        ingress_policy.gossip_burst_capacity = value;
    }
    if let Some(value) = profile.bundle_burst_capacity {
        ingress_policy.bundle_burst_capacity = value;
    }
    if let Some(value) = profile.rpc_burst_capacity {
        ingress_policy.rpc_burst_capacity = value;
    }
    if let Some(value) = profile.quic_burst_refill_ticks {
        ingress_policy.quic_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = profile.gossip_burst_refill_ticks {
        ingress_policy.gossip_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = profile.bundle_burst_refill_ticks {
        ingress_policy.bundle_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = profile.rpc_burst_refill_ticks {
        ingress_policy.rpc_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = profile.quic_cost_budget_per_window {
        ingress_policy.quic_cost_budget_per_window = value;
    }
    if let Some(value) = profile.gossip_cost_budget_per_window {
        ingress_policy.gossip_cost_budget_per_window = value;
    }
    if let Some(value) = profile.bundle_cost_budget_per_window {
        ingress_policy.bundle_cost_budget_per_window = value;
    }
    if let Some(value) = profile.rpc_cost_budget_per_window {
        ingress_policy.rpc_cost_budget_per_window = value;
    }
    if let Some(value) = profile.quic_cost_budget_window_ticks {
        ingress_policy.quic_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) = profile.gossip_cost_budget_window_ticks {
        ingress_policy.gossip_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) = profile.bundle_cost_budget_window_ticks {
        ingress_policy.bundle_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) = profile.rpc_cost_budget_window_ticks {
        ingress_policy.rpc_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) = profile.egress_retry_buffer_capacity {
        ingress_policy.egress_retry_buffer_capacity = value.max(1);
    }
    if let Some(value) = profile.egress_retry_max_wait_ticks {
        ingress_policy.egress_retry_max_wait_ticks = value.max(1);
    }
    if let Some(value) = profile.synthetic_batch_size_per_tick {
        ingress_policy.synthetic_batch_size_per_tick = value.max(1);
    }
    if let Some(value) = profile.synthetic_idle_ticks_between_batches {
        ingress_policy.synthetic_idle_ticks_between_batches = value;
    }
    if let Some(value) = profile.synthetic_payload_bytes {
        ingress_policy.synthetic_payload_bytes = value.max(1);
    }
    if let Some(value) = profile.synthetic_source_weight_quic {
        ingress_policy.synthetic_source_weight_quic = value;
    }
    if let Some(value) = profile.synthetic_source_weight_gossip {
        ingress_policy.synthetic_source_weight_gossip = value;
    }
    if let Some(value) = profile.synthetic_source_weight_bundle {
        ingress_policy.synthetic_source_weight_bundle = value;
    }
    if let Some(value) = profile.synthetic_source_weight_rpc {
        ingress_policy.synthetic_source_weight_rpc = value;
    }
    Ok(())
}
