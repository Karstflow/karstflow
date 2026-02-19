use crate::{ConfigError, Result};
use paradencer_net::{IngressMode, IngressPolicy};

pub(super) fn apply_env_overrides(ingress_policy: &mut IngressPolicy) -> Result<()> {
    if let Ok(value) = std::env::var("PARADENCER_INGRESS_MODE") {
        ingress_policy.ingress_mode =
            IngressMode::parse(&value).ok_or_else(|| ConfigError::InvalidScope {
                scope: "ingress policy",
                message: format!(
                    "invalid PARADENCER_INGRESS_MODE '{value}', expected one of: synthetic, udp"
                ),
            })?;
    }
    if let Some(value) = parse_optional_socket_addr_env("PARADENCER_INGRESS_UDP_BIND")? {
        ingress_policy.udp_bind_address = Some(value);
    }
    if let Some(value) = parse_optional_u16_env("PARADENCER_INGRESS_UDP_QUIC_SOURCE_PORT")? {
        ingress_policy.udp_quic_source_port = Some(value);
    }
    if let Some(value) = parse_optional_u16_env("PARADENCER_INGRESS_UDP_GOSSIP_SOURCE_PORT")? {
        ingress_policy.udp_gossip_source_port = Some(value);
    }
    if let Some(value) = parse_optional_u16_env("PARADENCER_INGRESS_UDP_BUNDLE_SOURCE_PORT")? {
        ingress_policy.udp_bundle_source_port = Some(value);
    }
    if let Some(value) = parse_optional_u16_env("PARADENCER_INGRESS_UDP_RPC_SOURCE_PORT")? {
        ingress_policy.udp_rpc_source_port = Some(value);
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_UDP_MAX_PACKETS_PER_TICK")? {
        ingress_policy.udp_max_packets_per_tick = value.max(1);
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_INGRESS_MAX_PAYLOAD_BYTES")? {
        ingress_policy.max_payload_bytes = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_INGRESS_ALLOW_QUIC")? {
        ingress_policy.allow_quic_source = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_INGRESS_ALLOW_GOSSIP")? {
        ingress_policy.allow_gossip_source = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_INGRESS_ALLOW_BUNDLE")? {
        ingress_policy.allow_bundle_source = value;
    }
    if let Some(value) = parse_optional_bool_env("PARADENCER_INGRESS_ALLOW_RPC")? {
        ingress_policy.allow_rpc_source = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_INGRESS_DEDUP_WINDOW")? {
        ingress_policy.dedup_window_capacity = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_QUIC_MIN_GAP_TICKS")? {
        ingress_policy.quic_min_gap_ticks = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_GOSSIP_MIN_GAP_TICKS")? {
        ingress_policy.gossip_min_gap_ticks = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_BUNDLE_MIN_GAP_TICKS")? {
        ingress_policy.bundle_min_gap_ticks = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_RPC_MIN_GAP_TICKS")? {
        ingress_policy.rpc_min_gap_ticks = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_QUIC_BURST_CAPACITY")? {
        ingress_policy.quic_burst_capacity = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_GOSSIP_BURST_CAPACITY")? {
        ingress_policy.gossip_burst_capacity = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_BUNDLE_BURST_CAPACITY")? {
        ingress_policy.bundle_burst_capacity = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_RPC_BURST_CAPACITY")? {
        ingress_policy.rpc_burst_capacity = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_QUIC_BURST_REFILL_TICKS")? {
        ingress_policy.quic_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_GOSSIP_BURST_REFILL_TICKS")? {
        ingress_policy.gossip_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_BUNDLE_BURST_REFILL_TICKS")? {
        ingress_policy.bundle_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_RPC_BURST_REFILL_TICKS")? {
        ingress_policy.rpc_burst_refill_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_QUIC_COST_BUDGET_PER_WINDOW")? {
        ingress_policy.quic_cost_budget_per_window = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_GOSSIP_COST_BUDGET_PER_WINDOW")?
    {
        ingress_policy.gossip_cost_budget_per_window = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_BUNDLE_COST_BUDGET_PER_WINDOW")?
    {
        ingress_policy.bundle_cost_budget_per_window = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_RPC_COST_BUDGET_PER_WINDOW")? {
        ingress_policy.rpc_cost_budget_per_window = value;
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_QUIC_COST_BUDGET_WINDOW_TICKS")?
    {
        ingress_policy.quic_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) =
        parse_optional_u64_env("PARADENCER_INGRESS_GOSSIP_COST_BUDGET_WINDOW_TICKS")?
    {
        ingress_policy.gossip_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) =
        parse_optional_u64_env("PARADENCER_INGRESS_BUNDLE_COST_BUDGET_WINDOW_TICKS")?
    {
        ingress_policy.bundle_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u64_env("PARADENCER_INGRESS_RPC_COST_BUDGET_WINDOW_TICKS")?
    {
        ingress_policy.rpc_cost_budget_window_ticks = value.max(1);
    }
    if let Some(value) =
        parse_optional_usize_env("PARADENCER_INGRESS_EGRESS_RETRY_BUFFER_CAPACITY")?
    {
        ingress_policy.egress_retry_buffer_capacity = value.max(1);
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_EGRESS_RETRY_MAX_WAIT_TICKS")? {
        ingress_policy.egress_retry_max_wait_ticks = value.max(1);
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_BATCH_SIZE_PER_TICK")? {
        ingress_policy.synthetic_batch_size_per_tick = value.max(1);
    }
    if let Some(value) =
        parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_IDLE_TICKS_BETWEEN_BATCHES")?
    {
        ingress_policy.synthetic_idle_ticks_between_batches = value;
    }
    if let Some(value) = parse_optional_usize_env("PARADENCER_INGRESS_SYNTH_PAYLOAD_BYTES")? {
        ingress_policy.synthetic_payload_bytes = value.max(1);
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_SOURCE_WEIGHT_QUIC")? {
        ingress_policy.synthetic_source_weight_quic = value;
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_SOURCE_WEIGHT_GOSSIP")? {
        ingress_policy.synthetic_source_weight_gossip = value;
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_SOURCE_WEIGHT_BUNDLE")? {
        ingress_policy.synthetic_source_weight_bundle = value;
    }
    if let Some(value) = parse_optional_u32_env("PARADENCER_INGRESS_SYNTH_SOURCE_WEIGHT_RPC")? {
        ingress_policy.synthetic_source_weight_rpc = value;
    }
    Ok(())
}

fn parse_optional_usize_env(name: &str) -> Result<Option<usize>> {
    match std::env::var(name).ok() {
        Some(raw) => {
            let value = raw
                .parse::<usize>()
                .map_err(|source| ConfigError::EnvParseInt {
                    name: name.to_string(),
                    ty: "usize",
                    source,
                })?;
            if value == 0 {
                Err(ConfigError::NonPositiveValue {
                    name: name.to_string(),
                })
            } else {
                Ok(Some(value))
            }
        }
        None => Ok(None),
    }
}

fn parse_optional_bool_env(name: &str) -> Result<Option<bool>> {
    match std::env::var(name).ok() {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(Some(true)),
            "0" | "false" | "no" => Ok(Some(false)),
            _ => Err(ConfigError::InvalidBooleanValue {
                name: name.to_string(),
                value: raw,
            }),
        },
        None => Ok(None),
    }
}

fn parse_optional_u64_env(name: &str) -> Result<Option<u64>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "u64",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_u32_env(name: &str) -> Result<Option<u32>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<u32>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "u32",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_u16_env(name: &str) -> Result<Option<u16>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<u16>()
            .map(Some)
            .map_err(|source| ConfigError::EnvParseInt {
                name: name.to_string(),
                ty: "u16",
                source,
            }),
        None => Ok(None),
    }
}

fn parse_optional_socket_addr_env(name: &str) -> Result<Option<std::net::SocketAddr>> {
    match std::env::var(name).ok() {
        Some(raw) => raw
            .parse::<std::net::SocketAddr>()
            .map(Some)
            .map_err(|source| ConfigError::InvalidSocketAddr {
                name: name.to_string(),
                value: raw,
                source,
            }),
        None => Ok(None),
    }
}
