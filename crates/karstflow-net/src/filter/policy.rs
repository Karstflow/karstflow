use super::domain::IngressSource;
use crate::IngressError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    Synthetic,
    Udp,
}

impl IngressMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "synthetic" => Some(Self::Synthetic),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngressPolicy {
    pub ingress_mode: IngressMode,
    pub udp_bind_address: Option<SocketAddr>,
    pub udp_quic_source_port: Option<u16>,
    pub udp_gossip_source_port: Option<u16>,
    pub udp_bundle_source_port: Option<u16>,
    pub udp_rpc_source_port: Option<u16>,
    pub udp_max_packets_per_tick: u32,
    pub max_payload_bytes: usize,
    pub allow_quic_source: bool,
    pub allow_gossip_source: bool,
    pub allow_bundle_source: bool,
    pub allow_rpc_source: bool,
    pub dedup_window_capacity: usize,
    pub quic_min_gap_ticks: u64,
    pub gossip_min_gap_ticks: u64,
    pub bundle_min_gap_ticks: u64,
    pub rpc_min_gap_ticks: u64,
    pub quic_burst_capacity: u64,
    pub gossip_burst_capacity: u64,
    pub bundle_burst_capacity: u64,
    pub rpc_burst_capacity: u64,
    pub quic_burst_refill_ticks: u64,
    pub gossip_burst_refill_ticks: u64,
    pub bundle_burst_refill_ticks: u64,
    pub rpc_burst_refill_ticks: u64,
    pub quic_cost_budget_per_window: u64,
    pub gossip_cost_budget_per_window: u64,
    pub bundle_cost_budget_per_window: u64,
    pub rpc_cost_budget_per_window: u64,
    pub quic_cost_budget_window_ticks: u64,
    pub gossip_cost_budget_window_ticks: u64,
    pub bundle_cost_budget_window_ticks: u64,
    pub rpc_cost_budget_window_ticks: u64,
    pub egress_retry_buffer_capacity: usize,
    pub egress_retry_max_wait_ticks: u32,
    pub synthetic_batch_size_per_tick: u32,
    pub synthetic_idle_ticks_between_batches: u32,
    pub synthetic_payload_bytes: usize,
    pub synthetic_source_weight_quic: u32,
    pub synthetic_source_weight_gossip: u32,
    pub synthetic_source_weight_bundle: u32,
    pub synthetic_source_weight_rpc: u32,
}

impl IngressPolicy {
    pub fn validate(&self) -> Result<(), IngressError> {
        if self.max_payload_bytes == 0 {
            return Err(IngressError::MaxPayloadMustBePositive);
        }
        if self.dedup_window_capacity == 0 {
            return Err(IngressError::DedupWindowMustBePositive);
        }
        if self.egress_retry_buffer_capacity == 0 {
            return Err(IngressError::EgressRetryBufferCapacityMustBePositive);
        }
        if self.egress_retry_max_wait_ticks == 0 {
            return Err(IngressError::EgressRetryMaxWaitTicksMustBePositive);
        }
        match self.ingress_mode {
            IngressMode::Synthetic => {
                if self.synthetic_batch_size_per_tick == 0 {
                    return Err(IngressError::SyntheticBatchSizeMustBePositive);
                }
                if self.synthetic_payload_bytes == 0 {
                    return Err(IngressError::SyntheticPayloadBytesMustBePositive);
                }
                if self
                    .synthetic_source_weight_quic
                    .saturating_add(self.synthetic_source_weight_gossip)
                    .saturating_add(self.synthetic_source_weight_bundle)
                    .saturating_add(self.synthetic_source_weight_rpc)
                    == 0
                {
                    return Err(IngressError::SyntheticSourceWeightsMustHavePositiveTotal);
                }
            }
            IngressMode::Udp => {
                if self.udp_bind_address.is_none() {
                    return Err(IngressError::UdpIngressModeRequiresBindAddress);
                }
                if self.udp_max_packets_per_tick == 0 {
                    return Err(IngressError::UdpMaxPacketsPerTickMustBePositive);
                }
            }
        }
        Ok(())
    }

    pub fn source_is_allowed(&self, source: IngressSource) -> bool {
        match source {
            IngressSource::Quic => self.allow_quic_source,
            IngressSource::Gossip => self.allow_gossip_source,
            IngressSource::Bundle => self.allow_bundle_source,
            IngressSource::Rpc => self.allow_rpc_source,
        }
    }

    pub fn source_min_gap_ticks(&self, source: IngressSource) -> u64 {
        match source {
            IngressSource::Quic => self.quic_min_gap_ticks,
            IngressSource::Gossip => self.gossip_min_gap_ticks,
            IngressSource::Bundle => self.bundle_min_gap_ticks,
            IngressSource::Rpc => self.rpc_min_gap_ticks,
        }
    }

    pub fn source_burst_capacity(&self, source: IngressSource) -> u64 {
        match source {
            IngressSource::Quic => self.quic_burst_capacity,
            IngressSource::Gossip => self.gossip_burst_capacity,
            IngressSource::Bundle => self.bundle_burst_capacity,
            IngressSource::Rpc => self.rpc_burst_capacity,
        }
    }

    pub fn source_burst_refill_ticks(&self, source: IngressSource) -> u64 {
        match source {
            IngressSource::Quic => self.quic_burst_refill_ticks,
            IngressSource::Gossip => self.gossip_burst_refill_ticks,
            IngressSource::Bundle => self.bundle_burst_refill_ticks,
            IngressSource::Rpc => self.rpc_burst_refill_ticks,
        }
    }

    pub fn source_cost_budget_per_window(&self, source: IngressSource) -> u64 {
        match source {
            IngressSource::Quic => self.quic_cost_budget_per_window,
            IngressSource::Gossip => self.gossip_cost_budget_per_window,
            IngressSource::Bundle => self.bundle_cost_budget_per_window,
            IngressSource::Rpc => self.rpc_cost_budget_per_window,
        }
    }

    pub fn source_cost_budget_window_ticks(&self, source: IngressSource) -> u64 {
        match source {
            IngressSource::Quic => self.quic_cost_budget_window_ticks,
            IngressSource::Gossip => self.gossip_cost_budget_window_ticks,
            IngressSource::Bundle => self.bundle_cost_budget_window_ticks,
            IngressSource::Rpc => self.rpc_cost_budget_window_ticks,
        }
    }

    pub fn synthetic_source_for_cursor(&self, cursor: u64) -> IngressSource {
        let total_weight = self.synthetic_source_weight_quic as u64
            + self.synthetic_source_weight_gossip as u64
            + self.synthetic_source_weight_bundle as u64
            + self.synthetic_source_weight_rpc as u64;
        let bounded_total = total_weight.max(1);
        let bucket = cursor % bounded_total;
        let quic_limit = self.synthetic_source_weight_quic as u64;
        let gossip_limit = quic_limit + self.synthetic_source_weight_gossip as u64;
        let bundle_limit = gossip_limit + self.synthetic_source_weight_bundle as u64;
        if bucket < quic_limit {
            IngressSource::Quic
        } else if bucket < gossip_limit {
            IngressSource::Gossip
        } else if bucket < bundle_limit {
            IngressSource::Bundle
        } else {
            IngressSource::Rpc
        }
    }

    pub fn classify_udp_source_port(&self, source_port: u16) -> IngressSource {
        if self.udp_gossip_source_port == Some(source_port) {
            IngressSource::Gossip
        } else if self.udp_bundle_source_port == Some(source_port) {
            IngressSource::Bundle
        } else if self.udp_rpc_source_port == Some(source_port) {
            IngressSource::Rpc
        } else {
            IngressSource::Quic
        }
    }
}

#[cfg(test)]
impl IngressPolicy {
    /// Test helper: creates a valid default policy suitable for unit tests.
    fn test_default() -> Self {
        Self::default()
    }

    fn test_udp() -> Self {
        Self {
            ingress_mode: IngressMode::Udp,
            udp_bind_address: Some("127.0.0.1:9000".parse().unwrap()),
            udp_max_packets_per_tick: 64,
            udp_quic_source_port: Some(9001),
            udp_gossip_source_port: Some(9002),
            udp_bundle_source_port: Some(9003),
            udp_rpc_source_port: Some(9004),
            ..Self::default()
        }
    }
}

impl Default for IngressPolicy {
    fn default() -> Self {
        Self {
            ingress_mode: IngressMode::Synthetic,
            udp_bind_address: None,
            udp_quic_source_port: None,
            udp_gossip_source_port: None,
            udp_bundle_source_port: None,
            udp_rpc_source_port: None,
            udp_max_packets_per_tick: 64,
            max_payload_bytes: 1232,
            allow_quic_source: true,
            allow_gossip_source: true,
            allow_bundle_source: true,
            allow_rpc_source: true,
            dedup_window_capacity: 32_768,
            quic_min_gap_ticks: 0,
            gossip_min_gap_ticks: 0,
            bundle_min_gap_ticks: 0,
            rpc_min_gap_ticks: 0,
            quic_burst_capacity: 0,
            gossip_burst_capacity: 0,
            bundle_burst_capacity: 0,
            rpc_burst_capacity: 0,
            quic_burst_refill_ticks: 1,
            gossip_burst_refill_ticks: 1,
            bundle_burst_refill_ticks: 1,
            rpc_burst_refill_ticks: 1,
            quic_cost_budget_per_window: 0,
            gossip_cost_budget_per_window: 0,
            bundle_cost_budget_per_window: 0,
            rpc_cost_budget_per_window: 0,
            quic_cost_budget_window_ticks: 1,
            gossip_cost_budget_window_ticks: 1,
            bundle_cost_budget_window_ticks: 1,
            rpc_cost_budget_window_ticks: 1,
            egress_retry_buffer_capacity: 1024,
            egress_retry_max_wait_ticks: 6,
            synthetic_batch_size_per_tick: 1,
            synthetic_idle_ticks_between_batches: 0,
            synthetic_payload_bytes: 1200,
            synthetic_source_weight_quic: 1,
            synthetic_source_weight_gossip: 0,
            synthetic_source_weight_bundle: 0,
            synthetic_source_weight_rpc: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_mode_parse_synthetic() {
        assert_eq!(
            IngressMode::parse("synthetic"),
            Some(IngressMode::Synthetic)
        );
        assert_eq!(
            IngressMode::parse("SYNTHETIC"),
            Some(IngressMode::Synthetic)
        );
    }

    #[test]
    fn ingress_mode_parse_udp() {
        assert_eq!(IngressMode::parse("udp"), Some(IngressMode::Udp));
        assert_eq!(IngressMode::parse("UDP"), Some(IngressMode::Udp));
    }

    #[test]
    fn ingress_mode_parse_invalid() {
        assert!(IngressMode::parse("tcp").is_none());
        assert!(IngressMode::parse("").is_none());
    }

    #[test]
    fn default_policy_validates() {
        let policy = IngressPolicy::test_default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_max_payload() {
        let mut policy = IngressPolicy::test_default();
        policy.max_payload_bytes = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_dedup_window() {
        let mut policy = IngressPolicy::test_default();
        policy.dedup_window_capacity = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_egress_retry_buffer() {
        let mut policy = IngressPolicy::test_default();
        policy.egress_retry_buffer_capacity = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_egress_retry_ticks() {
        let mut policy = IngressPolicy::test_default();
        policy.egress_retry_max_wait_ticks = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_synthetic_rejects_zero_batch_size() {
        let mut policy = IngressPolicy::test_default();
        policy.ingress_mode = IngressMode::Synthetic;
        policy.synthetic_batch_size_per_tick = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_synthetic_rejects_zero_payload_bytes() {
        let mut policy = IngressPolicy::test_default();
        policy.ingress_mode = IngressMode::Synthetic;
        policy.synthetic_payload_bytes = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_synthetic_rejects_zero_weights() {
        let mut policy = IngressPolicy::test_default();
        policy.ingress_mode = IngressMode::Synthetic;
        policy.synthetic_source_weight_quic = 0;
        policy.synthetic_source_weight_gossip = 0;
        policy.synthetic_source_weight_bundle = 0;
        policy.synthetic_source_weight_rpc = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_udp_requires_bind_address() {
        let mut policy = IngressPolicy::test_default();
        policy.ingress_mode = IngressMode::Udp;
        policy.udp_bind_address = None;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_udp_requires_nonzero_max_packets() {
        let mut policy = IngressPolicy::test_udp();
        policy.udp_max_packets_per_tick = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_udp_ok() {
        let policy = IngressPolicy::test_udp();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn source_is_allowed_defaults() {
        let policy = IngressPolicy::test_default();
        assert!(policy.source_is_allowed(IngressSource::Quic));
        assert!(policy.source_is_allowed(IngressSource::Gossip));
        assert!(policy.source_is_allowed(IngressSource::Bundle));
        assert!(policy.source_is_allowed(IngressSource::Rpc));
    }

    #[test]
    fn source_is_allowed_disabled() {
        let mut policy = IngressPolicy::test_default();
        policy.allow_quic_source = false;
        assert!(!policy.source_is_allowed(IngressSource::Quic));
        assert!(policy.source_is_allowed(IngressSource::Gossip));
    }

    #[test]
    fn source_min_gap_ticks_routing() {
        let mut policy = IngressPolicy::test_default();
        policy.quic_min_gap_ticks = 10;
        policy.gossip_min_gap_ticks = 20;
        policy.bundle_min_gap_ticks = 30;
        policy.rpc_min_gap_ticks = 40;
        assert_eq!(policy.source_min_gap_ticks(IngressSource::Quic), 10);
        assert_eq!(policy.source_min_gap_ticks(IngressSource::Gossip), 20);
        assert_eq!(policy.source_min_gap_ticks(IngressSource::Bundle), 30);
        assert_eq!(policy.source_min_gap_ticks(IngressSource::Rpc), 40);
    }

    #[test]
    fn synthetic_source_cursor_weighted() {
        let mut policy = IngressPolicy::test_default();
        policy.synthetic_source_weight_quic = 2;
        policy.synthetic_source_weight_gossip = 1;
        policy.synthetic_source_weight_bundle = 1;
        policy.synthetic_source_weight_rpc = 0;
        // total = 4, cursor 0,1 → Quic; 2 → Gossip; 3 → Bundle
        assert_eq!(policy.synthetic_source_for_cursor(0), IngressSource::Quic);
        assert_eq!(policy.synthetic_source_for_cursor(1), IngressSource::Quic);
        assert_eq!(policy.synthetic_source_for_cursor(2), IngressSource::Gossip);
        assert_eq!(policy.synthetic_source_for_cursor(3), IngressSource::Bundle);
        // wraps around
        assert_eq!(policy.synthetic_source_for_cursor(4), IngressSource::Quic);
    }

    #[test]
    fn classify_udp_source_port() {
        let policy = IngressPolicy::test_udp();
        assert_eq!(policy.classify_udp_source_port(9002), IngressSource::Gossip);
        assert_eq!(policy.classify_udp_source_port(9003), IngressSource::Bundle);
        assert_eq!(policy.classify_udp_source_port(9004), IngressSource::Rpc);
        // Unknown port defaults to Quic
        assert_eq!(policy.classify_udp_source_port(12345), IngressSource::Quic);
    }
}
