use serde::{Deserialize, Serialize};

/// Default fanout for both layer1 and layer2 of the turbine tree
pub const DEFAULT_FANOUT: usize = 200;

/// Default neighborhood size for network proximity optimization
pub const DEFAULT_NEIGHBORHOOD_SIZE: usize = 50;

/// Default retransmit batch size
pub const DEFAULT_RETRANSMIT_BATCH_SIZE: usize = 64;

/// Default tree rebuild interval in slots
pub const DEFAULT_TREE_REBUILD_INTERVAL_SLOTS: u64 = 432_000; // ~1 epoch

/// Configuration for the Turbine block propagation protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurbineConfig {
    /// Number of peers in layer1 (direct children of leader)
    pub fanout: usize,

    /// Number of layer2 peers per layer1 peer
    pub layer2_fanout: usize,

    /// Size of neighborhood for proximity-based peer selection
    pub neighborhood_size: usize,

    /// Number of shreds to batch together for retransmission
    pub retransmit_batch_size: usize,

    /// How often to rebuild the turbine tree (in slots)
    pub tree_rebuild_interval_slots: u64,

    /// Enable stake-weighted peer selection
    pub stake_weighted_selection: bool,

    /// Enable network proximity optimization
    pub neighborhood_optimization: bool,

    /// Maximum number of retransmit attempts per shred
    pub max_retransmit_attempts: usize,

    /// Timeout for waiting for acknowledgments (milliseconds)
    pub ack_timeout_ms: u64,

    /// Enable propagation metrics collection
    pub enable_metrics: bool,
}

impl Default for TurbineConfig {
    fn default() -> Self {
        Self {
            fanout: DEFAULT_FANOUT,
            layer2_fanout: DEFAULT_FANOUT,
            neighborhood_size: DEFAULT_NEIGHBORHOOD_SIZE,
            retransmit_batch_size: DEFAULT_RETRANSMIT_BATCH_SIZE,
            tree_rebuild_interval_slots: DEFAULT_TREE_REBUILD_INTERVAL_SLOTS,
            stake_weighted_selection: true,
            neighborhood_optimization: true,
            max_retransmit_attempts: 3,
            ack_timeout_ms: 100,
            enable_metrics: true,
        }
    }
}

impl TurbineConfig {
    /// Create a new turbine configuration with custom fanout
    pub fn with_fanout(fanout: usize) -> Self {
        Self {
            fanout,
            layer2_fanout: fanout,
            ..Default::default()
        }
    }

    /// Set the neighborhood size
    pub fn with_neighborhood_size(mut self, size: usize) -> Self {
        self.neighborhood_size = size;
        self
    }

    /// Set the tree rebuild interval
    pub fn with_rebuild_interval(mut self, slots: u64) -> Self {
        self.tree_rebuild_interval_slots = slots;
        self
    }

    /// Enable or disable stake-weighted selection
    pub fn with_stake_weighting(mut self, enabled: bool) -> Self {
        self.stake_weighted_selection = enabled;
        self
    }

    /// Enable or disable neighborhood optimization
    pub fn with_neighborhood_optimization(mut self, enabled: bool) -> Self {
        self.neighborhood_optimization = enabled;
        self
    }

    /// Set retransmit batch size
    pub fn with_retransmit_batch_size(mut self, size: usize) -> Self {
        self.retransmit_batch_size = size;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.fanout == 0 {
            return Err("Fanout must be greater than 0".to_string());
        }

        if self.layer2_fanout == 0 {
            return Err("Layer2 fanout must be greater than 0".to_string());
        }

        if self.neighborhood_size == 0 && self.neighborhood_optimization {
            return Err(
                "Neighborhood size must be greater than 0 when optimization is enabled".to_string(),
            );
        }

        if self.retransmit_batch_size == 0 {
            return Err("Retransmit batch size must be greater than 0".to_string());
        }

        if self.tree_rebuild_interval_slots == 0 {
            return Err("Tree rebuild interval must be greater than 0".to_string());
        }

        if self.max_retransmit_attempts == 0 {
            return Err("Max retransmit attempts must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Calculate the maximum number of nodes that can be reached
    pub fn max_reachable_nodes(&self) -> usize {
        // Layer 0 (root) + Layer 1 + Layer 2
        1 + self.fanout + (self.fanout * self.layer2_fanout)
    }

    /// Calculate theoretical propagation delay in hops
    pub fn propagation_hops(&self) -> usize {
        // Maximum hops from root to leaf: 2 (layer1 -> layer2)
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TurbineConfig::default();
        assert_eq!(config.fanout, DEFAULT_FANOUT);
        assert_eq!(config.layer2_fanout, DEFAULT_FANOUT);
        assert_eq!(config.neighborhood_size, DEFAULT_NEIGHBORHOOD_SIZE);
        assert!(config.stake_weighted_selection);
        assert!(config.neighborhood_optimization);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_custom_fanout() {
        let config = TurbineConfig::with_fanout(150);
        assert_eq!(config.fanout, 150);
        assert_eq!(config.layer2_fanout, 150);
    }

    #[test]
    fn test_builder_pattern() {
        let config = TurbineConfig::with_fanout(100)
            .with_neighborhood_size(30)
            .with_rebuild_interval(100_000)
            .with_stake_weighting(false);

        assert_eq!(config.fanout, 100);
        assert_eq!(config.neighborhood_size, 30);
        assert_eq!(config.tree_rebuild_interval_slots, 100_000);
        assert!(!config.stake_weighted_selection);
    }

    #[test]
    fn test_config_validation() {
        let mut config = TurbineConfig::default();
        assert!(config.validate().is_ok());

        config.fanout = 0;
        assert!(config.validate().is_err());

        config.fanout = 100;
        config.layer2_fanout = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_max_reachable_nodes() {
        let config = TurbineConfig::with_fanout(200);
        // 1 root + 200 layer1 + (200 * 200) layer2 = 40,201 nodes
        assert_eq!(config.max_reachable_nodes(), 1 + 200 + 200 * 200);
    }

    #[test]
    fn test_propagation_hops() {
        let config = TurbineConfig::default();
        assert_eq!(config.propagation_hops(), 2);
    }
}
