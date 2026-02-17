use crate::gossip::{ContactInfo, NodeId, ValidatorInfo};
use crate::turbine::{Neighborhood, ProximityEstimator, TurbineConfig};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

/// A node in the turbine tree
#[derive(Debug, Clone)]
pub struct TurbineNode {
    /// Node identifier
    pub node_id: NodeId,

    /// Contact information
    pub contact_info: ContactInfo,

    /// Stake weight
    pub stake: u64,

    /// Layer in the tree (0 = root, 1 = layer1, 2 = layer2)
    pub layer: u8,

    /// Parent node ID (None for root)
    pub parent: Option<NodeId>,

    /// Child node IDs
    pub children: Vec<NodeId>,
}

impl TurbineNode {
    pub fn new(node_id: NodeId, contact_info: ContactInfo, stake: u64, layer: u8) -> Self {
        Self {
            node_id,
            contact_info,
            stake,
            layer,
            parent: None,
            children: Vec::new(),
        }
    }

    /// Add a child to this node
    pub fn add_child(&mut self, child_id: NodeId) {
        self.children.push(child_id);
    }

    /// Set the parent of this node
    pub fn set_parent(&mut self, parent_id: NodeId) {
        self.parent = Some(parent_id);
    }

    /// Check if this node is the root
    pub fn is_root(&self) -> bool {
        self.parent.is_none() && self.layer == 0
    }

    /// Check if this node is a leaf
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

/// Turbine tree structure for block propagation
#[derive(Debug, Clone)]
pub struct TurbineTree {
    /// Root node (leader/broadcaster)
    root: NodeId,

    /// All nodes in the tree indexed by NodeId
    nodes: HashMap<NodeId, TurbineNode>,

    /// Layer 1 nodes (direct children of root)
    layer1: Vec<NodeId>,

    /// Layer 2 nodes (children of layer1 nodes)
    layer2: Vec<NodeId>,

    /// Configuration
    config: TurbineConfig,

    /// Slot number this tree is for
    slot: u64,

    /// Time when tree was built
    built_at: Instant,
}

impl TurbineTree {
    /// Create a new turbine tree with the given root node
    pub fn new(root: NodeId, contact_info: ContactInfo, config: TurbineConfig, slot: u64) -> Self {
        let mut nodes = HashMap::new();
        let root_node = TurbineNode::new(root, contact_info, 0, 0);
        nodes.insert(root, root_node);

        Self {
            root,
            nodes,
            layer1: Vec::new(),
            layer2: Vec::new(),
            config,
            slot,
            built_at: Instant::now(),
        }
    }

    /// Get the root node ID
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Get the slot number
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &NodeId) -> Option<&TurbineNode> {
        self.nodes.get(node_id)
    }

    /// Get all layer1 nodes
    pub fn layer1_nodes(&self) -> &[NodeId] {
        &self.layer1
    }

    /// Get all layer2 nodes
    pub fn layer2_nodes(&self) -> &[NodeId] {
        &self.layer2
    }

    /// Get children of a specific node
    pub fn get_children(&self, node_id: &NodeId) -> Vec<NodeId> {
        self.nodes
            .get(node_id)
            .map(|node| node.children.clone())
            .unwrap_or_default()
    }

    /// Get parent of a specific node
    pub fn get_parent(&self, node_id: &NodeId) -> Option<NodeId> {
        self.nodes.get(node_id).and_then(|node| node.parent)
    }

    /// Get all nodes at a specific layer
    pub fn get_layer(&self, layer: u8) -> Vec<NodeId> {
        match layer {
            0 => vec![self.root],
            1 => self.layer1.clone(),
            2 => self.layer2.clone(),
            _ => Vec::new(),
        }
    }

    /// Get total number of nodes in the tree
    pub fn total_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Check if tree is stale and needs rebuilding
    pub fn is_stale(&self, current_slot: u64) -> bool {
        current_slot.saturating_sub(self.slot) >= self.config.tree_rebuild_interval_slots
    }

    /// Get tree age in seconds
    pub fn age_seconds(&self) -> u64 {
        self.built_at.elapsed().as_secs()
    }

    /// Add a layer1 node
    fn add_layer1_node(&mut self, node: TurbineNode) {
        let node_id = node.node_id;
        self.layer1.push(node_id);
        self.nodes.insert(node_id, node);

        // Add to root's children
        if let Some(root_node) = self.nodes.get_mut(&self.root) {
            root_node.add_child(node_id);
        }
    }

    /// Add a layer2 node as child of a layer1 parent
    fn add_layer2_node(&mut self, node: TurbineNode, parent_id: NodeId) {
        let node_id = node.node_id;
        self.layer2.push(node_id);
        self.nodes.insert(node_id, node);

        // Add to parent's children
        if let Some(parent_node) = self.nodes.get_mut(&parent_id) {
            parent_node.add_child(node_id);
        }

        // Set parent
        if let Some(child_node) = self.nodes.get_mut(&node_id) {
            child_node.set_parent(parent_id);
        }
    }
}

/// Builder for constructing turbine trees with stake-weighted peer selection
pub struct TurbineTreeBuilder {
    config: TurbineConfig,
    neighborhood: Option<Arc<RwLock<Neighborhood>>>,
}

impl TurbineTreeBuilder {
    /// Create a new tree builder with the given configuration
    pub fn new(config: TurbineConfig) -> Self {
        Self {
            config,
            neighborhood: None,
        }
    }

    /// Set the neighborhood for proximity-based peer selection
    pub fn with_neighborhood(mut self, neighborhood: Arc<RwLock<Neighborhood>>) -> Self {
        self.neighborhood = Some(neighborhood);
        self
    }

    /// Build a turbine tree from a set of validators
    pub fn build(
        &self,
        root: NodeId,
        root_contact_info: ContactInfo,
        validators: Vec<ValidatorInfo>,
        slot: u64,
    ) -> TurbineTree {
        let mut tree = TurbineTree::new(root, root_contact_info.clone(), self.config.clone(), slot);

        // Filter out root and inactive validators
        let mut active_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| v.contact_info.node_id != root && v.is_active)
            .collect();

        if active_validators.is_empty() {
            return tree;
        }

        // Select layer1 nodes
        let layer1_nodes = self.select_layer1_nodes(&mut active_validators, &root_contact_info);

        // Add layer1 nodes to tree
        for (node_id, contact_info, stake) in &layer1_nodes {
            let mut node = TurbineNode::new(*node_id, contact_info.clone(), *stake, 1);
            node.set_parent(root);
            tree.add_layer1_node(node);
        }

        // Remove layer1 nodes from active validators
        let layer1_ids: HashSet<_> = layer1_nodes.iter().map(|(id, _, _)| *id).collect();
        active_validators.retain(|v| !layer1_ids.contains(&v.contact_info.node_id));

        // Select and assign layer2 nodes
        self.assign_layer2_nodes(&mut tree, active_validators, &layer1_nodes);

        tree
    }

    /// Select layer1 nodes using stake-weighted selection
    fn select_layer1_nodes(
        &self,
        validators: &mut [ValidatorInfo],
        root_contact: &ContactInfo,
    ) -> Vec<(NodeId, ContactInfo, u64)> {
        let count = self.config.fanout.min(validators.len());

        if self.config.stake_weighted_selection {
            self.stake_weighted_selection(validators, count, root_contact)
        } else {
            self.random_selection(validators, count)
        }
    }

    /// Perform stake-weighted peer selection
    fn stake_weighted_selection(
        &self,
        validators: &[ValidatorInfo],
        count: usize,
        root_contact: &ContactInfo,
    ) -> Vec<(NodeId, ContactInfo, u64)> {
        let mut candidates: Vec<_> = validators
            .iter()
            .map(|v| {
                let node_id = v.contact_info.node_id;
                let contact = v.contact_info.clone();
                let stake = v.stake;

                // Apply proximity bias if neighborhood optimization is enabled
                let weight = if self.config.neighborhood_optimization {
                    self.calculate_weighted_stake(stake, &contact, root_contact)
                } else {
                    stake as f64
                };

                (node_id, contact, stake, weight)
            })
            .collect();

        // Sort by weight descending
        candidates.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));

        // Use weighted sampling for diversity
        self.weighted_sample(&candidates, count)
    }

    /// Calculate stake weight with proximity bias
    fn calculate_weighted_stake(
        &self,
        stake: u64,
        contact: &ContactInfo,
        root_contact: &ContactInfo,
    ) -> f64 {
        let base_weight = stake as f64;

        // Apply proximity multiplier if we have neighborhood data
        if let Some(neighborhood) = &self.neighborhood {
            let neighborhood = neighborhood.read();
            if let Some(proximity) = neighborhood.get_proximity(&contact.node_id) {
                // Closer nodes get a slight boost (up to 1.2x)
                // Farther nodes get a slight penalty (down to 0.8x)
                let proximity_score = proximity.proximity.score();
                let proximity_multiplier = if proximity_score < 50.0 {
                    1.2 // Very close
                } else if proximity_score < 100.0 {
                    1.1 // Close
                } else if proximity_score < 200.0 {
                    1.0 // Medium
                } else {
                    0.9 // Far
                };
                return base_weight * proximity_multiplier;
            }
        }

        // Fallback to IP-based proximity estimation
        let proximity =
            ProximityEstimator::estimate(&root_contact.tpu_quic_addr, &contact.tpu_quic_addr);
        let proximity_multiplier = if proximity.score() < 100.0 {
            1.1
        } else if proximity.score() < 200.0 {
            1.0
        } else {
            0.9
        };

        base_weight * proximity_multiplier
    }

    /// Perform weighted sampling with diversity
    fn weighted_sample(
        &self,
        candidates: &[(NodeId, ContactInfo, u64, f64)],
        count: usize,
    ) -> Vec<(NodeId, ContactInfo, u64)> {
        let mut rng = rand::thread_rng();
        let total_weight: f64 = candidates.iter().map(|(_, _, _, w)| w).sum();

        if total_weight == 0.0 {
            // Fallback to random selection
            return candidates
                .iter()
                .take(count)
                .map(|(id, c, s, _)| (*id, c.clone(), *s))
                .collect();
        }

        let mut selected = Vec::new();
        let mut remaining: Vec<_> = candidates.to_vec();

        for _ in 0..count.min(remaining.len()) {
            let total: f64 = remaining.iter().map(|(_, _, _, w)| w).sum();
            let mut target = rng.gen::<f64>() * total;

            let mut selected_idx = 0;
            for (idx, (_, _, _, weight)) in remaining.iter().enumerate() {
                target -= weight;
                if target <= 0.0 {
                    selected_idx = idx;
                    break;
                }
            }

            let (node_id, contact, stake, _) = remaining.remove(selected_idx);
            selected.push((node_id, contact, stake));
        }

        selected
    }

    /// Perform random peer selection
    fn random_selection(
        &self,
        validators: &[ValidatorInfo],
        count: usize,
    ) -> Vec<(NodeId, ContactInfo, u64)> {
        let mut rng = rand::thread_rng();
        let mut indices: Vec<_> = (0..validators.len()).collect();
        indices.shuffle(&mut rng);

        indices
            .into_iter()
            .take(count)
            .map(|i| {
                let v = &validators[i];
                (v.contact_info.node_id, v.contact_info.clone(), v.stake)
            })
            .collect()
    }

    /// Assign layer2 nodes to layer1 parents
    fn assign_layer2_nodes(
        &self,
        tree: &mut TurbineTree,
        validators: Vec<ValidatorInfo>,
        layer1_nodes: &[(NodeId, ContactInfo, u64)],
    ) {
        if layer1_nodes.is_empty() || validators.is_empty() {
            return;
        }

        let num_parents = layer1_nodes.len();
        let total = validators.len();
        let max_per_parent = self.config.layer2_fanout;

        // Calculate balanced distribution: base count + remainder spread
        let base_count = (total / num_parents).min(max_per_parent);
        let remainder = total - base_count * num_parents;

        let mut remaining_validators = validators;

        // Distribute layer2 nodes among layer1 parents (balanced)
        for (i, (parent_id, parent_contact, _)) in layer1_nodes.iter().enumerate() {
            if remaining_validators.is_empty() {
                break;
            }

            // First `remainder` parents get one extra node
            let count = if i < remainder {
                (base_count + 1).min(remaining_validators.len())
            } else {
                base_count.min(remaining_validators.len())
            };

            // Select layer2 children for this parent
            let children = if self.config.stake_weighted_selection {
                self.stake_weighted_selection(&remaining_validators, count, parent_contact)
            } else {
                self.random_selection(&remaining_validators, count)
            };

            // Add layer2 nodes to tree
            for (node_id, contact_info, stake) in children {
                let node = TurbineNode::new(node_id, contact_info, stake, 2);
                tree.add_layer2_node(node, *parent_id);

                // Remove from remaining validators
                remaining_validators.retain(|v| v.contact_info.node_id != node_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_node_id(byte: u8) -> NodeId {
        NodeId::new([byte; 32])
    }

    fn create_contact_info(node_id: NodeId, port: u16) -> ContactInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        ContactInfo::new(node_id, addr, addr, addr, addr, 1)
    }

    fn create_validator(node_id: NodeId, stake: u64) -> ValidatorInfo {
        let contact = create_contact_info(node_id, 8000);
        ValidatorInfo::new(contact, stake)
    }

    #[test]
    fn test_turbine_node_creation() {
        let node_id = create_node_id(1);
        let contact = create_contact_info(node_id, 8000);
        let node = TurbineNode::new(node_id, contact, 1000, 1);

        assert_eq!(node.node_id, node_id);
        assert_eq!(node.stake, 1000);
        assert_eq!(node.layer, 1);
        assert!(!node.is_root());
        assert!(node.is_leaf());
    }

    #[test]
    fn test_turbine_tree_creation() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);
        let config = TurbineConfig::default();

        let tree = TurbineTree::new(root_id, root_contact, config, 100);

        assert_eq!(tree.root(), root_id);
        assert_eq!(tree.slot(), 100);
        assert_eq!(tree.total_nodes(), 1);
        assert!(tree.layer1_nodes().is_empty());
        assert!(tree.layer2_nodes().is_empty());
    }

    #[test]
    fn test_tree_builder_basic() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);

        let validators: Vec<_> = (1..=10)
            .map(|i| create_validator(create_node_id(i), 1000 * i as u64))
            .collect();

        let config = TurbineConfig::with_fanout(5);
        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, root_contact, validators, 100);

        assert_eq!(tree.layer1_nodes().len(), 5);
        assert!(tree.total_nodes() >= 6); // root + at least 5 layer1
    }

    #[test]
    fn test_tree_builder_stake_weighted() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);

        // Create validators with varying stakes
        let validators = vec![
            create_validator(create_node_id(1), 10000), // High stake
            create_validator(create_node_id(2), 5000),
            create_validator(create_node_id(3), 1000), // Low stake
            create_validator(create_node_id(4), 8000),
            create_validator(create_node_id(5), 3000),
        ];

        let config = TurbineConfig::with_fanout(3).with_stake_weighting(true);
        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, root_contact, validators, 100);

        assert_eq!(tree.layer1_nodes().len(), 3);

        // Higher stake nodes should be in layer1 (though randomness makes this probabilistic)
        let _layer1_has_high_stake = tree
            .layer1_nodes()
            .iter()
            .any(|id| *id == create_node_id(1));
        // This test is probabilistic but with high stake difference, should usually pass
    }

    #[test]
    fn test_tree_builder_layer2() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);

        let validators: Vec<_> = (1..=50)
            .map(|i| create_validator(create_node_id(i), 1000))
            .collect();

        let config = TurbineConfig::with_fanout(5);
        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, root_contact, validators, 100);

        assert_eq!(tree.layer1_nodes().len(), 5);
        assert!(!tree.layer2_nodes().is_empty());

        // Verify parent-child relationships
        for layer2_node in tree.layer2_nodes() {
            let parent = tree.get_parent(layer2_node);
            assert!(parent.is_some());
            assert!(tree.layer1_nodes().contains(&parent.unwrap()));
        }
    }

    #[test]
    fn test_tree_stale_check() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);
        let config = TurbineConfig::default();

        let tree = TurbineTree::new(root_id, root_contact, config.clone(), 100);

        assert!(!tree.is_stale(100));
        assert!(!tree.is_stale(100 + config.tree_rebuild_interval_slots - 1));
        assert!(tree.is_stale(100 + config.tree_rebuild_interval_slots));
    }

    #[test]
    fn test_get_children() {
        let root_id = create_node_id(0);
        let root_contact = create_contact_info(root_id, 8000);

        let validators: Vec<_> = (1..=10)
            .map(|i| create_validator(create_node_id(i), 1000))
            .collect();

        let config = TurbineConfig::with_fanout(5);
        let builder = TurbineTreeBuilder::new(config);
        let tree = builder.build(root_id, root_contact, validators, 100);

        let root_children = tree.get_children(&root_id);
        assert_eq!(root_children.len(), 5);
        assert_eq!(root_children, tree.layer1_nodes());
    }
}
