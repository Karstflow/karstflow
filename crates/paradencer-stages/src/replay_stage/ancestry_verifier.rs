/// Ancestry verification and fork relationship tracking
///
/// Provides utilities for verifying block ancestry chains, detecting forks,
/// and validating fork relationships for replay safety.
use crate::AssembledBlock;
use std::collections::{HashMap, HashSet};

/// Errors that can occur during ancestry verification
#[derive(Debug, Clone, PartialEq)]
pub enum AncestryError {
    /// Parent block not found
    ParentNotFound { slot: u64, parent_slot: u64 },
    /// Chain is disconnected
    DisconnectedChain { slot: u64 },
    /// Cycle detected in ancestry
    CycleDetected { slot: u64 },
    /// Slot is not descendant of expected ancestor
    NotDescendant { slot: u64, ancestor: u64 },
    /// Invalid ancestry relationship
    InvalidAncestry { slot: u64, reason: String },
    /// Maximum depth exceeded
    MaxDepthExceeded { depth: usize, max: usize },
}

/// Verifies block ancestry relationships and tracks fork structure
pub struct AncestryVerifier {
    /// Map of slot -> parent slot for known blocks
    ancestry_map: HashMap<u64, u64>,
    /// Set of verified slots
    verified_slots: HashSet<u64>,
    /// Maximum depth to search
    max_depth: usize,
}

impl AncestryVerifier {
    pub fn new(max_depth: usize) -> Self {
        Self {
            ancestry_map: HashMap::new(),
            verified_slots: HashSet::new(),
            max_depth,
        }
    }

    /// Register a block's ancestry
    pub fn register_block(&mut self, slot: u64, parent_slot: u64) {
        self.ancestry_map.insert(slot, parent_slot);
    }

    /// Verify a block's parent relationship
    pub fn verify_parent(&mut self, block: &AssembledBlock) -> Result<(), AncestryError> {
        let slot = block.slot;
        let parent_slot = block.parent_slot;

        // Check if parent exists in our map
        if !self.ancestry_map.contains_key(&parent_slot) && parent_slot > 0 {
            return Err(AncestryError::ParentNotFound { slot, parent_slot });
        }

        // Register this block
        self.register_block(slot, parent_slot);
        self.verified_slots.insert(slot);

        Ok(())
    }

    /// Check if slot is a descendant of ancestor
    pub fn is_descendant(&self, slot: u64, ancestor: u64) -> bool {
        if slot == ancestor {
            return true;
        }

        let mut current = slot;
        let mut depth = 0;

        while depth < self.max_depth {
            match self.ancestry_map.get(&current) {
                Some(&parent) => {
                    if parent == ancestor {
                        return true;
                    }
                    if parent == current {
                        // Self-reference would cause infinite loop
                        return false;
                    }
                    current = parent;
                    depth += 1;
                }
                None => return false,
            }
        }

        false
    }

    /// Get the ancestry chain from slot back to root
    pub fn get_ancestry_chain(&self, slot: u64) -> Result<Vec<u64>, AncestryError> {
        let mut chain = vec![slot];
        let mut current = slot;
        let mut depth = 0;

        while depth < self.max_depth {
            match self.ancestry_map.get(&current) {
                Some(&parent) => {
                    if parent == current {
                        return Err(AncestryError::CycleDetected { slot });
                    }

                    chain.push(parent);

                    // Stop at genesis (parent == 0 typically)
                    if parent == 0 {
                        break;
                    }

                    current = parent;
                    depth += 1;
                }
                None => {
                    if depth == 0 {
                        // No parent found for this slot
                        return Err(AncestryError::DisconnectedChain { slot });
                    }
                    break;
                }
            }
        }

        if depth >= self.max_depth {
            return Err(AncestryError::MaxDepthExceeded {
                depth,
                max: self.max_depth,
            });
        }

        Ok(chain)
    }

    /// Find the common ancestor of two slots
    pub fn find_common_ancestor(&self, slot_a: u64, slot_b: u64) -> Option<u64> {
        let chain_a = self.get_ancestry_chain(slot_a).ok()?;
        let chain_b = self.get_ancestry_chain(slot_b).ok()?;

        // Convert to sets for efficient lookup
        let set_a: HashSet<u64> = chain_a.iter().copied().collect();

        // Find first slot in chain_b that's also in chain_a
        for &slot in &chain_b {
            if set_a.contains(&slot) {
                return Some(slot);
            }
        }

        None
    }

    /// Get the depth from slot to ancestor
    pub fn get_depth(&self, slot: u64, ancestor: u64) -> Option<usize> {
        if !self.is_descendant(slot, ancestor) {
            return None;
        }

        let mut depth = 0;
        let mut current = slot;

        while current != ancestor && depth < self.max_depth {
            match self.ancestry_map.get(&current) {
                Some(&parent) => {
                    depth += 1;
                    current = parent;
                }
                None => return None,
            }
        }

        Some(depth)
    }

    /// Check if two slots are on the same fork
    pub fn is_same_fork(&self, slot_a: u64, slot_b: u64) -> bool {
        if slot_a == slot_b {
            return true;
        }

        // One is ancestor of the other
        self.is_descendant(slot_a, slot_b) || self.is_descendant(slot_b, slot_a)
    }

    /// Get all descendants of a slot
    pub fn get_descendants(&self, ancestor: u64) -> Vec<u64> {
        self.ancestry_map
            .keys()
            .filter(|&&slot| slot != ancestor && self.is_descendant(slot, ancestor))
            .copied()
            .collect()
    }

    /// Prune ancestry data below a root
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.ancestry_map.retain(|&slot, _| slot >= root_slot);
        self.verified_slots.retain(|&slot| slot >= root_slot);
    }

    /// Check if slot has been verified
    pub fn is_verified(&self, slot: u64) -> bool {
        self.verified_slots.contains(&slot)
    }

    /// Get total tracked slots
    pub fn tracked_slot_count(&self) -> usize {
        self.ancestry_map.len()
    }

    /// Detect cycles in ancestry
    pub fn detect_cycle(&self, starting_slot: u64) -> Option<Vec<u64>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        let mut current = starting_slot;

        while visited.len() < self.max_depth {
            if visited.contains(&current) {
                // Found a cycle
                let cycle_start = path.iter().position(|&s| s == current)?;
                return Some(path[cycle_start..].to_vec());
            }

            visited.insert(current);
            path.push(current);

            match self.ancestry_map.get(&current) {
                Some(&parent) if parent != current => current = parent,
                _ => break, // Stop at genesis (self-referencing) or missing parent
            }
        }

        None
    }

    /// Validate that a chain of blocks is properly connected
    pub fn validate_chain(&mut self, blocks: &[AssembledBlock]) -> Result<(), AncestryError> {
        for block in blocks {
            self.verify_parent(block)?;
        }

        // Check for any cycles
        for block in blocks {
            if let Some(cycle) = self.detect_cycle(block.slot) {
                return Err(AncestryError::CycleDetected { slot: cycle[0] });
            }
        }

        Ok(())
    }

    /// Get statistics about tracked ancestry
    pub fn stats(&self) -> AncestryStats {
        let mut max_depth = 0;
        let mut total_depth = 0;
        let mut counted = 0;

        for &slot in self.ancestry_map.keys() {
            if let Ok(chain) = self.get_ancestry_chain(slot) {
                let depth = chain.len() - 1;
                max_depth = max_depth.max(depth);
                total_depth += depth;
                counted += 1;
            }
        }

        let avg_depth = if counted > 0 {
            total_depth as f64 / counted as f64
        } else {
            0.0
        };

        AncestryStats {
            total_tracked: self.ancestry_map.len(),
            verified_slots: self.verified_slots.len(),
            max_depth,
            avg_depth,
        }
    }
}

impl Default for AncestryVerifier {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Statistics about ancestry tracking
#[derive(Debug, Clone)]
pub struct AncestryStats {
    pub total_tracked: usize,
    pub verified_slots: usize,
    pub max_depth: usize,
    pub avg_depth: f64,
}

/// Fork detector that identifies fork points in block chains
pub struct ForkDetector {
    /// Ancestry verifier for checking relationships
    verifier: AncestryVerifier,
    /// Known fork points
    fork_points: HashMap<u64, ForkPoint>,
}

impl ForkDetector {
    pub fn new(max_depth: usize) -> Self {
        Self {
            verifier: AncestryVerifier::new(max_depth),
            fork_points: HashMap::new(),
        }
    }

    /// Register a block and detect if it creates a fork
    pub fn register_block(&mut self, block: &AssembledBlock) -> Option<ForkPoint> {
        let slot = block.slot;
        let parent_slot = block.parent_slot;

        self.verifier.register_block(slot, parent_slot);

        // Check if parent already has children (exclude genesis self-reference)
        let siblings: Vec<u64> = self
            .verifier
            .ancestry_map
            .iter()
            .filter(|(&s, &p)| p == parent_slot && s != slot && s != p)
            .map(|(&s, _)| s)
            .collect();

        if !siblings.is_empty() {
            // Fork detected at parent
            let fork_point = ForkPoint {
                slot: parent_slot,
                children: {
                    let mut children = siblings;
                    children.push(slot);
                    children
                },
            };

            self.fork_points.insert(parent_slot, fork_point.clone());
            return Some(fork_point);
        }

        None
    }

    /// Get all detected fork points
    pub fn get_fork_points(&self) -> Vec<&ForkPoint> {
        self.fork_points.values().collect()
    }

    /// Get fork point at slot
    pub fn get_fork_point(&self, slot: u64) -> Option<&ForkPoint> {
        self.fork_points.get(&slot)
    }

    /// Check if slot is a fork point
    pub fn is_fork_point(&self, slot: u64) -> bool {
        self.fork_points.contains_key(&slot)
    }

    /// Get fork count
    pub fn fork_count(&self) -> usize {
        self.fork_points.len()
    }

    /// Prune fork points below root
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.verifier.prune_below_root(root_slot);
        self.fork_points.retain(|&slot, _| slot >= root_slot);
    }
}

/// Information about a fork point
#[derive(Debug, Clone)]
pub struct ForkPoint {
    /// Slot where fork occurs
    pub slot: u64,
    /// Child slots branching from this point
    pub children: Vec<u64>,
}

impl ForkPoint {
    /// Get number of branches at this fork
    pub fn branch_count(&self) -> usize {
        self.children.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;

    fn create_test_block(slot: u64, parent_slot: u64) -> AssembledBlock {
        AssembledBlock {
            slot,
            parent_slot,
            entries: vec![Entry {
                num_hashes: 1,
                hash: [1u8; 32],
                transactions: vec![],
            }],
            transaction_count: 0,
            total_bytes: 0,
            shred_count: 1,
        }
    }

    #[test]
    fn ancestry_verifier_registers_blocks() {
        let mut verifier = AncestryVerifier::new(100);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);

        assert!(verifier.is_descendant(2, 1));
        assert!(verifier.is_descendant(2, 0));
    }

    #[test]
    fn ancestry_verifier_verifies_parent() {
        let mut verifier = AncestryVerifier::new(100);

        let block0 = create_test_block(0, 0);
        let block1 = create_test_block(1, 0);

        verifier.register_block(0, 0);
        assert!(verifier.verify_parent(&block1).is_ok());
        assert!(verifier.is_verified(1));
    }

    #[test]
    fn ancestry_verifier_detects_missing_parent() {
        let mut verifier = AncestryVerifier::new(100);
        let block = create_test_block(10, 5);

        let result = verifier.verify_parent(&block);
        assert!(matches!(result, Err(AncestryError::ParentNotFound { .. })));
    }

    #[test]
    fn ancestry_verifier_gets_ancestry_chain() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 2);

        let chain = verifier.get_ancestry_chain(3).unwrap();
        assert_eq!(chain, vec![3, 2, 1, 0]);
    }

    #[test]
    fn ancestry_verifier_finds_common_ancestor() {
        let mut verifier = AncestryVerifier::new(100);

        //     0
        //     |
        //     1
        //    / \
        //   2   3
        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 1);

        let common = verifier.find_common_ancestor(2, 3);
        assert_eq!(common, Some(1));
    }

    #[test]
    fn ancestry_verifier_calculates_depth() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 2);

        assert_eq!(verifier.get_depth(3, 0), Some(3));
        assert_eq!(verifier.get_depth(3, 1), Some(2));
        assert_eq!(verifier.get_depth(3, 2), Some(1));
        assert_eq!(verifier.get_depth(3, 3), Some(0));
    }

    #[test]
    fn ancestry_verifier_checks_same_fork() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 1);
        verifier.register_block(4, 2);

        // Same chain
        assert!(verifier.is_same_fork(1, 2));
        assert!(verifier.is_same_fork(2, 4));
        assert!(verifier.is_same_fork(0, 4));

        // Different forks
        assert!(!verifier.is_same_fork(3, 4));
    }

    #[test]
    fn ancestry_verifier_gets_descendants() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 1);
        verifier.register_block(4, 2);

        let descendants = verifier.get_descendants(1);
        assert_eq!(descendants.len(), 3); // 2, 3, 4
        assert!(descendants.contains(&2));
        assert!(descendants.contains(&3));
        assert!(descendants.contains(&4));
    }

    #[test]
    fn ancestry_verifier_prunes_old_data() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 2);

        verifier.prune_below_root(2);

        assert_eq!(verifier.tracked_slot_count(), 2); // Only 2 and 3 remain
    }

    #[test]
    fn ancestry_verifier_detects_cycles() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(1, 2);
        verifier.register_block(2, 3);
        verifier.register_block(3, 1); // Cycle!

        let cycle = verifier.detect_cycle(1);
        assert!(cycle.is_some());
        assert!(cycle.unwrap().len() >= 3);
    }

    #[test]
    fn ancestry_verifier_validates_chain() {
        let mut verifier = AncestryVerifier::new(100);

        let blocks = vec![
            create_test_block(0, 0),
            create_test_block(1, 0),
            create_test_block(2, 1),
        ];

        assert!(verifier.validate_chain(&blocks).is_ok());
    }

    #[test]
    fn ancestry_verifier_provides_stats() {
        let mut verifier = AncestryVerifier::new(100);

        verifier.register_block(0, 0);
        verifier.register_block(1, 0);
        verifier.register_block(2, 1);
        verifier.register_block(3, 2);

        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 4);
        assert_eq!(stats.max_depth, 3);
    }

    #[test]
    fn fork_detector_detects_forks() {
        let mut detector = ForkDetector::new(100);

        let block1 = create_test_block(1, 0);
        let block2a = create_test_block(2, 1);
        let block2b = create_test_block(3, 1); // Fork at slot 1

        assert!(detector.register_block(&block1).is_none());
        assert!(detector.register_block(&block2a).is_none());

        let fork_point = detector.register_block(&block2b);
        assert!(fork_point.is_some());

        let fp = fork_point.unwrap();
        assert_eq!(fp.slot, 1);
        assert_eq!(fp.branch_count(), 2);
    }

    #[test]
    fn fork_detector_tracks_fork_points() {
        let mut detector = ForkDetector::new(100);

        let blocks = vec![
            create_test_block(0, 0),
            create_test_block(1, 0),
            create_test_block(2, 1),
            create_test_block(3, 1), // Fork at 1
        ];

        for block in blocks {
            detector.register_block(&block);
        }

        assert_eq!(detector.fork_count(), 1);
        assert!(detector.is_fork_point(1));
        assert!(!detector.is_fork_point(0));
    }

    #[test]
    fn fork_detector_prunes_old_forks() {
        let mut detector = ForkDetector::new(100);

        detector.register_block(&create_test_block(0, 0));
        detector.register_block(&create_test_block(1, 0));
        detector.register_block(&create_test_block(2, 0)); // Fork at 0

        assert_eq!(detector.fork_count(), 1);

        detector.prune_below_root(1);
        assert_eq!(detector.fork_count(), 0);
    }

    #[test]
    fn fork_point_counts_branches() {
        let fork_point = ForkPoint {
            slot: 100,
            children: vec![101, 102, 103],
        };

        assert_eq!(fork_point.branch_count(), 3);
    }
}
