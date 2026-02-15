use std::collections::HashMap;

/// Threshold constants for fork choice decisions
/// Based on Firedancer's tower implementation
const THRESHOLD_DEPTH: usize = 8;
const THRESHOLD_RATIO: f64 = 2.0 / 3.0; // 66.67% supermajority
const SWITCH_RATIO: f64 = 0.38; // 38% switch threshold

/// Fork metadata for fork choice algorithm
#[derive(Debug, Clone)]
pub struct ForkInfo {
    /// Slot number
    pub slot: u64,
    /// Parent slot
    pub parent: Option<u64>,
    /// Total stake weight voting for this fork
    pub stake_weight: u64,
    /// Whether this fork has been confirmed (>= threshold)
    pub confirmed: bool,
    /// Whether this fork has been optimistically confirmed
    pub optimistically_confirmed: bool,
}

impl ForkInfo {
    pub fn new(slot: u64, parent: Option<u64>) -> Self {
        Self {
            slot,
            parent,
            stake_weight: 0,
            confirmed: false,
            optimistically_confirmed: false,
        }
    }
}

/// Fork choice engine implementing GHOST (Greedy Heaviest Observed SubTree)
/// with Tower BFT lockout rules
#[derive(Debug)]
pub struct ForkChoice {
    /// Map of slot -> fork info
    forks: HashMap<u64, ForkInfo>,
    /// Total active stake in the network
    total_stake: u64,
    /// Current best slot (heaviest fork tip)
    best_slot: Option<u64>,
}

impl ForkChoice {
    pub fn new(total_stake: u64) -> Self {
        Self {
            forks: HashMap::new(),
            total_stake,
            best_slot: None,
        }
    }

    /// Add a fork to the tree
    pub fn add_fork(&mut self, slot: u64, parent: Option<u64>) {
        self.forks.insert(slot, ForkInfo::new(slot, parent));
    }

    /// Add stake weight to a fork (from a vote)
    pub fn add_stake(&mut self, slot: u64, stake: u64) {
        if let Some(fork) = self.forks.get_mut(&slot) {
            fork.stake_weight = fork.stake_weight.saturating_add(stake);
            self.update_confirmation(slot);
        }
    }

    /// Update confirmation status based on stake threshold
    fn update_confirmation(&mut self, slot: u64) {
        // First check optimistic confirmation (needs immutable borrow)
        let is_optimistic = self.check_optimistic_confirmation(slot);

        // Then update the fork (mutable borrow)
        if let Some(fork) = self.forks.get_mut(&slot) {
            let stake_ratio = fork.stake_weight as f64 / self.total_stake as f64;

            // Mark as confirmed if >= 66.67% stake
            if stake_ratio >= THRESHOLD_RATIO {
                fork.confirmed = true;
            }

            // Set optimistic confirmation
            if is_optimistic {
                fork.optimistically_confirmed = true;
            }
        }
    }

    /// Check if a fork meets optimistic confirmation criteria
    /// Requires THRESHOLD_DEPTH consecutive votes with supermajority
    fn check_optimistic_confirmation(&self, slot: u64) -> bool {
        let mut current = Some(slot);
        let mut depth = 0;

        while let Some(slot) = current {
            if let Some(fork) = self.forks.get(&slot) {
                let stake_ratio = fork.stake_weight as f64 / self.total_stake as f64;
                if stake_ratio < THRESHOLD_RATIO {
                    return false;
                }
                depth += 1;
                if depth >= THRESHOLD_DEPTH {
                    return true;
                }
                current = fork.parent;
            } else {
                break;
            }
        }

        false
    }

    /// Get the heaviest fork (most stake) at a given slot
    pub fn get_heaviest_fork(&self, from_slot: u64) -> Option<u64> {
        let mut best_slot = from_slot;
        let mut best_weight = self.forks.get(&from_slot)?.stake_weight;

        // Find all descendants and pick the heaviest
        for (slot, fork) in &self.forks {
            if *slot <= from_slot {
                continue;
            }
            if self.is_descendant(*slot, from_slot) && fork.stake_weight > best_weight {
                best_slot = *slot;
                best_weight = fork.stake_weight;
            }
        }

        Some(best_slot)
    }

    /// Check if a slot is a descendant of another slot
    pub fn is_descendant(&self, slot: u64, ancestor: u64) -> bool {
        if slot == ancestor {
            return true;
        }

        let mut current = Some(slot);
        while let Some(s) = current {
            if s == ancestor {
                return true;
            }
            current = self.forks.get(&s).and_then(|f| f.parent);
        }

        false
    }

    /// Check if a slot is an ancestor of another slot
    pub fn is_ancestor(&self, slot: u64, descendant: u64) -> bool {
        self.is_descendant(descendant, slot)
    }

    /// Check if switching from current fork to candidate fork is allowed
    /// Returns true if switch threshold (38%) is met
    pub fn can_switch_fork(&self, current: u64, candidate: u64) -> bool {
        let current_weight = self
            .forks
            .get(&current)
            .map(|f| f.stake_weight)
            .unwrap_or(0);
        let candidate_weight = self
            .forks
            .get(&candidate)
            .map(|f| f.stake_weight)
            .unwrap_or(0);

        if current_weight == 0 {
            return true;
        }

        let ratio = candidate_weight as f64 / current_weight as f64;
        ratio >= (1.0 + SWITCH_RATIO)
    }

    /// Compute the best fork to vote on using GHOST algorithm
    /// Starts from root and follows the heaviest subtree at each level
    pub fn compute_best_fork(&mut self, root: u64) -> Option<u64> {
        let mut current = root;

        loop {
            // Find all children of current slot
            let children: Vec<u64> = self
                .forks
                .iter()
                .filter(|(_, fork)| fork.parent == Some(current))
                .map(|(slot, _)| *slot)
                .collect();

            if children.is_empty() {
                // Reached a leaf, this is our best fork
                self.best_slot = Some(current);
                return Some(current);
            }

            // Pick the child with the most stake (GHOST)
            let best_child = children
                .into_iter()
                .max_by_key(|slot| self.forks.get(slot).map(|f| f.stake_weight).unwrap_or(0))?;

            current = best_child;
        }
    }

    /// Get the current best slot
    pub fn best_slot(&self) -> Option<u64> {
        self.best_slot
    }

    /// Get fork info for a slot
    pub fn get_fork(&self, slot: u64) -> Option<&ForkInfo> {
        self.forks.get(&slot)
    }

    /// Update total stake and recalculate confirmation status for all forks
    pub fn update_total_stake(&mut self, new_total_stake: u64) {
        self.total_stake = new_total_stake;

        // Recalculate confirmation status for all forks with new total
        let slots: Vec<u64> = self.forks.keys().copied().collect();
        for slot in slots {
            self.update_confirmation(slot);
        }
    }

    /// Prune forks below a new root
    pub fn set_root(&mut self, new_root: u64) {
        self.forks.retain(|slot, _| *slot >= new_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_choice_add_fork() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));

        assert!(fc.get_fork(1).is_some());
        assert!(fc.get_fork(2).is_some());
    }

    #[test]
    fn fork_choice_add_stake() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);
        fc.add_stake(1, 500);

        let fork = fc.get_fork(1).unwrap();
        assert_eq!(fork.stake_weight, 500);
    }

    #[test]
    fn fork_choice_confirmation_threshold() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);

        fc.add_stake(1, 650); // 65% - not enough
        assert!(!fc.get_fork(1).unwrap().confirmed);

        fc.add_stake(1, 20); // 67% - confirmed
        assert!(fc.get_fork(1).unwrap().confirmed);
    }

    #[test]
    fn fork_choice_descendant_check() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(2));

        assert!(fc.is_descendant(3, 1));
        assert!(fc.is_descendant(2, 1));
        assert!(fc.is_descendant(1, 1));
        assert!(!fc.is_descendant(1, 3));
    }

    #[test]
    fn fork_choice_switch_threshold() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);
        fc.add_fork(2, None);

        fc.add_stake(1, 500);
        fc.add_stake(2, 600); // 600/500 = 1.2, needs >= 1.38

        assert!(!fc.can_switch_fork(1, 2));

        fc.add_stake(2, 100); // 700/500 = 1.4 > 1.38
        assert!(fc.can_switch_fork(1, 2));
    }

    #[test]
    fn fork_choice_ghost_simple() {
        let mut fc = ForkChoice::new(1000);

        // Create a fork:
        //     1
        //    / \
        //   2   3
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(1));

        fc.add_stake(1, 300);
        fc.add_stake(2, 400); // Heavier
        fc.add_stake(3, 200);

        let best = fc.compute_best_fork(1);
        assert_eq!(best, Some(2)); // Follows heaviest path
    }

    #[test]
    fn fork_choice_ghost_deep() {
        let mut fc = ForkChoice::new(1000);

        // Create a deep fork:
        //     1
        //    / \
        //   2   5
        //  / \
        // 3   4
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(2));
        fc.add_fork(4, Some(2));
        fc.add_fork(5, Some(1));

        fc.add_stake(1, 100);
        fc.add_stake(2, 600); // Give fork 2 more stake than 5
        fc.add_stake(3, 300);
        fc.add_stake(4, 200);
        fc.add_stake(5, 150);

        let best = fc.compute_best_fork(1);
        // Should follow heaviest: 1->2 then 2->3 (heavier than 4)
        assert_eq!(best, Some(3));
    }

    #[test]
    fn fork_choice_prune_at_root() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(2));

        fc.set_root(2);

        assert!(fc.get_fork(1).is_none()); // Pruned
        assert!(fc.get_fork(2).is_some());
        assert!(fc.get_fork(3).is_some());
    }

    #[test]
    fn fork_choice_optimistic_confirmation() {
        let mut fc = ForkChoice::new(1000);

        // Create a chain of THRESHOLD_DEPTH slots
        fc.add_fork(1, None);
        for i in 2..=(THRESHOLD_DEPTH as u64 + 1) {
            fc.add_fork(i, Some(i - 1));
        }

        // Add supermajority stake to all
        for i in 1..=(THRESHOLD_DEPTH as u64 + 1) {
            fc.add_stake(i, 700); // 70% > threshold
        }

        let last_slot = THRESHOLD_DEPTH as u64 + 1;
        assert!(fc.get_fork(last_slot).unwrap().optimistically_confirmed);
    }
}
