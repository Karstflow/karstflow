use crate::{BankForks, Tower};
use karstflow_constants::consensus::{
    SUPERMAJORITY_THRESHOLD, SWITCH_FORK_THRESHOLD, VOTE_THRESHOLD_DEPTH, VOTE_THRESHOLD_SIZE,
};
use karstflow_storage::Pubkey;
use std::collections::HashMap;

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
    /// Per-validator latest vote slot (LMD rule: only latest vote counts).
    /// Maps validator pubkey to (voted_slot, stake).
    validator_latest_votes: HashMap<Pubkey, (u64, u64)>,
}

impl ForkChoice {
    pub fn new(total_stake: u64) -> Self {
        Self {
            forks: HashMap::new(),
            total_stake,
            best_slot: None,
            validator_latest_votes: HashMap::new(),
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
            if stake_ratio >= VOTE_THRESHOLD_SIZE {
                fork.confirmed = true;
            }

            // Set optimistic confirmation
            if is_optimistic {
                fork.optimistically_confirmed = true;
            }
        }
    }

    /// Check if a fork meets optimistic confirmation criteria
    /// Requires VOTE_THRESHOLD_DEPTH consecutive votes with supermajority
    fn check_optimistic_confirmation(&self, slot: u64) -> bool {
        let mut current = Some(slot);
        let mut depth = 0;

        while let Some(slot) = current {
            if let Some(fork) = self.forks.get(&slot) {
                let stake_ratio = fork.stake_weight as f64 / self.total_stake as f64;
                if stake_ratio < VOTE_THRESHOLD_SIZE {
                    return false;
                }
                depth += 1;
                if depth >= VOTE_THRESHOLD_DEPTH {
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
        ratio >= (1.0 + SWITCH_FORK_THRESHOLD)
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

    /// Select the best fork to vote on using stake-weighted GHOST.
    ///
    /// Integrates with Tower for lockout enforcement and BankForks for fork tree.
    /// Returns the slot to vote on, or None if no valid fork exists.
    pub fn select_fork(&self, bank_forks: &BankForks, tower: &Tower) -> Option<u64> {
        // Start from current root or genesis
        let root = tower.root().or(Some(bank_forks.root_slot()))?;

        // Ensure root fork exists
        if !self.forks.contains_key(&root) {
            return None;
        }

        // Run GHOST from root
        let mut current = root;
        let tower_root = tower.root().unwrap_or(0);

        loop {
            // Get all children of current slot
            let children: Vec<u64> = self
                .forks
                .iter()
                .filter(|(_, fork)| fork.parent == Some(current))
                .map(|(slot, _)| *slot)
                .collect();

            if children.is_empty() {
                // Reached a leaf - check if we can vote on it
                if current > tower_root && !self.is_locked_out_by_tower(current, tower, bank_forks)
                {
                    return Some(current);
                }
                return None;
            }

            // Filter children based on tower lockouts
            let valid_children: Vec<u64> = children
                .into_iter()
                .filter(|&slot| !self.is_locked_out_by_tower(slot, tower, bank_forks))
                .collect();

            if valid_children.is_empty() {
                // No valid children due to lockouts
                return None;
            }

            // Pick the child with the most stake (GHOST)
            let best_child = valid_children
                .into_iter()
                .max_by_key(|slot| self.forks.get(slot).map(|f| f.stake_weight).unwrap_or(0))?;

            current = best_child;
        }
    }

    /// Check if tower lockouts prevent voting on a slot.
    fn is_locked_out_by_tower(&self, slot: u64, tower: &Tower, bank_forks: &BankForks) -> bool {
        tower.is_locked_out(slot, |vote_slot, candidate_slot| {
            self.is_same_fork(vote_slot, candidate_slot, bank_forks)
        })
    }

    /// Check if two slots are on the same fork using BankForks ancestry.
    fn is_same_fork(&self, slot_a: u64, slot_b: u64, bank_forks: &BankForks) -> bool {
        if slot_a == slot_b {
            return true;
        }

        // Check if one is ancestor of the other
        bank_forks.is_ancestor(slot_a, slot_b) || bank_forks.is_ancestor(slot_b, slot_a)
    }

    /// Determine if we should switch from current fork to a candidate fork.
    ///
    /// Returns true if the candidate has sufficient stake advantage (38% more).
    pub fn should_switch_fork(
        &self,
        current_slot: u64,
        candidate_slot: u64,
        bank_forks: &BankForks,
    ) -> bool {
        // Don't switch to same fork
        if current_slot == candidate_slot {
            return false;
        }

        // Don't switch if candidate is ancestor of current (staying on same chain)
        if bank_forks.is_ancestor(candidate_slot, current_slot) {
            return false;
        }

        // Check stake threshold for switching
        self.can_switch_fork(current_slot, candidate_slot)
    }

    /// Update root and detect finalization.
    ///
    /// Checks if any slot has reached finalization threshold (2/3+ stake + sufficient depth).
    /// Returns the new root slot if finalization occurred.
    pub fn update_root(&mut self, bank_forks: &mut BankForks) -> Option<u64> {
        let current_root = bank_forks.root_slot();

        // Find the highest slot that can be finalized
        let mut finalization_candidate = None;

        for (slot, fork) in &self.forks {
            // Must be above current root
            if *slot <= current_root {
                continue;
            }

            // Must have supermajority
            let ratio = fork.stake_weight as f64 / self.total_stake as f64;
            if ratio < VOTE_THRESHOLD_SIZE {
                continue;
            }

            // Must be optimistically confirmed (sufficient depth)
            if !fork.optimistically_confirmed {
                continue;
            }

            // Update candidate to highest qualifying slot
            finalization_candidate = Some(
                finalization_candidate
                    .map(|current: u64| current.max(*slot))
                    .unwrap_or(*slot),
            );
        }

        // Set new root if we found a finalization candidate
        if let Some(new_root) = finalization_candidate {
            // Update BankForks root
            if bank_forks.set_root(new_root).is_ok() {
                // Prune our fork tree
                self.set_root(new_root);
                return Some(new_root);
            }
        }

        None
    }

    /// Get all fork tips (slots with no children).
    pub fn get_fork_tips(&self) -> Vec<u64> {
        let all_slots: Vec<u64> = self.forks.keys().copied().collect();
        let mut tips = Vec::new();

        for slot in all_slots {
            // Check if this slot has any children
            let has_children = self.forks.values().any(|f| f.parent == Some(slot));
            if !has_children {
                tips.push(slot);
            }
        }

        tips
    }

    /// Get the fork path from a slot back to root.
    pub fn get_fork_path(&self, slot: u64) -> Vec<u64> {
        let mut path = vec![slot];
        let mut current = slot;

        while let Some(fork) = self.forks.get(&current) {
            if let Some(parent) = fork.parent {
                path.push(parent);
                current = parent;
            } else {
                break;
            }
        }

        path.reverse();
        path
    }

    /// Calculate stake distribution across all forks.
    pub fn stake_distribution(&self) -> HashMap<u64, u64> {
        self.forks
            .iter()
            .map(|(slot, fork)| (*slot, fork.stake_weight))
            .collect()
    }

    /// Record a validator's vote with LMD (Latest Message Driven) semantics.
    ///
    /// If the validator already has a recorded vote, the old vote's stake is
    /// subtracted from its slot (and all ancestors), and the new vote's stake
    /// is added to the new slot (and all ancestors). This implements the core
    /// LMD-GHOST rule: only the latest vote from each validator counts.
    pub fn record_validator_vote(&mut self, validator: Pubkey, slot: u64, stake: u64) {
        // Remove old vote's stake from its ancestry
        if let Some(&(old_slot, old_stake)) = self.validator_latest_votes.get(&validator) {
            if old_slot == slot {
                // Same slot, just update stake if changed
                if old_stake != stake {
                    self.subtract_stake_from_ancestry(old_slot, old_stake);
                    self.add_stake_to_ancestry(slot, stake);
                    self.validator_latest_votes.insert(validator, (slot, stake));
                    self.update_confirmation(slot);
                }
                return;
            }
            self.subtract_stake_from_ancestry(old_slot, old_stake);
        }

        // Add new vote's stake to its ancestry
        self.add_stake_to_ancestry(slot, stake);
        self.validator_latest_votes.insert(validator, (slot, stake));

        // Update confirmation status for the voted slot
        self.update_confirmation(slot);
    }

    /// Add stake to a slot and all of its ancestors.
    fn add_stake_to_ancestry(&mut self, slot: u64, stake: u64) {
        let mut current = Some(slot);
        while let Some(s) = current {
            if let Some(fork) = self.forks.get_mut(&s) {
                fork.stake_weight = fork.stake_weight.saturating_add(stake);
                current = fork.parent;
            } else {
                break;
            }
        }
    }

    /// Subtract stake from a slot and all of its ancestors.
    fn subtract_stake_from_ancestry(&mut self, slot: u64, stake: u64) {
        let mut current = Some(slot);
        while let Some(s) = current {
            if let Some(fork) = self.forks.get_mut(&s) {
                fork.stake_weight = fork.stake_weight.saturating_sub(stake);
                current = fork.parent;
            } else {
                break;
            }
        }
    }

    /// Calculate the subtree weight for a slot by summing the stake
    /// of all descendants (including self).
    pub fn subtree_weight(&self, slot: u64) -> u64 {
        let own_weight = self.forks.get(&slot).map(|f| f.stake_weight).unwrap_or(0);
        let children_weight: u64 = self
            .forks
            .iter()
            .filter(|(_, f)| f.parent == Some(slot))
            .map(|(child_slot, _)| self.subtree_weight(*child_slot))
            .sum();
        own_weight.saturating_add(children_weight)
    }

    /// Select the heaviest fork using GHOST traversal with ancestry-propagated weights.
    ///
    /// Starting from the root, at each level picks the child with the
    /// highest stake weight (ties broken by lower slot number). With LMD-GHOST
    /// ancestry propagation, each node's `stake_weight` already includes all
    /// descendant votes, so direct comparison is correct.
    pub fn select_heaviest_fork(&mut self, root: u64) -> Option<u64> {
        if !self.forks.contains_key(&root) {
            return None;
        }

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
                self.best_slot = Some(current);
                return Some(current);
            }

            // Pick child with highest stake weight, break ties by lower slot
            let mut best_child = children[0];
            let mut best_weight = self
                .forks
                .get(&children[0])
                .map(|f| f.stake_weight)
                .unwrap_or(0);

            for &child in &children[1..] {
                let weight = self.forks.get(&child).map(|f| f.stake_weight).unwrap_or(0);
                if weight > best_weight || (weight == best_weight && child < best_child) {
                    best_child = child;
                    best_weight = weight;
                }
            }

            current = best_child;
        }
    }

    /// Compute the highest slot that has achieved supermajority (2/3+ stake).
    ///
    /// Walks from the highest slot downward to find the highest slot
    /// with at least SUPERMAJORITY_THRESHOLD of total stake.
    /// This slot is a candidate for becoming the new root.
    pub fn compute_supermajority_root(&self, current_root: Option<u64>) -> Option<u64> {
        if self.total_stake == 0 {
            return current_root;
        }

        let mut candidate = current_root;

        for (&slot, fork) in &self.forks {
            // Must be above current root
            if let Some(root) = current_root {
                if slot <= root {
                    continue;
                }
            }

            let ratio = fork.stake_weight as f64 / self.total_stake as f64;
            if ratio >= SUPERMAJORITY_THRESHOLD {
                candidate = Some(match candidate {
                    Some(c) => c.max(slot),
                    None => slot,
                });
            }
        }

        candidate
    }

    /// Prune the fork tree to only contain descendants of the new root.
    ///
    /// Also prunes validator vote records that point to pruned slots.
    pub fn prune_non_descendants(&mut self, new_root: u64) {
        // Keep only descendants of new_root (and the root itself)
        let slots_to_keep: Vec<u64> = self
            .forks
            .keys()
            .copied()
            .filter(|&slot| slot == new_root || self.is_descendant(slot, new_root))
            .collect();

        self.forks.retain(|slot, _| slots_to_keep.contains(slot));

        // Prune validator votes pointing to removed slots
        self.validator_latest_votes
            .retain(|_, (slot, _)| self.forks.contains_key(slot));
    }

    /// Get the number of tracked validator votes.
    pub fn validator_vote_count(&self) -> usize {
        self.validator_latest_votes.len()
    }

    /// Get the latest vote slot for a specific validator.
    pub fn validator_vote_slot(&self, validator: &Pubkey) -> Option<u64> {
        self.validator_latest_votes.get(validator).map(|(s, _)| *s)
    }

    /// Get all validator vote entries.
    pub fn all_validator_votes(&self) -> &HashMap<Pubkey, (u64, u64)> {
        &self.validator_latest_votes
    }

    /// Get statistics about the fork choice state.
    pub fn stats(&self) -> ForkChoiceStats {
        let total_forks = self.forks.len();
        let confirmed_forks = self.forks.values().filter(|f| f.confirmed).count();
        let optimistically_confirmed_forks = self
            .forks
            .values()
            .filter(|f| f.optimistically_confirmed)
            .count();

        let fork_tips = self.get_fork_tips();
        let max_stake = self
            .forks
            .values()
            .map(|f| f.stake_weight)
            .max()
            .unwrap_or(0);

        ForkChoiceStats {
            total_forks,
            confirmed_forks,
            optimistically_confirmed_forks,
            fork_tips_count: fork_tips.len(),
            total_stake: self.total_stake,
            max_fork_stake: max_stake,
            best_slot: self.best_slot,
        }
    }
}

/// Statistics about fork choice state.
#[derive(Debug, Clone)]
pub struct ForkChoiceStats {
    pub total_forks: usize,
    pub confirmed_forks: usize,
    pub optimistically_confirmed_forks: usize,
    pub fork_tips_count: usize,
    pub total_stake: u64,
    pub max_fork_stake: u64,
    pub best_slot: Option<u64>,
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

        // Create a chain of VOTE_THRESHOLD_DEPTH slots
        fc.add_fork(1, None);
        for i in 2..=(VOTE_THRESHOLD_DEPTH as u64 + 1) {
            fc.add_fork(i, Some(i - 1));
        }

        // Add supermajority stake to all
        for i in 1..=(VOTE_THRESHOLD_DEPTH as u64 + 1) {
            fc.add_stake(i, 700); // 70% > threshold
        }

        let last_slot = VOTE_THRESHOLD_DEPTH as u64 + 1;
        assert!(fc.get_fork(last_slot).unwrap().optimistically_confirmed);
    }

    #[test]
    fn fork_choice_gets_fork_tips() {
        let mut fc = ForkChoice::new(1000);

        // Create tree:
        //     1
        //    / \
        //   2   3
        //   |
        //   4
        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(1));
        fc.add_fork(4, Some(2));

        let tips = fc.get_fork_tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&3));
        assert!(tips.contains(&4));
    }

    #[test]
    fn fork_choice_gets_fork_path() {
        let mut fc = ForkChoice::new(1000);

        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(2));
        fc.add_fork(4, Some(3));

        let path = fc.get_fork_path(4);
        assert_eq!(path, vec![1, 2, 3, 4]);
    }

    #[test]
    fn fork_choice_stake_distribution() {
        let mut fc = ForkChoice::new(1000);

        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_stake(1, 500);
        fc.add_stake(2, 700);

        let dist = fc.stake_distribution();
        assert_eq!(dist.get(&1), Some(&500));
        assert_eq!(dist.get(&2), Some(&700));
    }

    #[test]
    fn fork_choice_provides_stats() {
        let mut fc = ForkChoice::new(1000);

        fc.add_fork(1, None);
        fc.add_fork(2, Some(1));
        fc.add_stake(1, 500);
        fc.add_stake(2, 700);

        fc.compute_best_fork(1);

        let stats = fc.stats();
        assert_eq!(stats.total_forks, 2);
        assert_eq!(stats.total_stake, 1000);
        assert_eq!(stats.max_fork_stake, 700);
        assert_eq!(stats.best_slot, Some(2));
    }

    #[test]
    fn lmd_ghost_only_latest_vote_counts() {
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(0, None);
        fc.add_fork(1, Some(0));
        fc.add_fork(2, Some(1));

        let validator = Pubkey::from([1u8; 32]);

        // Validator votes for slot 1
        fc.record_validator_vote(validator, 1, 500);
        assert_eq!(fc.get_fork(1).unwrap().stake_weight, 500);
        assert_eq!(fc.get_fork(0).unwrap().stake_weight, 500); // ancestor gets stake

        // Validator switches to slot 2 — old vote removed from slot 1
        fc.record_validator_vote(validator, 2, 500);
        assert_eq!(fc.get_fork(2).unwrap().stake_weight, 500);
        assert_eq!(fc.get_fork(1).unwrap().stake_weight, 500); // still in ancestry
        assert_eq!(fc.get_fork(0).unwrap().stake_weight, 500); // still in ancestry

        // Slot 1 should NOT have direct vote stake anymore (only ancestry)
        // The key test: only one validator's worth of stake in the tree
        assert_eq!(fc.validator_vote_count(), 1);
        assert_eq!(fc.validator_vote_slot(&validator), Some(2));
    }

    #[test]
    fn lmd_ghost_fork_competition() {
        let mut fc = ForkChoice::new(1000);
        // Tree: 0 → 1 → 2 (fork A)
        //              → 3 (fork B)
        fc.add_fork(0, None);
        fc.add_fork(1, Some(0));
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(1));

        let val_a = Pubkey::from([1u8; 32]);
        let val_b = Pubkey::from([2u8; 32]);

        // Validator A (300 stake) votes for slot 2
        fc.record_validator_vote(val_a, 2, 300);
        // Validator B (400 stake) votes for slot 3
        fc.record_validator_vote(val_b, 3, 400);

        // Ancestry: slot 0 and 1 should have both validators' stake
        assert_eq!(fc.get_fork(0).unwrap().stake_weight, 700);
        assert_eq!(fc.get_fork(1).unwrap().stake_weight, 700);

        // Competing forks at the leaf level
        assert_eq!(fc.get_fork(2).unwrap().stake_weight, 300);
        assert_eq!(fc.get_fork(3).unwrap().stake_weight, 400);

        // GHOST should pick slot 3 (heavier fork)
        let best = fc.compute_best_fork(0);
        assert_eq!(best, Some(3));

        // select_heaviest_fork should agree
        let heaviest = fc.select_heaviest_fork(0);
        assert_eq!(heaviest, Some(3));
    }

    #[test]
    fn lmd_ghost_validator_switches_fork() {
        let mut fc = ForkChoice::new(1000);
        // Tree: 0 → 1 → 2 (fork A)
        //              → 3 (fork B)
        fc.add_fork(0, None);
        fc.add_fork(1, Some(0));
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(1));

        let val_a = Pubkey::from([1u8; 32]);
        let val_b = Pubkey::from([2u8; 32]);

        // Both validators initially vote for slot 2
        fc.record_validator_vote(val_a, 2, 300);
        fc.record_validator_vote(val_b, 2, 400);
        assert_eq!(fc.get_fork(2).unwrap().stake_weight, 700);
        assert_eq!(fc.compute_best_fork(0), Some(2));

        // Validator B switches to slot 3
        fc.record_validator_vote(val_b, 3, 400);

        // Slot 2 should lose B's stake, slot 3 gains it
        assert_eq!(fc.get_fork(2).unwrap().stake_weight, 300);
        assert_eq!(fc.get_fork(3).unwrap().stake_weight, 400);

        // GHOST now picks slot 3
        assert_eq!(fc.compute_best_fork(0), Some(3));
    }

    #[test]
    fn lmd_ghost_confirmation_triggers_on_ancestry_vote() {
        // total_stake=1000, VOTE_THRESHOLD_SIZE=0.6667
        let mut fc = ForkChoice::new(1000);
        fc.add_fork(0, None);
        fc.add_fork(1, Some(0));

        let val_a = Pubkey::from([1u8; 32]);
        let val_b = Pubkey::from([2u8; 32]);

        // 300 stake — not enough for confirmation
        fc.record_validator_vote(val_a, 1, 300);
        assert!(!fc.get_fork(1).unwrap().confirmed);

        // 700 more stake — now 1000 total on slot 1, which is 100% >= 66.7%
        fc.record_validator_vote(val_b, 1, 700);
        assert!(fc.get_fork(1).unwrap().confirmed);
    }

    #[test]
    fn select_heaviest_fork_consistent_with_compute_best_fork() {
        let mut fc = ForkChoice::new(1000);
        // Deep tree: 0 → 1 → 2 → 4
        //                  → 3
        fc.add_fork(0, None);
        fc.add_fork(1, Some(0));
        fc.add_fork(2, Some(1));
        fc.add_fork(3, Some(1));
        fc.add_fork(4, Some(2));

        let val_a = Pubkey::from([1u8; 32]);
        let val_b = Pubkey::from([2u8; 32]);
        let val_c = Pubkey::from([3u8; 32]);

        // A votes for slot 4 (deep chain), B and C vote for slot 3
        fc.record_validator_vote(val_a, 4, 200);
        fc.record_validator_vote(val_b, 3, 300);
        fc.record_validator_vote(val_c, 3, 400);

        // Both methods should agree: slot 3 is heavier (700 vs 200)
        let best = fc.compute_best_fork(0);
        let heaviest = fc.select_heaviest_fork(0);
        assert_eq!(best, heaviest);
        assert_eq!(best, Some(3));
    }
}
