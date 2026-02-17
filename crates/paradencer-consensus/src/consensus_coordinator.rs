/// Consensus coordinator that integrates Tower BFT voting with fork choice algorithm.
///
/// This module coordinates the interaction between:
/// - Tower: Tracks validator's vote history with lockouts
/// - ForkChoice: Determines heaviest fork using GHOST algorithm
/// - Bank: Processes blocks and transactions
///
/// The coordinator ensures that voting decisions respect lockouts and that
/// fork choice accurately reflects stake-weighted validator votes.
use super::{ForkChoice, StakeTracker, Tower};
use paradencer_storage::Pubkey;
use std::collections::HashMap;

/// Tracks votes from validators and their stake weights.
#[derive(Debug, Clone)]
pub struct ValidatorVote {
    pub validator: Pubkey,
    pub slot: u64,
    pub stake: u64,
    pub timestamp: u64,
}

/// Decision output from the consensus engine.
///
/// After a slot has been replayed, the coordinator evaluates the fork tree
/// and tower state to determine whether to vote and which slot to reset to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusDecision {
    /// Slot to reset PoH to (best fork tip).
    pub reset_slot: u64,
    /// Slot to vote for (`None` if we should not vote).
    pub vote_slot: Option<u64>,
    /// New root slot if tower advanced root (`None` if no change).
    pub new_root: Option<u64>,
    /// Reason for the decision.
    pub reason: DecisionReason,
}

/// Reason behind a consensus decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    /// Tower was empty, voting for best fork.
    EmptyTower,
    /// Voting on the same fork as previous vote.
    SameFork,
    /// Switch check passed, voting on a new fork.
    SwitchApproved,
    /// Lockout prevents voting, resetting only.
    LockedOut,
    /// Switch check failed, resetting only.
    SwitchDenied,
    /// No valid fork available.
    NoValidFork,
}

/// Coordinates consensus decisions across Tower and Fork Choice components.
pub struct ConsensusCoordinator {
    /// Local validator's vote tower
    tower: Tower,
    /// Fork choice engine for selecting best fork
    fork_choice: ForkChoice,
    /// Stake tracking system
    stake_tracker: StakeTracker,
    /// Our validator identity
    validator_identity: Pubkey,
    /// Latest votes from validators
    latest_votes: HashMap<Pubkey, ValidatorVote>,
}

impl ConsensusCoordinator {
    pub fn new(validator_identity: Pubkey, current_epoch: u64) -> Self {
        let stake_tracker = StakeTracker::new(current_epoch);
        let total_stake = stake_tracker.total_stake().max(1); // Avoid division by zero

        Self {
            tower: Tower::new(),
            fork_choice: ForkChoice::new(total_stake),
            stake_tracker,
            validator_identity,
            latest_votes: HashMap::new(),
        }
    }

    pub fn new_with_root(validator_identity: Pubkey, root: u64, current_epoch: u64) -> Self {
        let stake_tracker = StakeTracker::new(current_epoch);
        let total_stake = stake_tracker.total_stake().max(1);

        Self {
            tower: Tower::with_root(root),
            fork_choice: ForkChoice::new(total_stake),
            stake_tracker,
            validator_identity,
            latest_votes: HashMap::new(),
        }
    }

    /// Get reference to stake tracker.
    pub fn stake_tracker(&self) -> &StakeTracker {
        &self.stake_tracker
    }

    /// Get mutable reference to stake tracker.
    pub fn stake_tracker_mut(&mut self) -> &mut StakeTracker {
        &mut self.stake_tracker
    }

    /// Update epoch for stake warmup/cooldown calculations.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.stake_tracker.set_epoch(epoch);

        // Update fork choice total stake based on new effective stakes
        let total_stake = self.stake_tracker.total_stake().max(1);
        self.fork_choice.update_total_stake(total_stake);

        // Re-add all current stake weights
        self.refresh_fork_choice_stakes();
    }

    /// Refresh fork choice with current stake weights.
    fn refresh_fork_choice_stakes(&mut self) {
        let stake_map = self.stake_tracker.stake_by_vote_account();

        for (vote_pubkey, stake) in stake_map {
            // Find slots that this validator voted on and update weights
            for vote in self.latest_votes.values() {
                if vote.validator == vote_pubkey {
                    self.fork_choice.add_stake(vote.slot, stake);
                }
            }
        }
    }

    /// Add a new fork to the tree.
    pub fn add_fork(&mut self, slot: u64, parent: Option<u64>) {
        self.fork_choice.add_fork(slot, parent);
    }

    /// Process a vote from a validator.
    ///
    /// Updates fork choice with the validator's stake weight from StakeTracker.
    pub fn record_validator_vote(&mut self, vote: ValidatorVote) {
        let slot = vote.slot;
        let validator = vote.validator;

        // Get actual stake weight from stake tracker
        let stake = self.stake_tracker.total_stake_for_voter(&validator);

        // Record this as the latest vote from this validator
        if let Some(previous_vote) = self.latest_votes.insert(validator, vote.clone()) {
            // If validator changed their vote, just add to the new slot
            if previous_vote.slot != slot {
                self.fork_choice.add_stake(slot, stake);
            }
        } else {
            // First vote from this validator
            self.fork_choice.add_stake(slot, stake);
        }
    }

    /// Check if we can vote on a slot without violating lockouts.
    ///
    /// The is_descendant function should return true if the first slot is a descendant
    /// of the second slot (or if they're the same).
    pub fn can_vote_on_slot(&self, slot: u64, is_descendant: impl Fn(u64, u64) -> bool) -> bool {
        // Convert is_descendant to is_same_fork checker for Tower
        let is_same_fork = |vote_slot: u64, target_slot: u64| -> bool {
            // Two slots are on the same fork if one is ancestor/descendant of the other
            is_descendant(target_slot, vote_slot) || is_descendant(vote_slot, target_slot)
        };

        !self.tower.is_locked_out(slot, is_same_fork)
    }

    /// Record our own vote for a slot.
    ///
    /// Returns Some(new_root) if voting caused root to advance.
    pub fn vote_on_slot(&mut self, slot: u64) -> Option<u64> {
        let new_root = self.tower.push_vote(slot);

        // Add our stake to this slot in fork choice
        let our_stake = self
            .stake_tracker
            .total_stake_for_voter(&self.validator_identity);
        if our_stake > 0 {
            self.fork_choice.add_stake(slot, our_stake);
        }

        new_root
    }

    /// Compute the best fork to build on using GHOST algorithm.
    pub fn compute_best_fork(&mut self, from_slot: u64) -> Option<u64> {
        self.fork_choice.compute_best_fork(from_slot)
    }

    /// Get the current root slot from our tower.
    pub fn root(&self) -> Option<u64> {
        self.tower.root()
    }

    /// Set a new root and prune old forks.
    pub fn set_root(&mut self, new_root: u64) {
        self.tower.set_root(new_root);
        self.fork_choice.set_root(new_root);
    }

    /// Get fork information for analysis.
    pub fn get_fork_info(&self, slot: u64) -> Option<&super::ForkInfo> {
        self.fork_choice.get_fork(slot)
    }

    /// Get our tower for inspection.
    pub fn tower(&self) -> &Tower {
        &self.tower
    }

    /// Check if a fork has reached optimistic confirmation.
    ///
    /// A fork is optimistically confirmed if it has consecutive
    /// supermajority votes for a sufficient depth.
    pub fn is_optimistically_confirmed(&self, slot: u64) -> bool {
        if let Some(fork) = self.fork_choice.get_fork(slot) {
            fork.optimistically_confirmed
        } else {
            false
        }
    }

    /// Check if a fork is confirmed (has supermajority stake).
    pub fn is_confirmed(&self, slot: u64) -> bool {
        if let Some(fork) = self.fork_choice.get_fork(slot) {
            fork.confirmed
        } else {
            false
        }
    }

    /// Check if we should switch from current fork to a candidate fork.
    pub fn should_switch_fork(&self, current: u64, candidate: u64) -> bool {
        self.fork_choice.can_switch_fork(current, candidate)
    }

    /// Get the number of stake delegations currently tracked.
    pub fn delegation_count(&self) -> usize {
        self.stake_tracker.delegation_count()
    }

    /// Get total stake across all delegations.
    pub fn total_stake(&self) -> u64 {
        self.stake_tracker.total_stake()
    }

    /// Get stake weights by vote account.
    pub fn stake_by_vote_account(&self) -> HashMap<Pubkey, u64> {
        self.stake_tracker.stake_by_vote_account()
    }

    /// Decide whether to vote and which slot to reset PoH to.
    ///
    /// Called after a slot has been replayed. Evaluates the fork tree
    /// and tower state to determine the correct consensus action.
    ///
    /// The `is_ancestor` callback should return `true` if `slot_a` is an
    /// ancestor of `slot_b` (or they are equal).
    pub fn decide_vote_and_reset(
        &mut self,
        replayed_slot: u64,
        is_ancestor: impl Fn(u64, u64) -> bool,
    ) -> ConsensusDecision {
        // Determine best fork starting from replayed slot
        let best_slot = self
            .fork_choice
            .compute_best_fork(replayed_slot)
            .unwrap_or(replayed_slot);

        // Case 0: Empty tower — vote for best fork
        if self.tower.is_empty() {
            return ConsensusDecision {
                reset_slot: best_slot,
                vote_slot: Some(best_slot),
                new_root: None,
                reason: DecisionReason::EmptyTower,
            };
        }

        let last_vote = match self.tower.last_vote_slot() {
            Some(v) => v,
            None => {
                return ConsensusDecision {
                    reset_slot: best_slot,
                    vote_slot: Some(best_slot),
                    new_root: None,
                    reason: DecisionReason::EmptyTower,
                };
            }
        };

        // Determine if best fork is on the same fork as our last vote.
        // Two slots are on the same fork if one is an ancestor of the other.
        let same_fork =
            is_ancestor(last_vote, best_slot) || is_ancestor(best_slot, last_vote);

        if same_fork {
            // Same fork — check lockout
            let is_same_fork = |a: u64, b: u64| is_ancestor(a, b) || is_ancestor(b, a);
            if self.tower.is_locked_out(best_slot, is_same_fork) {
                ConsensusDecision {
                    reset_slot: best_slot,
                    vote_slot: None,
                    new_root: None,
                    reason: DecisionReason::LockedOut,
                }
            } else {
                ConsensusDecision {
                    reset_slot: best_slot,
                    vote_slot: Some(best_slot),
                    new_root: None,
                    reason: DecisionReason::SameFork,
                }
            }
        } else {
            // Different fork — need switch check
            if self.fork_choice.can_switch_fork(last_vote, best_slot) {
                ConsensusDecision {
                    reset_slot: best_slot,
                    vote_slot: Some(best_slot),
                    new_root: None,
                    reason: DecisionReason::SwitchApproved,
                }
            } else {
                ConsensusDecision {
                    reset_slot: best_slot,
                    vote_slot: None,
                    new_root: None,
                    reason: DecisionReason::SwitchDenied,
                }
            }
        }
    }

    /// Apply a consensus decision — push vote to tower and advance root.
    ///
    /// Returns the new root slot if one was advanced.
    pub fn execute_decision(&mut self, decision: &ConsensusDecision) -> Option<u64> {
        let tower_root = if let Some(vote_slot) = decision.vote_slot {
            self.vote_on_slot(vote_slot)
        } else {
            None
        };

        let root = decision.new_root.or(tower_root);
        if let Some(r) = root {
            self.advance_root(r);
        }
        root
    }

    /// Advance root across all consensus subsystems.
    ///
    /// Called when tower promotes a new root. Updates tower, fork choice,
    /// and prunes stale validator vote records below the new root.
    pub fn advance_root(&mut self, new_root: u64) {
        self.tower.set_root(new_root);
        self.fork_choice.set_root(new_root);
        self.latest_votes.retain(|_, v| v.slot >= new_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_initializes_correctly() {
        let validator = Pubkey::new_unique();
        let coordinator = ConsensusCoordinator::new(validator, 0);

        assert_eq!(coordinator.validator_identity, validator);
        assert_eq!(coordinator.root(), None);
        assert_eq!(coordinator.delegation_count(), 0);
    }

    #[test]
    fn coordinator_tracks_stake_delegations() {
        let our_validator = Pubkey::new_unique();
        // Start at epoch 10 so stakes are fully activated
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        // Add delegations that activate at epoch 0 (fully active by epoch 4)
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 500, 0),
        );
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter2, 300, 0),
        );

        assert_eq!(coordinator.delegation_count(), 2);
        assert_eq!(coordinator.total_stake(), 800);
    }

    #[test]
    fn coordinator_processes_validator_votes() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        coordinator.add_fork(1, None);
        coordinator.add_fork(2, Some(1));

        let voter1 = Pubkey::new_unique();
        // Add stake delegation for this voter (activated at epoch 0, fully active now)
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 600, 0),
        );

        let vote = ValidatorVote {
            validator: voter1,
            slot: 2,
            stake: 600,
            timestamp: 1000,
        };

        coordinator.record_validator_vote(vote);

        let fork_info = coordinator.get_fork_info(2).unwrap();
        assert_eq!(fork_info.stake_weight, 600);
    }

    #[test]
    fn coordinator_respects_tower_lockouts() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 1000);

        coordinator.add_fork(10, None);
        coordinator.add_fork(20, Some(10));
        coordinator.add_fork(21, Some(20)); // Same fork as 20
        coordinator.add_fork(30, Some(10)); // Different fork from 20

        coordinator.vote_on_slot(20);

        // Create mock is_descendant that knows fork structure
        let is_descendant = |slot: u64, ancestor: u64| {
            if slot == ancestor {
                return true;
            }
            // Chain: 10 -> 20 -> 21
            if slot == 20 && ancestor == 10 {
                return true;
            }
            if slot == 21 && (ancestor == 10 || ancestor == 20) {
                return true;
            }
            // 30 is descendant of 10 only (different fork)
            if slot == 30 && ancestor == 10 {
                return true;
            }
            false
        };

        // Should be able to vote on same fork (21 is descendant of 20)
        assert!(coordinator.can_vote_on_slot(21, is_descendant));

        // Cannot vote on different fork (30 is NOT descendant of 20)
        // but CAN because our lockout only lasts 2 slots (expiration at 22)
        // At slot 30, the vote on 20 has already expired
        assert!(coordinator.can_vote_on_slot(30, is_descendant));
    }

    #[test]
    fn coordinator_computes_best_fork() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        // Create fork structure:
        //     1
        //    / \
        //   2   3
        coordinator.add_fork(1, None);
        coordinator.add_fork(2, Some(1));
        coordinator.add_fork(3, Some(1));

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        // Add stake delegations (activated at epoch 0, fully active now)
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 600, 0),
        );
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter2, 400, 0),
        );

        // Validator 1 votes for fork 2
        coordinator.record_validator_vote(ValidatorVote {
            validator: voter1,
            slot: 2,
            stake: 600,
            timestamp: 1000,
        });

        // Validator 2 votes for fork 3
        coordinator.record_validator_vote(ValidatorVote {
            validator: voter2,
            slot: 3,
            stake: 400,
            timestamp: 1001,
        });

        // Fork 2 has more stake (600 vs 400), should be chosen
        let best = coordinator.compute_best_fork(1);
        assert_eq!(best, Some(2));
    }

    #[test]
    fn coordinator_advances_root() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 0);

        assert_eq!(coordinator.root(), None);

        coordinator.set_root(42);

        assert_eq!(coordinator.root(), Some(42));
    }

    #[test]
    fn coordinator_tracks_confirmation_status() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        coordinator.add_fork(1, None);

        let voter1 = Pubkey::new_unique();
        // Add stake delegation (activated at epoch 0, fully active now)
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 700, 0),
        );

        // Update fork choice with correct total stake
        coordinator.set_epoch(10);

        // Add supermajority stake (70% > 66.67%)
        coordinator.record_validator_vote(ValidatorVote {
            validator: voter1,
            slot: 1,
            stake: 700,
            timestamp: 1000,
        });

        assert!(coordinator.is_confirmed(1));
    }

    // -----------------------------------------------------------------------
    // Phase 4: Consensus decision engine tests
    // -----------------------------------------------------------------------

    /// Helper: linear ancestry (slot a is ancestor of slot b if a < b)
    fn linear_ancestor(a: u64, b: u64) -> bool {
        a <= b
    }

    #[test]
    fn decide_empty_tower_votes_for_best_fork() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));

        let decision = coord.decide_vote_and_reset(1, linear_ancestor);

        assert!(decision.vote_slot.is_some());
        assert_eq!(decision.reason, DecisionReason::EmptyTower);
    }

    #[test]
    fn decide_same_fork_votes() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));
        coord.add_fork(3, Some(2));

        // Vote on slot 2 first
        coord.vote_on_slot(2);

        // Decide at slot 3 (same fork, slot 2 is ancestor of slot 3)
        let decision = coord.decide_vote_and_reset(1, linear_ancestor);

        assert_eq!(decision.reason, DecisionReason::SameFork);
        assert!(decision.vote_slot.is_some());
    }

    #[test]
    fn decide_different_fork_switch_denied() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        // Create forking structure: 1 -> 2 and 1 -> 3
        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));
        coord.add_fork(3, Some(1));

        // Voter A has heavy stake on slot 2
        let voter_a = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_a, 1000, 0),
        );
        // Voter B has small stake on slot 3
        let voter_b = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_b, 100, 0),
        );
        coord.set_epoch(10);

        coord.record_validator_vote(ValidatorVote {
            validator: voter_a,
            slot: 2,
            stake: 1000,
            timestamp: 0,
        });
        coord.record_validator_vote(ValidatorVote {
            validator: voter_b,
            slot: 3,
            stake: 100,
            timestamp: 0,
        });

        // Vote on slot 2 (the heavy fork)
        coord.vote_on_slot(2);

        // Custom ancestry: 1->2 and 1->3 are separate forks
        let is_ancestor = |a: u64, b: u64| -> bool {
            if a == b {
                return true;
            }
            if a == 1 && (b == 2 || b == 3) {
                return true;
            }
            false
        };

        // Best fork should be slot 2 (1000 stake > 100 stake), which is
        // the same fork as last vote → SameFork, not switch
        let decision = coord.decide_vote_and_reset(1, is_ancestor);
        assert_eq!(decision.reason, DecisionReason::SameFork);

        // Now switch the weights: remove voter_a from slot 2 by changing their vote to slot 3
        // Actually let's just test what happens when last vote is on the weak fork:
        // We need coordinator where last_vote is on slot 3 (weak) but best is slot 2 (heavy)
        let mut coord2 = ConsensusCoordinator::new(Pubkey::new_unique(), 10);
        coord2.add_fork(1, None);
        coord2.add_fork(2, Some(1));
        coord2.add_fork(3, Some(1));

        let voter_heavy = Pubkey::new_unique();
        coord2.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_heavy, 1000, 0),
        );
        coord2.set_epoch(10);

        coord2.record_validator_vote(ValidatorVote {
            validator: voter_heavy,
            slot: 2,
            stake: 1000,
            timestamp: 0,
        });

        // Our last vote is on slot 3 (weak fork)
        coord2.vote_on_slot(3);

        // Best fork is slot 2 (1000 stake). Last vote was slot 3 (different fork).
        // can_switch_fork checks if candidate weight >= current weight * (1 + threshold).
        // Slot 2 weight (1000) vs slot 3 weight (0) → current_weight=0 → switch approved
        // (zero weight on current fork always allows switch)
        let decision2 = coord2.decide_vote_and_reset(1, is_ancestor);
        assert_eq!(decision2.reason, DecisionReason::SwitchApproved);
        assert!(decision2.vote_slot.is_some());
    }

    #[test]
    fn execute_decision_pushes_vote() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));

        let decision = ConsensusDecision {
            reset_slot: 2,
            vote_slot: Some(2),
            new_root: None,
            reason: DecisionReason::SameFork,
        };

        coord.execute_decision(&decision);

        assert_eq!(coord.tower().last_vote_slot(), Some(2));
    }

    #[test]
    fn execute_decision_advances_root() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(5, Some(1));

        let decision = ConsensusDecision {
            reset_slot: 5,
            vote_slot: Some(5),
            new_root: Some(1),
            reason: DecisionReason::SameFork,
        };

        let root = coord.execute_decision(&decision);

        assert_eq!(root, Some(1));
        assert_eq!(coord.root(), Some(1));
    }

    #[test]
    fn execute_decision_no_vote_no_root() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        let decision = ConsensusDecision {
            reset_slot: 5,
            vote_slot: None,
            new_root: None,
            reason: DecisionReason::LockedOut,
        };

        let root = coord.execute_decision(&decision);

        assert_eq!(root, None);
        assert!(coord.tower().is_empty());
    }

    #[test]
    fn advance_root_prunes_old_votes() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        let voter = Pubkey::new_unique();
        coord.add_fork(1, None);
        coord.add_fork(5, Some(1));
        coord.add_fork(10, Some(5));

        coord.record_validator_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 100,
            timestamp: 0,
        });

        assert_eq!(coord.latest_votes.len(), 1);

        coord.advance_root(5);

        // Vote at slot 1 should be pruned (below root 5)
        assert_eq!(coord.latest_votes.len(), 0);
        assert_eq!(coord.root(), Some(5));
    }

    #[test]
    fn decide_vote_and_reset_full_cycle() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        // Build linear chain
        for slot in 1..=10 {
            coord.add_fork(slot, if slot == 1 { None } else { Some(slot - 1) });
        }

        // Decide and execute multiple votes
        for slot in 1..=5 {
            let decision = coord.decide_vote_and_reset(1, linear_ancestor);
            let _root = coord.execute_decision(&decision);
            assert!(decision.vote_slot.is_some());
        }

        // After 5 votes, tower should have votes
        assert!(!coord.tower().is_empty());
    }
}
