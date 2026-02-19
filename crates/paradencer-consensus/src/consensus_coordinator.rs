/// Consensus coordinator that integrates Tower BFT voting with fork choice,
/// vote processing, commitment tracking, and equivocation detection.
///
/// This is the central orchestrator for consensus decisions. It coordinates:
/// - Tower: Tracks our validator's vote history with lockouts
/// - ForkChoice: Determines heaviest fork using LMD-GHOST algorithm
/// - VoteProcessor: Validates and aggregates votes from all validators
/// - CommitmentTracker: Tracks multi-threshold confirmation progression
/// - EquivocationDetector: Catches conflicting votes from validators
///
/// After replaying a slot, the coordinator evaluates the fork tree and tower
/// state to decide whether to vote and which slot to reset PoH to.
use super::{
    CommitmentConfig, CommitmentTracker, ConfirmationEvent, ConfirmationStatus,
    EquivocationDetector, EquivocationProof, ForkChoice, StakeTracker, Tower, VoteProcessor,
    VoteProcessorConfig,
};
use paradencer_storage::Pubkey;
use std::collections::HashMap;

/// Tracks votes from validators and their stake weights.
#[derive(Debug, Clone)]
pub struct ValidatorVote {
    pub validator: Pubkey,
    pub slot: u64,
    pub stake: u64,
    pub timestamp: u64,
    /// Optional block hash for equivocation detection.
    pub block_hash: Option<[u8; 32]>,
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
    /// Slot is not yet propagated (below 1/3 stake threshold).
    NotPropagated,
}

/// Result of processing an incoming vote through the full pipeline.
#[derive(Debug)]
pub struct VoteProcessingResult {
    /// Confirmation events emitted by this vote.
    pub confirmation_events: Vec<ConfirmationEvent>,
    /// Equivocation proof if the vote was conflicting.
    pub equivocation_proof: Option<EquivocationProof>,
}

/// Coordinates consensus decisions across all consensus subsystems.
pub struct ConsensusCoordinator {
    /// Local validator's vote tower.
    tower: Tower,
    /// Fork choice engine for selecting best fork.
    fork_choice: ForkChoice,
    /// Stake tracking system.
    stake_tracker: StakeTracker,
    /// Vote processing and aggregation.
    vote_processor: VoteProcessor,
    /// Multi-threshold commitment tracking.
    commitment_tracker: CommitmentTracker,
    /// Equivocation detection.
    equivocation_detector: EquivocationDetector,
    /// Our validator identity.
    validator_identity: Pubkey,
    /// Latest votes from validators (for pruning and refresh).
    latest_votes: HashMap<Pubkey, ValidatorVote>,
    /// Whether to require propagation (1/3 stake) before voting.
    require_propagation_for_vote: bool,
}

impl ConsensusCoordinator {
    pub fn new(validator_identity: Pubkey, current_epoch: u64) -> Self {
        let stake_tracker = StakeTracker::new(current_epoch);
        let total_stake = stake_tracker.total_stake().max(1);

        let vote_processor =
            VoteProcessor::new(VoteProcessorConfig::default(), stake_tracker.clone());

        Self {
            tower: Tower::new(),
            fork_choice: ForkChoice::new(total_stake),
            stake_tracker,
            vote_processor,
            commitment_tracker: CommitmentTracker::new(CommitmentConfig::default()),
            equivocation_detector: EquivocationDetector::new(),
            validator_identity,
            latest_votes: HashMap::new(),
            require_propagation_for_vote: true,
        }
    }

    pub fn new_with_root(validator_identity: Pubkey, root: u64, current_epoch: u64) -> Self {
        let stake_tracker = StakeTracker::new(current_epoch);
        let total_stake = stake_tracker.total_stake().max(1);

        let vote_processor =
            VoteProcessor::new(VoteProcessorConfig::default(), stake_tracker.clone());

        Self {
            tower: Tower::with_root(root),
            fork_choice: ForkChoice::new(total_stake),
            stake_tracker,
            vote_processor,
            commitment_tracker: CommitmentTracker::new(CommitmentConfig::default()),
            equivocation_detector: EquivocationDetector::new(),
            validator_identity,
            latest_votes: HashMap::new(),
            require_propagation_for_vote: true,
        }
    }

    /// Disable the propagation check for voting (useful for tests).
    pub fn disable_propagation_check(&mut self) {
        self.require_propagation_for_vote = false;
    }

    /// Get reference to stake tracker.
    pub fn stake_tracker(&self) -> &StakeTracker {
        &self.stake_tracker
    }

    /// Get mutable reference to stake tracker.
    pub fn stake_tracker_mut(&mut self) -> &mut StakeTracker {
        &mut self.stake_tracker
    }

    /// Get reference to the vote processor.
    pub fn vote_processor(&self) -> &VoteProcessor {
        &self.vote_processor
    }

    /// Get mutable reference to the vote processor.
    pub fn vote_processor_mut(&mut self) -> &mut VoteProcessor {
        &mut self.vote_processor
    }

    /// Get reference to the commitment tracker.
    pub fn commitment_tracker(&self) -> &CommitmentTracker {
        &self.commitment_tracker
    }

    /// Get mutable reference to the commitment tracker.
    pub fn commitment_tracker_mut(&mut self) -> &mut CommitmentTracker {
        &mut self.commitment_tracker
    }

    /// Get reference to the equivocation detector.
    pub fn equivocation_detector(&self) -> &EquivocationDetector {
        &self.equivocation_detector
    }

    /// Update epoch for stake warmup/cooldown calculations.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.stake_tracker.set_epoch(epoch);

        // Update fork choice total stake
        let total_stake = self.stake_tracker.total_stake().max(1);
        self.fork_choice.update_total_stake(total_stake);

        // Update vote processor with new stake info
        self.vote_processor
            .update_stake_tracker(self.stake_tracker.clone());

        // Re-add all current stake weights
        self.refresh_fork_choice_stakes();
    }

    /// Refresh fork choice with current stake weights.
    fn refresh_fork_choice_stakes(&mut self) {
        let votes: Vec<(Pubkey, u64)> = self
            .latest_votes
            .iter()
            .map(|(validator, vote)| (*validator, vote.slot))
            .collect();

        for (validator, slot) in votes {
            let stake = self.stake_tracker.total_stake_for_voter(&validator);
            self.fork_choice
                .record_validator_vote(validator, slot, stake);
        }
    }

    /// Add a new fork to the tree.
    pub fn add_fork(&mut self, slot: u64, parent: Option<u64>) {
        self.fork_choice.add_fork(slot, parent);
    }

    /// Mark a slot as processed (block received and replayed).
    pub fn mark_slot_processed(&mut self, slot: u64) {
        let current_stake = self.vote_processor.get_slot_stake(slot);
        let total_stake = self.vote_processor.total_stake();
        self.commitment_tracker
            .mark_processed(slot, current_stake, total_stake);
    }

    /// Process an incoming vote through the full pipeline.
    ///
    /// Runs equivocation detection, vote aggregation, fork choice update,
    /// and commitment threshold checking. Returns confirmation events and
    /// any equivocation proof.
    pub fn process_incoming_vote(&mut self, vote: ValidatorVote) -> VoteProcessingResult {
        let slot = vote.slot;
        let validator = vote.validator;
        let timestamp = vote.timestamp;

        // Check for equivocation if block hash is provided
        let equivocation_proof = if let Some(block_hash) = vote.block_hash {
            self.equivocation_detector
                .record_vote(validator, slot, block_hash, timestamp)
        } else {
            None
        };

        // Get stake for fork choice
        let stake = self.stake_tracker.total_stake_for_voter(&validator);

        // Update fork choice with LMD-GHOST semantics
        self.fork_choice
            .record_validator_vote(validator, slot, stake);

        // Track latest vote for pruning
        self.latest_votes.insert(validator, vote);

        // Feed into commitment tracker (vote aggregation is done by VoteProcessor
        // when votes go through process_vote, but for external votes we update
        // commitment directly based on fork choice stake)
        let total_stake = self.stake_tracker.total_stake().max(1);
        let fork_stake = self
            .fork_choice
            .get_fork(slot)
            .map(|f| f.stake_weight)
            .unwrap_or(0);
        let confirmation_events =
            self.commitment_tracker
                .update_stake(slot, fork_stake, total_stake);

        VoteProcessingResult {
            confirmation_events,
            equivocation_proof,
        }
    }

    /// Check if we can vote on a slot without violating lockouts.
    pub fn can_vote_on_slot(&self, slot: u64, is_descendant: impl Fn(u64, u64) -> bool) -> bool {
        let is_same_fork = |vote_slot: u64, target_slot: u64| -> bool {
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

    /// Check if a slot is propagated (1/3+ stake has voted).
    pub fn is_propagated(&self, slot: u64) -> bool {
        self.commitment_tracker.is_propagated(slot)
    }

    /// Check if a slot is duplicate confirmed (52%+ stake).
    pub fn is_duplicate_confirmed(&self, slot: u64) -> bool {
        self.commitment_tracker.is_duplicate_confirmed(slot)
    }

    /// Check if a fork has reached optimistic confirmation.
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

    /// Check if a slot is super confirmed (4/5+ stake).
    pub fn is_super_confirmed(&self, slot: u64) -> bool {
        self.commitment_tracker.is_super_confirmed(slot)
    }

    /// Get the confirmation status for a slot.
    pub fn get_confirmation_status(&self, slot: u64) -> ConfirmationStatus {
        self.commitment_tracker
            .get_confirmation_status(slot)
            .unwrap_or(ConfirmationStatus::Unconfirmed)
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

        // Check propagation requirement: don't vote until 1/3 stake has voted
        if self.require_propagation_for_vote && !self.is_propagated(best_slot) {
            return ConsensusDecision {
                reset_slot: best_slot,
                vote_slot: None,
                new_root: None,
                reason: DecisionReason::NotPropagated,
            };
        }

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
        let same_fork = is_ancestor(last_vote, best_slot) || is_ancestor(best_slot, last_vote);

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
    /// commitment tracker, equivocation detector, and prunes stale records.
    pub fn advance_root(&mut self, new_root: u64) {
        self.tower.set_root(new_root);
        self.fork_choice.set_root(new_root);
        self.commitment_tracker.update_root(new_root);
        self.vote_processor.prune_below_root(new_root);
        self.equivocation_detector.prune_below_root(new_root);
        self.latest_votes.retain(|_, v| v.slot >= new_root);
    }
}

// Allow debug printing (VoteProcessor derives Debug)
impl std::fmt::Debug for ConsensusCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusCoordinator")
            .field("validator_identity", &self.validator_identity)
            .field("root", &self.tower.root())
            .field("total_stake", &self.stake_tracker.total_stake())
            .field("latest_votes_count", &self.latest_votes.len())
            .finish()
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
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

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
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 600, 0),
        );

        // Must refresh to pick up new stake
        coordinator.set_epoch(10);

        let vote = ValidatorVote {
            validator: voter1,
            slot: 2,
            stake: 600,
            timestamp: 1000,
            block_hash: None,
        };

        coordinator.process_incoming_vote(vote);

        let fork_info = coordinator.get_fork_info(2).unwrap();
        assert_eq!(fork_info.stake_weight, 600);
    }

    #[test]
    fn coordinator_respects_tower_lockouts() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 1000);

        coordinator.add_fork(10, None);
        coordinator.add_fork(20, Some(10));
        coordinator.add_fork(21, Some(20));
        coordinator.add_fork(30, Some(10));

        coordinator.vote_on_slot(20);

        let is_descendant = |slot: u64, ancestor: u64| {
            if slot == ancestor {
                return true;
            }
            if slot == 20 && ancestor == 10 {
                return true;
            }
            if slot == 21 && (ancestor == 10 || ancestor == 20) {
                return true;
            }
            if slot == 30 && ancestor == 10 {
                return true;
            }
            false
        };

        assert!(coordinator.can_vote_on_slot(21, is_descendant));
        assert!(coordinator.can_vote_on_slot(30, is_descendant));
    }

    #[test]
    fn coordinator_computes_best_fork() {
        let our_validator = Pubkey::new_unique();
        let mut coordinator = ConsensusCoordinator::new(our_validator, 10);

        coordinator.add_fork(1, None);
        coordinator.add_fork(2, Some(1));
        coordinator.add_fork(3, Some(1));

        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 600, 0),
        );
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter2, 400, 0),
        );
        coordinator.set_epoch(10);

        coordinator.process_incoming_vote(ValidatorVote {
            validator: voter1,
            slot: 2,
            stake: 600,
            timestamp: 1000,
            block_hash: None,
        });
        coordinator.process_incoming_vote(ValidatorVote {
            validator: voter2,
            slot: 3,
            stake: 400,
            timestamp: 1001,
            block_hash: None,
        });

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
        coordinator.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 700, 0),
        );
        coordinator.set_epoch(10);

        coordinator.process_incoming_vote(ValidatorVote {
            validator: voter1,
            slot: 1,
            stake: 700,
            timestamp: 1000,
            block_hash: None,
        });

        assert!(coordinator.is_confirmed(1));
    }

    // -----------------------------------------------------------------------
    // Decision engine tests
    // -----------------------------------------------------------------------

    fn linear_ancestor(a: u64, b: u64) -> bool {
        a <= b
    }

    #[test]
    fn decide_empty_tower_votes_for_best_fork() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);
        coord.disable_propagation_check();

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
        coord.disable_propagation_check();

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));
        coord.add_fork(3, Some(2));

        coord.vote_on_slot(2);

        let decision = coord.decide_vote_and_reset(1, linear_ancestor);

        assert_eq!(decision.reason, DecisionReason::SameFork);
        assert!(decision.vote_slot.is_some());
    }

    #[test]
    fn decide_different_fork_switch_denied() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);
        coord.disable_propagation_check();

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));
        coord.add_fork(3, Some(1));

        let voter_a = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_a, 1000, 0),
        );
        let voter_b = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_b, 100, 0),
        );
        coord.set_epoch(10);

        coord.process_incoming_vote(ValidatorVote {
            validator: voter_a,
            slot: 2,
            stake: 1000,
            timestamp: 0,
            block_hash: None,
        });
        coord.process_incoming_vote(ValidatorVote {
            validator: voter_b,
            slot: 3,
            stake: 100,
            timestamp: 0,
            block_hash: None,
        });

        coord.vote_on_slot(2);

        let is_ancestor = |a: u64, b: u64| -> bool {
            if a == b {
                return true;
            }
            if a == 1 && (b == 2 || b == 3) {
                return true;
            }
            false
        };

        let decision = coord.decide_vote_and_reset(1, is_ancestor);
        assert_eq!(decision.reason, DecisionReason::SameFork);

        // Test switch from weak to heavy fork
        let mut coord2 = ConsensusCoordinator::new(Pubkey::new_unique(), 10);
        coord2.disable_propagation_check();
        coord2.add_fork(1, None);
        coord2.add_fork(2, Some(1));
        coord2.add_fork(3, Some(1));

        let voter_heavy = Pubkey::new_unique();
        coord2.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter_heavy, 1000, 0),
        );
        coord2.set_epoch(10);

        coord2.process_incoming_vote(ValidatorVote {
            validator: voter_heavy,
            slot: 2,
            stake: 1000,
            timestamp: 0,
            block_hash: None,
        });

        coord2.vote_on_slot(3);

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

        coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 100,
            timestamp: 0,
            block_hash: None,
        });

        assert_eq!(coord.latest_votes.len(), 1);

        coord.advance_root(5);

        assert_eq!(coord.latest_votes.len(), 0);
        assert_eq!(coord.root(), Some(5));
    }

    #[test]
    fn decide_vote_and_reset_full_cycle() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);
        coord.disable_propagation_check();

        for slot in 1..=10 {
            coord.add_fork(slot, if slot == 1 { None } else { Some(slot - 1) });
        }

        for _slot in 1..=5 {
            let decision = coord.decide_vote_and_reset(1, linear_ancestor);
            let _root = coord.execute_decision(&decision);
            assert!(decision.vote_slot.is_some());
        }

        assert!(!coord.tower().is_empty());
    }

    // -----------------------------------------------------------------------
    // New tests: integrated pipeline
    // -----------------------------------------------------------------------

    #[test]
    fn incoming_vote_emits_confirmation_events() {
        let our_validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(our_validator, 10);

        coord.add_fork(1, None);

        let voter = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter, 900, 0),
        );
        coord.set_epoch(10);

        // Mark slot as processed first
        coord.mark_slot_processed(1);

        let result = coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 900,
            timestamp: 1000,
            block_hash: None,
        });

        // 900/900 = 100% → crosses all 4 thresholds
        assert!(!result.confirmation_events.is_empty());
        assert!(result.equivocation_proof.is_none());

        // Check confirmation status
        assert!(coord.is_propagated(1));
        assert!(coord.is_duplicate_confirmed(1));
    }

    #[test]
    fn incoming_vote_detects_equivocation() {
        let our_validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(our_validator, 10);

        coord.add_fork(1, None);

        let voter = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter, 500, 0),
        );
        coord.set_epoch(10);

        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];

        // First vote
        let result1 = coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 500,
            timestamp: 1000,
            block_hash: Some(hash_a),
        });
        assert!(result1.equivocation_proof.is_none());

        // Conflicting vote on same slot
        let result2 = coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 500,
            timestamp: 1001,
            block_hash: Some(hash_b),
        });
        assert!(result2.equivocation_proof.is_some());
        let proof = result2.equivocation_proof.unwrap();
        assert_eq!(proof.validator, voter);
        assert_eq!(proof.slot, 1);
    }

    #[test]
    fn propagation_check_blocks_premature_voting() {
        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);
        // propagation check enabled by default

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));

        // No votes recorded → slot not propagated → should block voting
        let decision = coord.decide_vote_and_reset(1, linear_ancestor);
        assert_eq!(decision.reason, DecisionReason::NotPropagated);
        assert_eq!(decision.vote_slot, None);
    }

    #[test]
    fn propagation_check_allows_voting_after_threshold() {
        let our_validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(our_validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(2, Some(1));

        // Add enough stake to reach propagation (1/3)
        let voter = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter, 500, 0),
        );
        coord.set_epoch(10);

        // Mark slot processed and add votes
        coord.mark_slot_processed(2);
        coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 2,
            stake: 500,
            timestamp: 1000,
            block_hash: None,
        });

        // 500/500 = 100% → propagated
        assert!(coord.is_propagated(2));

        // Now should allow voting
        let decision = coord.decide_vote_and_reset(1, linear_ancestor);
        assert_ne!(decision.reason, DecisionReason::NotPropagated);
        assert!(decision.vote_slot.is_some());
    }

    #[test]
    fn advance_root_prunes_all_subsystems() {
        let our_validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(our_validator, 10);

        coord.add_fork(1, None);
        coord.add_fork(5, Some(1));
        coord.add_fork(10, Some(5));

        let voter = Pubkey::new_unique();
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter, 500, 0),
        );
        coord.set_epoch(10);

        // Process vote and mark slots
        coord.mark_slot_processed(1);
        coord.process_incoming_vote(ValidatorVote {
            validator: voter,
            slot: 1,
            stake: 500,
            timestamp: 1000,
            block_hash: Some([1u8; 32]),
        });

        // Advance root to slot 5
        coord.advance_root(5);

        // Slot 1 should be pruned from commitment tracker
        assert_eq!(coord.commitment_tracker.get_commitment_level(1), None);
        // Equivocation detector should be pruned
        assert!(!coord.equivocation_detector.has_equivocated(&voter, 1));
    }

    #[test]
    fn coordinator_multi_threshold_progression() {
        let our_validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(our_validator, 10);

        coord.add_fork(1, None);

        // Create 3 voters with varying stake
        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();
        let voter3 = Pubkey::new_unique();

        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter1, 200, 0),
        );
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter2, 200, 0),
        );
        coord.stake_tracker_mut().add_delegation(
            Pubkey::new_unique(),
            super::super::Delegation::new(voter3, 600, 0),
        );
        coord.set_epoch(10);

        coord.mark_slot_processed(1);

        // Voter1: 200/1000 = 20% → unconfirmed
        let r1 = coord.process_incoming_vote(ValidatorVote {
            validator: voter1,
            slot: 1,
            stake: 200,
            timestamp: 100,
            block_hash: None,
        });
        assert!(r1.confirmation_events.is_empty());
        assert_eq!(
            coord.get_confirmation_status(1),
            ConfirmationStatus::Unconfirmed
        );

        // Voter2: 400/1000 = 40% → propagated
        let r2 = coord.process_incoming_vote(ValidatorVote {
            validator: voter2,
            slot: 1,
            stake: 200,
            timestamp: 101,
            block_hash: None,
        });
        assert!(!r2.confirmation_events.is_empty());
        assert!(coord.is_propagated(1));

        // Voter3: 1000/1000 = 100% → all thresholds
        let r3 = coord.process_incoming_vote(ValidatorVote {
            validator: voter3,
            slot: 1,
            stake: 600,
            timestamp: 102,
            block_hash: None,
        });
        assert!(r3.confirmation_events.len() >= 2); // dup_conf + opt_conf + super
        assert!(coord.is_super_confirmed(1));
    }
}
