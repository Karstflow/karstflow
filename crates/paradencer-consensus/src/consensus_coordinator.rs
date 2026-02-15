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
}
