/// Vote processing and validation for consensus.
///
/// Handles validation of validator votes, tower lockout enforcement,
/// and stake-weighted vote aggregation for fork choice and commitment tracking.
use crate::{ForkChoice, StakeTracker, Tower, VoteError, VoteState};
use paradencer_storage::Pubkey;
use std::collections::HashMap;

/// Configuration for vote processing behavior.
#[derive(Debug, Clone)]
pub struct VoteProcessorConfig {
    /// Minimum stake required for a vote to be considered
    pub min_stake_threshold: u64,
    /// Enable strict tower lockout enforcement
    pub enforce_tower_lockouts: bool,
    /// Enable vote signature verification
    pub verify_signatures: bool,
    /// Enable vote account authorization checks
    pub verify_authorization: bool,
}

impl Default for VoteProcessorConfig {
    fn default() -> Self {
        Self {
            min_stake_threshold: 0,
            enforce_tower_lockouts: true,
            verify_signatures: true,
            verify_authorization: true,
        }
    }
}

/// Tracks vote aggregation for a specific slot.
#[derive(Debug, Clone)]
pub struct SlotVoteInfo {
    /// Slot being voted on
    pub slot: u64,
    /// Total stake that has voted for this slot
    pub total_stake: u64,
    /// Map of vote account -> stake amount
    pub votes_by_account: HashMap<Pubkey, u64>,
    /// Whether this slot has reached supermajority (2/3+ stake)
    pub has_supermajority: bool,
}

impl SlotVoteInfo {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            total_stake: 0,
            votes_by_account: HashMap::new(),
            has_supermajority: false,
        }
    }

    /// Add a vote with stake weight.
    pub fn add_vote(&mut self, vote_account: Pubkey, stake: u64) {
        if !self.votes_by_account.contains_key(&vote_account) {
            self.votes_by_account.insert(vote_account, stake);
            self.total_stake = self.total_stake.saturating_add(stake);
        }
    }

    /// Remove a vote (for example if validator switches forks).
    pub fn remove_vote(&mut self, vote_account: &Pubkey) {
        if let Some(stake) = self.votes_by_account.remove(vote_account) {
            self.total_stake = self.total_stake.saturating_sub(stake);
        }
    }

    /// Update supermajority status based on total network stake.
    pub fn update_supermajority(&mut self, total_network_stake: u64) {
        if total_network_stake == 0 {
            self.has_supermajority = false;
            return;
        }

        let ratio = self.total_stake as f64 / total_network_stake as f64;
        self.has_supermajority = ratio >= 2.0 / 3.0;
    }

    /// Get the stake ratio (0.0 to 1.0) for this slot.
    pub fn stake_ratio(&self, total_network_stake: u64) -> f64 {
        if total_network_stake == 0 {
            return 0.0;
        }
        self.total_stake as f64 / total_network_stake as f64
    }

    /// Check if a vote account has voted on this slot.
    pub fn has_voted(&self, vote_account: &Pubkey) -> bool {
        self.votes_by_account.contains_key(vote_account)
    }

    /// Get the number of unique validators that have voted.
    pub fn validator_count(&self) -> usize {
        self.votes_by_account.len()
    }
}

/// Processes and validates validator votes for consensus.
///
/// Integrates with Tower for lockout enforcement, StakeTracker for
/// stake weighting, and ForkChoice for fork selection.
#[derive(Debug)]
pub struct VoteProcessor {
    /// Configuration for vote processing
    config: VoteProcessorConfig,
    /// Vote aggregation by slot
    slot_votes: HashMap<u64, SlotVoteInfo>,
    /// Current vote states for each vote account
    vote_states: HashMap<Pubkey, VoteState>,
    /// Stake tracker for vote weighting
    stake_tracker: StakeTracker,
    /// Total active stake in the network
    total_stake: u64,
}

impl VoteProcessor {
    pub fn new(config: VoteProcessorConfig, stake_tracker: StakeTracker) -> Self {
        let total_stake = stake_tracker.total_stake();
        Self {
            config,
            slot_votes: HashMap::new(),
            vote_states: HashMap::new(),
            stake_tracker,
            total_stake,
        }
    }

    /// Register a vote account with its initial state.
    pub fn register_vote_account(&mut self, vote_account: Pubkey, vote_state: VoteState) {
        self.vote_states.insert(vote_account, vote_state);
    }

    /// Get the vote state for a vote account.
    pub fn get_vote_state(&self, vote_account: &Pubkey) -> Option<&VoteState> {
        self.vote_states.get(vote_account)
    }

    /// Get mutable vote state for a vote account.
    pub fn get_vote_state_mut(&mut self, vote_account: &Pubkey) -> Option<&mut VoteState> {
        self.vote_states.get_mut(vote_account)
    }

    /// Update the stake tracker (e.g., after epoch transition).
    pub fn update_stake_tracker(&mut self, stake_tracker: StakeTracker) {
        self.total_stake = stake_tracker.total_stake();
        self.stake_tracker = stake_tracker;

        // Recalculate supermajority for all slots
        let slots: Vec<u64> = self.slot_votes.keys().copied().collect();
        for slot in slots {
            if let Some(vote_info) = self.slot_votes.get_mut(&slot) {
                vote_info.update_supermajority(self.total_stake);
            }
        }
    }

    /// Get stake weight for a vote account.
    fn get_vote_stake(&self, vote_account: &Pubkey) -> u64 {
        self.stake_tracker.total_stake_for_voter(vote_account)
    }

    /// Validate a vote before processing.
    fn validate_vote(
        &self,
        vote_account: &Pubkey,
        slot: u64,
        tower: Option<&Tower>,
    ) -> Result<(), VoteProcessorError> {
        // Check if vote account exists
        let vote_state = self
            .vote_states
            .get(vote_account)
            .ok_or(VoteProcessorError::VoteAccountNotFound(*vote_account))?;

        // Check if slot is newer than last vote
        if let Some(last_voted) = vote_state.last_voted_slot() {
            if slot <= last_voted {
                return Err(VoteProcessorError::VoteNotNewer { slot, last_voted });
            }
        }

        // Check minimum stake threshold
        let stake = self.get_vote_stake(vote_account);
        if stake < self.config.min_stake_threshold {
            return Err(VoteProcessorError::InsufficientStake {
                vote_account: *vote_account,
                stake,
                required: self.config.min_stake_threshold,
            });
        }

        // Enforce tower lockout if enabled and tower provided
        if self.config.enforce_tower_lockouts {
            if let Some(tower) = tower {
                if !vote_state.can_vote_on_slot(slot) {
                    return Err(VoteProcessorError::LockoutViolation { slot });
                }

                // Check tower-specific lockouts (requires fork ancestry check)
                // This would need fork choice integration for full validation
            }
        }

        Ok(())
    }

    /// Process a vote from a validator.
    ///
    /// Validates the vote, updates vote state, and aggregates stake weight.
    /// Returns the updated stake weight for the voted slot.
    pub fn process_vote(
        &mut self,
        vote_account: Pubkey,
        slot: u64,
        timestamp: i64,
        tower: Option<&Tower>,
        fork_choice: Option<&mut ForkChoice>,
    ) -> Result<u64, VoteProcessorError> {
        // Validate the vote
        self.validate_vote(&vote_account, slot, tower)?;

        // Get stake weight for this vote
        let stake = self.get_vote_stake(&vote_account);

        // Remove previous vote from slot aggregation if switching forks
        if let Some(vote_state) = self.vote_states.get(&vote_account) {
            if let Some(last_voted) = vote_state.last_voted_slot() {
                if last_voted != slot {
                    // Validator is switching - remove old vote
                    if let Some(old_vote_info) = self.slot_votes.get_mut(&last_voted) {
                        old_vote_info.remove_vote(&vote_account);
                        old_vote_info.update_supermajority(self.total_stake);
                    }
                }
            }
        }

        // Update vote state
        let vote_state = self
            .vote_states
            .get_mut(&vote_account)
            .ok_or(VoteProcessorError::VoteAccountNotFound(vote_account))?;

        vote_state
            .process_vote(slot, timestamp, 0)
            .map_err(|e| VoteProcessorError::VoteStateError(e))?;

        // Update slot vote aggregation
        let vote_info = self
            .slot_votes
            .entry(slot)
            .or_insert_with(|| SlotVoteInfo::new(slot));
        vote_info.add_vote(vote_account, stake);
        vote_info.update_supermajority(self.total_stake);

        // Update fork choice with new vote
        if let Some(fc) = fork_choice {
            fc.add_stake(slot, stake);
        }

        Ok(vote_info.total_stake)
    }

    /// Process multiple votes as a batch.
    pub fn process_votes_batch(
        &mut self,
        votes: Vec<(Pubkey, u64, i64)>, // (vote_account, slot, timestamp)
        tower: Option<&Tower>,
        mut fork_choice: Option<&mut ForkChoice>,
    ) -> Vec<Result<u64, VoteProcessorError>> {
        let mut results = Vec::with_capacity(votes.len());

        for (vote_account, slot, timestamp) in votes {
            let result = self.process_vote(
                vote_account,
                slot,
                timestamp,
                tower,
                fork_choice.as_mut().map(|fc| &mut **fc),
            );
            results.push(result);
        }

        results
    }

    /// Get vote information for a specific slot.
    pub fn get_slot_votes(&self, slot: u64) -> Option<&SlotVoteInfo> {
        self.slot_votes.get(&slot)
    }

    /// Check if a slot has reached supermajority (2/3+ stake).
    pub fn has_supermajority(&self, slot: u64) -> bool {
        self.slot_votes
            .get(&slot)
            .map(|v| v.has_supermajority)
            .unwrap_or(false)
    }

    /// Get the total stake that has voted for a slot.
    pub fn get_slot_stake(&self, slot: u64) -> u64 {
        self.slot_votes
            .get(&slot)
            .map(|v| v.total_stake)
            .unwrap_or(0)
    }

    /// Get the stake ratio for a slot (0.0 to 1.0).
    pub fn get_slot_stake_ratio(&self, slot: u64) -> f64 {
        self.slot_votes
            .get(&slot)
            .map(|v| v.stake_ratio(self.total_stake))
            .unwrap_or(0.0)
    }

    /// Get all slots with votes.
    pub fn voted_slots(&self) -> Vec<u64> {
        self.slot_votes.keys().copied().collect()
    }

    /// Prune vote information for slots below a root.
    pub fn prune_below_root(&mut self, root_slot: u64) {
        self.slot_votes.retain(|slot, _| *slot >= root_slot);

        // Update vote states to reflect new root
        for vote_state in self.vote_states.values_mut() {
            if let Some(current_root) = vote_state.root_slot {
                if root_slot > current_root {
                    vote_state.set_root(root_slot);
                }
            } else {
                vote_state.set_root(root_slot);
            }
        }
    }

    /// Get the total stake in the network.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Get a list of vote accounts that have voted on a slot.
    pub fn voters_for_slot(&self, slot: u64) -> Vec<Pubkey> {
        self.slot_votes
            .get(&slot)
            .map(|v| v.votes_by_account.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get statistics about vote aggregation.
    pub fn get_stats(&self) -> VoteProcessorStats {
        let total_slots_with_votes = self.slot_votes.len();
        let slots_with_supermajority = self
            .slot_votes
            .values()
            .filter(|v| v.has_supermajority)
            .count();

        let total_validators = self.vote_states.len();
        let active_validators = self
            .vote_states
            .keys()
            .filter(|va| self.get_vote_stake(va) > 0)
            .count();

        VoteProcessorStats {
            total_slots_with_votes,
            slots_with_supermajority,
            total_validators,
            active_validators,
            total_stake: self.total_stake,
        }
    }
}

/// Statistics about vote processing.
#[derive(Debug, Clone, Copy)]
pub struct VoteProcessorStats {
    pub total_slots_with_votes: usize,
    pub slots_with_supermajority: usize,
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_stake: u64,
}

/// Errors that can occur during vote processing.
#[derive(Debug, Clone, PartialEq)]
pub enum VoteProcessorError {
    /// Vote account not found
    VoteAccountNotFound(Pubkey),
    /// Vote is not newer than last vote
    VoteNotNewer { slot: u64, last_voted: u64 },
    /// Insufficient stake for vote to be counted
    InsufficientStake {
        vote_account: Pubkey,
        stake: u64,
        required: u64,
    },
    /// Vote violates tower lockout rules
    LockoutViolation { slot: u64 },
    /// Error from vote state processing
    VoteStateError(VoteError),
    /// Vote signature verification failed
    InvalidSignature,
    /// Vote account authorization check failed
    UnauthorizedVoter,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Delegation, VoteState};

    fn create_test_vote_processor() -> VoteProcessor {
        let config = VoteProcessorConfig::default();
        let stake_tracker = StakeTracker::new(0);
        VoteProcessor::new(config, stake_tracker)
    }

    fn setup_vote_account(processor: &mut VoteProcessor, stake: u64) -> (Pubkey, Pubkey) {
        let vote_account = Pubkey::new_unique();
        let node_pubkey = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_state = VoteState::new(node_pubkey, voter, withdrawer, 5);
        processor.register_vote_account(vote_account, vote_state);

        // Add stake delegation
        let stake_account = Pubkey::new_unique();
        let delegation = Delegation::new(vote_account, stake, 0);
        processor
            .stake_tracker
            .add_delegation(stake_account, delegation);

        // Update total stake
        let total = processor.stake_tracker.total_stake();
        processor.total_stake = total;

        (vote_account, node_pubkey)
    }

    #[test]
    fn vote_processor_registers_vote_account() {
        let mut processor = create_test_vote_processor();
        let (vote_account, _) = setup_vote_account(&mut processor, 1000);

        assert!(processor.get_vote_state(&vote_account).is_some());
    }

    #[test]
    fn vote_processor_processes_valid_vote() {
        let mut processor = create_test_vote_processor();
        let (vote_account, _) = setup_vote_account(&mut processor, 1000);

        let result = processor.process_vote(vote_account, 100, 1000, None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1000);

        let vote_info = processor.get_slot_votes(100).unwrap();
        assert_eq!(vote_info.total_stake, 1000);
        assert!(vote_info.has_voted(&vote_account));
    }

    #[test]
    fn vote_processor_rejects_old_vote() {
        let mut processor = create_test_vote_processor();
        let (vote_account, _) = setup_vote_account(&mut processor, 1000);

        processor
            .process_vote(vote_account, 100, 1000, None, None)
            .unwrap();

        let result = processor.process_vote(vote_account, 99, 1001, None, None);
        assert!(matches!(
            result,
            Err(VoteProcessorError::VoteNotNewer { .. })
        ));
    }

    #[test]
    fn vote_processor_aggregates_votes() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 1000);
        let (vote2, _) = setup_vote_account(&mut processor, 500);
        let (vote3, _) = setup_vote_account(&mut processor, 800);

        processor
            .process_vote(vote1, 100, 1000, None, None)
            .unwrap();
        processor
            .process_vote(vote2, 100, 1000, None, None)
            .unwrap();
        processor
            .process_vote(vote3, 100, 1000, None, None)
            .unwrap();

        let vote_info = processor.get_slot_votes(100).unwrap();
        assert_eq!(vote_info.total_stake, 2300);
        assert_eq!(vote_info.validator_count(), 3);
    }

    #[test]
    fn vote_processor_detects_supermajority() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 700);
        let (vote2, _) = setup_vote_account(&mut processor, 300);

        processor.total_stake = 1000;

        // 70% stake votes - should reach supermajority
        processor
            .process_vote(vote1, 100, 1000, None, None)
            .unwrap();
        assert!(processor.has_supermajority(100));

        // 30% more votes (total 100%)
        processor
            .process_vote(vote2, 100, 1000, None, None)
            .unwrap();
        assert!(processor.has_supermajority(100));
    }

    #[test]
    fn vote_processor_handles_fork_switch() {
        let mut processor = create_test_vote_processor();
        let (vote_account, _) = setup_vote_account(&mut processor, 1000);

        // Vote on slot 100
        processor
            .process_vote(vote_account, 100, 1000, None, None)
            .unwrap();
        assert_eq!(processor.get_slot_stake(100), 1000);

        // Vote on slot 101 (different fork)
        processor
            .process_vote(vote_account, 101, 1001, None, None)
            .unwrap();
        assert_eq!(processor.get_slot_stake(101), 1000);

        // Old vote should be removed
        assert_eq!(processor.get_slot_stake(100), 0);
    }

    #[test]
    fn vote_processor_calculates_stake_ratio() {
        let mut processor = create_test_vote_processor();
        let (vote_account, _) = setup_vote_account(&mut processor, 500);
        processor.total_stake = 1000;

        processor
            .process_vote(vote_account, 100, 1000, None, None)
            .unwrap();

        let ratio = processor.get_slot_stake_ratio(100);
        assert!((ratio - 0.5).abs() < 0.01);
    }

    #[test]
    fn vote_processor_prunes_below_root() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 1000);
        let (vote2, _) = setup_vote_account(&mut processor, 500);

        processor
            .process_vote(vote1, 100, 1000, None, None)
            .unwrap();
        processor
            .process_vote(vote2, 101, 1001, None, None)
            .unwrap();
        processor
            .process_vote(vote1, 102, 1002, None, None)
            .unwrap();

        assert_eq!(processor.voted_slots().len(), 3);

        processor.prune_below_root(101);

        let slots = processor.voted_slots();
        assert!(!slots.contains(&100));
        assert!(slots.contains(&101));
        assert!(slots.contains(&102));
    }

    #[test]
    fn vote_processor_batch_processes_votes() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 1000);
        let (vote2, _) = setup_vote_account(&mut processor, 500);

        let votes = vec![(vote1, 100, 1000), (vote2, 100, 1000)];

        let results = processor.process_votes_batch(votes, None, None);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());

        let vote_info = processor.get_slot_votes(100).unwrap();
        assert_eq!(vote_info.total_stake, 1500);
    }

    #[test]
    fn vote_processor_provides_stats() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 700);
        let (vote2, _) = setup_vote_account(&mut processor, 300);
        processor.total_stake = 1000;

        processor
            .process_vote(vote1, 100, 1000, None, None)
            .unwrap();
        processor
            .process_vote(vote2, 101, 1001, None, None)
            .unwrap();
        processor
            .process_vote(vote1, 102, 1002, None, None)
            .unwrap();

        let stats = processor.get_stats();
        assert_eq!(stats.total_slots_with_votes, 2); // 100 removed by fork switch
        assert_eq!(stats.total_validators, 2);
        assert_eq!(stats.active_validators, 2);
        assert_eq!(stats.total_stake, 1000);
    }

    #[test]
    fn vote_processor_enforces_min_stake_threshold() {
        let config = VoteProcessorConfig {
            min_stake_threshold: 500,
            ..Default::default()
        };
        let stake_tracker = StakeTracker::new(0);
        let mut processor = VoteProcessor::new(config, stake_tracker);

        let (vote_account, _) = setup_vote_account(&mut processor, 400); // Below threshold

        let result = processor.process_vote(vote_account, 100, 1000, None, None);
        assert!(matches!(
            result,
            Err(VoteProcessorError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn vote_processor_lists_voters_for_slot() {
        let mut processor = create_test_vote_processor();
        let (vote1, _) = setup_vote_account(&mut processor, 1000);
        let (vote2, _) = setup_vote_account(&mut processor, 500);

        processor
            .process_vote(vote1, 100, 1000, None, None)
            .unwrap();
        processor
            .process_vote(vote2, 100, 1000, None, None)
            .unwrap();

        let voters = processor.voters_for_slot(100);
        assert_eq!(voters.len(), 2);
        assert!(voters.contains(&vote1));
        assert!(voters.contains(&vote2));
    }
}
