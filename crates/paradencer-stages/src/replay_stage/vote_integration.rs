use crate::AssembledBlock;
use paradencer_consensus::{
    ConsensusDecision, DecisionReason, ForkChoice, Tower, VoteProcessor, VoteProcessorError,
    VoteUpdate,
};
use std::sync::{Arc, Mutex, RwLock};

/// Errors that can occur during vote integration
#[derive(Debug, Clone)]
pub enum VoteIntegrationError {
    /// Vote processor error
    VoteProcessorError(String),
    /// Tower error
    TowerError(String),
    /// No votes found in block
    NoVotesInBlock,
    /// Vote extraction failed
    VoteExtractionFailed(String),
    /// Lock acquisition failed
    LockFailed,
}

impl From<VoteProcessorError> for VoteIntegrationError {
    fn from(err: VoteProcessorError) -> Self {
        VoteIntegrationError::VoteProcessorError(format!("{:?}", err))
    }
}

/// Integrates vote processing with Tower BFT consensus
///
/// Responsibilities:
/// - Extract votes from blocks
/// - Process votes through VoteProcessor
/// - Update Tower with vote outcomes
/// - Feed vote stake into ForkChoice for GHOST algorithm
/// - Track vote statistics
pub struct VoteIntegration {
    /// Vote processor for aggregating votes
    pub vote_processor: Arc<Mutex<VoteProcessor>>,
    /// Tower for lockout enforcement
    pub tower: Arc<RwLock<Tower>>,
    /// Fork choice engine that receives vote stake
    pub fork_choice: Arc<Mutex<ForkChoice>>,
}

impl VoteIntegration {
    pub fn new(
        vote_processor: Arc<Mutex<VoteProcessor>>,
        tower: Arc<RwLock<Tower>>,
        fork_choice: Arc<Mutex<ForkChoice>>,
    ) -> Self {
        Self {
            vote_processor,
            tower,
            fork_choice,
        }
    }

    /// Process votes from an assembled block
    ///
    /// Extracts vote transactions from the block and processes them through
    /// the VoteProcessor. Updates fork choice with vote stake.
    pub fn process_votes_from_block(
        &mut self,
        block: &AssembledBlock,
    ) -> Result<usize, VoteIntegrationError> {
        // Extract vote transactions from block entries
        let votes = self.extract_votes_from_block(block)?;

        if votes.is_empty() {
            // Not an error - blocks may not contain votes
            return Ok(0);
        }

        // Process each vote through vote processor with fork choice integration
        let mut processed_count = 0;
        let mut vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        let mut fork_choice = self
            .fork_choice
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        for (vote_account, slot, timestamp) in votes {
            match vote_processor.process_vote(
                vote_account,
                slot,
                timestamp,
                None,
                Some(&mut fork_choice),
            ) {
                Ok(_stake) => {
                    processed_count += 1;
                }
                Err(e) => {
                    // Log but don't fail - individual vote failures are acceptable
                    eprintln!(
                        "Vote processing failed for account {:?} on slot {}: {:?}",
                        vote_account, slot, e
                    );
                }
            }
        }

        Ok(processed_count)
    }

    /// Process vote updates extracted by the bank executor.
    ///
    /// When Bank::process_transaction() detects vote program instructions,
    /// it produces VoteUpdate records containing the vote account and voted
    /// slot. This method feeds those updates into VoteProcessor and ForkChoice
    /// so the GHOST algorithm has real stake data.
    pub fn process_vote_updates(
        &mut self,
        vote_updates: &[VoteUpdate],
    ) -> Result<usize, VoteIntegrationError> {
        if vote_updates.is_empty() {
            return Ok(0);
        }

        let mut vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        let mut fork_choice = self
            .fork_choice
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        let mut processed = 0;
        for update in vote_updates {
            if let Some(voted_slot) = update.voted_slot {
                match vote_processor.process_vote(
                    update.vote_account,
                    voted_slot,
                    0, // timestamp not available from VoteUpdate
                    None,
                    Some(&mut fork_choice),
                ) {
                    Ok(_) => processed += 1,
                    Err(e) => {
                        eprintln!(
                            "Vote update failed for {:?} slot {}: {:?}",
                            update.vote_account, voted_slot, e
                        );
                    }
                }
            }
        }

        Ok(processed)
    }

    /// Extract vote transactions from block entries.
    ///
    /// Parses raw transaction bytes from block entries to identify vote
    /// program transactions and extract vote data. Returns empty if no
    /// vote transactions are found (blocks may contain only non-vote txns).
    fn extract_votes_from_block(
        &self,
        _block: &AssembledBlock,
    ) -> Result<Vec<(paradencer_storage::Pubkey, u64, i64)>, VoteIntegrationError> {
        // Transaction bytes in entries are not yet deserialized into
        // SanitizedTransaction format at this stage. Vote extraction
        // happens during bank execution via bank_executor::extract_vote_updates().
        // The process_vote_updates() method handles those results.
        Ok(Vec::new())
    }

    /// Update tower with successful block replay
    ///
    /// Records a vote in the tower for the replayed slot if it's valid
    /// according to lockout rules.
    pub fn update_tower(
        &mut self,
        slot: u64,
        _block_hash: [u8; 32],
    ) -> Result<Option<u64>, VoteIntegrationError> {
        let mut tower = self
            .tower
            .write()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        // Check if we should vote on this slot based on tower lockouts
        // In production, this would integrate with fork choice to determine
        // if this slot is on the heaviest fork

        // Simple implementation: record vote if slot is greater than last vote
        if let Some(last_vote) = tower.last_vote_slot() {
            if slot <= last_vote {
                // Slot is not newer than last vote - don't vote
                return Ok(None);
            }
        }

        // Push vote to tower
        let new_root = tower.push_vote(slot);

        Ok(new_root)
    }

    /// Record a vote with full tower validation
    ///
    /// Validates the vote against tower lockout rules before recording.
    pub fn record_vote_with_validation<F>(
        &mut self,
        slot: u64,
        is_same_fork: F,
    ) -> Result<Option<u64>, VoteIntegrationError>
    where
        F: Fn(u64, u64) -> bool,
    {
        let mut tower = self
            .tower
            .write()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        tower
            .record_vote(slot, is_same_fork)
            .map_err(|e| VoteIntegrationError::TowerError(format!("{:?}", e)))
    }

    /// Get the current tower root
    pub fn tower_root(&self) -> Result<Option<u64>, VoteIntegrationError> {
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(tower.root())
    }

    /// Get the last voted slot from tower
    pub fn last_vote_slot(&self) -> Result<Option<u64>, VoteIntegrationError> {
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(tower.last_vote_slot())
    }

    /// Check if tower is locked out from voting on a slot
    pub fn is_locked_out<F>(&self, slot: u64, is_same_fork: F) -> Result<bool, VoteIntegrationError>
    where
        F: Fn(u64, u64) -> bool,
    {
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(tower.is_locked_out(slot, is_same_fork))
    }

    /// Get vote statistics from vote processor
    pub fn get_vote_stats(&self) -> Result<VoteIntegrationStats, VoteIntegrationError> {
        let vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        let processor_stats = vote_processor.get_stats();

        Ok(VoteIntegrationStats {
            total_votes_processed: processor_stats.total_slots_with_votes,
            slots_with_supermajority: processor_stats.slots_with_supermajority,
            active_validators: processor_stats.active_validators,
            tower_vote_count: tower.len(),
            tower_root: tower.root(),
            last_vote_slot: tower.last_vote_slot(),
        })
    }

    /// Check if a slot has reached supermajority stake
    pub fn has_supermajority(&self, slot: u64) -> Result<bool, VoteIntegrationError> {
        let vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(vote_processor.has_supermajority(slot))
    }

    /// Get total stake that has voted for a slot
    pub fn get_slot_stake(&self, slot: u64) -> Result<u64, VoteIntegrationError> {
        let vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(vote_processor.get_slot_stake(slot))
    }

    /// Check if we can switch to a different fork.
    ///
    /// Uses tower's switching threshold: at least 38% of total stake must be
    /// locked out on forks other than our current fork.
    pub fn can_switch_fork(
        &self,
        candidate_slot: u64,
        total_stake: u64,
        current_fork_stake: u64,
        is_same_fork: impl Fn(u64, u64) -> bool,
    ) -> Result<bool, VoteIntegrationError> {
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(tower.can_switch_to(
            candidate_slot,
            total_stake,
            current_fork_stake,
            is_same_fork,
        ))
    }

    /// Run a consensus decision after replaying a slot.
    ///
    /// Evaluates fork choice, tower lockouts, and switch thresholds to
    /// determine whether to vote and which fork to reset to. If a vote
    /// is made and tower produces a new root, returns the new root slot.
    pub fn run_consensus_decision(
        &self,
        replayed_slot: u64,
        is_ancestor: impl Fn(u64, u64) -> bool + Copy,
    ) -> Result<ConsensusDecision, VoteIntegrationError> {
        let mut fc = self
            .fork_choice
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        // Compute best fork
        let root = tower.root().unwrap_or(0);
        let best_slot = fc.compute_best_fork(root).unwrap_or(replayed_slot);

        // Empty tower → vote for best fork
        if tower.is_empty() || tower.last_vote_slot().is_none() {
            drop(tower);
            drop(fc);
            // Push vote
            let mut tower_w = self
                .tower
                .write()
                .map_err(|_| VoteIntegrationError::LockFailed)?;
            let _ = tower_w.push_vote(best_slot);
            return Ok(ConsensusDecision {
                reset_slot: best_slot,
                vote_slot: Some(best_slot),
                new_root: None,
                reason: DecisionReason::EmptyTower,
            });
        }

        let last_vote = tower.last_vote_slot().unwrap();
        let same_fork = is_ancestor(last_vote, best_slot) || is_ancestor(best_slot, last_vote);

        let decision = if same_fork {
            let is_same_fork = |a: u64, b: u64| is_ancestor(a, b) || is_ancestor(b, a);
            if tower.is_locked_out(best_slot, is_same_fork) {
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
            // Different fork — check switch threshold
            if fc.can_switch_fork(last_vote, best_slot) {
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
        };

        // Release read locks before taking write lock
        drop(tower);
        drop(fc);

        // Execute: push vote to tower if decided
        let mut new_root = None;
        if let Some(vote_slot) = decision.vote_slot {
            let mut tower_w = self
                .tower
                .write()
                .map_err(|_| VoteIntegrationError::LockFailed)?;
            new_root = tower_w.push_vote(vote_slot);
        }

        Ok(ConsensusDecision {
            new_root,
            ..decision
        })
    }
}

/// Statistics about vote integration
#[derive(Debug, Clone)]
pub struct VoteIntegrationStats {
    /// Total votes processed by vote processor
    pub total_votes_processed: usize,
    /// Slots that have reached supermajority
    pub slots_with_supermajority: usize,
    /// Number of active validators
    pub active_validators: usize,
    /// Number of votes in tower
    pub tower_vote_count: usize,
    /// Current tower root
    pub tower_root: Option<u64>,
    /// Last slot voted on in tower
    pub last_vote_slot: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;
    use paradencer_consensus::{Delegation, StakeTracker, VoteProcessorConfig, VoteState};
    use paradencer_storage::Pubkey;

    const TEST_TOTAL_STAKE: u64 = 10_000;

    fn create_test_vote_processor() -> Arc<Mutex<VoteProcessor>> {
        let config = VoteProcessorConfig::default();
        let stake_tracker = StakeTracker::new(0);
        Arc::new(Mutex::new(VoteProcessor::new(config, stake_tracker)))
    }

    fn create_test_tower() -> Arc<RwLock<Tower>> {
        Arc::new(RwLock::new(Tower::new()))
    }

    fn create_test_fork_choice() -> Arc<Mutex<ForkChoice>> {
        Arc::new(Mutex::new(ForkChoice::new(TEST_TOTAL_STAKE)))
    }

    fn create_test_integration() -> VoteIntegration {
        VoteIntegration::new(
            create_test_vote_processor(),
            create_test_tower(),
            create_test_fork_choice(),
        )
    }

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
    fn vote_integration_initializes() {
        let _integration = create_test_integration();
    }

    #[test]
    fn vote_integration_processes_empty_block() {
        let mut integration = create_test_integration();

        let block = create_test_block(100, 99);
        let result = integration.process_votes_from_block(&block);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn vote_integration_updates_tower() {
        let mut integration = create_test_integration();

        let result = integration.update_tower(100, [1u8; 32]);
        assert!(result.is_ok());

        let last_vote = integration.last_vote_slot().unwrap();
        assert_eq!(last_vote, Some(100));
    }

    #[test]
    fn vote_integration_enforces_tower_ordering() {
        let mut integration = create_test_integration();

        // Vote on slot 100
        integration.update_tower(100, [1u8; 32]).unwrap();

        // Try to vote on slot 99 (should fail silently - returns None)
        let result = integration.update_tower(99, [2u8; 32]).unwrap();
        assert_eq!(result, None);

        // Last vote should still be 100
        let last_vote = integration.last_vote_slot().unwrap();
        assert_eq!(last_vote, Some(100));
    }

    #[test]
    fn vote_integration_tracks_tower_root() {
        let integration = create_test_integration();

        let root = integration.tower_root().unwrap();
        assert_eq!(root, None);
    }

    #[test]
    fn vote_integration_checks_lockout() {
        let mut integration = create_test_integration();

        // Vote on slot 100
        integration.update_tower(100, [1u8; 32]).unwrap();

        // Same fork check
        let same_fork = |_a: u64, _b: u64| true;
        let locked_out = integration.is_locked_out(101, same_fork).unwrap();
        assert!(!locked_out);

        // Different fork check
        let different_fork = |a: u64, b: u64| a == b;
        let locked_out = integration.is_locked_out(101, different_fork).unwrap();
        assert!(locked_out);
    }

    #[test]
    fn vote_integration_gets_stats() {
        let mut integration = create_test_integration();

        integration.update_tower(100, [1u8; 32]).unwrap();
        integration.update_tower(101, [2u8; 32]).unwrap();

        let stats = integration.get_vote_stats().unwrap();
        assert_eq!(stats.tower_vote_count, 2);
        assert_eq!(stats.last_vote_slot, Some(101));
    }

    #[test]
    fn vote_integration_checks_supermajority() {
        let integration = create_test_integration();

        let has_supermajority = integration.has_supermajority(100).unwrap();
        assert!(!has_supermajority);
    }

    #[test]
    fn vote_integration_gets_slot_stake() {
        let integration = create_test_integration();

        let stake = integration.get_slot_stake(100).unwrap();
        assert_eq!(stake, 0);
    }

    #[test]
    fn vote_integration_validates_votes() {
        let mut integration = create_test_integration();

        let same_fork = |_a: u64, _b: u64| true;

        let result = integration.record_vote_with_validation(100, same_fork);
        assert!(result.is_ok());

        let result = integration.record_vote_with_validation(101, same_fork);
        assert!(result.is_ok());
    }

    #[test]
    fn vote_integration_detects_fork_switch_threshold() {
        let mut integration = create_test_integration();

        integration.update_tower(100, [1u8; 32]).unwrap();

        let different_fork = |a: u64, b: u64| a == b;

        // total_stake=1000, current_fork_stake=700 → other=300/1000=30% < 38% → cannot switch
        let can_switch = integration
            .can_switch_fork(200, 1000, 700, different_fork)
            .unwrap();
        assert!(!can_switch);

        // total_stake=1000, current_fork_stake=500 → other=500/1000=50% >= 38% → can switch
        let can_switch = integration
            .can_switch_fork(200, 1000, 500, different_fork)
            .unwrap();
        assert!(can_switch);
    }

    /// Create a vote processor with a registered validator that has stake.
    fn create_staked_vote_processor(
        vote_account: Pubkey,
        stake_amount: u64,
    ) -> Arc<Mutex<VoteProcessor>> {
        let config = VoteProcessorConfig::default();
        let stake_account = Pubkey::new_unique();
        let mut stake_tracker = StakeTracker::new(0);
        // Use bootstrap activation (u64::MAX) for immediate full effective stake
        stake_tracker.add_delegation(
            stake_account,
            Delegation::new(vote_account, stake_amount, u64::MAX),
        );
        let mut vp = VoteProcessor::new(config, stake_tracker);
        vp.register_vote_account(
            vote_account,
            VoteState::new(vote_account, vote_account, vote_account, 0),
        );
        Arc::new(Mutex::new(vp))
    }

    #[test]
    fn vote_updates_flow_to_fork_choice() {
        let validator = Pubkey::new_unique();
        let vote_processor = create_staked_vote_processor(validator, 1000);

        let tower = create_test_tower();
        let fork_choice = create_test_fork_choice();

        // Register the slot in fork choice so add_stake has somewhere to land
        fork_choice.lock().unwrap().add_fork(100, None);

        let mut integration = VoteIntegration::new(vote_processor, tower, fork_choice.clone());

        // Create a VoteUpdate like bank_executor would produce
        let updates = vec![VoteUpdate {
            vote_account: validator,
            voted_slot: Some(100),
        }];

        let processed = integration.process_vote_updates(&updates).unwrap();
        assert_eq!(processed, 1);

        // Verify stake landed in ForkChoice
        let fc = fork_choice.lock().unwrap();
        let fork = fc.get_fork(100).unwrap();
        assert_eq!(fork.stake_weight, 1000);
    }

    #[test]
    fn vote_updates_without_slot_are_skipped() {
        let mut integration = create_test_integration();

        let updates = vec![VoteUpdate {
            vote_account: Pubkey::new_unique(),
            voted_slot: None,
        }];

        let processed = integration.process_vote_updates(&updates).unwrap();
        assert_eq!(processed, 0);
    }

    #[test]
    fn empty_vote_updates_returns_zero() {
        let mut integration = create_test_integration();

        let processed = integration.process_vote_updates(&[]).unwrap();
        assert_eq!(processed, 0);
    }

    #[test]
    fn multiple_vote_updates_accumulate_stake() {
        let config = VoteProcessorConfig::default();
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let stake_a = Pubkey::new_unique();
        let stake_b = Pubkey::new_unique();

        let mut stake_tracker = StakeTracker::new(0);
        stake_tracker.add_delegation(stake_a, Delegation::new(validator_a, 500, u64::MAX));
        stake_tracker.add_delegation(stake_b, Delegation::new(validator_b, 700, u64::MAX));

        let mut vp = VoteProcessor::new(config, stake_tracker);
        vp.register_vote_account(
            validator_a,
            VoteState::new(validator_a, validator_a, validator_a, 0),
        );
        vp.register_vote_account(
            validator_b,
            VoteState::new(validator_b, validator_b, validator_b, 0),
        );
        let vote_processor = Arc::new(Mutex::new(vp));

        let tower = create_test_tower();
        let fork_choice = create_test_fork_choice();
        fork_choice.lock().unwrap().add_fork(50, None);

        let mut integration = VoteIntegration::new(vote_processor, tower, fork_choice.clone());

        let updates = vec![
            VoteUpdate {
                vote_account: validator_a,
                voted_slot: Some(50),
            },
            VoteUpdate {
                vote_account: validator_b,
                voted_slot: Some(50),
            },
        ];

        let processed = integration.process_vote_updates(&updates).unwrap();
        assert_eq!(processed, 2);

        let fc = fork_choice.lock().unwrap();
        let fork = fc.get_fork(50).unwrap();
        assert_eq!(fork.stake_weight, 1200); // 500 + 700
    }

    #[test]
    fn fork_choice_accessible_after_construction() {
        let integration = create_test_integration();

        // Verify fork_choice is accessible and usable
        let mut fc = integration.fork_choice.lock().unwrap();
        fc.add_fork(1, None);
        fc.add_stake(1, 100);
        assert_eq!(fc.get_fork(1).unwrap().stake_weight, 100);
    }

    #[test]
    fn consensus_decision_votes_on_empty_tower() {
        let integration = create_test_integration();

        // Set up fork choice with a simple chain
        {
            let mut fc = integration.fork_choice.lock().unwrap();
            fc.add_fork(0, None);
            fc.add_fork(1, Some(0));
            fc.add_stake(1, 500);
        }

        let is_ancestor = |_a: u64, _b: u64| true;
        let decision = integration.run_consensus_decision(1, is_ancestor).unwrap();

        assert_eq!(decision.reason, DecisionReason::EmptyTower);
        assert!(decision.vote_slot.is_some());

        // Tower should now have a vote
        let tower = integration.tower.read().unwrap();
        assert!(tower.last_vote_slot().is_some());
    }

    #[test]
    fn consensus_decision_votes_on_same_fork() {
        let integration = create_test_integration();

        // Set up fork choice
        {
            let mut fc = integration.fork_choice.lock().unwrap();
            fc.add_fork(0, None);
            fc.add_fork(1, Some(0));
            fc.add_fork(2, Some(1));
            fc.add_stake(2, 500);
        }

        // First vote
        {
            let mut tower = integration.tower.write().unwrap();
            tower.push_vote(1);
        }

        // Same fork (all ancestors)
        let is_ancestor = |_a: u64, _b: u64| true;
        let decision = integration.run_consensus_decision(2, is_ancestor).unwrap();

        assert_eq!(decision.reason, DecisionReason::SameFork);
        assert!(decision.vote_slot.is_some());
    }
}
