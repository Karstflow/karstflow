use crate::AssembledBlock;
use paradencer_consensus::{Tower, VoteProcessor, VoteProcessorError};
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
/// - Track vote statistics
pub struct VoteIntegration {
    /// Vote processor for aggregating votes
    pub vote_processor: Arc<Mutex<VoteProcessor>>,
    /// Tower for lockout enforcement
    pub tower: Arc<RwLock<Tower>>,
}

impl VoteIntegration {
    pub fn new(vote_processor: Arc<Mutex<VoteProcessor>>, tower: Arc<RwLock<Tower>>) -> Self {
        Self {
            vote_processor,
            tower,
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

        // Process each vote through vote processor
        let mut processed_count = 0;
        let mut vote_processor = self
            .vote_processor
            .lock()
            .map_err(|_| VoteIntegrationError::LockFailed)?;

        for (vote_account, slot, timestamp) in votes {
            // Note: We pass None for tower and fork_choice here since they're
            // updated separately. In production, you might want to pass them
            // for integrated validation.
            match vote_processor.process_vote(vote_account, slot, timestamp, None, None) {
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

    /// Extract vote transactions from block
    ///
    /// In a real implementation, this would:
    /// 1. Parse each transaction in the block
    /// 2. Identify vote program transactions
    /// 3. Deserialize vote instruction data
    /// 4. Extract vote account, voted slot, and timestamp
    ///
    /// For now, we simulate this with mock data.
    fn extract_votes_from_block(
        &self,
        _block: &AssembledBlock,
    ) -> Result<Vec<(paradencer_storage::Pubkey, u64, i64)>, VoteIntegrationError> {
        // In production:
        // - Iterate through block.entries
        // - For each entry, iterate through entry.transactions
        // - Deserialize transactions and check if they're vote transactions
        // - Extract vote data (vote_account, slot, timestamp)

        // For now, return empty - real implementation would parse transactions
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

    /// Check if we can switch to a different fork
    ///
    /// Uses tower's switching threshold (38% advantage required)
    pub fn can_switch_fork(
        &self,
        candidate_slot: u64,
        candidate_stake: u64,
        is_same_fork: impl Fn(u64, u64) -> bool,
    ) -> Result<bool, VoteIntegrationError> {
        let tower = self
            .tower
            .read()
            .map_err(|_| VoteIntegrationError::LockFailed)?;
        Ok(tower.can_switch_to(candidate_slot, candidate_stake, is_same_fork))
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
    use paradencer_consensus::{StakeTracker, VoteProcessorConfig, VoteState};
    use paradencer_storage::Pubkey;

    fn create_test_vote_processor() -> Arc<Mutex<VoteProcessor>> {
        let config = VoteProcessorConfig::default();
        let stake_tracker = StakeTracker::new(0);
        Arc::new(Mutex::new(VoteProcessor::new(config, stake_tracker)))
    }

    fn create_test_tower() -> Arc<RwLock<Tower>> {
        Arc::new(RwLock::new(Tower::new()))
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
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let _integration = VoteIntegration::new(vote_processor, tower);
    }

    #[test]
    fn vote_integration_processes_empty_block() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        let block = create_test_block(100, 99);
        let result = integration.process_votes_from_block(&block);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // No votes in block
    }

    #[test]
    fn vote_integration_updates_tower() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        let result = integration.update_tower(100, [1u8; 32]);
        assert!(result.is_ok());

        let last_vote = integration.last_vote_slot().unwrap();
        assert_eq!(last_vote, Some(100));
    }

    #[test]
    fn vote_integration_enforces_tower_ordering() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

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
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let integration = VoteIntegration::new(vote_processor, tower);

        let root = integration.tower_root().unwrap();
        assert_eq!(root, None);
    }

    #[test]
    fn vote_integration_checks_lockout() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        // Vote on slot 100
        integration.update_tower(100, [1u8; 32]).unwrap();

        // Same fork check
        let same_fork = |_a: u64, _b: u64| true;
        let locked_out = integration.is_locked_out(101, same_fork).unwrap();
        assert!(!locked_out); // Not locked out on same fork

        // Different fork check
        let different_fork = |a: u64, b: u64| a == b;
        let locked_out = integration.is_locked_out(101, different_fork).unwrap();
        assert!(locked_out); // Locked out on different fork (within lockout window)
    }

    #[test]
    fn vote_integration_gets_stats() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        integration.update_tower(100, [1u8; 32]).unwrap();
        integration.update_tower(101, [2u8; 32]).unwrap();

        let stats = integration.get_vote_stats().unwrap();
        assert_eq!(stats.tower_vote_count, 2);
        assert_eq!(stats.last_vote_slot, Some(101));
    }

    #[test]
    fn vote_integration_checks_supermajority() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let integration = VoteIntegration::new(vote_processor, tower);

        // No votes yet
        let has_supermajority = integration.has_supermajority(100).unwrap();
        assert!(!has_supermajority);
    }

    #[test]
    fn vote_integration_gets_slot_stake() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let integration = VoteIntegration::new(vote_processor, tower);

        // No votes yet
        let stake = integration.get_slot_stake(100).unwrap();
        assert_eq!(stake, 0);
    }

    #[test]
    fn vote_integration_validates_votes() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        let same_fork = |_a: u64, _b: u64| true;

        // First vote should succeed
        let result = integration.record_vote_with_validation(100, same_fork);
        assert!(result.is_ok());

        // Second vote on same fork should succeed
        let result = integration.record_vote_with_validation(101, same_fork);
        assert!(result.is_ok());
    }

    #[test]
    fn vote_integration_detects_fork_switch_threshold() {
        let vote_processor = create_test_vote_processor();
        let tower = create_test_tower();
        let mut integration = VoteIntegration::new(vote_processor, tower);

        integration.update_tower(100, [1u8; 32]).unwrap();

        let different_fork = |a: u64, b: u64| a == b;

        // Insufficient stake to switch (ratio < 1.38)
        let can_switch = integration.can_switch_fork(200, 1, different_fork).unwrap();
        assert!(!can_switch);

        // Sufficient stake to switch (ratio >= 1.38)
        let can_switch = integration.can_switch_fork(200, 2, different_fork).unwrap();
        assert!(can_switch);
    }
}
