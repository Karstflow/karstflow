/// Integration tests for consensus components.
///
/// Tests the interaction between Tower, ForkChoice, VoteProcessor, and CommitmentTracker
/// to ensure correct consensus behavior.
#[cfg(test)]
mod tests {
    use crate::{
        CommitmentConfig, CommitmentLevel, CommitmentTracker, Delegation, ForkChoice, StakeTracker,
        Tower, VoteProcessor, VoteProcessorConfig, VoteState,
    };
    use paradencer_storage::Pubkey;
    use std::collections::HashMap;

    /// Test scenario: Three validators with different stake weights vote on forks.
    #[test]
    fn consensus_three_validators_fork_choice() {
        // Setup: 3 validators with stakes: 700, 200, 100 (total 1000)
        let mut stake_tracker = StakeTracker::new(0);
        let validator1 = Pubkey::new_unique();
        let validator2 = Pubkey::new_unique();
        let validator3 = Pubkey::new_unique();

        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator1, 700, u64::MAX),
        );
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator2, 200, u64::MAX),
        );
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator3, 100, u64::MAX),
        );

        // Setup vote processor
        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker.clone());

        // Register vote accounts
        for vote_account in &[validator1, validator2, validator3] {
            let node = Pubkey::new_unique();
            let voter = Pubkey::new_unique();
            let withdrawer = Pubkey::new_unique();
            let state = VoteState::new(node, voter, withdrawer, 5);
            vote_processor.register_vote_account(*vote_account, state);
        }

        // Setup fork choice
        let mut fork_choice = ForkChoice::new(1000);
        fork_choice.add_fork(0, None); // Genesis
        fork_choice.add_fork(1, Some(0));
        fork_choice.add_fork(2, Some(1));
        fork_choice.add_fork(3, Some(1)); // Competing fork

        // Validator 1 (700 stake) votes for fork 1->2
        vote_processor
            .process_vote(validator1, 1, 1000, None, Some(&mut fork_choice))
            .unwrap();
        vote_processor
            .process_vote(validator1, 2, 1001, None, Some(&mut fork_choice))
            .unwrap();

        // Validator 2 (200 stake) votes for fork 1->3
        vote_processor
            .process_vote(validator2, 1, 1000, None, Some(&mut fork_choice))
            .unwrap();
        vote_processor
            .process_vote(validator2, 3, 1001, None, Some(&mut fork_choice))
            .unwrap();

        // Fork choice should pick fork 1->2 (700 stake) over 1->3 (200 stake)
        let best = fork_choice.compute_best_fork(0);
        assert_eq!(best, Some(2));

        // Check stake weights in fork choice tree (cumulative)
        assert!(fork_choice.get_fork(1).unwrap().stake_weight >= 900);
        assert!(fork_choice.get_fork(2).unwrap().stake_weight >= 700);
        assert!(fork_choice.get_fork(3).unwrap().stake_weight >= 200);

        // Vote processor tracks latest votes only — slot 1 votes cleared
        // when validators advanced to slots 2 and 3
        assert!(vote_processor.has_supermajority(2)); // 700/1000 > 2/3
    }

    /// Test scenario: Supermajority detection and optimistic confirmation.
    #[test]
    fn consensus_supermajority_and_optimistic_confirmation() {
        let mut stake_tracker = StakeTracker::new(0);
        let validator1 = Pubkey::new_unique();
        let validator2 = Pubkey::new_unique();
        let validator3 = Pubkey::new_unique();

        // Stake distribution: 400, 300, 300 (total 1000)
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator1, 400, u64::MAX),
        );
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator2, 300, u64::MAX),
        );
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator3, 300, u64::MAX),
        );

        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        for vote_account in &[validator1, validator2, validator3] {
            let state = VoteState::new(
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                5,
            );
            vote_processor.register_vote_account(*vote_account, state);
        }

        let mut commitment_tracker = CommitmentTracker::default();

        // Validator 1 and 2 vote (70% stake - supermajority)
        vote_processor
            .process_vote(validator1, 100, 1000, None, None)
            .unwrap();
        vote_processor
            .process_vote(validator2, 100, 1000, None, None)
            .unwrap();

        // Check supermajority
        assert!(vote_processor.has_supermajority(100));
        assert_eq!(vote_processor.get_slot_stake_ratio(100), 0.7);

        // Update commitment tracker
        let stake = vote_processor.get_slot_stake(100);
        commitment_tracker.mark_processed(100, stake, 1000);

        // Should be able to mark confirmed with sufficient depth
        assert!(commitment_tracker.check_optimistic_confirmation(100, 8));
        commitment_tracker.mark_confirmed(100);

        assert_eq!(
            commitment_tracker.get_commitment_level(100),
            Some(CommitmentLevel::Confirmed)
        );
    }

    /// Test scenario: Tower lockout enforcement prevents voting on conflicting fork.
    #[test]
    fn consensus_tower_lockout_enforcement() {
        let mut tower = Tower::new();

        // Vote on slot 100
        tower.push_vote(100);
        assert_eq!(tower.last_vote_slot(), Some(100));

        // Check lockout - slot 100 locks out slot 101 on different fork
        let different_fork = |a: u64, b: u64| a == b; // Only same slot is same fork

        assert!(tower.is_locked_out(101, &different_fork));

        // Can vote on slot 102 after lockout expires
        assert!(!tower.is_locked_out(102, &different_fork));

        // Try to record vote on locked out slot
        let result = tower.record_vote(101, &different_fork);
        assert!(result.is_err());
    }

    /// Test scenario: Fork switching with stake threshold.
    #[test]
    fn consensus_fork_switching_threshold() {
        let mut fork_choice = ForkChoice::new(1000);

        fork_choice.add_fork(0, None);
        fork_choice.add_fork(1, Some(0));
        fork_choice.add_fork(2, Some(0)); // Competing fork

        // Current fork has 500 stake
        fork_choice.add_stake(1, 500);

        // Competing fork needs 38% more to switch (690+)
        fork_choice.add_stake(2, 600);
        assert!(!fork_choice.can_switch_fork(1, 2)); // Not enough

        fork_choice.add_stake(2, 100); // Now 700
        assert!(fork_choice.can_switch_fork(1, 2)); // Sufficient
    }

    /// Test scenario: Root progression through finalization.
    #[test]
    fn consensus_root_progression() {
        let config = CommitmentConfig {
            finalization_depth: 10,
            ..Default::default()
        };
        let mut commitment_tracker = CommitmentTracker::new(config);

        // Process chain of slots with supermajority
        for slot in 100..=110 {
            commitment_tracker.mark_processed(slot, 700, 1000);
            commitment_tracker.update_confirmation_depth(slot, (110 - slot + 1) as usize);
            commitment_tracker.mark_confirmed(slot);
        }

        // Slot 100 has depth 11 (>= finalization_depth 10), should be ready for finalization
        let ready = commitment_tracker.slots_ready_for_finalization();
        assert!(!ready.is_empty());
        assert!(ready.contains(&100));

        // Update root
        let new_root = commitment_tracker.update_root(100);
        assert_eq!(new_root, Some(100));
        assert_eq!(commitment_tracker.root_slot(), Some(100));

        // Check commitment level
        assert_eq!(
            commitment_tracker.get_commitment_level(100),
            Some(CommitmentLevel::Finalized)
        );
    }

    /// Test scenario: Vote processor handles fork switches correctly.
    #[test]
    fn consensus_vote_processor_fork_switch() {
        let mut stake_tracker = StakeTracker::new(0);
        let validator = Pubkey::new_unique();

        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator, 1000, u64::MAX),
        );

        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        let state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );
        vote_processor.register_vote_account(validator, state);

        // Vote on slot 100
        vote_processor
            .process_vote(validator, 100, 1000, None, None)
            .unwrap();
        assert_eq!(vote_processor.get_slot_stake(100), 1000);

        // Switch to slot 101 (different fork)
        vote_processor
            .process_vote(validator, 101, 1001, None, None)
            .unwrap();
        assert_eq!(vote_processor.get_slot_stake(101), 1000);

        // Old vote should be removed
        assert_eq!(vote_processor.get_slot_stake(100), 0);
    }

    /// Test scenario: Commitment level transitions.
    #[test]
    fn consensus_commitment_level_transitions() {
        let mut commitment_tracker = CommitmentTracker::default();

        // Slot starts at processed
        commitment_tracker.mark_processed(100, 700, 1000);
        assert!(commitment_tracker.has_commitment(100, CommitmentLevel::Processed));
        assert!(!commitment_tracker.has_commitment(100, CommitmentLevel::Confirmed));

        // Move to confirmed
        commitment_tracker.mark_confirmed(100);
        assert!(commitment_tracker.has_commitment(100, CommitmentLevel::Confirmed));
        assert!(!commitment_tracker.has_commitment(100, CommitmentLevel::Finalized));

        // Move to finalized
        commitment_tracker.mark_finalized(100);
        assert!(commitment_tracker.has_commitment(100, CommitmentLevel::Finalized));

        // Finalized implies confirmed
        assert!(commitment_tracker.has_commitment(100, CommitmentLevel::Confirmed));
    }

    /// Test scenario: Multiple validators voting creates correct stake aggregation.
    #[test]
    fn consensus_vote_aggregation() {
        let mut stake_tracker = StakeTracker::new(0);
        let validators: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let stakes = vec![300, 250, 200, 150, 100]; // Total 1000

        for (i, validator) in validators.iter().enumerate() {
            stake_tracker.add_delegation(
                Pubkey::new_unique(),
                Delegation::new(*validator, stakes[i], u64::MAX),
            );
        }

        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        for validator in &validators {
            let state = VoteState::new(
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                5,
            );
            vote_processor.register_vote_account(*validator, state);
        }

        // First 3 validators vote (total 750 stake - supermajority)
        for (i, validator) in validators.iter().take(3).enumerate() {
            vote_processor
                .process_vote(*validator, 100, 1000, None, None)
                .unwrap();
        }

        assert_eq!(vote_processor.get_slot_stake(100), 750);
        assert!(vote_processor.has_supermajority(100));

        let vote_info = vote_processor.get_slot_votes(100).unwrap();
        assert_eq!(vote_info.validator_count(), 3);
    }

    /// Test scenario: Tower with full history promotes root.
    #[test]
    fn consensus_tower_root_promotion() {
        use paradencer_constants::consensus::MAX_LOCKOUT_HISTORY;
        let mut tower = Tower::new();

        // Fill tower to max
        for i in 0..MAX_LOCKOUT_HISTORY {
            tower.push_vote(100 + i as u64);
        }

        assert_eq!(tower.len(), MAX_LOCKOUT_HISTORY);
        assert_eq!(tower.root(), None);

        // Next vote promotes root
        let new_root = tower.push_vote(100 + MAX_LOCKOUT_HISTORY as u64);
        assert_eq!(new_root, Some(100));
        assert_eq!(tower.root(), Some(100));
    }

    /// Test scenario: Fork choice with deep fork tree.
    #[test]
    fn consensus_deep_fork_tree() {
        let mut fork_choice = ForkChoice::new(1000);

        // Build deep chain
        fork_choice.add_fork(0, None);
        for i in 1..=20 {
            fork_choice.add_fork(i, Some(i - 1));
            fork_choice.add_stake(i, 700); // Supermajority on each
        }

        // Add competing fork at slot 10
        fork_choice.add_fork(100, Some(10));
        fork_choice.add_stake(100, 200);

        // Best fork should follow the heaviest path (main chain)
        let best = fork_choice.compute_best_fork(0);
        assert_eq!(best, Some(20));

        // Check ancestry
        assert!(fork_choice.is_descendant(20, 0));
        assert!(fork_choice.is_descendant(20, 10));
        assert!(!fork_choice.is_descendant(100, 20));
    }

    /// Test scenario: Vote processor with minimum stake threshold.
    #[test]
    fn consensus_min_stake_threshold() {
        let mut stake_tracker = StakeTracker::new(0);
        let validator = Pubkey::new_unique();

        // Validator has 400 stake
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator, 400, u64::MAX),
        );

        // Set threshold to 500
        let config = VoteProcessorConfig {
            min_stake_threshold: 500,
            ..Default::default()
        };
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        let state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );
        vote_processor.register_vote_account(validator, state);

        // Vote should be rejected
        let result = vote_processor.process_vote(validator, 100, 1000, None, None);
        assert!(result.is_err());
    }

    /// Test scenario: Commitment pruning below root.
    #[test]
    fn consensus_commitment_pruning() {
        let mut commitment_tracker = CommitmentTracker::default();

        for slot in 100..=110 {
            commitment_tracker.mark_processed(slot, 700, 1000);
        }

        assert_eq!(commitment_tracker.commitment_counts().processed, 11);

        // Set root at 105
        commitment_tracker.update_root(105);

        // Slots below 105 should be pruned
        assert!(commitment_tracker.get_commitment_level(100).is_none());
        assert!(commitment_tracker.get_commitment_level(105).is_some());
        assert!(commitment_tracker.get_commitment_level(110).is_some());
    }

    /// Test scenario: Batch vote processing.
    #[test]
    fn consensus_batch_vote_processing() {
        let mut stake_tracker = StakeTracker::new(0);
        let validators: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();

        for validator in &validators {
            stake_tracker.add_delegation(
                Pubkey::new_unique(),
                Delegation::new(*validator, 333, u64::MAX),
            );
        }

        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        for validator in &validators {
            let state = VoteState::new(
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                5,
            );
            vote_processor.register_vote_account(*validator, state);
        }

        // Batch process votes
        let votes = vec![
            (validators[0], 100, 1000),
            (validators[1], 100, 1000),
            (validators[2], 100, 1000),
        ];

        let results = vote_processor.process_votes_batch(votes, None, None);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));

        assert_eq!(vote_processor.get_slot_stake(100), 999);
    }

    /// Test scenario: Statistics and metrics collection.
    #[test]
    fn consensus_statistics_collection() {
        let mut stake_tracker = StakeTracker::new(0);
        let validator = Pubkey::new_unique();
        stake_tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator, 700, u64::MAX),
        );

        let config = VoteProcessorConfig::default();
        let mut vote_processor = VoteProcessor::new(config, stake_tracker);

        let state = VoteState::new(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5,
        );
        vote_processor.register_vote_account(validator, state);

        vote_processor
            .process_vote(validator, 100, 1000, None, None)
            .unwrap();
        vote_processor
            .process_vote(validator, 101, 1001, None, None)
            .unwrap();

        let stats = vote_processor.get_stats();
        assert_eq!(stats.total_validators, 1);
        assert_eq!(stats.active_validators, 1);
        assert!(stats.slots_with_supermajority > 0);

        // Fork choice stats
        let mut fork_choice = ForkChoice::new(1000);
        fork_choice.add_fork(0, None);
        fork_choice.add_fork(1, Some(0));
        fork_choice.add_stake(1, 700);

        let fc_stats = fork_choice.stats();
        assert_eq!(fc_stats.total_forks, 2);
        assert!(fc_stats.confirmed_forks > 0);
    }
}
