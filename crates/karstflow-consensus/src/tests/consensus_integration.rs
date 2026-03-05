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
    use karstflow_storage::Pubkey;

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

        assert!(tower.is_locked_out(101, different_fork));

        // Can vote on slot 102 after lockout expires
        assert!(!tower.is_locked_out(102, different_fork));

        // Try to record vote on locked out slot
        let result = tower.record_vote(101, different_fork);
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
        let stakes = [300, 250, 200, 150, 100]; // Total 1000

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
        for validator in validators.iter().take(3) {
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
        use karstflow_constants::consensus::MAX_LOCKOUT_HISTORY;
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

    // -----------------------------------------------------------------------
    // Wave 10: Vote flow and consensus decision integration
    // -----------------------------------------------------------------------

    #[test]
    fn vote_updates_flow_to_consensus_coordinator() {
        use crate::{
            bank_executor::VoteUpdate, Bank, ConsensusCoordinator, EpochSchedule, Inflation,
            LeaderSchedule, Rent,
        };
        use karstflow_storage::AccountDatabase;
        use std::sync::Arc;

        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());

        let bank = Bank::new_genesis_with_config(
            accounts,
            epoch_schedule,
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        let mut coordinator = ConsensusCoordinator::new(validator, 10);
        coordinator.add_fork(0, None);
        coordinator.add_fork(5, Some(0));
        coordinator.add_fork(10, Some(5));

        // Add stake so the validator has weight
        coordinator
            .stake_tracker_mut()
            .add_delegation(Pubkey::new_unique(), Delegation::new(validator, 500, 0));
        coordinator.set_epoch(10);

        // Simulate vote updates from transaction execution
        let updates = vec![
            VoteUpdate {
                vote_account: validator,
                voted_slot: Some(5),
            },
            VoteUpdate {
                vote_account: validator,
                voted_slot: Some(10),
            },
            VoteUpdate {
                vote_account: Pubkey::new_unique(),
                voted_slot: None, // No vote extracted
            },
        ];

        bank.route_vote_updates(&updates, &mut coordinator);

        // The last vote for this validator should be slot 10
        // (recorded_validator_vote updates the latest_votes map)
        let fork_info = coordinator.get_fork_info(10);
        assert!(fork_info.is_some());
        assert!(fork_info.unwrap().stake_weight > 0);
    }

    #[test]
    fn consensus_decision_after_replay() {
        use crate::{ConsensusCoordinator, DecisionReason};

        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);
        coord.disable_propagation_check();

        // Linear chain: 1 -> 2 -> 3 -> 4 -> 5
        for slot in 1..=5 {
            coord.add_fork(slot, if slot == 1 { None } else { Some(slot - 1) });
        }

        let linear = |a: u64, b: u64| -> bool { a <= b };

        // First replay → empty tower → vote
        let d1 = coord.decide_vote_and_reset(1, linear);
        assert_eq!(d1.reason, DecisionReason::EmptyTower);
        coord.execute_decision(&d1);

        // Second replay → same fork → vote
        let d2 = coord.decide_vote_and_reset(1, linear);
        assert_eq!(d2.reason, DecisionReason::SameFork);
        coord.execute_decision(&d2);

        // Tower should have votes now
        assert!(!coord.tower().is_empty());
    }

    #[test]
    fn root_advancement_prunes_forks() {
        use crate::ConsensusCoordinator;

        let validator = Pubkey::new_unique();
        let mut coord = ConsensusCoordinator::new(validator, 10);

        // Add a voter with stake
        let voter = Pubkey::new_unique();
        coord
            .stake_tracker_mut()
            .add_delegation(Pubkey::new_unique(), Delegation::new(voter, 1000, 0));
        coord.set_epoch(10);

        // Build chain and add votes
        for slot in 1..=20 {
            coord.add_fork(slot, if slot == 1 { None } else { Some(slot - 1) });
        }

        // Record a vote at slot 5
        coord.process_incoming_vote(crate::ValidatorVote {
            validator: voter,
            slot: 5,
            stake: 1000,
            timestamp: 0,
            block_hash: None,
        });

        // Advance root to 10
        coord.advance_root(10);

        assert_eq!(coord.root(), Some(10));

        // Vote at slot 5 should have been pruned (below root)
        // The fork info for slot 5 should be gone (pruned by set_root)
        assert!(coord.get_fork_info(5).is_none());
    }

    #[test]
    fn epoch_boundary_end_to_end() {
        use crate::{Bank, EpochSchedule, Inflation, LeaderSchedule, Rent, StakeHistory};
        use karstflow_constants::ledger::TICKS_PER_SLOT;
        use karstflow_storage::AccountDatabase;
        use std::sync::{Arc, RwLock};

        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let leader_schedule = Arc::new(LeaderSchedule::new(0, &validators).unwrap());

        // Create vote account in the DB
        let vote_account = karstflow_storage::Account::new(1_000_000, vec![], Pubkey::default());
        accounts.store_published_account(validator, vote_account);

        let mut parent = Bank::new_genesis_with_config(
            accounts.clone(),
            epoch_schedule.clone(),
            leader_schedule,
            1_000_000_000_000,
            Rent::default(),
            Inflation::default(),
        );

        // Set up epoch state
        let mut tracker = crate::StakeTracker::new(1);
        tracker.add_delegation(
            Pubkey::new_unique(),
            Delegation::new(validator, 1_000_000_000, 0),
        );
        let tracker = Arc::new(RwLock::new(tracker));
        let history = Arc::new(RwLock::new(StakeHistory::new()));
        parent.set_stake_tracker(tracker.clone());
        parent.set_stake_history(history.clone());

        // Create bank at epoch 1 boundary
        let slot = epoch_schedule.get_first_slot_in_epoch(1);
        let child_schedule = Arc::new(LeaderSchedule::new(1, &validators).unwrap());
        let child = Bank::new_from_parent(&parent, slot, child_schedule);

        // Complete the slot
        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }

        let result = child.finish_slot().unwrap();
        assert!(result.epoch_boundary);

        // Verify rewards were applied
        let acct = accounts.get_published_account(&validator).unwrap();
        assert!(
            acct.meta.lamports > 1_000_000,
            "Vote account should have received rewards: {}",
            acct.meta.lamports
        );

        // Verify stake history was updated
        let h = history.read().unwrap();
        assert!(
            h.get(0).is_some(),
            "Stake history should have epoch 0 entry"
        );
        assert!(h.get(0).unwrap().effective > 0);

        // Verify capitalization increased
        assert!(child.capitalization() > 1_000_000_000_000);
    }

    #[test]
    fn bank_hash_reflects_account_state() {
        use crate::{Bank, EpochSchedule, LeaderSchedule};
        use karstflow_storage::{Account, AccountDatabase};
        use std::sync::Arc;

        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule =
            Arc::new(LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1_000)]).unwrap());

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let initial_hash = bank.hash();

        // Writing an account changes the bank hash
        let pubkey = Pubkey::new_unique();
        let account = Account::new(5000, vec![10, 20, 30], Pubkey::new_unique());
        bank.update_account_hash(&pubkey, None, &account);

        assert_ne!(bank.hash(), initial_hash);
    }

    #[test]
    fn bank_hash_deterministic_replay() {
        use crate::{Bank, EpochSchedule, LeaderSchedule};
        use karstflow_storage::{Account, AccountDatabase};
        use std::sync::Arc;

        let make_bank = || {
            let accounts = Arc::new(AccountDatabase::new());
            let epoch_schedule = Arc::new(EpochSchedule::default());
            let leader_schedule =
                Arc::new(LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1_000)]).unwrap());
            Bank::new_genesis(accounts, epoch_schedule, leader_schedule)
        };

        let pk = Pubkey::from([0x42; 32]);
        let owner = Pubkey::from([0x11; 32]);
        let account = Account::new(1000, vec![1, 2, 3], owner);

        let b1 = make_bank();
        b1.update_account_hash(&pk, None, &account);
        b1.add_signatures(2);
        b1.set_last_blockhash([0xAA; 32]);

        let b2 = make_bank();
        b2.update_account_hash(&pk, None, &account);
        b2.add_signatures(2);
        b2.set_last_blockhash([0xAA; 32]);

        assert_eq!(b1.hash(), b2.hash());
    }

    #[test]
    fn lthash_incremental_matches_recompute() {
        use crate::{Bank, EpochSchedule, LeaderSchedule};
        use karstflow_crypto::lthash::{hash_account, LatticeHashValue};
        use karstflow_storage::{Account, AccountDatabase};
        use std::sync::Arc;

        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule =
            Arc::new(LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1_000)]).unwrap());

        let bank = Bank::new_genesis(accounts, epoch_schedule, leader_schedule);

        let owner = Pubkey::from([0x11; 32]);
        let pk1 = Pubkey::from([1u8; 32]);
        let pk2 = Pubkey::from([2u8; 32]);
        let pk3 = Pubkey::from([3u8; 32]);

        let acc1 = Account::new(1000, vec![1], owner);
        let acc2 = Account::new(2000, vec![2, 3], owner);
        let acc3 = Account::new(3000, vec![4, 5, 6], owner);

        // Add accounts incrementally via bank
        bank.update_account_hash(&pk1, None, &acc1);
        bank.update_account_hash(&pk2, None, &acc2);
        bank.update_account_hash(&pk3, None, &acc3);

        let incremental = bank.lthash();

        // Recompute from scratch using raw hash_account
        let mut full = LatticeHashValue::zero();
        let h1 = hash_account(&pk1.to_bytes(), &owner.to_bytes(), 1000, false, &[1]);
        let h2 = hash_account(&pk2.to_bytes(), &owner.to_bytes(), 2000, false, &[2, 3]);
        let h3 = hash_account(&pk3.to_bytes(), &owner.to_bytes(), 3000, false, &[4, 5, 6]);
        full.add(&h1);
        full.add(&h2);
        full.add(&h3);

        assert_eq!(incremental, full);
    }

    #[test]
    fn parent_child_hash_chain() {
        use crate::{Bank, EpochSchedule, LeaderSchedule};
        use karstflow_constants::ledger::TICKS_PER_SLOT;
        use karstflow_storage::{Account, AccountDatabase};
        use std::sync::Arc;

        let accounts = Arc::new(AccountDatabase::new());
        let epoch_schedule = Arc::new(EpochSchedule::default());
        let leader_schedule =
            Arc::new(LeaderSchedule::new(0, &[(Pubkey::new_unique(), 1_000)]).unwrap());

        // Set up parent with some state
        let parent = Bank::new_genesis(accounts, epoch_schedule, leader_schedule.clone());
        let pk = Pubkey::new_unique();
        let acc = Account::new(1000, vec![1], Pubkey::new_unique());
        parent.update_account_hash(&pk, None, &acc);
        parent.add_signatures(5);

        // Complete parent
        for _ in 0..TICKS_PER_SLOT {
            parent.register_tick().unwrap();
        }
        parent.freeze().unwrap();
        let parent_bank_hash = parent.hash();

        // Create child
        let child = Bank::new_from_parent(&parent, 1, leader_schedule.clone());

        // Child's parent_hash is parent's bank hash
        assert_eq!(child.parent_hash(), parent_bank_hash);

        // Child starts with signature_count=0 and inherited lthash
        assert_eq!(child.signature_count(), 0);
        assert!(!child.lthash().is_zero());

        // Modify child
        let pk2 = Pubkey::new_unique();
        let acc2 = Account::new(2000, vec![2], Pubkey::new_unique());
        child.update_account_hash(&pk2, None, &acc2);
        child.add_signatures(3);

        // Child hash differs from parent
        assert_ne!(child.hash(), parent_bank_hash);

        // Create grandchild
        for _ in 0..TICKS_PER_SLOT {
            child.register_tick().unwrap();
        }
        child.freeze().unwrap();
        let child_bank_hash = child.hash();

        let grandchild = Bank::new_from_parent(&child, 2, leader_schedule);
        assert_eq!(grandchild.parent_hash(), child_bank_hash);
        assert_ne!(grandchild.parent_hash(), parent_bank_hash);
    }
}
