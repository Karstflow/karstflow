//! Consensus workflow example demonstrating fork choice and vote processing.
//!
//! This example shows how to use Tower, ForkChoice, VoteProcessor, and CommitmentTracker
//! together to implement a complete consensus mechanism.

use paradencer_consensus::{
    CommitmentConfig, CommitmentLevel, CommitmentTracker, Delegation, ForkChoice, StakeTracker,
    Tower, VoteProcessor, VoteProcessorConfig, VoteState,
};
use paradencer_storage::Pubkey;
use std::collections::HashMap;

fn main() {
    println!("=== Paradencer Consensus Workflow Example ===\n");

    // Setup: Create 5 validators with varying stakes
    let validators = setup_validators();
    let total_stake: u64 = validators.values().sum();

    println!("Network Setup:");
    println!("  Total validators: {}", validators.len());
    println!("  Total stake: {}\n", total_stake);

    // Initialize consensus components
    let mut tower = Tower::new();
    let mut fork_choice = ForkChoice::new(total_stake);
    let mut vote_processor = setup_vote_processor(&validators);
    let mut commitment_tracker = CommitmentTracker::new(CommitmentConfig::default());

    println!("=== Phase 1: Genesis and Initial Fork ===\n");

    // Create genesis and first fork
    fork_choice.add_fork(0, None); // Genesis
    fork_choice.add_fork(1, Some(0));

    println!("Created genesis (slot 0) and slot 1");

    // All validators vote on slot 1
    println!("\nAll validators vote on slot 1:");
    for (vote_account, stake) in &validators {
        vote_processor
            .process_vote(*vote_account, 1, 1000, None, Some(&mut fork_choice))
            .unwrap();
        println!("  {} voted (stake: {})", vote_account, stake);
    }

    let slot1_stake = vote_processor.get_slot_stake(1);
    let slot1_ratio = vote_processor.get_slot_stake_ratio(1);
    println!("\nSlot 1 results:");
    println!("  Total stake: {}", slot1_stake);
    println!("  Stake ratio: {:.2}%", slot1_ratio * 100.0);
    println!(
        "  Has supermajority: {}",
        vote_processor.has_supermajority(1)
    );

    // Update commitment
    commitment_tracker.mark_processed(1, slot1_stake, total_stake);

    println!("\n=== Phase 2: Fork Creation ===\n");

    // Create competing forks at slot 2
    fork_choice.add_fork(2, Some(1)); // Main fork
    fork_choice.add_fork(3, Some(1)); // Competing fork

    println!("Created competing forks:");
    println!("  Slot 2 (main fork)");
    println!("  Slot 3 (competing fork)");

    // Validators split their votes
    let validator_list: Vec<_> = validators.iter().collect();

    println!("\nVote distribution:");

    // First 3 validators (60% stake) vote for slot 2
    for i in 0..3 {
        let (vote_account, stake) = validator_list[i];
        vote_processor
            .process_vote(*vote_account, 2, 1001, None, Some(&mut fork_choice))
            .unwrap();
        println!("  {} voted for slot 2 (stake: {})", vote_account, stake);
    }

    // Last 2 validators (40% stake) vote for slot 3
    for i in 3..5 {
        let (vote_account, stake) = validator_list[i];
        vote_processor
            .process_vote(*vote_account, 3, 1001, None, Some(&mut fork_choice))
            .unwrap();
        println!("  {} voted for slot 3 (stake: {})", vote_account, stake);
    }

    let slot2_stake = vote_processor.get_slot_stake(2);
    let slot3_stake = vote_processor.get_slot_stake(3);

    println!("\nFork comparison:");
    println!(
        "  Slot 2 stake: {} ({:.1}%)",
        slot2_stake,
        (slot2_stake as f64 / total_stake as f64) * 100.0
    );
    println!(
        "  Slot 3 stake: {} ({:.1}%)",
        slot3_stake,
        (slot3_stake as f64 / total_stake as f64) * 100.0
    );

    // Fork choice selects heaviest fork
    let best = fork_choice.compute_best_fork(0).unwrap();
    println!("\nFork choice selected: slot {}", best);

    // Update commitment for both forks
    commitment_tracker.mark_processed(2, slot2_stake, total_stake);
    commitment_tracker.mark_processed(3, slot3_stake, total_stake);

    println!("\n=== Phase 3: Tower Voting ===\n");

    // Record vote in tower
    let is_same_fork = |a: u64, b: u64| a == b || a < b; // Simple ancestry check

    println!("Recording vote in tower:");
    match tower.record_vote(1, &is_same_fork) {
        Ok(new_root) => {
            println!("  Voted on slot 1");
            if let Some(root) = new_root {
                println!("  New root: {}", root);
            }
        }
        Err(e) => println!("  Error: {:?}", e),
    }

    println!("\nTower state:");
    println!("  Votes: {:?}", tower.vote_slots());
    println!("  Length: {}", tower.len());
    println!("  Root: {:?}", tower.root());

    // Try to vote on best fork
    match tower.record_vote(best, &is_same_fork) {
        Ok(_) => println!("\n  Successfully voted on slot {}", best),
        Err(e) => println!("\n  Could not vote on slot {}: {:?}", best, e),
    }

    println!("\n=== Phase 4: Optimistic Confirmation ===\n");

    // Build chain on slot 2 with supermajority
    println!("Building confirmed chain:");
    for i in 4..=11 {
        fork_choice.add_fork(i, Some(i - 1));

        // All validators vote on this chain
        for (vote_account, _) in &validators {
            vote_processor
                .process_vote(
                    *vote_account,
                    i,
                    1000 + i as i64,
                    None,
                    Some(&mut fork_choice),
                )
                .unwrap();
        }

        let stake = vote_processor.get_slot_stake(i);
        commitment_tracker.mark_processed(i, stake, total_stake);

        println!(
            "  Slot {} - stake: {} ({:.1}%)",
            i,
            stake,
            (stake as f64 / total_stake as f64) * 100.0
        );
    }

    // Check optimistic confirmation on slot 4
    let has_depth = 8; // Simulated depth
    if commitment_tracker.check_optimistic_confirmation(4, has_depth) {
        commitment_tracker.mark_confirmed(4);
        println!("\nSlot 4 is optimistically confirmed!");
        println!(
            "  Commitment level: {:?}",
            commitment_tracker.get_commitment_level(4)
        );
    }

    println!("\n=== Phase 5: Finalization ===\n");

    // Update confirmation depths
    for slot in 4..=11 {
        let depth = 11 - slot + 1;
        commitment_tracker.update_confirmation_depth(slot as u64, depth as usize);
    }

    // Check for slots ready for finalization
    let ready = commitment_tracker.slots_ready_for_finalization();
    println!("Slots ready for finalization: {:?}", ready);

    if !ready.is_empty() {
        let finalization_slot = ready[0];

        // Mark as finalized
        commitment_tracker.mark_finalized(finalization_slot);

        println!("\nFinalized slot {}!", finalization_slot);
        println!(
            "  Commitment level: {:?}",
            commitment_tracker.get_commitment_level(finalization_slot)
        );
        println!("  New root: {:?}", commitment_tracker.root_slot());

        // Update tower root
        tower.set_root(finalization_slot);
        println!("  Updated tower root to {}", finalization_slot);
    }

    println!("\n=== Phase 6: Statistics ===\n");

    // Vote processor stats
    let vp_stats = vote_processor.get_stats();
    println!("Vote Processor Stats:");
    println!(
        "  Total slots with votes: {}",
        vp_stats.total_slots_with_votes
    );
    println!(
        "  Slots with supermajority: {}",
        vp_stats.slots_with_supermajority
    );
    println!("  Total validators: {}", vp_stats.total_validators);
    println!("  Active validators: {}", vp_stats.active_validators);

    // Fork choice stats
    let fc_stats = fork_choice.stats();
    println!("\nFork Choice Stats:");
    println!("  Total forks: {}", fc_stats.total_forks);
    println!("  Confirmed forks: {}", fc_stats.confirmed_forks);
    println!(
        "  Optimistically confirmed: {}",
        fc_stats.optimistically_confirmed_forks
    );
    println!("  Fork tips: {}", fc_stats.fork_tips_count);
    println!("  Best slot: {:?}", fc_stats.best_slot);

    // Commitment tracker stats
    let ct_stats = commitment_tracker.stats();
    println!("\nCommitment Tracker Stats:");
    println!("  Processed slots: {}", ct_stats.counts.processed);
    println!("  Confirmed slots: {}", ct_stats.counts.confirmed);
    println!("  Finalized slots: {}", ct_stats.counts.finalized);
    println!("  Root slot: {:?}", ct_stats.root_slot);
    println!("  Highest processed: {:?}", ct_stats.highest_processed);
    println!("  Highest confirmed: {:?}", ct_stats.highest_confirmed);

    // Tower info
    println!("\nTower Stats:");
    println!("  Votes in tower: {}", tower.len());
    println!("  Root: {:?}", tower.root());
    println!("  Last vote: {:?}", tower.last_vote_slot());
    println!(
        "  Total lockout distance: {}",
        tower.total_lockout_distance()
    );
    println!("  Max lockout: {:?}", tower.max_lockout());

    println!("\n=== Consensus Workflow Complete ===\n");
}

fn setup_validators() -> HashMap<Pubkey, u64> {
    let mut validators = HashMap::new();

    // Create 5 validators with varying stakes
    let stakes = vec![300, 250, 200, 150, 100];

    for stake in stakes {
        let validator = Pubkey::new_unique();
        validators.insert(validator, stake);
    }

    validators
}

fn setup_vote_processor(validators: &HashMap<Pubkey, u64>) -> VoteProcessor {
    let mut stake_tracker = StakeTracker::new(0);

    // Add stake delegations
    for (vote_account, stake) in validators {
        let stake_account = Pubkey::new_unique();
        let delegation = Delegation::new(*vote_account, *stake, 0);
        stake_tracker.add_delegation(stake_account, delegation);
    }

    let config = VoteProcessorConfig::default();
    let mut vote_processor = VoteProcessor::new(config, stake_tracker);

    // Register vote accounts
    for vote_account in validators.keys() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let state = VoteState::new(node, voter, withdrawer, 5);
        vote_processor.register_vote_account(*vote_account, state);
    }

    vote_processor
}
