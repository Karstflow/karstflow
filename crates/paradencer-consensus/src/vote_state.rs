/// Vote state tracking for validator vote accounts.
///
/// Vote accounts store a validator's voting history, including:
/// - Slots voted on with lockout periods
/// - Epoch credits earned for voting
/// - Authorized voters and withdrawers
/// - Commission rate for delegator rewards
use paradencer_storage::Pubkey;
use std::collections::VecDeque;

/// Maximum number of votes to track in vote account history.
pub const MAX_LOCKOUT_HISTORY: usize = 32;

/// Maximum number of epoch credits to track.
pub const MAX_EPOCH_CREDITS: usize = 64;

/// A vote for a specific slot with confirmation count for lockout calculation.
///
/// Each vote has an associated lockout period that doubles with each
/// subsequent vote. The confirmation_count tracks how many votes have
/// been made since this one, determining the lockout duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteLockout {
    /// Slot number that was voted on
    pub slot: u64,
    /// Number of confirmations (votes) since this vote
    pub confirmation_count: u32,
}

impl VoteLockout {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            confirmation_count: 1,
        }
    }

    /// Calculate the lockout expiration slot.
    ///
    /// Lockout doubles with each confirmation: 2^confirmation_count slots.
    pub fn expiration_slot(&self) -> u64 {
        self.slot
            .saturating_add(self.lockout_distance())
    }

    /// Calculate lockout distance: 2^confirmation_count
    pub fn lockout_distance(&self) -> u64 {
        // Use checked_shl to handle overflow, cap at u64::MAX
        1u64.checked_shl(self.confirmation_count)
            .unwrap_or(u64::MAX)
    }

    /// Check if this vote has expired (lockout period passed) at a given slot.
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expiration_slot()
    }

    /// Increment confirmation count (called when a new vote is added).
    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by);
    }
}

/// Vote with latency tracking.
///
/// Tracks when the vote was submitted relative to when the slot was produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandedVote {
    /// Latency in slots between slot production and vote submission
    pub latency: u8,
    /// The vote lockout information
    pub lockout: VoteLockout,
}

impl LandedVote {
    pub fn new(slot: u64, latency: u8) -> Self {
        Self {
            latency,
            lockout: VoteLockout::new(slot),
        }
    }

    /// Get the slot this vote is for.
    pub fn slot(&self) -> u64 {
        self.lockout.slot
    }
}

/// Credits earned in a specific epoch.
///
/// Tracks voting participation and rewards for an epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCredits {
    /// Epoch number
    pub epoch: u64,
    /// Total credits earned in this epoch
    pub credits: u64,
    /// Credits from previous epoch (for delta calculation)
    pub prev_credits: u64,
}

impl EpochCredits {
    pub fn new(epoch: u64, credits: u64, prev_credits: u64) -> Self {
        Self {
            epoch,
            credits,
            prev_credits,
        }
    }

    /// Get credits earned this epoch (delta from previous).
    pub fn credits_earned(&self) -> u64 {
        self.credits.saturating_sub(self.prev_credits)
    }
}

/// Block timestamp for last voted slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTimestamp {
    /// Slot number
    pub slot: u64,
    /// Unix timestamp when block was produced
    pub timestamp: i64,
}

impl BlockTimestamp {
    pub fn new(slot: u64, timestamp: i64) -> Self {
        Self { slot, timestamp }
    }
}

/// Core vote account state (version 3).
///
/// Stores validator voting history, credits, and authorization info.
#[derive(Debug, Clone)]
pub struct VoteState {
    /// Validator node identity pubkey
    pub node_pubkey: Pubkey,
    /// Authorized withdrawer (can withdraw stake)
    pub authorized_withdrawer: Pubkey,
    /// Commission rate (0-100) taken from delegator rewards
    pub commission: u8,
    /// Recent vote history with lockouts
    pub votes: VecDeque<LandedVote>,
    /// Root slot (finalized, cannot be rolled back)
    pub root_slot: Option<u64>,
    /// Currently authorized voter
    pub authorized_voter: Pubkey,
    /// Credits earned per epoch
    pub epoch_credits: VecDeque<EpochCredits>,
    /// Last block timestamp
    pub last_timestamp: BlockTimestamp,
}

impl VoteState {
    /// Create a new vote state for a validator.
    pub fn new(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
    ) -> Self {
        Self {
            node_pubkey,
            authorized_withdrawer,
            commission,
            votes: VecDeque::with_capacity(MAX_LOCKOUT_HISTORY),
            root_slot: None,
            authorized_voter,
            epoch_credits: VecDeque::with_capacity(MAX_EPOCH_CREDITS),
            last_timestamp: BlockTimestamp::new(0, 0),
        }
    }

    /// Process a new vote for a slot.
    ///
    /// Adds the vote to history and updates confirmation counts for existing votes.
    pub fn process_vote(&mut self, slot: u64, timestamp: i64, latency: u8) -> Result<(), VoteError> {
        // Verify vote is newer than last vote
        if let Some(last_vote) = self.votes.back() {
            if slot <= last_vote.slot() {
                return Err(VoteError::SlotNotNewer);
            }
        }

        // Add new vote
        let vote = LandedVote::new(slot, latency);
        self.votes.push_back(vote);

        // Update timestamp
        self.last_timestamp = BlockTimestamp::new(slot, timestamp);

        // Trim to max history
        while self.votes.len() > MAX_LOCKOUT_HISTORY {
            self.votes.pop_front();
        }

        // Increment confirmation counts for existing votes
        let votes_count = self.votes.len();
        for (i, vote) in self.votes.iter_mut().enumerate() {
            if i < votes_count - 1 {
                // Don't increment the vote we just added
                vote.lockout.increase_confirmation_count(1);
            }
        }

        Ok(())
    }

    /// Get the most recent vote slot.
    pub fn last_voted_slot(&self) -> Option<u64> {
        self.votes.back().map(|v| v.slot())
    }

    /// Set a new root slot.
    ///
    /// Root slot represents finalized state that cannot be rolled back.
    /// Prunes votes older than root.
    pub fn set_root(&mut self, new_root: u64) {
        self.root_slot = Some(new_root);

        // Remove votes older than root
        self.votes.retain(|vote| vote.slot() >= new_root);
    }

    /// Get total credits earned across all epochs.
    pub fn total_credits(&self) -> u64 {
        self.epoch_credits
            .iter()
            .map(|ec| ec.credits_earned())
            .sum()
    }

    /// Get credits for a specific epoch.
    pub fn credits_for_epoch(&self, epoch: u64) -> Option<u64> {
        self.epoch_credits
            .iter()
            .find(|ec| ec.epoch == epoch)
            .map(|ec| ec.credits_earned())
    }

    /// Add credits for an epoch.
    pub fn add_epoch_credits(&mut self, epoch: u64, credits: u64) {
        let prev_credits = self.epoch_credits
            .back()
            .map(|ec| ec.credits)
            .unwrap_or(0);

        let total_credits = prev_credits + credits;
        let epoch_credit = EpochCredits::new(epoch, total_credits, prev_credits);

        self.epoch_credits.push_back(epoch_credit);

        // Trim to max history
        while self.epoch_credits.len() > MAX_EPOCH_CREDITS {
            self.epoch_credits.pop_front();
        }
    }

    /// Check if a slot can be voted on without violating lockouts.
    ///
    /// Returns true if no active lockouts prevent voting on this slot.
    pub fn can_vote_on_slot(&self, slot: u64) -> bool {
        // Can't vote on slot older than root
        if let Some(root) = self.root_slot {
            if slot < root {
                return false;
            }
        }

        // Check if any lockouts prevent voting on this slot
        for vote in &self.votes {
            if !vote.lockout.is_expired(slot) && vote.slot() > slot {
                // There's an unexpired vote for a later slot, can't vote earlier
                return false;
            }
        }

        true
    }

    /// Get the number of active votes (not expired).
    pub fn active_vote_count(&self, current_slot: u64) -> usize {
        self.votes
            .iter()
            .filter(|v| !v.lockout.is_expired(current_slot))
            .count()
    }
}

/// Errors that can occur during vote processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteError {
    /// Attempted to vote on slot not newer than last vote
    SlotNotNewer,
    /// Vote violates lockout rules
    LockoutViolation,
    /// Invalid authorized voter
    UnauthorizedVoter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_lockout_calculates_expiration() {
        let vote = VoteLockout::new(100);
        // Initial confirmation_count = 1, lockout = 2^1 = 2
        assert_eq!(vote.expiration_slot(), 102);

        let mut vote = VoteLockout::new(100);
        vote.confirmation_count = 3;
        // lockout = 2^3 = 8
        assert_eq!(vote.expiration_slot(), 108);
    }

    #[test]
    fn vote_lockout_checks_expiration() {
        let vote = VoteLockout::new(100);
        assert!(!vote.is_expired(101));
        assert!(vote.is_expired(102)); // Expires at 102
        assert!(vote.is_expired(103));
    }

    #[test]
    fn landed_vote_creates_with_latency() {
        let vote = LandedVote::new(50, 3);
        assert_eq!(vote.slot(), 50);
        assert_eq!(vote.latency, 3);
        assert_eq!(vote.lockout.confirmation_count, 1);
    }

    #[test]
    fn epoch_credits_calculates_earned() {
        let credits = EpochCredits::new(5, 1000, 700);
        assert_eq!(credits.credits_earned(), 300);
    }

    #[test]
    fn vote_state_creates_new() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let state = VoteState::new(node, voter, withdrawer, 10);

        assert_eq!(state.node_pubkey, node);
        assert_eq!(state.authorized_voter, voter);
        assert_eq!(state.authorized_withdrawer, withdrawer);
        assert_eq!(state.commission, 10);
        assert_eq!(state.votes.len(), 0);
        assert_eq!(state.root_slot, None);
    }

    #[test]
    fn vote_state_processes_vote() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Process first vote
        state.process_vote(100, 1000, 2).unwrap();
        assert_eq!(state.votes.len(), 1);
        assert_eq!(state.last_voted_slot(), Some(100));
        assert_eq!(state.last_timestamp.slot, 100);
        assert_eq!(state.last_timestamp.timestamp, 1000);

        // Process second vote
        state.process_vote(101, 1002, 1).unwrap();
        assert_eq!(state.votes.len(), 2);
        assert_eq!(state.last_voted_slot(), Some(101));

        // First vote should have increased confirmation count
        assert_eq!(state.votes[0].lockout.confirmation_count, 2);
    }

    #[test]
    fn vote_state_rejects_old_vote() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.process_vote(100, 1000, 0).unwrap();

        // Try to vote on same slot
        let result = state.process_vote(100, 1001, 0);
        assert_eq!(result, Err(VoteError::SlotNotNewer));

        // Try to vote on older slot
        let result = state.process_vote(99, 1001, 0);
        assert_eq!(result, Err(VoteError::SlotNotNewer));
    }

    #[test]
    fn vote_state_sets_root() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Add votes
        state.process_vote(100, 1000, 0).unwrap();
        state.process_vote(101, 1001, 0).unwrap();
        state.process_vote(102, 1002, 0).unwrap();

        // Set root at 101
        state.set_root(101);

        assert_eq!(state.root_slot, Some(101));
        // Vote at 100 should be pruned
        assert_eq!(state.votes.len(), 2);
        assert_eq!(state.votes[0].slot(), 101);
        assert_eq!(state.votes[1].slot(), 102);
    }

    #[test]
    fn vote_state_tracks_epoch_credits() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.add_epoch_credits(0, 100);
        state.add_epoch_credits(1, 150);
        state.add_epoch_credits(2, 200);

        assert_eq!(state.total_credits(), 450);
        assert_eq!(state.credits_for_epoch(1), Some(150));
    }

    #[test]
    fn vote_state_checks_lockout_violations() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Vote on slot 100
        state.process_vote(100, 1000, 0).unwrap();

        // Can vote on newer slots
        assert!(state.can_vote_on_slot(101));
        assert!(state.can_vote_on_slot(200));

        // Cannot vote on older slots
        assert!(!state.can_vote_on_slot(99));
        assert!(!state.can_vote_on_slot(50));

        // Vote on 101
        state.process_vote(101, 1001, 0).unwrap();

        // Now cannot vote on 100 (there's a later vote)
        assert!(!state.can_vote_on_slot(100));
    }

    #[test]
    fn vote_state_trims_vote_history() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Add MAX_LOCKOUT_HISTORY + 10 votes
        for i in 0..(MAX_LOCKOUT_HISTORY + 10) {
            state.process_vote(i as u64, i as i64 * 1000, 0).unwrap();
        }

        // Should be trimmed to MAX_LOCKOUT_HISTORY
        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);

        // Oldest votes should be removed, newest preserved
        assert_eq!(state.votes.front().unwrap().slot(), 10);
        assert_eq!(state.votes.back().unwrap().slot(), 41);
    }

    #[test]
    fn vote_state_counts_active_votes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.process_vote(100, 1000, 0).unwrap();
        state.process_vote(101, 1001, 0).unwrap();

        // At slot 101, both votes are active
        assert_eq!(state.active_vote_count(101), 2);

        // Vote at 100 has confirmation_count=2 after second vote, expiration=100+2^2=104
        // Vote at 101 has confirmation_count=1, expiration=101+2^1=103
        // At slot 103, vote at 101 has expired
        assert_eq!(state.active_vote_count(103), 1);

        // At slot 104, both have expired
        assert_eq!(state.active_vote_count(104), 0);
    }
}
