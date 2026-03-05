use karstflow_constants::consensus::{
    INITIAL_LOCKOUT, MAX_CONFIRMATION_COUNT, MAX_LOCKOUT_HISTORY, SWITCH_FORK_THRESHOLD,
    VOTE_THRESHOLD_DEPTH, VOTE_THRESHOLD_SIZE,
};

/// A single vote in the tower with lockout information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TowerVote {
    /// Slot number that was voted for
    pub slot: u64,
    /// Confirmation count - number of consecutive votes on same fork
    pub confirmation_count: u32,
}

impl TowerVote {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            confirmation_count: 1,
        }
    }

    /// Calculate the lockout for this vote
    /// lockout = INITIAL_LOCKOUT^confirmation_count
    pub fn lockout(&self) -> u64 {
        (INITIAL_LOCKOUT as u64).saturating_pow(self.confirmation_count)
    }

    /// Calculate the expiration slot for this vote
    /// expiration = slot + lockout
    pub fn expiration_slot(&self) -> u64 {
        self.slot.saturating_add(self.lockout())
    }

    /// Check if this vote locks out voting for a given slot
    pub fn is_locked_out_at(&self, slot: u64) -> bool {
        self.expiration_slot() > slot
    }

    /// Increment the confirmation count (double the lockout)
    pub fn increment_confirmation(&mut self) {
        self.confirmation_count = self.confirmation_count.saturating_add(1);
    }
}

/// Tower BFT voting structure
/// Maintains a stack of votes with exponentially increasing lockouts
#[derive(Debug, Clone)]
pub struct Tower {
    /// Stack of votes, most recent at the end
    votes: Vec<TowerVote>,
    /// Current root slot - cannot rollback past this
    root: Option<u64>,
    /// Maximum number of votes to maintain in tower
    max_size: usize,
}

impl Tower {
    pub fn new() -> Self {
        Self {
            votes: Vec::new(),
            root: None,
            max_size: MAX_LOCKOUT_HISTORY,
        }
    }

    pub fn with_root(root: u64) -> Self {
        Self {
            votes: Vec::new(),
            root: Some(root),
            max_size: MAX_LOCKOUT_HISTORY,
        }
    }

    pub fn root(&self) -> Option<u64> {
        self.root
    }

    pub fn votes(&self) -> &[TowerVote] {
        &self.votes
    }

    pub fn last_vote_slot(&self) -> Option<u64> {
        self.votes.last().map(|v| v.slot)
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    /// Simulate voting for a slot, returning how many votes would remain
    /// after expiring votes that would be popped.
    /// Expires votes from the TOP (most recent) while they're expired.
    fn simulate_vote(&self, slot: u64) -> usize {
        let mut count = self.votes.len();
        // Iterate from top (most recent) backwards, checking expiration
        while count > 0 {
            let vote = &self.votes[count - 1];
            // Vote is still valid if new slot hasn't reached expiration
            // Break when we find a vote that's still locked out (not expired)
            if slot < vote.expiration_slot() {
                break;
            }
            // Vote has expired, will be popped
            count -= 1;
        }
        count
    }

    /// Check if we are locked out from voting for the given slot
    /// on a different fork. This checks all votes in the tower.
    pub fn is_locked_out(&self, slot: u64, is_same_fork: impl Fn(u64, u64) -> bool) -> bool {
        // Cannot vote for anything at or before root
        if let Some(root) = self.root {
            if slot <= root {
                return true;
            }
        }

        // Check each vote in the tower
        for vote in &self.votes {
            // If this vote locks out the slot and they're on different forks
            if vote.is_locked_out_at(slot) && !is_same_fork(vote.slot, slot) {
                return true;
            }
        }

        false
    }

    /// Push a new vote onto the tower
    /// Returns Some(new_root) if a new root was created, None otherwise
    pub fn push_vote(&mut self, slot: u64) -> Option<u64> {
        // Sanity check: new vote must be greater than last vote
        if let Some(last) = self.last_vote_slot() {
            if slot <= last {
                return None; // Invalid vote
            }
        }

        // Simulate to determine expired votes
        let remaining = self.simulate_vote(slot);

        // Pop expired votes
        self.votes.truncate(remaining);

        // If tower is full, pop bottom vote as new root (BEFORE adding new vote)
        let new_root = if self.votes.len() >= self.max_size {
            let bottom = self.votes.remove(0);
            self.root = Some(bottom.slot);
            Some(bottom.slot)
        } else {
            None
        };

        // Increment confirmation counts for existing votes
        // Iterate from newest to oldest, incrementing while pattern is consecutive (1, 2, 3, ...)
        let mut prev_conf = 0u32;
        for vote in self.votes.iter_mut().rev() {
            prev_conf += 1;
            if vote.confirmation_count != prev_conf {
                break; // Stop if pattern breaks
            }
            vote.increment_confirmation();
        }

        // Add the new vote (always has conf=1)
        self.votes.push(TowerVote::new(slot));

        new_root
    }

    /// Reset the tower to a specific root
    pub fn set_root(&mut self, new_root: u64) {
        self.root = Some(new_root);
        self.votes.retain(|v| v.slot > new_root);
    }

    /// Clear all votes but preserve root
    pub fn clear_votes(&mut self) {
        self.votes.clear();
    }

    /// Record a vote and check for lockout violations.
    ///
    /// This validates that voting on the slot doesn't violate any tower lockouts.
    /// Returns Err if the vote would violate lockouts.
    pub fn record_vote(
        &mut self,
        slot: u64,
        is_same_fork: impl Fn(u64, u64) -> bool,
    ) -> Result<Option<u64>, TowerError> {
        // Check if we're locked out from voting on this slot
        if self.is_locked_out(slot, is_same_fork) {
            return Err(TowerError::LockoutViolation { slot });
        }

        // Push the vote and potentially get a new root
        let new_root = self.push_vote(slot);
        Ok(new_root)
    }

    /// Check if voting on a candidate slot would violate switching threshold.
    ///
    /// Uses real stake weights to determine if enough of the network is locked
    /// out on other forks (>= 38% of total stake), making a fork switch safe.
    ///
    /// - `candidate`: the slot we want to switch to
    /// - `total_stake`: total active stake in the network
    /// - `current_fork_stake`: stake currently on our fork (last vote's fork)
    /// - `is_same_fork`: closure that checks if two slots are on the same fork
    pub fn can_switch_to(
        &self,
        candidate: u64,
        total_stake: u64,
        current_fork_stake: u64,
        is_same_fork: impl Fn(u64, u64) -> bool,
    ) -> bool {
        // Get our last vote
        let last_vote_slot = match self.last_vote_slot() {
            Some(slot) => slot,
            None => return true, // No previous vote, can vote anywhere
        };

        // If candidate is on same fork, no switch needed
        if is_same_fork(last_vote_slot, candidate) {
            return true;
        }

        // Stake on other forks = total minus our fork's stake
        let stake_on_other_forks = total_stake.saturating_sub(current_fork_stake);
        self.check_switch_threshold(total_stake, stake_on_other_forks)
    }

    /// Get the lockout expiration for the most recent vote.
    pub fn last_vote_lockout_expiration(&self) -> Option<u64> {
        self.votes.last().map(|v| v.expiration_slot())
    }

    /// Get all vote slots in the tower.
    pub fn vote_slots(&self) -> Vec<u64> {
        self.votes.iter().map(|v| v.slot).collect()
    }

    /// Check if a slot is in the tower.
    pub fn contains_vote(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.slot == slot)
    }

    /// Get the vote at a specific index.
    pub fn get_vote(&self, index: usize) -> Option<&TowerVote> {
        self.votes.get(index)
    }

    /// Get the total lockout distance of the tower.
    ///
    /// This is the sum of all individual vote lockouts.
    pub fn total_lockout_distance(&self) -> u64 {
        self.votes.iter().map(|v| v.lockout()).sum()
    }

    /// Get the highest lockout in the tower.
    pub fn max_lockout(&self) -> Option<u64> {
        self.votes.iter().map(|v| v.lockout()).max()
    }

    /// Check if tower is at maximum capacity.
    pub fn is_full(&self) -> bool {
        self.votes.len() >= self.max_size
    }

    /// Get the number of votes that would remain after voting on a slot.
    pub fn simulate_vote_count(&self, slot: u64) -> usize {
        self.simulate_vote(slot)
    }

    /// Check if any vote locks out a given slot.
    pub fn is_any_vote_locked_out(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.is_locked_out_at(slot))
    }

    /// Get threshold for switching from this tower state.
    ///
    /// Returns the minimum stake ratio needed to switch forks.
    pub fn switching_threshold(&self) -> f64 {
        1.0 + SWITCH_FORK_THRESHOLD
    }

    /// Reconstruct a tower from saved persistence state.
    ///
    /// Used during validator restart to restore the tower from disk.
    pub fn from_saved(votes: Vec<TowerVote>, root: Option<u64>) -> Self {
        Self {
            votes,
            root,
            max_size: MAX_LOCKOUT_HISTORY,
        }
    }

    /// Check the threshold condition at a given depth in the tower.
    ///
    /// Returns true if enough stake (VOTE_THRESHOLD_SIZE = 2/3) has voted
    /// for the same fork at the specified depth. This is used to decide
    /// whether it is safe to continue voting on the current fork.
    pub fn check_threshold(
        &self,
        depth: usize,
        stake_for_slot: impl Fn(u64) -> u64,
        total_stake: u64,
    ) -> bool {
        if total_stake == 0 {
            return false;
        }

        // Check from the top of the tower down to the given depth
        let check_depth = depth.min(self.votes.len());
        if check_depth == 0 {
            return true; // No votes to check threshold for
        }

        // The vote at the threshold depth from the top
        let idx = self.votes.len().saturating_sub(check_depth);
        if idx >= self.votes.len() {
            return true;
        }

        let vote = &self.votes[idx];
        let stake = stake_for_slot(vote.slot);
        let ratio = stake as f64 / total_stake as f64;

        ratio >= VOTE_THRESHOLD_SIZE
    }

    /// Evaluate whether switching to a different fork is safe based on
    /// actual stake distribution across forks.
    ///
    /// The switch check ensures that at least SWITCH_FORK_THRESHOLD (38%)
    /// of total stake is locked out on forks other than our last vote's fork.
    /// This prevents unnecessary fork switches when most of the network
    /// is on our current fork.
    pub fn check_switch_threshold(&self, total_stake: u64, stake_on_other_forks: u64) -> bool {
        if total_stake == 0 {
            return true;
        }

        // If we have no votes, we can freely switch
        if self.votes.is_empty() {
            return true;
        }

        let ratio = stake_on_other_forks as f64 / total_stake as f64;
        ratio >= SWITCH_FORK_THRESHOLD
    }

    /// Verify that a tower state is internally consistent.
    ///
    /// Checks:
    /// - Vote slots are strictly monotonically increasing
    /// - Confirmation counts are monotonically decreasing from bottom to top
    /// - No confirmation count exceeds MAX_CONFIRMATION_COUNT
    /// - No confirmation count is zero
    /// - Root (if present) is less than all vote slots
    /// - Tower does not exceed maximum size
    pub fn verify(&self) -> Result<(), TowerError> {
        // Check tower size
        if self.votes.len() > self.max_size {
            return Err(TowerError::TowerTooLarge {
                size: self.votes.len(),
                max: self.max_size,
            });
        }

        // Check root is below all votes
        if let Some(root) = self.root {
            for vote in &self.votes {
                if vote.slot <= root {
                    return Err(TowerError::VoteBelowRoot {
                        slot: vote.slot,
                        root,
                    });
                }
            }
        }

        // Check vote slots are strictly increasing
        for i in 1..self.votes.len() {
            if self.votes[i].slot <= self.votes[i - 1].slot {
                return Err(TowerError::SlotsNotOrdered {
                    slot: self.votes[i].slot,
                    prev_slot: self.votes[i - 1].slot,
                });
            }
        }

        // Check confirmation counts are monotonically decreasing (bottom has highest)
        // and within valid range
        for i in 0..self.votes.len() {
            let conf = self.votes[i].confirmation_count;
            if conf == 0 {
                return Err(TowerError::ZeroConfirmation {
                    slot: self.votes[i].slot,
                });
            }
            if conf > MAX_CONFIRMATION_COUNT {
                return Err(TowerError::ConfirmationTooLarge {
                    slot: self.votes[i].slot,
                    confirmation: conf,
                });
            }

            // Each vote deeper in the tower should have higher or equal confirmation
            if i > 0 && self.votes[i].confirmation_count > self.votes[i - 1].confirmation_count {
                return Err(TowerError::ConfirmationsNotOrdered {
                    slot: self.votes[i].slot,
                    confirmation: self.votes[i].confirmation_count,
                });
            }
        }

        Ok(())
    }

    /// Generate the compact list of vote slots for a tower sync transaction.
    ///
    /// Returns the vote slots in order (oldest to newest) along with the
    /// current tower root. This is used to construct vote instructions
    /// for submission to the network.
    pub fn create_vote_slots(&self) -> (Vec<u64>, Option<u64>) {
        let slots = self.vote_slots();
        (slots, self.root)
    }

    /// Select the best slot to vote on from the given candidates.
    ///
    /// Picks the candidate with the highest fork weight that would not
    /// violate tower lockouts.
    pub fn select_vote_slot(
        &self,
        candidates: &[(u64, u64)], // (slot, fork_weight)
        is_same_fork: impl Fn(u64, u64) -> bool,
    ) -> Option<u64> {
        let last_vote = self.last_vote_slot();

        let mut best: Option<(u64, u64)> = None; // (slot, weight)

        for &(slot, weight) in candidates {
            // Must be newer than last vote
            if let Some(last) = last_vote {
                if slot <= last {
                    continue;
                }
            }

            // Must not be locked out
            if self.is_locked_out(slot, &is_same_fork) {
                continue;
            }

            // Pick highest weight, break ties by lower slot
            match best {
                None => best = Some((slot, weight)),
                Some((_, best_weight)) => {
                    if weight > best_weight || (weight == best_weight && slot < best.unwrap().0) {
                        best = Some((slot, weight));
                    }
                }
            }
        }

        best.map(|(slot, _)| slot)
    }

    /// Get the threshold depth used for vote safety checks.
    pub fn threshold_depth(&self) -> usize {
        VOTE_THRESHOLD_DEPTH
    }
}

/// Errors that can occur during tower operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TowerError {
    /// Attempted to vote on a slot locked out by tower
    LockoutViolation { slot: u64 },
    /// Vote is not newer than last vote
    VoteNotNewer { slot: u64, last_vote: u64 },
    /// Cannot vote on slot at or before root
    VoteBelowRoot { slot: u64, root: u64 },
    /// Vote slots are not strictly ordered
    SlotsNotOrdered { slot: u64, prev_slot: u64 },
    /// Confirmation count is zero (invalid)
    ZeroConfirmation { slot: u64 },
    /// Confirmation count exceeds maximum
    ConfirmationTooLarge { slot: u64, confirmation: u32 },
    /// Confirmations are not monotonically ordered
    ConfirmationsNotOrdered { slot: u64, confirmation: u32 },
    /// Tower exceeds maximum allowed size
    TowerTooLarge { size: usize, max: usize },
}

impl Default for Tower {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_vote_lockout_calculation() {
        let vote = TowerVote::new(100);
        assert_eq!(vote.lockout(), 2); // 2^1
        assert_eq!(vote.expiration_slot(), 102);

        let mut vote = TowerVote::new(100);
        vote.increment_confirmation();
        assert_eq!(vote.confirmation_count, 2);
        assert_eq!(vote.lockout(), 4); // 2^2
        assert_eq!(vote.expiration_slot(), 104);
    }

    #[test]
    fn tower_vote_lockout_detection() {
        let vote = TowerVote::new(100);
        assert!(vote.is_locked_out_at(100));
        assert!(vote.is_locked_out_at(101));
        assert!(!vote.is_locked_out_at(102));
        assert!(!vote.is_locked_out_at(103));
    }

    #[test]
    fn tower_new_empty() {
        let tower = Tower::new();
        assert!(tower.is_empty());
        assert_eq!(tower.len(), 0);
        assert_eq!(tower.root(), None);
        assert_eq!(tower.last_vote_slot(), None);
    }

    #[test]
    fn tower_push_single_vote() {
        let mut tower = Tower::new();
        let root = tower.push_vote(10);

        assert_eq!(root, None);
        assert_eq!(tower.len(), 1);
        assert_eq!(tower.last_vote_slot(), Some(10));
        assert_eq!(tower.votes()[0].slot, 10);
        assert_eq!(tower.votes()[0].confirmation_count, 1);
    }

    #[test]
    fn tower_push_consecutive_votes() {
        let mut tower = Tower::new();

        // Vote for slot 100
        tower.push_vote(100);
        assert_eq!(tower.votes()[0].confirmation_count, 1);
        assert_eq!(tower.votes()[0].lockout(), 2);

        // Vote for slot 101 - previous vote gets conf=2 (lockout=4)
        tower.push_vote(101);
        assert_eq!(tower.len(), 2);
        assert_eq!(tower.votes()[0].confirmation_count, 2);
        assert_eq!(tower.votes()[1].confirmation_count, 1);

        // Vote for slot 102 - votes get conf=3,2,1 (lockouts=8,4,2)
        tower.push_vote(102);
        assert_eq!(tower.len(), 3);
        assert_eq!(tower.votes()[0].confirmation_count, 3);
        assert_eq!(tower.votes()[1].confirmation_count, 2);
        assert_eq!(tower.votes()[2].confirmation_count, 1);
    }

    #[test]
    fn tower_expire_votes() {
        let mut tower = Tower::new();

        tower.push_vote(10); // After push: conf:1, lockout:2, expires at 12
        tower.push_vote(11); // After push: vote 10 now has conf:2, lockout:4, expires at 14
                             //             vote 11 has conf:1, lockout:2, expires at 13
        assert_eq!(tower.len(), 2);

        // Vote at slot far enough to expire vote 11 (13) but not 10 (14)
        tower.push_vote(13);
        assert_eq!(tower.len(), 2); // Vote 11 expired, 10 and 13 remain
        assert_eq!(tower.votes()[0].slot, 10);
        assert_eq!(tower.votes()[1].slot, 13);
    }

    #[test]
    fn tower_root_promotion() {
        let mut tower = Tower::new();

        // Fill tower to max with consecutive slots
        for i in 0..MAX_LOCKOUT_HISTORY {
            tower.push_vote(100 + i as u64);
        }

        assert_eq!(tower.len(), MAX_LOCKOUT_HISTORY);
        assert_eq!(tower.root(), None);

        // Next vote promotes root
        let new_root = tower.push_vote(100 + MAX_LOCKOUT_HISTORY as u64);
        assert!(new_root.is_some());
        assert_eq!(tower.root(), Some(100)); // First vote was at slot 100
        assert_eq!(tower.len(), MAX_LOCKOUT_HISTORY);
    }

    #[test]
    fn tower_lockout_check_same_fork() {
        let mut tower = Tower::new();
        tower.push_vote(10);
        tower.push_vote(20);

        // Same fork check - all slots are on same fork
        let same_fork = |_a: u64, _b: u64| true;

        // Not locked out if on same fork
        assert!(!tower.is_locked_out(30, same_fork));
    }

    #[test]
    fn tower_lockout_check_different_fork() {
        let mut tower = Tower::new();
        tower.push_vote(10); // lockout: 2, expires at 12

        // Different fork check
        let different_fork = |a: u64, b: u64| a == b;

        // Locked out from slot 11 on different fork
        assert!(tower.is_locked_out(11, different_fork));
        // Not locked out from slot 12+ on different fork
        assert!(!tower.is_locked_out(12, different_fork));
    }

    #[test]
    fn tower_set_root() {
        let mut tower = Tower::new();
        tower.push_vote(10);
        tower.push_vote(20);
        tower.push_vote(30);

        tower.set_root(20);
        assert_eq!(tower.root(), Some(20));
        assert_eq!(tower.len(), 1); // Only vote 30 remains
        assert_eq!(tower.votes()[0].slot, 30);
    }

    #[test]
    fn tower_clear_votes() {
        let mut tower = Tower::with_root(10);
        tower.push_vote(20);
        tower.push_vote(30);

        tower.clear_votes();
        assert!(tower.is_empty());
        assert_eq!(tower.root(), Some(10)); // Root preserved
    }

    #[test]
    fn tower_record_vote_success() {
        let mut tower = Tower::new();
        let same_fork = |_a: u64, _b: u64| true;

        let result = tower.record_vote(100, same_fork);
        assert!(result.is_ok());
        assert_eq!(tower.last_vote_slot(), Some(100));
    }

    #[test]
    fn tower_record_vote_lockout_violation() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        let different_fork = |a: u64, b: u64| a == b;

        // Try to vote on locked out slot
        let result = tower.record_vote(101, different_fork);
        assert!(matches!(result, Err(TowerError::LockoutViolation { .. })));
    }

    #[test]
    fn tower_can_switch_to_with_threshold() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        // Closure: slots are on the same fork if equal
        let same_fork = |a: u64, b: u64| a == b;

        // total_stake=1000, current_fork_stake=500 → other_forks=500/1000=50% >= 38% → can switch
        assert!(tower.can_switch_to(200, 1000, 500, same_fork));

        // total_stake=1000, current_fork_stake=700 → other_forks=300/1000=30% < 38% → cannot switch
        assert!(!tower.can_switch_to(200, 1000, 700, same_fork));

        // total_stake=1000, current_fork_stake=620 → other_forks=380/1000=38% >= 38% → can switch
        assert!(tower.can_switch_to(200, 1000, 620, same_fork));

        // No previous vote → can switch anywhere
        let empty_tower = Tower::new();
        assert!(empty_tower.can_switch_to(200, 0, 0, same_fork));

        // Same fork → always allowed regardless of stake
        let always_same = |_a: u64, _b: u64| true;
        assert!(tower.can_switch_to(200, 1000, 1000, always_same));
    }

    #[test]
    fn tower_vote_slots_list() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101);
        tower.push_vote(102);

        let slots = tower.vote_slots();
        assert_eq!(slots, vec![100, 101, 102]);
    }

    #[test]
    fn tower_contains_vote_check() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101); // 100 gets conf=2 (lockout 4), stays

        assert!(tower.contains_vote(100));
        assert!(tower.contains_vote(101));
        assert!(!tower.contains_vote(99));
    }

    #[test]
    fn tower_total_lockout_distance() {
        let mut tower = Tower::new();
        tower.push_vote(100); // After push: lockout = 2
        tower.push_vote(101); // After push: vote 100 lockout = 4, vote 101 lockout = 2

        let total = tower.total_lockout_distance();
        assert_eq!(total, 6); // 4 + 2
    }

    #[test]
    fn tower_max_lockout() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101);
        tower.push_vote(102);

        // First vote should have highest lockout after 3 votes
        let max = tower.max_lockout();
        assert_eq!(max, Some(8)); // 2^3
    }

    #[test]
    fn tower_is_full_check() {
        let mut tower = Tower::new();
        assert!(!tower.is_full());

        for i in 0..MAX_LOCKOUT_HISTORY {
            tower.push_vote(i as u64);
        }

        assert!(tower.is_full());
    }

    #[test]
    fn tower_simulate_vote_count() {
        let mut tower = Tower::new();
        tower.push_vote(10);
        tower.push_vote(11);

        // Vote at 13 would expire vote at 11 (expires at 13)
        let count = tower.simulate_vote_count(13);
        assert_eq!(count, 1);
    }

    #[test]
    fn tower_is_any_vote_locked_out() {
        let mut tower = Tower::new();
        tower.push_vote(10);

        assert!(tower.is_any_vote_locked_out(10));
        assert!(tower.is_any_vote_locked_out(11));
        assert!(!tower.is_any_vote_locked_out(12));
    }

    #[test]
    fn tower_switching_threshold_constant() {
        let tower = Tower::new();
        assert!((tower.switching_threshold() - 1.38).abs() < 0.001);
    }

    #[test]
    fn tower_from_saved_restores_state() {
        let votes = vec![
            TowerVote {
                slot: 10,
                confirmation_count: 3,
            },
            TowerVote {
                slot: 20,
                confirmation_count: 2,
            },
            TowerVote {
                slot: 30,
                confirmation_count: 1,
            },
        ];
        let tower = Tower::from_saved(votes.clone(), Some(5));

        assert_eq!(tower.root(), Some(5));
        assert_eq!(tower.len(), 3);
        assert_eq!(tower.votes()[0].slot, 10);
        assert_eq!(tower.votes()[2].confirmation_count, 1);
    }

    #[test]
    fn tower_verify_valid_tower() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101);
        tower.push_vote(102);

        assert!(tower.verify().is_ok());
    }

    #[test]
    fn tower_verify_empty_tower() {
        let tower = Tower::new();
        assert!(tower.verify().is_ok());
    }

    #[test]
    fn tower_verify_detects_unordered_slots() {
        let votes = vec![
            TowerVote {
                slot: 20,
                confirmation_count: 2,
            },
            TowerVote {
                slot: 10,
                confirmation_count: 1,
            },
        ];
        let tower = Tower::from_saved(votes, None);

        assert!(matches!(
            tower.verify(),
            Err(TowerError::SlotsNotOrdered { .. })
        ));
    }

    #[test]
    fn tower_verify_detects_zero_confirmation() {
        let votes = vec![TowerVote {
            slot: 10,
            confirmation_count: 0,
        }];
        let tower = Tower::from_saved(votes, None);

        assert!(matches!(
            tower.verify(),
            Err(TowerError::ZeroConfirmation { .. })
        ));
    }

    #[test]
    fn tower_verify_detects_excessive_confirmation() {
        let votes = vec![TowerVote {
            slot: 10,
            confirmation_count: 100,
        }];
        let tower = Tower::from_saved(votes, None);

        assert!(matches!(
            tower.verify(),
            Err(TowerError::ConfirmationTooLarge { .. })
        ));
    }

    #[test]
    fn tower_verify_detects_vote_below_root() {
        let votes = vec![TowerVote {
            slot: 5,
            confirmation_count: 1,
        }];
        let tower = Tower::from_saved(votes, Some(10));

        assert!(matches!(
            tower.verify(),
            Err(TowerError::VoteBelowRoot { .. })
        ));
    }

    #[test]
    fn tower_verify_detects_confirmation_order_violation() {
        let votes = vec![
            TowerVote {
                slot: 10,
                confirmation_count: 1,
            },
            TowerVote {
                slot: 20,
                confirmation_count: 3,
            },
        ];
        let tower = Tower::from_saved(votes, None);

        assert!(matches!(
            tower.verify(),
            Err(TowerError::ConfirmationsNotOrdered { .. })
        ));
    }

    #[test]
    fn tower_check_threshold_passes_with_supermajority() {
        let mut tower = Tower::new();
        for i in 0..10 {
            tower.push_vote(100 + i);
        }

        // 70% stake at the threshold depth slot - should pass
        let result = tower.check_threshold(VOTE_THRESHOLD_DEPTH, |_slot| 700, 1000);
        assert!(result);
    }

    #[test]
    fn tower_check_threshold_fails_without_supermajority() {
        let mut tower = Tower::new();
        for i in 0..10 {
            tower.push_vote(100 + i);
        }

        // 50% stake - below 2/3 threshold
        let result = tower.check_threshold(VOTE_THRESHOLD_DEPTH, |_slot| 500, 1000);
        assert!(!result);
    }

    #[test]
    fn tower_check_switch_threshold_passes() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        // 40% stake on other forks, above 38% threshold
        assert!(tower.check_switch_threshold(1000, 400));
    }

    #[test]
    fn tower_check_switch_threshold_fails() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        // 30% stake on other forks, below 38% threshold
        assert!(!tower.check_switch_threshold(1000, 300));
    }

    #[test]
    fn tower_check_switch_threshold_empty_tower() {
        let tower = Tower::new();
        // Empty tower can always switch
        assert!(tower.check_switch_threshold(1000, 0));
    }

    #[test]
    fn tower_create_vote_slots() {
        let mut tower = Tower::new();
        tower.push_vote(100);
        tower.push_vote(101);
        tower.push_vote(102);

        let (slots, root) = tower.create_vote_slots();
        assert_eq!(slots, vec![100, 101, 102]);
        assert_eq!(root, None);
    }

    #[test]
    fn tower_create_vote_slots_with_root() {
        let mut tower = Tower::new();
        // Fill up tower to get a root
        for i in 0..32 {
            tower.push_vote(100 + i);
        }
        assert!(tower.root().is_some());

        let (slots, root) = tower.create_vote_slots();
        assert!(root.is_some());
        assert!(!slots.is_empty());
    }

    #[test]
    fn tower_select_vote_slot_picks_heaviest() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        let candidates = vec![(101, 500), (102, 800), (103, 300)];

        let same_fork = |_a: u64, _b: u64| true;
        let selected = tower.select_vote_slot(&candidates, same_fork);
        assert_eq!(selected, Some(102)); // Highest weight
    }

    #[test]
    fn tower_select_vote_slot_respects_lockouts() {
        let mut tower = Tower::new();
        tower.push_vote(100);

        // Candidate 101 is locked out (different fork, within lockout)
        let candidates = vec![(101, 900), (102, 500)];

        let different_fork = |a: u64, b: u64| a == b;
        let selected = tower.select_vote_slot(&candidates, different_fork);
        // 101 is locked out (within lockout period of vote 100), 102 is not (beyond lockout=2)
        assert_eq!(selected, Some(102));
    }

    #[test]
    fn tower_select_vote_slot_empty_candidates() {
        let tower = Tower::new();
        let same_fork = |_a: u64, _b: u64| true;
        assert_eq!(tower.select_vote_slot(&[], same_fork), None);
    }

    #[test]
    fn tower_threshold_depth_constant() {
        let tower = Tower::new();
        assert_eq!(tower.threshold_depth(), VOTE_THRESHOLD_DEPTH);
    }
}
