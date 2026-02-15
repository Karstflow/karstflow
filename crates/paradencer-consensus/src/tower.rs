use paradencer_constants::consensus::{INITIAL_LOCKOUT, MAX_LOCKOUT_HISTORY};

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
}
