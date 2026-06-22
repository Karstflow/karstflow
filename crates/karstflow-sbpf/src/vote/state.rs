/// Vote state for the vote program executor.
///
/// This module provides the vote state types used by the vote program
/// during transaction execution. It includes lockout calculations,
/// vote processing, and serialization/deserialization.
use karstflow_constants::consensus::{
    INITIAL_LOCKOUT, MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY,
};
use karstflow_constants::vote_program::{VOTE_CREDITS_GRACE_SLOTS, VOTE_CREDITS_MAXIMUM_PER_SLOT};
use karstflow_types::Pubkey;

/// A vote lockout tracking slot and confirmation depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockout {
    pub slot: u64,
    pub confirmation_count: u32,
}

impl Lockout {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            confirmation_count: 1,
        }
    }

    pub fn with_confirmation_count(slot: u64, confirmation_count: u32) -> Self {
        Self {
            slot,
            confirmation_count,
        }
    }

    /// Calculate the slot at which the lockout expires.
    ///
    /// Lockout distance = INITIAL_LOCKOUT^confirmation_count.
    /// For INITIAL_LOCKOUT=2 this gives 2^confirmation_count.
    pub fn expiration_slot(&self) -> u64 {
        let lockout = (INITIAL_LOCKOUT as u64)
            .checked_pow(self.confirmation_count)
            .unwrap_or(u64::MAX);
        self.slot.saturating_add(lockout)
    }

    /// The last slot at which this vote is still locked out.
    pub fn last_locked_out_slot(&self) -> u64 {
        self.expiration_slot()
    }

    /// Check if the lockout is still active at the given slot.
    pub fn is_locked_out_at_slot(&self, slot: u64) -> bool {
        self.expiration_slot() > slot
    }

    /// Increment the confirmation count.
    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by);
    }
}

/// A landed vote with latency tracking for timely vote credits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandedVote {
    pub latency: u8,
    pub lockout: Lockout,
}

impl LandedVote {
    pub fn new(slot: u64, latency: u8) -> Self {
        Self {
            latency,
            lockout: Lockout::new(slot),
        }
    }

    pub fn with_lockout(lockout: Lockout, latency: u8) -> Self {
        Self { latency, lockout }
    }

    pub fn slot(&self) -> u64 {
        self.lockout.slot
    }
}

/// Core vote account state used during program execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteState {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
    pub votes: Vec<LandedVote>,
    pub root_slot: Option<u64>,
    pub epoch_credits: Vec<(u64, u64, u64)>,
    /// Authorized-voter BLS public key (48-byte compressed G1), set when the
    /// account is initialized via the V2 path with a verified proof of
    /// possession (Alpenglow vote-account groundwork). `None` for accounts
    /// initialized without one.
    pub bls_pubkey: Option<[u8; 48]>,
}

impl VoteState {
    pub fn new(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
    ) -> Self {
        Self {
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
            votes: Vec::new(),
            root_slot: None,
            epoch_credits: Vec::new(),
            bls_pubkey: None,
        }
    }

    /// Process a single vote for a slot.
    ///
    /// Validates the vote is newer than the current state, pops expired
    /// lockouts, adds the new vote, increments confirmations, and promotes
    /// to root when tower reaches max height.
    pub fn process_vote(&mut self, slot: u64, _hash: [u8; 32]) -> Result<(), VoteError> {
        if let Some(root) = self.root_slot {
            if slot <= root {
                return Err(VoteError::VoteBelowRoot { slot, root });
            }
        }

        if let Some(last_vote) = self.votes.last() {
            if slot <= last_vote.slot() {
                return Err(VoteError::VoteNotSequential {
                    vote_slot: slot,
                    last_vote_slot: last_vote.slot(),
                });
            }
        }

        // Pop expired lockouts from the top of the tower
        while let Some(back) = self.votes.last() {
            if slot >= back.lockout.expiration_slot() {
                self.votes.pop();
            } else {
                break;
            }
        }

        // Increment confirmation counts for existing votes
        for vote in &mut self.votes {
            vote.lockout.increase_confirmation_count(1);
        }

        // Push the new vote
        self.votes.push(LandedVote::new(slot, 0));

        // Check if tower exceeds max height, promote oldest to root
        if self.votes.len() > MAX_LOCKOUT_HISTORY {
            let oldest = self.votes.remove(0);
            self.root_slot = Some(oldest.slot());
        }

        self.update_credits(slot);

        Ok(())
    }

    /// Apply a complete vote state update (tower sync / compact update).
    ///
    /// Validates the new state against the current state and replaces it.
    pub fn apply_vote_state_update(
        &mut self,
        new_votes: Vec<LandedVote>,
        new_root: Option<u64>,
        epoch: u64,
        current_slot: u64,
    ) -> Result<(), VoteError> {
        if new_votes.len() > MAX_LOCKOUT_HISTORY {
            return Err(VoteError::TooManyVotes);
        }

        if new_votes.is_empty() {
            return Err(VoteError::EmptySlots);
        }

        // Validate root doesn't roll back
        if let Some(current_root) = self.root_slot {
            match new_root {
                Some(proposed_root) if proposed_root < current_root => {
                    return Err(VoteError::RootRollBack);
                }
                None => {
                    return Err(VoteError::RootRollBack);
                }
                _ => {}
            }
        }

        // Validate ordering and confirmation counts
        let mut prev: Option<&LandedVote> = None;
        for vote in &new_votes {
            if vote.lockout.confirmation_count == 0 {
                return Err(VoteError::ZeroConfirmations);
            }
            if vote.lockout.confirmation_count > MAX_LOCKOUT_HISTORY as u32 {
                return Err(VoteError::ConfirmationTooLarge);
            }
            if let Some(nr) = new_root {
                if vote.slot() <= nr && nr != 0 {
                    return Err(VoteError::SlotSmallerThanRoot);
                }
            }
            if let Some(p) = prev {
                if p.slot() >= vote.slot() {
                    return Err(VoteError::SlotsNotOrdered);
                }
                if p.lockout.confirmation_count <= vote.lockout.confirmation_count {
                    return Err(VoteError::ConfirmationsNotOrdered);
                }
                if vote.slot() > p.lockout.last_locked_out_slot() {
                    return Err(VoteError::LockoutMismatch);
                }
            }
            prev = Some(vote);
        }

        // Calculate earned credits from newly rooted votes
        let earned_credits = if let Some(new_root) = new_root {
            let mut earned = 0u64;
            for vote in &self.votes {
                if vote.slot() <= new_root {
                    earned = earned.saturating_add(Self::credits_for_vote(vote));
                } else {
                    break;
                }
            }
            earned
        } else {
            0
        };

        // Verify lockout consistency with current state
        self.verify_lockout_consistency(&new_votes)?;

        // Build final state with proper latencies
        let mut final_votes = Vec::with_capacity(new_votes.len());
        for new_vote in &new_votes {
            let latency = if new_vote.latency > 0 {
                new_vote.latency
            } else {
                self.find_existing_latency(new_vote.slot())
                    .unwrap_or_else(|| {
                        current_slot
                            .saturating_sub(new_vote.slot())
                            .min(u8::MAX as u64) as u8
                    })
            };
            final_votes.push(LandedVote::with_lockout(new_vote.lockout, latency));
        }

        // Update credits if root changed
        let root_changed = match (self.root_slot, new_root) {
            (None, None) => false,
            (Some(old), Some(new)) => old != new,
            _ => true,
        };
        if root_changed && earned_credits > 0 {
            self.add_epoch_credits(epoch, earned_credits);
        }

        // Apply new state
        self.root_slot = new_root;
        self.votes = final_votes;

        Ok(())
    }

    fn credits_for_vote(vote: &LandedVote) -> u64 {
        let latency = vote.latency as u64;
        if latency <= VOTE_CREDITS_GRACE_SLOTS {
            VOTE_CREDITS_MAXIMUM_PER_SLOT
        } else {
            let excess = latency.saturating_sub(VOTE_CREDITS_GRACE_SLOTS);
            VOTE_CREDITS_MAXIMUM_PER_SLOT.saturating_sub(excess).max(1)
        }
    }

    fn verify_lockout_consistency(&self, new_votes: &[LandedVote]) -> Result<(), VoteError> {
        let mut current_idx = 0;
        let mut new_idx = 0;

        while current_idx < self.votes.len() && new_idx < new_votes.len() {
            let current = &self.votes[current_idx];
            let new_vote = &new_votes[new_idx];

            if current.slot() < new_vote.slot() {
                // Current vote is being expired - check lockout
                let conf = current
                    .lockout
                    .confirmation_count
                    .min(MAX_LOCKOUT_HISTORY as u32);
                let last_locked = current.lockout.slot.saturating_add(
                    (INITIAL_LOCKOUT as u64)
                        .checked_pow(conf)
                        .unwrap_or(u64::MAX),
                );
                if last_locked >= new_vote.slot() {
                    return Err(VoteError::LockoutConflict);
                }
                current_idx += 1;
            } else if current.slot() == new_vote.slot() {
                if new_vote.lockout.confirmation_count < current.lockout.confirmation_count {
                    return Err(VoteError::ConfirmationRollBack);
                }
                current_idx += 1;
                new_idx += 1;
            } else {
                new_idx += 1;
            }
        }

        Ok(())
    }

    fn find_existing_latency(&self, slot: u64) -> Option<u8> {
        self.votes
            .iter()
            .find(|v| v.slot() == slot)
            .map(|v| v.latency)
    }

    fn add_epoch_credits(&mut self, epoch: u64, credits: u64) {
        let prev = self.epoch_credits.last().map(|(_, c, _)| *c).unwrap_or(0);
        let total = prev.saturating_add(credits);

        if let Some(last) = self.epoch_credits.last_mut() {
            if last.0 == epoch {
                last.1 = last.1.saturating_add(credits);
                return;
            }
        }

        self.epoch_credits.push((epoch, total, prev));
        while self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
            self.epoch_credits.remove(0);
        }
    }

    /// Process a slot advancement (used for slot processing without a vote instruction).
    pub fn process_slot(&mut self, slot: u64) {
        for vote in &mut self.votes {
            if vote.slot() < slot {
                vote.lockout.increase_confirmation_count(1);
            }
        }

        if let Some(oldest) = self.votes.first() {
            if oldest.lockout.confirmation_count >= MAX_LOCKOUT_HISTORY as u32 {
                let oldest_slot = oldest.slot();
                self.root_slot = Some(oldest_slot);
                self.votes.remove(0);
            }
        }
    }

    pub fn last_voted_slot(&self) -> Option<u64> {
        self.votes.last().map(|v| v.slot())
    }

    pub fn is_locked_out(&self, slot: u64) -> bool {
        self.votes
            .iter()
            .any(|v| v.lockout.is_locked_out_at_slot(slot))
    }

    pub fn tower_height(&self) -> usize {
        self.votes.len()
    }

    pub fn has_voted_for(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.slot() == slot)
    }

    fn update_credits(&mut self, slot: u64) {
        let credits_earned = 1_u64;

        if let Some((last_slot, last_credits, _)) = self.epoch_credits.last_mut() {
            if slot > *last_slot {
                let new_credits = last_credits.saturating_add(credits_earned);
                self.epoch_credits.push((slot, new_credits, credits_earned));
            }
        } else {
            self.epoch_credits
                .push((slot, credits_earned, credits_earned));
        }
    }

    /// Serialize the vote state to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(self.node_pubkey.as_bytes());
        data.extend_from_slice(self.authorized_voter.as_bytes());
        data.extend_from_slice(self.authorized_withdrawer.as_bytes());
        data.push(self.commission);

        data.extend_from_slice(&(self.votes.len() as u32).to_le_bytes());
        for vote in &self.votes {
            data.extend_from_slice(&vote.lockout.slot.to_le_bytes());
            data.extend_from_slice(&vote.lockout.confirmation_count.to_le_bytes());
        }

        if let Some(root) = self.root_slot {
            data.push(1);
            data.extend_from_slice(&root.to_le_bytes());
        } else {
            data.push(0);
        }

        // Epoch credits: count(4) + entries(24 each: epoch(8) + credits(8) + prev_credits(8))
        data.extend_from_slice(&(self.epoch_credits.len() as u32).to_le_bytes());
        for &(epoch, credits, prev_credits) in &self.epoch_credits {
            data.extend_from_slice(&epoch.to_le_bytes());
            data.extend_from_slice(&credits.to_le_bytes());
            data.extend_from_slice(&prev_credits.to_le_bytes());
        }

        // Optional BLS pubkey trailer: a presence byte followed by 48 bytes is
        // appended only when set, so accounts without one serialize identically
        // to the pre-BLS format (no trailing bytes).
        if let Some(bls_pubkey) = self.bls_pubkey {
            data.push(1);
            data.extend_from_slice(&bls_pubkey);
        }

        data
    }

    /// Deserialize vote state from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, VoteError> {
        if data.len() < 32 + 32 + 32 + 1 {
            return Err(VoteError::InvalidAccountData);
        }

        let mut offset = 0;

        let node_pubkey = Pubkey::new_from_array(
            data[offset..offset + 32]
                .try_into()
                .map_err(|_| VoteError::InvalidAccountData)?,
        );
        offset += 32;

        let authorized_voter = Pubkey::new_from_array(
            data[offset..offset + 32]
                .try_into()
                .map_err(|_| VoteError::InvalidAccountData)?,
        );
        offset += 32;

        let authorized_withdrawer = Pubkey::new_from_array(
            data[offset..offset + 32]
                .try_into()
                .map_err(|_| VoteError::InvalidAccountData)?,
        );
        offset += 32;

        let commission = data[offset];
        offset += 1;

        if data.len() < offset + 4 {
            return Err(VoteError::InvalidAccountData);
        }

        let vote_count = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| VoteError::InvalidAccountData)?,
        ) as usize;
        offset += 4;

        let mut votes = Vec::with_capacity(vote_count.min(MAX_LOCKOUT_HISTORY));
        for _ in 0..vote_count {
            if data.len() < offset + 8 + 4 {
                return Err(VoteError::InvalidAccountData);
            }

            let slot = u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?,
            );
            offset += 8;

            let confirmation_count = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?,
            );
            offset += 4;

            votes.push(LandedVote {
                latency: 0,
                lockout: Lockout {
                    slot,
                    confirmation_count,
                },
            });
        }

        let root_slot = if data.len() > offset && data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(VoteError::InvalidAccountData);
            }
            let slot = u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?,
            );
            offset += 8;
            Some(slot)
        } else {
            if data.len() > offset {
                offset += 1; // skip the 0 byte
            }
            None
        };

        // Epoch credits: count(4) + entries(24 each: epoch(8) + credits(8) + prev_credits(8))
        let mut epoch_credits = Vec::new();
        if offset + 4 <= data.len() {
            let ec_count = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?,
            ) as usize;
            offset += 4;

            for _ in 0..ec_count.min(MAX_EPOCH_CREDITS_HISTORY) {
                if data.len() < offset + 24 {
                    break;
                }
                let epoch = u64::from_le_bytes(
                    data[offset..offset + 8]
                        .try_into()
                        .map_err(|_| VoteError::InvalidAccountData)?,
                );
                offset += 8;
                let credits = u64::from_le_bytes(
                    data[offset..offset + 8]
                        .try_into()
                        .map_err(|_| VoteError::InvalidAccountData)?,
                );
                offset += 8;
                let prev_credits = u64::from_le_bytes(
                    data[offset..offset + 8]
                        .try_into()
                        .map_err(|_| VoteError::InvalidAccountData)?,
                );
                offset += 8;
                epoch_credits.push((epoch, credits, prev_credits));
            }
        }

        // Optional BLS pubkey trailer: present only when a presence byte plus a
        // full 48-byte key remain. Absent trailers (pre-BLS accounts) decode to
        // `None`.
        let bls_pubkey =
            if offset < data.len() && data[offset] == 1 && data.len() >= offset + 1 + 48 {
                let key: [u8; 48] = data[offset + 1..offset + 1 + 48]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?;
                Some(key)
            } else {
                None
            };

        Ok(Self {
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
            votes,
            root_slot,
            epoch_credits,
            bls_pubkey,
        })
    }
}

/// Errors that can occur during vote state processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteError {
    InvalidAccountData,
    VoteBelowRoot { slot: u64, root: u64 },
    VoteNotSequential { vote_slot: u64, last_vote_slot: u64 },
    Unauthorized,
    InsufficientFunds,
    TooManyVotes,
    EmptySlots,
    RootRollBack,
    ZeroConfirmations,
    ConfirmationTooLarge,
    SlotSmallerThanRoot,
    SlotsNotOrdered,
    ConfirmationsNotOrdered,
    LockoutMismatch,
    LockoutConflict,
    ConfirmationRollBack,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_computes_expiration_correctly() {
        let lockout = Lockout::new(100);
        assert_eq!(lockout.expiration_slot(), 102);

        let mut lockout = Lockout::new(100);
        lockout.increase_confirmation_count(1);
        assert_eq!(lockout.confirmation_count, 2);
        assert_eq!(lockout.expiration_slot(), 104);

        lockout.increase_confirmation_count(1);
        assert_eq!(lockout.confirmation_count, 3);
        assert_eq!(lockout.expiration_slot(), 108);
    }

    #[test]
    fn lockout_detects_locked_out_slots() {
        let lockout = Lockout::new(100);
        assert!(lockout.is_locked_out_at_slot(100));
        assert!(lockout.is_locked_out_at_slot(101));
        assert!(!lockout.is_locked_out_at_slot(102));
        assert!(!lockout.is_locked_out_at_slot(103));
    }

    #[test]
    fn lockout_with_confirmation_count() {
        let lockout = Lockout::with_confirmation_count(50, 5);
        assert_eq!(lockout.slot, 50);
        assert_eq!(lockout.confirmation_count, 5);
        // 2^5 = 32
        assert_eq!(lockout.expiration_slot(), 82);
    }

    #[test]
    fn vote_state_initializes_correctly() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let state = VoteState::new(node, voter, withdrawer, 5);

        assert_eq!(state.node_pubkey, node);
        assert_eq!(state.authorized_voter, voter);
        assert_eq!(state.authorized_withdrawer, withdrawer);
        assert_eq!(state.commission, 5);
        assert_eq!(state.votes.len(), 0);
        assert_eq!(state.root_slot, None);
    }

    #[test]
    fn vote_state_processes_votes_sequentially() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        // Use consecutive slots so lockouts don't expire between votes
        assert!(state.process_vote(10, hash).is_ok());
        assert!(state.process_vote(11, hash).is_ok());
        assert!(state.process_vote(12, hash).is_ok());

        assert_eq!(state.votes.len(), 3);
        assert_eq!(state.last_voted_slot(), Some(12));
    }

    #[test]
    fn vote_state_rejects_non_sequential_votes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        state.process_vote(20, hash).unwrap();

        assert!(matches!(
            state.process_vote(10, hash),
            Err(VoteError::VoteNotSequential { .. })
        ));
        assert!(matches!(
            state.process_vote(20, hash),
            Err(VoteError::VoteNotSequential { .. })
        ));
    }

    #[test]
    fn vote_state_increases_confirmation_counts() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        // Use consecutive slots so lockouts don't expire between votes
        state.process_vote(10, hash).unwrap();
        assert_eq!(state.votes[0].lockout.confirmation_count, 1);

        state.process_vote(11, hash).unwrap();
        assert_eq!(state.votes[0].lockout.confirmation_count, 2);
        assert_eq!(state.votes[1].lockout.confirmation_count, 1);

        state.process_vote(12, hash).unwrap();
        assert_eq!(state.votes[0].lockout.confirmation_count, 3);
        assert_eq!(state.votes[1].lockout.confirmation_count, 2);
        assert_eq!(state.votes[2].lockout.confirmation_count, 1);
    }

    #[test]
    fn vote_state_promotes_root_at_max_lockout() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        // Use consecutive slots so lockouts accumulate without expiring
        for i in 0..MAX_LOCKOUT_HISTORY {
            state.process_vote(100 + i as u64, hash).unwrap();
        }

        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);
        assert_eq!(state.root_slot, None);

        state
            .process_vote(100 + MAX_LOCKOUT_HISTORY as u64, hash)
            .unwrap();

        assert!(state.root_slot.is_some());
        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);
    }

    #[test]
    fn vote_state_pops_expired_lockouts() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        // Vote on slot 10 (lockout: 2^1=2, expires at 12)
        state.process_vote(10, hash).unwrap();
        // Vote on slot 11 (confirmation for 10 bumps to 2, lockout 2^2=4, expires 14)
        state.process_vote(11, hash).unwrap();

        // Vote on slot 100 - both should be expired and popped
        state.process_vote(100, hash).unwrap();

        // Only the latest vote should remain (expired ones were popped)
        // Vote 10 with conf 3 => 2^3=8, exp=18 < 100 => popped
        // Vote 11 with conf 2 => 2^2=4, exp=15 < 100 => popped
        assert_eq!(state.votes.len(), 1);
        assert_eq!(state.votes[0].slot(), 100);
    }

    #[test]
    fn vote_state_serializes_and_deserializes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 10);

        let hash = [0u8; 32];
        state.process_vote(100, hash).unwrap();
        state.process_vote(200, hash).unwrap();

        let data = state.serialize();
        let deserialized = VoteState::deserialize(&data).unwrap();

        assert_eq!(state.node_pubkey, deserialized.node_pubkey);
        assert_eq!(state.authorized_voter, deserialized.authorized_voter);
        assert_eq!(state.commission, deserialized.commission);
        assert_eq!(state.votes.len(), deserialized.votes.len());
        for (a, b) in state.votes.iter().zip(deserialized.votes.iter()) {
            assert_eq!(a.lockout.slot, b.lockout.slot);
            assert_eq!(a.lockout.confirmation_count, b.lockout.confirmation_count);
        }
    }

    #[test]
    fn vote_state_without_bls_serializes_identically() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 10);
        state.process_vote(100, [0u8; 32]).unwrap();

        // bls_pubkey defaults to None, so the trailer must not change the bytes.
        let bytes = state.serialize();
        assert_eq!(state.bls_pubkey, None);
        let roundtrip = VoteState::deserialize(&bytes).unwrap();
        assert_eq!(roundtrip.bls_pubkey, None);
        assert_eq!(roundtrip.serialize(), bytes);
    }

    #[test]
    fn vote_state_roundtrips_with_bls_pubkey() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 4);
        state.process_vote(50, [0u8; 32]).unwrap();
        let mut bls = [0u8; 48];
        for (i, b) in bls.iter_mut().enumerate() {
            *b = i as u8;
        }
        state.bls_pubkey = Some(bls);

        let bytes = state.serialize();
        // The trailer adds exactly the presence byte + 48 key bytes.
        let mut no_bls = state.clone();
        no_bls.bls_pubkey = None;
        assert_eq!(bytes.len(), no_bls.serialize().len() + 1 + 48);

        let roundtrip = VoteState::deserialize(&bytes).unwrap();
        assert_eq!(roundtrip.bls_pubkey, Some(bls));
        assert_eq!(roundtrip.node_pubkey, node);
        assert_eq!(roundtrip.commission, 4);
    }

    #[test]
    fn vote_state_rejects_vote_below_root() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);
        state.root_slot = Some(100);

        let hash = [0u8; 32];
        assert!(matches!(
            state.process_vote(50, hash),
            Err(VoteError::VoteBelowRoot { .. })
        ));
    }

    #[test]
    fn apply_vote_state_update_rejects_root_rollback() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);
        state.root_slot = Some(100);

        let new_votes = vec![LandedVote::with_lockout(
            Lockout::with_confirmation_count(150, 1),
            1,
        )];

        let result = state.apply_vote_state_update(new_votes, Some(50), 0, 150);
        assert_eq!(result, Err(VoteError::RootRollBack));
    }

    #[test]
    fn apply_vote_state_update_rejects_unordered_slots() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let new_votes = vec![
            LandedVote::with_lockout(Lockout::with_confirmation_count(200, 2), 1),
            LandedVote::with_lockout(Lockout::with_confirmation_count(100, 1), 1),
        ];

        let result = state.apply_vote_state_update(new_votes, None, 0, 200);
        assert_eq!(result, Err(VoteError::SlotsNotOrdered));
    }

    #[test]
    fn apply_vote_state_update_succeeds_with_valid_state() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let new_votes = vec![
            LandedVote::with_lockout(Lockout::with_confirmation_count(100, 3), 1),
            LandedVote::with_lockout(Lockout::with_confirmation_count(101, 2), 1),
            LandedVote::with_lockout(Lockout::with_confirmation_count(102, 1), 1),
        ];

        let result = state.apply_vote_state_update(new_votes, Some(50), 0, 102);
        assert!(result.is_ok());
        assert_eq!(state.root_slot, Some(50));
        assert_eq!(state.votes.len(), 3);
    }

    #[test]
    fn tower_height_tracks_votes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        assert_eq!(state.tower_height(), 0);
        let hash = [0u8; 32];
        state.process_vote(10, hash).unwrap();
        assert_eq!(state.tower_height(), 1);
    }

    #[test]
    fn has_voted_for_checks_slot() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        state.process_vote(42, hash).unwrap();

        assert!(state.has_voted_for(42));
        assert!(!state.has_voted_for(43));
    }
}
