use paradencer_constants::consensus::{INITIAL_LOCKOUT, MAX_LOCKOUT_HISTORY};
use paradencer_types::Pubkey;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteState {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
    pub votes: Vec<Lockout>,
    pub root_slot: Option<u64>,
    pub credits: Vec<(u64, u64, u64)>,
    pub epoch_credits: Vec<(u64, u64, u64)>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockout {
    pub slot: u64,
    pub confirmation_count: u32,
}

#[allow(dead_code)]
impl Lockout {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            confirmation_count: 1,
        }
    }

    pub fn expiration_slot(&self) -> u64 {
        let lockout = INITIAL_LOCKOUT.saturating_pow(self.confirmation_count);
        self.slot.saturating_add(lockout as u64)
    }

    pub fn is_locked_out_at_slot(&self, slot: u64) -> bool {
        self.expiration_slot() > slot
    }

    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by);
    }
}

#[allow(dead_code)]
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
            credits: Vec::new(),
            epoch_credits: Vec::new(),
        }
    }

    pub fn process_vote(&mut self, slot: u64, _hash: [u8; 32]) -> Result<(), VoteError> {
        if let Some(root) = self.root_slot {
            if slot <= root {
                return Err(VoteError::VoteBelowRoot { slot, root });
            }
        }

        if let Some(last_vote) = self.votes.last() {
            if slot <= last_vote.slot {
                return Err(VoteError::VoteNotSequential {
                    vote_slot: slot,
                    last_vote_slot: last_vote.slot,
                });
            }
        }

        if self.votes.len() >= MAX_LOCKOUT_HISTORY {
            let oldest_vote = self.votes[0];
            if oldest_vote.confirmation_count >= MAX_LOCKOUT_HISTORY as u32 {
                self.root_slot = Some(oldest_vote.slot);
                self.votes.remove(0);
            }
        }

        for vote in &mut self.votes {
            vote.increase_confirmation_count(1);
        }

        self.votes.push(Lockout::new(slot));

        self.update_credits(slot);

        Ok(())
    }

    pub fn process_slot(&mut self, slot: u64) {
        for vote in &mut self.votes {
            if vote.slot < slot {
                vote.increase_confirmation_count(1);
            }
        }

        if let Some(oldest_vote) = self.votes.first() {
            if oldest_vote.confirmation_count >= MAX_LOCKOUT_HISTORY as u32 {
                self.root_slot = Some(oldest_vote.slot);
                self.votes.remove(0);
            }
        }
    }

    pub fn last_voted_slot(&self) -> Option<u64> {
        self.votes.last().map(|v| v.slot)
    }

    pub fn is_locked_out(&self, slot: u64) -> bool {
        for vote in &self.votes {
            if vote.is_locked_out_at_slot(slot) {
                return true;
            }
        }
        false
    }

    pub fn tower_height(&self) -> usize {
        self.votes.len()
    }

    pub fn has_voted_for(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.slot == slot)
    }

    fn update_credits(&mut self, slot: u64) {
        let credits_earned = 1_u64;

        if let Some((last_slot, last_credits, _)) = self.credits.last_mut() {
            if slot > *last_slot {
                let new_credits = last_credits.saturating_add(credits_earned);
                self.credits.push((slot, new_credits, credits_earned));
            }
        } else {
            self.credits.push((slot, credits_earned, credits_earned));
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(self.node_pubkey.as_bytes());
        data.extend_from_slice(self.authorized_voter.as_bytes());
        data.extend_from_slice(self.authorized_withdrawer.as_bytes());
        data.push(self.commission);

        data.extend_from_slice(&(self.votes.len() as u32).to_le_bytes());
        for vote in &self.votes {
            data.extend_from_slice(&vote.slot.to_le_bytes());
            data.extend_from_slice(&vote.confirmation_count.to_le_bytes());
        }

        if let Some(root) = self.root_slot {
            data.push(1);
            data.extend_from_slice(&root.to_le_bytes());
        } else {
            data.push(0);
        }

        data
    }

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

        let mut votes = Vec::new();
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

            votes.push(Lockout {
                slot,
                confirmation_count,
            });
        }

        let root_slot = if data.len() > offset && data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(VoteError::InvalidAccountData);
            }
            Some(u64::from_le_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| VoteError::InvalidAccountData)?,
            ))
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
            credits: Vec::new(),
            epoch_credits: Vec::new(),
        })
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteError {
    InvalidAccountData,
    VoteBelowRoot { slot: u64, root: u64 },
    VoteNotSequential { vote_slot: u64, last_vote_slot: u64 },
    Unauthorized,
    InsufficientFunds,
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
        assert!(state.process_vote(10, hash).is_ok());
        assert!(state.process_vote(20, hash).is_ok());
        assert!(state.process_vote(30, hash).is_ok());

        assert_eq!(state.votes.len(), 3);
        assert_eq!(state.last_voted_slot(), Some(30));
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
        state.process_vote(10, hash).unwrap();
        assert_eq!(state.votes[0].confirmation_count, 1);

        state.process_vote(20, hash).unwrap();
        assert_eq!(state.votes[0].confirmation_count, 2);
        assert_eq!(state.votes[1].confirmation_count, 1);

        state.process_vote(30, hash).unwrap();
        assert_eq!(state.votes[0].confirmation_count, 3);
        assert_eq!(state.votes[1].confirmation_count, 2);
        assert_eq!(state.votes[2].confirmation_count, 1);
    }

    #[test]
    fn vote_state_promotes_root_at_max_lockout() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        let hash = [0u8; 32];
        for i in 0..MAX_LOCKOUT_HISTORY {
            state.process_vote(i as u64 * 10, hash).unwrap();
        }

        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);
        assert_eq!(state.root_slot, None);

        state
            .process_vote((MAX_LOCKOUT_HISTORY * 10) as u64, hash)
            .unwrap();

        assert!(state.root_slot.is_some());
        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);
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
        assert_eq!(state.votes, deserialized.votes);
    }
}
