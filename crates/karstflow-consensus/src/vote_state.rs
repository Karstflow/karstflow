/// Vote state tracking for validator vote accounts.
///
/// Vote accounts store a validator's voting history, including:
/// - Slots voted on with lockout periods
/// - Epoch credits earned for voting
/// - Authorized voters and withdrawers (with per-epoch rotation)
/// - Commission rate for delegator rewards
/// - Prior voters circular buffer for tracking authority changes
use karstflow_constants::consensus::{
    INITIAL_LOCKOUT, MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY,
};
use karstflow_constants::vote_program::{
    MAX_AUTHORIZED_VOTERS, MAX_PRIOR_VOTERS, VOTE_CREDITS_GRACE_SLOTS,
    VOTE_CREDITS_MAXIMUM_PER_SLOT,
};
use karstflow_storage::Pubkey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, VecDeque};

fn serialize_bls_key<S: Serializer>(key: &Option<[u8; 48]>, s: S) -> Result<S::Ok, S::Error> {
    match key {
        Some(k) => s.serialize_some(&k[..]),
        None => s.serialize_none(),
    }
}

fn deserialize_bls_key<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 48]>, D::Error> {
    let opt: Option<Vec<u8>> = Option::deserialize(d)?;
    match opt {
        Some(v) if v.len() == 48 => {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&v);
            Ok(Some(arr))
        }
        Some(_) => Err(serde::de::Error::custom("BLS key must be 48 bytes")),
        None => Ok(None),
    }
}

/// A vote for a specific slot with confirmation count for lockout calculation.
///
/// Each vote has an associated lockout period that doubles with each
/// subsequent confirmation. The confirmation_count tracks how many votes
/// have been made since this one, determining the lockout duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn with_confirmation_count(slot: u64, confirmation_count: u32) -> Self {
        Self {
            slot,
            confirmation_count,
        }
    }

    /// Calculate the lockout expiration slot.
    ///
    /// Lockout = INITIAL_LOCKOUT^confirmation_count slots.
    /// For INITIAL_LOCKOUT=2 this is 2^confirmation_count.
    pub fn expiration_slot(&self) -> u64 {
        self.slot.saturating_add(self.lockout_distance())
    }

    /// Calculate lockout distance: INITIAL_LOCKOUT^confirmation_count
    pub fn lockout_distance(&self) -> u64 {
        (INITIAL_LOCKOUT as u64)
            .checked_pow(self.confirmation_count)
            .unwrap_or(u64::MAX)
    }

    /// The last slot at which this vote is still locked out (inclusive).
    pub fn last_locked_out_slot(&self) -> u64 {
        self.expiration_slot()
    }

    /// Check if this vote has expired (lockout period passed) at a given slot.
    pub fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expiration_slot()
    }

    /// Check if this vote is still locked at the given slot.
    pub fn is_locked_out_at_slot(&self, slot: u64) -> bool {
        self.expiration_slot() > slot
    }

    /// Increment confirmation count (called when a new vote is added).
    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by);
    }
}

/// Vote with latency tracking.
///
/// Tracks when the vote was submitted relative to when the slot was produced.
/// The latency is used to compute timely vote credits: votes submitted faster
/// earn more credits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn with_lockout(lockout: VoteLockout, latency: u8) -> Self {
        Self { latency, lockout }
    }

    /// Get the slot this vote is for.
    pub fn slot(&self) -> u64 {
        self.lockout.slot
    }
}

/// Credits earned in a specific epoch.
///
/// Tracks voting participation and rewards for an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCredits {
    /// Epoch number
    pub epoch: u64,
    /// Cumulative credits including this epoch
    pub credits: u64,
    /// Cumulative credits from the previous epoch
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Per-epoch authorized voter tracking with rotation support.
///
/// Maintains a mapping from epoch to the authorized voter for that epoch,
/// allowing vote authority to be changed effective at the next epoch boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedVoters {
    /// Map from epoch to the authorized voter pubkey for that epoch.
    authorized_voters: BTreeMap<u64, Pubkey>,
}

impl AuthorizedVoters {
    pub fn new(epoch: u64, voter: Pubkey) -> Self {
        let mut voters = BTreeMap::new();
        voters.insert(epoch, voter);
        Self {
            authorized_voters: voters,
        }
    }

    /// Get the authorized voter for a specific epoch.
    ///
    /// Uses the latest authorized voter whose epoch is <= the requested epoch.
    pub fn get_authorized_voter(&self, epoch: u64) -> Option<&Pubkey> {
        self.authorized_voters
            .range(..=epoch)
            .next_back()
            .map(|(_, voter)| voter)
    }

    /// Get the authorized voter for a specific epoch, updating state to purge
    /// entries that have been superseded.
    pub fn get_and_update_authorized_voter(&mut self, epoch: u64) -> Option<Pubkey> {
        let voter = self.get_authorized_voter(epoch).copied()?;

        // Remove entries for epochs older than the current one, except
        // keep the latest entry that's <= current epoch
        self.purge_authorized_voters(epoch);

        Some(voter)
    }

    /// Set a new authorized voter for a target epoch.
    ///
    /// Returns the previous voter for the current epoch if one exists.
    pub fn set_authorized_voter(
        &mut self,
        new_voter: Pubkey,
        current_epoch: u64,
        target_epoch: u64,
    ) -> Result<Pubkey, VoteError> {
        // Check that target_epoch > current_epoch
        if target_epoch <= current_epoch {
            return Err(VoteError::TooSoonToReauthorize);
        }

        // If there's already an entry for the target_epoch, reject unless it's from a
        // reauthorization in the same epoch
        if let Some(existing) = self.authorized_voters.get(&target_epoch) {
            if *existing != new_voter {
                return Err(VoteError::TooSoonToReauthorize);
            }
        }

        // Get the current authorized voter
        let current_voter = self
            .get_authorized_voter(current_epoch)
            .copied()
            .ok_or(VoteError::UnauthorizedVoter)?;

        // Insert the new voter for the target epoch
        self.authorized_voters.insert(target_epoch, new_voter);

        // Trim to maximum authorized voters
        while self.authorized_voters.len() > MAX_AUTHORIZED_VOTERS {
            // Remove the oldest entry
            if let Some((&oldest_epoch, _)) = self.authorized_voters.iter().next() {
                self.authorized_voters.remove(&oldest_epoch);
            }
        }

        Ok(current_voter)
    }

    /// Remove expired voter entries that are older than the given epoch,
    /// keeping the latest entry <= epoch.
    fn purge_authorized_voters(&mut self, epoch: u64) {
        // Keep only the latest voter that's <= epoch and any future voters
        let entries_to_keep: Vec<(u64, Pubkey)> = {
            let latest_effective = self
                .authorized_voters
                .range(..=epoch)
                .next_back()
                .map(|(&e, &v)| (e, v));
            let future: Vec<(u64, Pubkey)> = self
                .authorized_voters
                .range((epoch + 1)..)
                .map(|(&e, &v)| (e, v))
                .collect();

            let mut result = future;
            if let Some(latest) = latest_effective {
                result.push(latest);
            }
            result
        };

        self.authorized_voters.clear();
        for (e, v) in entries_to_keep {
            self.authorized_voters.insert(e, v);
        }
    }

    /// Number of authorized voter entries.
    pub fn len(&self) -> usize {
        self.authorized_voters.len()
    }

    /// Whether there are no authorized voter entries.
    pub fn is_empty(&self) -> bool {
        self.authorized_voters.is_empty()
    }

    /// Check if there is a voter entry exactly at the given epoch.
    pub fn contains_epoch(&self, epoch: u64) -> bool {
        self.authorized_voters.contains_key(&epoch)
    }

    /// Get a reference to the underlying map.
    pub fn inner(&self) -> &BTreeMap<u64, Pubkey> {
        &self.authorized_voters
    }
}

/// Circular buffer tracking prior authorized voters.
///
/// When a vote authority changes, the prior authority is recorded here so
/// that stake delegators can see who previously controlled the vote account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriorVoters {
    /// Circular buffer of prior voter entries: (pubkey, start_epoch, end_epoch)
    entries: Vec<(Pubkey, u64, u64)>,
    /// Index of the next write position in the circular buffer.
    index: usize,
    /// Whether the buffer has wrapped around.
    is_full: bool,
}

impl PriorVoters {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_PRIOR_VOTERS),
            index: 0,
            is_full: false,
        }
    }

    /// Record a prior voter authority.
    pub fn record(&mut self, voter: Pubkey, start_epoch: u64, end_epoch: u64) {
        let entry = (voter, start_epoch, end_epoch);

        if self.entries.len() < MAX_PRIOR_VOTERS {
            self.entries.push(entry);
            self.index = self.entries.len() % MAX_PRIOR_VOTERS;
        } else {
            self.entries[self.index] = entry;
            self.index = (self.index + 1) % MAX_PRIOR_VOTERS;
            self.is_full = true;
        }
    }

    /// Number of recorded prior voter entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no prior voter entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all prior voter entries.
    pub fn entries(&self) -> &[(Pubkey, u64, u64)] {
        &self.entries
    }
}

impl Default for PriorVoters {
    fn default() -> Self {
        Self::new()
    }
}

/// Vote state serialization size for V3 format.
pub const VOTE_STATE_V3_SIZE: usize = 3762;

/// Vote state serialization size for V4 format (same as V3).
pub const VOTE_STATE_V4_SIZE: usize = 3762;

/// Default block revenue commission in basis points (100% = 10000 bps).
pub const DEFAULT_BLOCK_REVENUE_COMMISSION_BPS: u16 = 10_000;

/// Core vote account state.
///
/// Stores validator voting history, credits, and authorization info.
/// This combines fields from VoteState versions 2, 3, and 4 to support
/// full serialization round-tripping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteState {
    /// Validator node identity pubkey
    pub node_pubkey: Pubkey,
    /// Authorized withdrawer (can withdraw stake)
    pub authorized_withdrawer: Pubkey,
    /// Commission rate (0-100) taken from delegator rewards (V3 legacy)
    pub commission: u8,
    /// Recent vote history with lockouts and latencies
    pub votes: VecDeque<LandedVote>,
    /// Root slot (finalized, cannot be rolled back)
    pub root_slot: Option<u64>,
    /// Per-epoch authorized voters with rotation support
    pub authorized_voters: AuthorizedVoters,
    /// Prior voters circular buffer (tracks authority changes)
    pub prior_voters: PriorVoters,
    /// Credits earned per epoch
    pub epoch_credits: VecDeque<EpochCredits>,
    /// Last block timestamp
    pub last_timestamp: BlockTimestamp,
    // ----- V4 fields -----
    /// Inflation rewards commission in basis points (V4).
    /// Derived from `commission * 100` during V3→V4 migration.
    pub inflation_rewards_commission_bps: u16,
    /// Account collecting inflation rewards (V4).
    /// Defaults to the vote account pubkey during migration.
    pub inflation_rewards_collector: Pubkey,
    /// Account collecting block revenue (V4).
    /// Defaults to the node identity during migration.
    pub block_revenue_collector: Pubkey,
    /// Block revenue commission in basis points (V4).
    /// Defaults to 10000 (100%) during migration.
    pub block_revenue_commission_bps: u16,
    /// Pending delegator rewards accumulator (V4).
    pub pending_delegator_rewards: u64,
    /// BLS proof-of-possession compressed public key (V4, optional).
    #[serde(
        serialize_with = "serialize_bls_key",
        deserialize_with = "deserialize_bls_key"
    )]
    pub bls_pubkey: Option<[u8; 48]>,
}

impl VoteState {
    /// Create a new vote state for a validator (V3-compatible defaults).
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
            authorized_voters: AuthorizedVoters::new(0, authorized_voter),
            prior_voters: PriorVoters::new(),
            epoch_credits: VecDeque::with_capacity(MAX_EPOCH_CREDITS_HISTORY),
            last_timestamp: BlockTimestamp::new(0, 0),
            inflation_rewards_commission_bps: (commission as u16) * 100,
            inflation_rewards_collector: Pubkey::default(),
            block_revenue_collector: node_pubkey,
            block_revenue_commission_bps: DEFAULT_BLOCK_REVENUE_COMMISSION_BPS,
            pending_delegator_rewards: 0,
            bls_pubkey: None,
        }
    }

    /// Create a new vote state for a specific epoch (V3-compatible defaults).
    pub fn new_for_epoch(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        epoch: u64,
    ) -> Self {
        Self {
            node_pubkey,
            authorized_withdrawer,
            commission,
            votes: VecDeque::with_capacity(MAX_LOCKOUT_HISTORY),
            root_slot: None,
            authorized_voters: AuthorizedVoters::new(epoch, authorized_voter),
            prior_voters: PriorVoters::new(),
            epoch_credits: VecDeque::with_capacity(MAX_EPOCH_CREDITS_HISTORY),
            last_timestamp: BlockTimestamp::new(0, 0),
            inflation_rewards_commission_bps: (commission as u16) * 100,
            inflation_rewards_collector: Pubkey::default(),
            block_revenue_collector: node_pubkey,
            block_revenue_commission_bps: DEFAULT_BLOCK_REVENUE_COMMISSION_BPS,
            pending_delegator_rewards: 0,
            bls_pubkey: None,
        }
    }

    /// Create a V4 vote state with explicit V4 fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v4(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        inflation_rewards_commission_bps: u16,
        inflation_rewards_collector: Pubkey,
        block_revenue_collector: Pubkey,
        block_revenue_commission_bps: u16,
        epoch: u64,
    ) -> Self {
        Self {
            node_pubkey,
            authorized_withdrawer,
            commission: (inflation_rewards_commission_bps / 100) as u8,
            votes: VecDeque::with_capacity(MAX_LOCKOUT_HISTORY),
            root_slot: None,
            authorized_voters: AuthorizedVoters::new(epoch, authorized_voter),
            prior_voters: PriorVoters::new(),
            epoch_credits: VecDeque::with_capacity(MAX_EPOCH_CREDITS_HISTORY),
            last_timestamp: BlockTimestamp::new(0, 0),
            inflation_rewards_commission_bps,
            inflation_rewards_collector,
            block_revenue_collector,
            block_revenue_commission_bps,
            pending_delegator_rewards: 0,
            bls_pubkey: None,
        }
    }

    /// Convert a V3-format vote state to V4 in-place.
    ///
    /// Maps legacy fields to the new V4 split commission model:
    /// - `commission * 100` → `inflation_rewards_commission_bps`
    /// - vote account pubkey → `inflation_rewards_collector`
    /// - `node_pubkey` → `block_revenue_collector`
    /// - 10000 bps (100%) → `block_revenue_commission_bps`
    pub fn convert_v3_to_v4(&mut self, vote_account_pubkey: &Pubkey) {
        self.inflation_rewards_commission_bps = (self.commission as u16) * 100;
        self.inflation_rewards_collector = *vote_account_pubkey;
        self.block_revenue_collector = self.node_pubkey;
        self.block_revenue_commission_bps = DEFAULT_BLOCK_REVENUE_COMMISSION_BPS;
        self.pending_delegator_rewards = 0;
        self.bls_pubkey = None;
    }

    /// Check if this vote state has a BLS proof-of-possession key set.
    pub fn has_bls_pubkey(&self) -> bool {
        self.bls_pubkey.is_some()
    }

    /// Get the currently authorized voter for an epoch.
    pub fn get_authorized_voter(&self, epoch: u64) -> Option<&Pubkey> {
        self.authorized_voters.get_authorized_voter(epoch)
    }

    /// Set a new authorized voter for a target epoch.
    ///
    /// The new voter becomes effective at the target epoch. Records the
    /// previous voter in the prior voters buffer.
    pub fn set_new_authorized_voter(
        &mut self,
        new_voter: Pubkey,
        current_epoch: u64,
        target_epoch: u64,
    ) -> Result<(), VoteError> {
        let prior_voter =
            self.authorized_voters
                .set_authorized_voter(new_voter, current_epoch, target_epoch)?;

        // Record the prior voter
        self.prior_voters
            .record(prior_voter, current_epoch, target_epoch);

        Ok(())
    }

    /// Process a new vote for a slot using the tower vote processing logic.
    ///
    /// This is the core vote processing that handles lockout popping.
    /// When a new vote is added:
    /// 1. Pop expired votes from the back of the tower
    /// 2. Add the new vote
    /// 3. Increment confirmation counts for remaining votes
    /// 4. If tower reaches max height, promote oldest to root
    pub fn process_next_vote_slot(&mut self, slot: u64, epoch: u64, current_slot: u64) {
        // Pop expired lockouts from the top of the tower.
        // A vote is popped when the new vote slot >= its expiration slot.
        while let Some(back) = self.votes.back() {
            if slot >= back.lockout.expiration_slot() {
                self.votes.pop_back();
            } else {
                break;
            }
        }

        // Compute latency for this vote
        let latency = Self::compute_vote_latency(slot, current_slot);

        // Push the new vote
        let landed = LandedVote::new(slot, latency);
        self.votes.push_back(landed);

        // Increment confirmation counts for all existing votes
        // (the new vote confirms all previous votes)
        let count = self.votes.len();
        if count > 1 {
            for i in 0..count - 1 {
                self.votes[i].lockout.increase_confirmation_count(1);
            }
        }

        // If the tower has grown beyond max height, pop the oldest vote
        // and promote it to root.
        self.check_and_promote_root(epoch);
    }

    /// Pop the oldest vote and promote to root when tower is full.
    fn check_and_promote_root(&mut self, epoch: u64) {
        if self.votes.len() > MAX_LOCKOUT_HISTORY {
            if let Some(front) = self.votes.pop_front() {
                self.root_slot = Some(front.slot());
                // Award credits for the rooted vote
                self.increment_credits(epoch, 1);
            }
        }
    }

    /// Process a simplified vote (for backward compatibility).
    pub fn process_vote(
        &mut self,
        slot: u64,
        timestamp: i64,
        latency: u8,
    ) -> Result<(), VoteError> {
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

        // Increment confirmation counts for all votes except the new one
        let count = self.votes.len();
        for i in 0..count.saturating_sub(1) {
            self.votes[i].lockout.increase_confirmation_count(1);
        }

        // Check if we should promote oldest to root
        while self.votes.len() > MAX_LOCKOUT_HISTORY {
            if let Some(front) = self.votes.pop_front() {
                self.root_slot = Some(front.slot());
            }
        }

        Ok(())
    }

    /// Apply a complete vote state update (tower sync).
    ///
    /// Validates the new state against the current state and applies it.
    /// This is used for CompactUpdateVoteState and TowerSync instructions.
    pub fn apply_vote_state_update(
        &mut self,
        new_votes: &[LandedVote],
        new_root: Option<u64>,
        has_timestamp: bool,
        timestamp: i64,
        epoch: u64,
        current_slot: u64,
    ) -> Result<(), VoteError> {
        // Validate new vote state is not too large
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

        // Validate the new vote state ordering and confirmations
        let mut prev: Option<&LandedVote> = None;
        for vote in new_votes {
            if vote.lockout.confirmation_count == 0 {
                return Err(VoteError::ZeroConfirmations);
            }
            if vote.lockout.confirmation_count > MAX_LOCKOUT_HISTORY as u32 {
                return Err(VoteError::ConfirmationTooLarge);
            }
            if let Some(nr) = new_root {
                if vote.lockout.slot <= nr && nr != 0 {
                    return Err(VoteError::SlotSmallerThanRoot);
                }
            }
            if let Some(p) = prev {
                if p.lockout.slot >= vote.lockout.slot {
                    return Err(VoteError::SlotsNotOrdered);
                }
                if p.lockout.confirmation_count <= vote.lockout.confirmation_count {
                    return Err(VoteError::ConfirmationsNotOrdered);
                }
                if vote.lockout.slot > p.lockout.last_locked_out_slot() {
                    return Err(VoteError::NewVoteStateLockoutMismatch);
                }
            }
            prev = Some(vote);
        }

        // Calculate credits earned from newly rooted votes
        let earned_credits = self.calculate_earned_credits(new_root);

        // Check for lockout conflicts between current and new state
        self.verify_lockout_consistency(new_votes)?;

        // Build the final vote state with proper latencies
        let mut final_votes: VecDeque<LandedVote> = VecDeque::with_capacity(new_votes.len());
        for new_vote in new_votes {
            let latency = if new_vote.latency > 0 {
                new_vote.latency
            } else {
                // For new slots, compute latency from current slot
                let existing_latency = self.find_existing_latency(new_vote.lockout.slot);
                existing_latency.unwrap_or_else(|| {
                    Self::compute_vote_latency(new_vote.lockout.slot, current_slot)
                })
            };
            final_votes.push_back(LandedVote::with_lockout(new_vote.lockout, latency));
        }

        // If root changed, increment credits
        let root_changed = match (self.root_slot, new_root) {
            (None, None) => false,
            (Some(old), Some(new)) => old != new,
            _ => true,
        };
        if root_changed && earned_credits > 0 {
            self.increment_credits(epoch, earned_credits);
        }

        // Apply the new state
        self.root_slot = new_root;
        self.votes = final_votes;

        // Process timestamp
        if has_timestamp {
            if let Some(last) = self.votes.back() {
                self.process_timestamp(last.slot(), timestamp)?;
            }
        }

        Ok(())
    }

    /// Calculate credits earned from votes being rooted.
    fn calculate_earned_credits(&self, new_root: Option<u64>) -> u64 {
        let Some(new_root) = new_root else {
            return 0;
        };

        let mut earned = 0u64;
        for (idx, vote) in self.votes.iter().enumerate() {
            if vote.lockout.slot <= new_root {
                earned = earned.saturating_add(Self::credits_for_vote_at_index(idx, vote));
            } else {
                break;
            }
        }
        earned
    }

    /// Calculate credits for a vote at a given index, using timely vote credits.
    fn credits_for_vote_at_index(_index: usize, vote: &LandedVote) -> u64 {
        let latency = vote.latency as u64;
        // With timely_vote_credits: credits decrease as latency increases
        // max_credits if latency <= grace_slots, then decreasing
        if latency <= VOTE_CREDITS_GRACE_SLOTS {
            VOTE_CREDITS_MAXIMUM_PER_SLOT
        } else {
            let excess = latency.saturating_sub(VOTE_CREDITS_GRACE_SLOTS);
            VOTE_CREDITS_MAXIMUM_PER_SLOT.saturating_sub(excess).max(1)
        }
    }

    /// Verify that expired votes in current state don't conflict with new state.
    fn verify_lockout_consistency(&self, new_votes: &[LandedVote]) -> Result<(), VoteError> {
        let mut current_idx = 0;
        let mut new_idx = 0;

        while current_idx < self.votes.len() && new_idx < new_votes.len() {
            let current = &self.votes[current_idx];
            let new_vote = &new_votes[new_idx];

            if current.lockout.slot < new_vote.lockout.slot {
                // The current vote is being expired - check lockout
                let confirmation_count = current
                    .lockout
                    .confirmation_count
                    .min(MAX_LOCKOUT_HISTORY as u32);
                let last_locked = current.lockout.slot.saturating_add(
                    (INITIAL_LOCKOUT as u64)
                        .checked_pow(confirmation_count)
                        .unwrap_or(u64::MAX),
                );
                if last_locked >= new_vote.lockout.slot {
                    return Err(VoteError::LockoutConflict);
                }
                current_idx += 1;
            } else if current.lockout.slot == new_vote.lockout.slot {
                // Same slot - check confirmation count doesn't decrease
                if new_vote.lockout.confirmation_count < current.lockout.confirmation_count {
                    return Err(VoteError::ConfirmationRollBack);
                }
                current_idx += 1;
                new_idx += 1;
            } else {
                // New vote has smaller slot than current - it's a new addition
                new_idx += 1;
            }
        }

        Ok(())
    }

    /// Find the existing latency for a slot in the current vote history.
    fn find_existing_latency(&self, slot: u64) -> Option<u8> {
        self.votes
            .iter()
            .find(|v| v.lockout.slot == slot)
            .map(|v| v.latency)
    }

    /// Compute vote latency (difference between current slot and vote slot).
    fn compute_vote_latency(vote_slot: u64, current_slot: u64) -> u8 {
        current_slot.saturating_sub(vote_slot).min(u8::MAX as u64) as u8
    }

    /// Process a timestamp update.
    fn process_timestamp(&mut self, slot: u64, timestamp: i64) -> Result<(), VoteError> {
        if slot < self.last_timestamp.slot || timestamp < self.last_timestamp.timestamp {
            // Timestamp must not go backward (both slot and time must advance)
            if slot > self.last_timestamp.slot {
                // Slot advanced but timestamp didn't - that's OK in some cases
                self.last_timestamp = BlockTimestamp::new(slot, timestamp);
            }
            return Ok(());
        }
        self.last_timestamp = BlockTimestamp::new(slot, timestamp);
        Ok(())
    }

    /// Increment epoch credits by the given amount.
    pub fn increment_credits(&mut self, epoch: u64, credits: u64) {
        if credits == 0 {
            return;
        }

        // Get the current cumulative credit count
        let current_credits = self.epoch_credits.back().map(|ec| ec.credits).unwrap_or(0);

        // Check if we're adding to the same epoch or a new one
        if let Some(last) = self.epoch_credits.back_mut() {
            if last.epoch == epoch {
                last.credits = last.credits.saturating_add(credits);
                return;
            }
        }

        // New epoch
        let new_credits = current_credits.saturating_add(credits);
        self.epoch_credits
            .push_back(EpochCredits::new(epoch, new_credits, current_credits));

        // Trim to max history
        while self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
            self.epoch_credits.pop_front();
        }
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

    /// Add credits for an epoch (simple interface for backward compatibility).
    pub fn add_epoch_credits(&mut self, epoch: u64, credits: u64) {
        let prev_credits = self.epoch_credits.back().map(|ec| ec.credits).unwrap_or(0);
        let total_credits = prev_credits + credits;
        let epoch_credit = EpochCredits::new(epoch, total_credits, prev_credits);
        self.epoch_credits.push_back(epoch_credit);

        // Trim to max history
        while self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
            self.epoch_credits.pop_front();
        }
    }

    /// Check if a slot can be voted on without violating lockouts.
    pub fn can_vote_on_slot(&self, slot: u64) -> bool {
        // Cannot vote on slot older than root
        if let Some(root) = self.root_slot {
            if slot < root {
                return false;
            }
        }

        // Check if any lockouts prevent voting on this slot
        for vote in &self.votes {
            if !vote.lockout.is_expired(slot) && vote.slot() > slot {
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

    /// Get tower height (number of votes in the stack).
    pub fn tower_height(&self) -> usize {
        self.votes.len()
    }

    /// Check if the vote state contains a vote for the given slot.
    pub fn contains_slot(&self, slot: u64) -> bool {
        self.votes.iter().any(|v| v.lockout.slot == slot)
    }

    /// Serialize vote state to bytes.
    ///
    /// Uses a simplified format: node_pubkey(32) + authorized_voter(32) +
    /// authorized_withdrawer(32) + commission(1) + vote_count(4) +
    /// votes(12 each) + root_option(1) + root_slot(8 if present) +
    /// epoch_credits_count(4) + epoch_credits(24 each) +
    /// timestamp_slot(8) + timestamp(8)
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Node pubkey
        data.extend_from_slice(self.node_pubkey.as_bytes());

        // Authorized voter (use first/current authorized voter)
        let voter = self
            .authorized_voters
            .inner()
            .values()
            .last()
            .copied()
            .unwrap_or(Pubkey::zeroed());
        data.extend_from_slice(voter.as_bytes());

        // Authorized withdrawer
        data.extend_from_slice(self.authorized_withdrawer.as_bytes());

        // Commission
        data.push(self.commission);

        // Votes
        data.extend_from_slice(&(self.votes.len() as u32).to_le_bytes());
        for vote in &self.votes {
            data.extend_from_slice(&vote.lockout.slot.to_le_bytes());
            data.extend_from_slice(&vote.lockout.confirmation_count.to_le_bytes());
        }

        // Root slot
        if let Some(root) = self.root_slot {
            data.push(1);
            data.extend_from_slice(&root.to_le_bytes());
        } else {
            data.push(0);
        }

        // Epoch credits
        data.extend_from_slice(&(self.epoch_credits.len() as u32).to_le_bytes());
        for ec in &self.epoch_credits {
            data.extend_from_slice(&ec.epoch.to_le_bytes());
            data.extend_from_slice(&ec.credits.to_le_bytes());
            data.extend_from_slice(&ec.prev_credits.to_le_bytes());
        }

        // Last timestamp
        data.extend_from_slice(&self.last_timestamp.slot.to_le_bytes());
        data.extend_from_slice(&self.last_timestamp.timestamp.to_le_bytes());

        data
    }

    /// Deserialize vote state from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, VoteError> {
        let min_size = 32 + 32 + 32 + 1 + 4; // pubkeys + commission + vote_count
        if data.len() < min_size {
            return Err(VoteError::InvalidAccountData);
        }

        let mut offset = 0;

        let node_pubkey = Self::read_pubkey(data, &mut offset)?;
        let authorized_voter = Self::read_pubkey(data, &mut offset)?;
        let authorized_withdrawer = Self::read_pubkey(data, &mut offset)?;

        let commission = data[offset];
        offset += 1;

        let vote_count = Self::read_u32(data, &mut offset)? as usize;
        let mut votes = VecDeque::with_capacity(vote_count.min(MAX_LOCKOUT_HISTORY));
        for _ in 0..vote_count {
            let slot = Self::read_u64(data, &mut offset)?;
            let confirmation_count = Self::read_u32(data, &mut offset)?;
            votes.push_back(LandedVote {
                latency: 0,
                lockout: VoteLockout {
                    slot,
                    confirmation_count,
                },
            });
        }

        let root_slot = if offset < data.len() && data[offset] == 1 {
            offset += 1;
            Some(Self::read_u64(data, &mut offset)?)
        } else {
            if offset < data.len() {
                offset += 1; // skip the 0 byte
            }
            None
        };

        // Epoch credits (optional)
        let mut epoch_credits = VecDeque::new();
        if offset + 4 <= data.len() {
            let ec_count = Self::read_u32(data, &mut offset)? as usize;
            for _ in 0..ec_count {
                if offset + 24 > data.len() {
                    break;
                }
                let epoch = Self::read_u64(data, &mut offset)?;
                let credits = Self::read_u64(data, &mut offset)?;
                let prev_credits = Self::read_u64(data, &mut offset)?;
                epoch_credits.push_back(EpochCredits::new(epoch, credits, prev_credits));
            }
        }

        // Last timestamp (optional)
        let last_timestamp = if offset + 16 <= data.len() {
            let ts_slot = Self::read_u64(data, &mut offset)?;
            let ts = Self::read_i64(data, &mut offset)?;
            BlockTimestamp::new(ts_slot, ts)
        } else {
            BlockTimestamp::new(0, 0)
        };

        Ok(Self {
            node_pubkey,
            authorized_withdrawer,
            commission,
            votes,
            root_slot,
            authorized_voters: AuthorizedVoters::new(0, authorized_voter),
            prior_voters: PriorVoters::new(),
            epoch_credits,
            last_timestamp,
            inflation_rewards_commission_bps: (commission as u16) * 100,
            inflation_rewards_collector: Pubkey::default(),
            block_revenue_collector: node_pubkey,
            block_revenue_commission_bps: DEFAULT_BLOCK_REVENUE_COMMISSION_BPS,
            pending_delegator_rewards: 0,
            bls_pubkey: None,
        })
    }

    fn read_pubkey(data: &[u8], offset: &mut usize) -> Result<Pubkey, VoteError> {
        if *offset + 32 > data.len() {
            return Err(VoteError::InvalidAccountData);
        }
        let bytes: [u8; 32] = data[*offset..*offset + 32]
            .try_into()
            .map_err(|_| VoteError::InvalidAccountData)?;
        *offset += 32;
        Ok(Pubkey::new_from_array(bytes))
    }

    fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32, VoteError> {
        if *offset + 4 > data.len() {
            return Err(VoteError::InvalidAccountData);
        }
        let bytes: [u8; 4] = data[*offset..*offset + 4]
            .try_into()
            .map_err(|_| VoteError::InvalidAccountData)?;
        *offset += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, VoteError> {
        if *offset + 8 > data.len() {
            return Err(VoteError::InvalidAccountData);
        }
        let bytes: [u8; 8] = data[*offset..*offset + 8]
            .try_into()
            .map_err(|_| VoteError::InvalidAccountData)?;
        *offset += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i64(data: &[u8], offset: &mut usize) -> Result<i64, VoteError> {
        if *offset + 8 > data.len() {
            return Err(VoteError::InvalidAccountData);
        }
        let bytes: [u8; 8] = data[*offset..*offset + 8]
            .try_into()
            .map_err(|_| VoteError::InvalidAccountData)?;
        *offset += 8;
        Ok(i64::from_le_bytes(bytes))
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
    /// Vote is too old (below current root or slot hash history)
    VoteTooOld,
    /// Slots in vote don't match slot hashes
    SlotsMismatch,
    /// Hash for last slot doesn't match
    SlotsHashMismatch,
    /// Vote contains no slots
    EmptySlots,
    /// Timestamp is older than previous timestamp
    TimestampTooOld,
    /// Too soon to reauthorize (target epoch too close)
    TooSoonToReauthorize,
    /// Existing lockout would be violated by new vote state
    LockoutConflict,
    /// New vote state lockouts don't properly expire previous votes
    NewVoteStateLockoutMismatch,
    /// Slots in the proposed state are not ordered
    SlotsNotOrdered,
    /// Confirmations in proposed state are not in decreasing order
    ConfirmationsNotOrdered,
    /// A vote has zero confirmations
    ZeroConfirmations,
    /// Confirmation count exceeds MAX_LOCKOUT_HISTORY
    ConfirmationTooLarge,
    /// New root is smaller than current root
    RootRollBack,
    /// Confirmation count decreased for an existing vote
    ConfirmationRollBack,
    /// Vote slot is smaller than the proposed root
    SlotSmallerThanRoot,
    /// Too many votes in the proposed state
    TooManyVotes,
    /// All votes were filtered out as too old
    VotesTooOldAllFiltered,
    /// Proposed root is on a different fork
    RootOnDifferentFork,
    /// Cannot close a vote account with active epoch credits
    ActiveVoteAccountClose,
    /// Commission update too late in epoch
    CommissionUpdateTooLate,
    /// Invalid account data for deserialization
    InvalidAccountData,
    /// Insufficient funds for operation
    InsufficientFunds,
}

/// Maximum number of epoch credits to track.
pub const MAX_EPOCH_CREDITS: usize = karstflow_constants::consensus::MAX_EPOCH_CREDITS_HISTORY;

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
    fn vote_lockout_is_locked_out_at_slot() {
        let vote = VoteLockout::new(100);
        assert!(vote.is_locked_out_at_slot(100));
        assert!(vote.is_locked_out_at_slot(101));
        assert!(!vote.is_locked_out_at_slot(102));
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
        assert_eq!(*state.get_authorized_voter(0).unwrap(), voter);
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

        state.process_vote(100, 1000, 2).unwrap();
        assert_eq!(state.votes.len(), 1);
        assert_eq!(state.last_voted_slot(), Some(100));
        assert_eq!(state.last_timestamp.slot, 100);
        assert_eq!(state.last_timestamp.timestamp, 1000);

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

        let result = state.process_vote(100, 1001, 0);
        assert_eq!(result, Err(VoteError::SlotNotNewer));

        let result = state.process_vote(99, 1001, 0);
        assert_eq!(result, Err(VoteError::SlotNotNewer));
    }

    #[test]
    fn vote_state_sets_root() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.process_vote(100, 1000, 0).unwrap();
        state.process_vote(101, 1001, 0).unwrap();
        state.process_vote(102, 1002, 0).unwrap();

        state.set_root(101);

        assert_eq!(state.root_slot, Some(101));
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

        state.process_vote(100, 1000, 0).unwrap();

        assert!(state.can_vote_on_slot(101));
        assert!(state.can_vote_on_slot(200));

        assert!(!state.can_vote_on_slot(99));
        assert!(!state.can_vote_on_slot(50));

        state.process_vote(101, 1001, 0).unwrap();

        assert!(!state.can_vote_on_slot(100));
    }

    #[test]
    fn vote_state_trims_vote_history() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        for i in 0..(MAX_LOCKOUT_HISTORY + 10) {
            state.process_vote(i as u64, i as i64 * 1000, 0).unwrap();
        }

        assert_eq!(state.votes.len(), MAX_LOCKOUT_HISTORY);

        // Oldest votes should be removed, newest preserved
        assert_eq!(state.votes.front().unwrap().slot(), 10);
        assert_eq!(state.votes.back().unwrap().slot(), 40);
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
        assert_eq!(state.active_vote_count(103), 1);

        assert_eq!(state.active_vote_count(104), 0);
    }

    #[test]
    fn authorized_voters_tracks_per_epoch() {
        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        let mut av = AuthorizedVoters::new(0, voter1);

        assert_eq!(*av.get_authorized_voter(0).unwrap(), voter1);
        assert_eq!(*av.get_authorized_voter(5).unwrap(), voter1);

        // Set new voter for epoch 5
        let prior = av.set_authorized_voter(voter2, 3, 5).unwrap();
        assert_eq!(prior, voter1);

        // Before epoch 5, voter1 is still active
        assert_eq!(*av.get_authorized_voter(4).unwrap(), voter1);

        // At epoch 5 and after, voter2 is active
        assert_eq!(*av.get_authorized_voter(5).unwrap(), voter2);
        assert_eq!(*av.get_authorized_voter(10).unwrap(), voter2);
    }

    #[test]
    fn authorized_voters_rejects_past_target_epoch() {
        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        let mut av = AuthorizedVoters::new(0, voter1);

        let result = av.set_authorized_voter(voter2, 5, 3);
        assert!(result.is_err());
    }

    #[test]
    fn prior_voters_records_and_wraps() {
        let mut pv = PriorVoters::new();

        for i in 0..(MAX_PRIOR_VOTERS + 5) {
            pv.record(Pubkey::new_unique(), i as u64, (i + 1) as u64);
        }

        assert_eq!(pv.len(), MAX_PRIOR_VOTERS);
        assert!(pv.is_full);
    }

    #[test]
    fn process_next_vote_slot_pops_expired_lockouts() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Vote on slot 10 (lockout: 2^1=2, expires at 12)
        state.process_next_vote_slot(10, 0, 10);
        assert_eq!(state.votes.len(), 1);

        // Vote on slot 11 (slot 10 lockout: 2^2=4, expires at 14)
        state.process_next_vote_slot(11, 0, 11);
        assert_eq!(state.votes.len(), 2);

        // Vote on slot 100 - should pop slot 10 and 11 (both expired)
        state.process_next_vote_slot(100, 0, 100);
        // slot 10 had confirmation_count=3 after slot 11 vote, exp=10+8=18 < 100 -> popped
        // slot 11 had confirmation_count=2, exp=11+4=15 < 100 -> popped
        // Only slot 100 remains
        assert_eq!(state.votes.len(), 1);
        assert_eq!(state.votes[0].slot(), 100);
    }

    #[test]
    fn process_next_vote_slot_promotes_root_at_max_height() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 0);

        // Fill tower to max height + 1
        for i in 0..=(MAX_LOCKOUT_HISTORY as u64) {
            // Use slots spaced enough apart that none expire
            let slot = i;
            state.process_next_vote_slot(slot, 0, slot);
        }

        // After exceeding MAX_LOCKOUT_HISTORY, root should be set
        assert!(state.root_slot.is_some());
        assert!(state.votes.len() <= MAX_LOCKOUT_HISTORY);
    }

    #[test]
    fn apply_vote_state_update_validates_ordering() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Try unordered slots
        let new_votes = vec![
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(200, 2), 1),
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(100, 1), 1),
        ];

        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 200);
        assert_eq!(result, Err(VoteError::SlotsNotOrdered));
    }

    #[test]
    fn apply_vote_state_update_validates_confirmations_ordering() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Confirmations must decrease from oldest to newest
        let new_votes = vec![
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(100, 1), 1),
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(200, 2), 1),
        ];

        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 200);
        assert_eq!(result, Err(VoteError::ConfirmationsNotOrdered));
    }

    #[test]
    fn apply_vote_state_update_rejects_zero_confirmations() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        let new_votes = vec![LandedVote::with_lockout(
            VoteLockout::with_confirmation_count(100, 0),
            1,
        )];

        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 100);
        assert_eq!(result, Err(VoteError::ZeroConfirmations));
    }

    #[test]
    fn apply_vote_state_update_rejects_too_many_votes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        let new_votes: Vec<LandedVote> = (0..=(MAX_LOCKOUT_HISTORY as u64))
            .rev()
            .enumerate()
            .map(|(i, slot)| {
                LandedVote::with_lockout(
                    VoteLockout::with_confirmation_count(
                        slot * 10 + 100,
                        (MAX_LOCKOUT_HISTORY - i) as u32 + 1,
                    ),
                    1,
                )
            })
            .collect();

        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 500);
        assert_eq!(result, Err(VoteError::TooManyVotes));
    }

    #[test]
    fn apply_vote_state_update_rejects_root_rollback() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);
        state.root_slot = Some(100);

        let new_votes = vec![LandedVote::with_lockout(
            VoteLockout::with_confirmation_count(150, 1),
            1,
        )];

        // Try to set root to lower value
        let result = state.apply_vote_state_update(&new_votes, Some(50), false, 0, 0, 150);
        assert_eq!(result, Err(VoteError::RootRollBack));

        // Try to remove root entirely
        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 150);
        assert_eq!(result, Err(VoteError::RootRollBack));
    }

    #[test]
    fn apply_vote_state_update_succeeds_with_valid_state() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Create a valid new state with properly ordered confirmations
        let new_votes = vec![
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(100, 3), 1),
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(101, 2), 1),
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(102, 1), 1),
        ];

        let result = state.apply_vote_state_update(&new_votes, Some(50), true, 1000, 0, 102);
        assert!(result.is_ok());
        assert_eq!(state.root_slot, Some(50));
        assert_eq!(state.votes.len(), 3);
        assert_eq!(state.last_timestamp.timestamp, 1000);
    }

    #[test]
    fn vote_state_serializes_and_deserializes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 10);

        state.process_vote(100, 1000, 2).unwrap();
        state.process_vote(200, 2000, 1).unwrap();
        state.root_slot = Some(50);
        state.add_epoch_credits(0, 100);
        state.add_epoch_credits(1, 200);

        let data = state.serialize();
        let deserialized = VoteState::deserialize(&data).unwrap();

        assert_eq!(state.node_pubkey, deserialized.node_pubkey);
        assert_eq!(
            state.authorized_withdrawer,
            deserialized.authorized_withdrawer
        );
        assert_eq!(state.commission, deserialized.commission);
        assert_eq!(state.votes.len(), deserialized.votes.len());
        assert_eq!(state.root_slot, deserialized.root_slot);
        assert_eq!(state.epoch_credits.len(), deserialized.epoch_credits.len());
        assert_eq!(state.last_timestamp, deserialized.last_timestamp);
    }

    #[test]
    fn vote_state_deserialize_rejects_too_short() {
        let data = vec![0u8; 10];
        assert_eq!(
            VoteState::deserialize(&data),
            Err(VoteError::InvalidAccountData)
        );
    }

    #[test]
    fn increment_credits_handles_same_epoch() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.increment_credits(5, 10);
        state.increment_credits(5, 15);

        assert_eq!(state.epoch_credits.len(), 1);
        assert_eq!(state.epoch_credits[0].credits, 25);
    }

    #[test]
    fn increment_credits_handles_new_epoch() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.increment_credits(5, 10);
        state.increment_credits(6, 20);

        assert_eq!(state.epoch_credits.len(), 2);
        assert_eq!(state.epoch_credits[0].epoch, 5);
        assert_eq!(state.epoch_credits[0].credits, 10);
        assert_eq!(state.epoch_credits[1].epoch, 6);
        assert_eq!(state.epoch_credits[1].credits, 30); // cumulative
        assert_eq!(state.epoch_credits[1].prev_credits, 10);
    }

    #[test]
    fn increment_credits_skips_zero() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.increment_credits(5, 0);
        assert_eq!(state.epoch_credits.len(), 0);
    }

    #[test]
    fn vote_state_tower_height() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        assert_eq!(state.tower_height(), 0);
        state.process_vote(100, 1000, 0).unwrap();
        assert_eq!(state.tower_height(), 1);
        state.process_vote(101, 1001, 0).unwrap();
        assert_eq!(state.tower_height(), 2);
    }

    #[test]
    fn vote_state_contains_slot() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        state.process_vote(100, 1000, 0).unwrap();
        state.process_vote(200, 2000, 0).unwrap();

        assert!(state.contains_slot(100));
        assert!(state.contains_slot(200));
        assert!(!state.contains_slot(150));
    }

    #[test]
    fn authorized_voters_get_and_update_purges_old_entries() {
        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();

        let mut av = AuthorizedVoters::new(0, voter1);
        av.set_authorized_voter(voter2, 0, 5).unwrap();

        assert_eq!(av.len(), 2);

        // Retrieving at epoch 10 should purge the epoch-0 entry
        // but keep the latest effective entry
        let result = av.get_and_update_authorized_voter(10);
        assert_eq!(result, Some(voter2));
        // Should have purged old entries, keeping only the effective one
        assert!(av.len() <= 1);
    }

    #[test]
    fn vote_lockout_with_confirmation_count() {
        let lockout = VoteLockout::with_confirmation_count(100, 5);
        assert_eq!(lockout.slot, 100);
        assert_eq!(lockout.confirmation_count, 5);
        // 2^5 = 32
        assert_eq!(lockout.lockout_distance(), 32);
        assert_eq!(lockout.expiration_slot(), 132);
    }

    #[test]
    fn vote_state_new_for_epoch() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let state = VoteState::new_for_epoch(node, voter, withdrawer, 10, 42);

        assert_eq!(*state.get_authorized_voter(42).unwrap(), voter);
        assert!(state.get_authorized_voter(41).is_none());
    }

    #[test]
    fn apply_vote_state_update_rejects_lockout_mismatch() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // slot 100, conf 2 => lockout distance = 2^2 = 4, expires at 104
        // slot 200 > 104, so this would be fine
        // But if slot 200 > last_locked_out_slot of 100 (which is 104), then NewVoteStateLockoutMismatch
        // The check is: new_vote.slot > prev_vote.last_locked_out_slot()
        // 100 with conf=2: last_locked=100+4=104, slot 105 > 104 => mismatch
        let new_votes = vec![
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(100, 2), 1),
            LandedVote::with_lockout(VoteLockout::with_confirmation_count(105, 1), 1),
        ];

        let result = state.apply_vote_state_update(&new_votes, None, false, 0, 0, 200);
        assert_eq!(result, Err(VoteError::NewVoteStateLockoutMismatch));
    }

    #[test]
    fn apply_vote_state_update_slot_smaller_than_root() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        // Vote slot 50 is smaller than proposed root 100
        let new_votes = vec![LandedVote::with_lockout(
            VoteLockout::with_confirmation_count(50, 1),
            1,
        )];

        let result = state.apply_vote_state_update(&new_votes, Some(100), false, 0, 0, 200);
        assert_eq!(result, Err(VoteError::SlotSmallerThanRoot));
    }

    #[test]
    fn apply_vote_state_update_empty_votes() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        let result = state.apply_vote_state_update(&[], None, false, 0, 0, 200);
        assert_eq!(result, Err(VoteError::EmptySlots));
    }

    #[test]
    fn epoch_credits_trims_to_max() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter, withdrawer, 5);

        for i in 0..(MAX_EPOCH_CREDITS_HISTORY + 10) {
            state.add_epoch_credits(i as u64, 10);
        }

        assert_eq!(state.epoch_credits.len(), MAX_EPOCH_CREDITS_HISTORY);
    }

    #[test]
    fn set_new_authorized_voter_records_prior() {
        let node = Pubkey::new_unique();
        let voter1 = Pubkey::new_unique();
        let voter2 = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut state = VoteState::new(node, voter1, withdrawer, 5);

        state.set_new_authorized_voter(voter2, 0, 5).unwrap();

        assert_eq!(state.prior_voters.len(), 1);
        let (pv, start, end) = state.prior_voters.entries()[0];
        assert_eq!(pv, voter1);
        assert_eq!(start, 0);
        assert_eq!(end, 5);
    }

    #[test]
    fn vote_state_new_v4_constructor() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let infl_collector = Pubkey::new_unique();
        let block_collector = Pubkey::new_unique();

        let state = VoteState::new_v4(
            node,
            voter,
            withdrawer,
            500, // 5% in bps
            infl_collector,
            block_collector,
            8000,
            10,
        );

        assert_eq!(state.inflation_rewards_commission_bps, 500);
        assert_eq!(state.inflation_rewards_collector, infl_collector);
        assert_eq!(state.block_revenue_collector, block_collector);
        assert_eq!(state.block_revenue_commission_bps, 8000);
        assert_eq!(state.commission, 5); // 500/100
        assert_eq!(state.pending_delegator_rewards, 0);
        assert!(!state.has_bls_pubkey());
    }

    #[test]
    fn vote_state_convert_v3_to_v4() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let vote_account_pk = Pubkey::new_unique();

        let mut state = VoteState::new(node, voter, withdrawer, 7);
        state.convert_v3_to_v4(&vote_account_pk);

        assert_eq!(state.inflation_rewards_commission_bps, 700); // 7 * 100
        assert_eq!(state.inflation_rewards_collector, vote_account_pk);
        assert_eq!(state.block_revenue_collector, node);
        assert_eq!(
            state.block_revenue_commission_bps,
            DEFAULT_BLOCK_REVENUE_COMMISSION_BPS
        );
        assert_eq!(state.pending_delegator_rewards, 0);
        assert!(!state.has_bls_pubkey());
    }

    #[test]
    fn vote_state_bls_pubkey_serde_roundtrip() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        // Without BLS key
        let state = VoteState::new(node, voter, withdrawer, 5);
        let serialized = bincode::serialize(&state).unwrap();
        let deserialized: VoteState = bincode::deserialize(&serialized).unwrap();
        assert_eq!(state, deserialized);
        assert!(!deserialized.has_bls_pubkey());

        // With BLS key
        let mut state_with_bls = VoteState::new(node, voter, withdrawer, 5);
        let bls_key = [0xABu8; 48];
        state_with_bls.bls_pubkey = Some(bls_key);
        let serialized = bincode::serialize(&state_with_bls).unwrap();
        let deserialized: VoteState = bincode::deserialize(&serialized).unwrap();
        assert_eq!(state_with_bls, deserialized);
        assert!(deserialized.has_bls_pubkey());
        assert_eq!(deserialized.bls_pubkey.unwrap(), bls_key);
    }
}
