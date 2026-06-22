//! Byte-exact bincode wire codec for on-chain vote-account `data`.
//!
//! This is the canonical Solana vote-account layout (matching the reference
//! `fd_vote_codec.c` / agave `VoteStateVersions`), as opposed to the simplified
//! self-consistent format used by [`VoteState::serialize`]. Producing these
//! exact bytes is required for mainnet compatibility: cross-validator vote
//! decoding, bank-hash account-data hashing, and client-side (e.g. solders)
//! decoding of `getAccountInfo` results all depend on the precise layout.
//!
//! All integers are little-endian; vectors and maps are length-prefixed with a
//! `u64` (bincode default fixint encoding). The leading `u32` discriminant
//! selects the variant:
//!
//! - `0` uninitialized
//! - `1` `V1_14_11`  — votes are `Lockout` (no latency), has `prior_voters`
//! - `2` `V3`        — votes are `LandedVote` (with latency), has `prior_voters`
//! - `3` `V4`        — no `commission`/`prior_voters`; adds split-commission
//!   collectors, basis-point commissions, pending delegator rewards, and an
//!   optional BLS proof-of-possession public key
//!
//! V4 is the Alpenglow vote-account format gated behind `vote_state_v4`.

use crate::vote_state::{
    AuthorizedVoters, BlockTimestamp, EpochCredits, LandedVote, PriorVoters, VoteError,
    VoteLockout, VoteState, DEFAULT_BLOCK_REVENUE_COMMISSION_BPS, VOTE_STATE_V3_SIZE,
};
use karstflow_constants::consensus::{MAX_EPOCH_CREDITS_HISTORY, MAX_LOCKOUT_HISTORY};
use karstflow_constants::vote_program::{MAX_AUTHORIZED_VOTERS, MAX_PRIOR_VOTERS};
use karstflow_storage::Pubkey;

/// Discriminant for an uninitialized vote account.
pub const VOTE_DISCRIMINANT_UNINITIALIZED: u32 = 0;
/// Discriminant for the `V1_14_11` vote-account layout.
pub const VOTE_DISCRIMINANT_V1_14_11: u32 = 1;
/// Discriminant for the `V3` (Current) vote-account layout.
pub const VOTE_DISCRIMINANT_V3: u32 = 2;
/// Discriminant for the `V4` (Alpenglow) vote-account layout.
pub const VOTE_DISCRIMINANT_V4: u32 = 3;

/// Per-entry wire sizes (bytes).
const PRIOR_VOTER_SZ: usize = 48; // 32 pubkey + u64 + u64

/// On-wire vote-account layout version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteStateVersion {
    /// `Lockout` votes, no latency; carries `prior_voters`.
    V1_14_11,
    /// `LandedVote` votes (with latency); carries `prior_voters`.
    V3,
    /// Alpenglow: split-commission collectors + optional BLS pubkey.
    V4,
}

impl VoteStateVersion {
    /// The `u32` discriminant written as the first wire field.
    pub fn discriminant(self) -> u32 {
        match self {
            VoteStateVersion::V1_14_11 => VOTE_DISCRIMINANT_V1_14_11,
            VoteStateVersion::V3 => VOTE_DISCRIMINANT_V3,
            VoteStateVersion::V4 => VOTE_DISCRIMINANT_V4,
        }
    }
}

impl VoteState {
    /// Serialize to byte-exact bincode for the given wire `version`.
    ///
    /// The returned bytes are the populated prefix; see [`Self::to_account_data`]
    /// to obtain the fixed `3762`-byte account allocation.
    pub fn serialize_versioned(&self, version: VoteStateVersion) -> Vec<u8> {
        let mut out = Vec::with_capacity(VOTE_STATE_V3_SIZE);
        out.extend_from_slice(&version.discriminant().to_le_bytes());
        out.extend_from_slice(self.node_pubkey.as_bytes());
        out.extend_from_slice(self.authorized_withdrawer.as_bytes());

        match version {
            VoteStateVersion::V1_14_11 | VoteStateVersion::V3 => {
                out.push(self.commission);
                let with_latency = matches!(version, VoteStateVersion::V3);
                write_votes(&mut out, &self.votes, with_latency);
                write_option_u64(&mut out, self.root_slot);
                write_authorized_voters(&mut out, &self.authorized_voters);
                write_prior_voters(&mut out, &self.prior_voters);
                write_epoch_credits(&mut out, &self.epoch_credits);
                write_block_timestamp(&mut out, &self.last_timestamp);
            }
            VoteStateVersion::V4 => {
                out.extend_from_slice(self.inflation_rewards_collector.as_bytes());
                out.extend_from_slice(self.block_revenue_collector.as_bytes());
                out.extend_from_slice(&self.inflation_rewards_commission_bps.to_le_bytes());
                out.extend_from_slice(&self.block_revenue_commission_bps.to_le_bytes());
                out.extend_from_slice(&self.pending_delegator_rewards.to_le_bytes());
                match &self.bls_pubkey {
                    Some(k) => {
                        out.push(1);
                        out.extend_from_slice(&k[..]);
                    }
                    None => out.push(0),
                }
                write_votes(&mut out, &self.votes, true);
                write_option_u64(&mut out, self.root_slot);
                write_authorized_voters(&mut out, &self.authorized_voters);
                write_epoch_credits(&mut out, &self.epoch_credits);
                write_block_timestamp(&mut out, &self.last_timestamp);
            }
        }

        out
    }

    /// Serialize into a fixed `3762`-byte vote-account `data` allocation
    /// (bincode prefix, zero-padded to the canonical size).
    pub fn to_account_data(&self, version: VoteStateVersion) -> Result<Vec<u8>, VoteError> {
        let mut data = self.serialize_versioned(version);
        if data.len() > VOTE_STATE_V3_SIZE {
            return Err(VoteError::InvalidAccountData);
        }
        data.resize(VOTE_STATE_V3_SIZE, 0);
        Ok(data)
    }

    /// Decode a vote account from byte-exact bincode, auto-detecting the
    /// version from the leading `u32` discriminant.
    pub fn deserialize_versioned(data: &[u8]) -> Result<Self, VoteError> {
        let mut r = Reader::new(data);
        let disc = r.u32()?;
        match disc {
            VOTE_DISCRIMINANT_V1_14_11 => decode_v1_v3(&mut r, false),
            VOTE_DISCRIMINANT_V3 => decode_v1_v3(&mut r, true),
            VOTE_DISCRIMINANT_V4 => decode_v4(&mut r),
            _ => Err(VoteError::InvalidAccountData),
        }
    }
}

fn write_votes(
    out: &mut Vec<u8>,
    votes: &std::collections::VecDeque<LandedVote>,
    with_latency: bool,
) {
    out.extend_from_slice(&(votes.len() as u64).to_le_bytes());
    for v in votes {
        if with_latency {
            out.push(v.latency);
        }
        out.extend_from_slice(&v.lockout.slot.to_le_bytes());
        out.extend_from_slice(&v.lockout.confirmation_count.to_le_bytes());
    }
}

fn write_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn write_authorized_voters(out: &mut Vec<u8>, voters: &AuthorizedVoters) {
    let map = voters.inner();
    out.extend_from_slice(&(map.len() as u64).to_le_bytes());
    // BTreeMap iterates in ascending key order, matching bincode's BTreeMap encoding.
    for (epoch, pubkey) in map {
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(pubkey.as_bytes());
    }
}

fn write_prior_voters(out: &mut Vec<u8>, prior: &PriorVoters) {
    let entries = prior.entries();
    for i in 0..MAX_PRIOR_VOTERS {
        match entries.get(i) {
            Some((pubkey, start, end)) => {
                out.extend_from_slice(pubkey.as_bytes());
                out.extend_from_slice(&start.to_le_bytes());
                out.extend_from_slice(&end.to_le_bytes());
            }
            None => out.extend_from_slice(&[0u8; PRIOR_VOTER_SZ]),
        }
    }
    out.extend_from_slice(&(prior.write_index() as u64).to_le_bytes());
    out.push(entries.is_empty() as u8);
}

fn write_epoch_credits(out: &mut Vec<u8>, credits: &std::collections::VecDeque<EpochCredits>) {
    out.extend_from_slice(&(credits.len() as u64).to_le_bytes());
    for ec in credits {
        out.extend_from_slice(&ec.epoch.to_le_bytes());
        out.extend_from_slice(&ec.credits.to_le_bytes());
        out.extend_from_slice(&ec.prev_credits.to_le_bytes());
    }
}

fn write_block_timestamp(out: &mut Vec<u8>, ts: &BlockTimestamp) {
    out.extend_from_slice(&ts.slot.to_le_bytes());
    out.extend_from_slice(&ts.timestamp.to_le_bytes());
}

fn decode_v1_v3(r: &mut Reader, with_latency: bool) -> Result<VoteState, VoteError> {
    let node_pubkey = r.pubkey()?;
    let authorized_withdrawer = r.pubkey()?;
    let commission = r.u8()?;
    let votes = read_votes(r, with_latency)?;
    let root_slot = r.opt_u64()?;
    let authorized_voters = read_authorized_voters(r)?;
    let prior_voters = read_prior_voters(r)?;
    let epoch_credits = read_epoch_credits(r)?;
    let last_timestamp = read_block_timestamp(r)?;

    Ok(VoteState {
        node_pubkey,
        authorized_withdrawer,
        commission,
        votes,
        root_slot,
        authorized_voters,
        prior_voters,
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

fn decode_v4(r: &mut Reader) -> Result<VoteState, VoteError> {
    let node_pubkey = r.pubkey()?;
    let authorized_withdrawer = r.pubkey()?;
    let inflation_rewards_collector = r.pubkey()?;
    let block_revenue_collector = r.pubkey()?;
    let inflation_rewards_commission_bps = r.u16()?;
    let block_revenue_commission_bps = r.u16()?;
    let pending_delegator_rewards = r.u64()?;
    let bls_pubkey = read_option_bls(r)?;
    let votes = read_votes(r, true)?;
    let root_slot = r.opt_u64()?;
    let authorized_voters = read_authorized_voters(r)?;
    let epoch_credits = read_epoch_credits(r)?;
    let last_timestamp = read_block_timestamp(r)?;

    // Mirror new_v4: derive the legacy u8 percentage, saturating so an
    // out-of-range bps value cannot wrap on truncation.
    let commission = (inflation_rewards_commission_bps / 100).min(u8::MAX as u16) as u8;

    Ok(VoteState {
        node_pubkey,
        authorized_withdrawer,
        commission,
        votes,
        root_slot,
        authorized_voters,
        prior_voters: PriorVoters::new(),
        epoch_credits,
        last_timestamp,
        inflation_rewards_commission_bps,
        inflation_rewards_collector,
        block_revenue_collector,
        block_revenue_commission_bps,
        pending_delegator_rewards,
        bls_pubkey,
    })
}

fn read_votes(
    r: &mut Reader,
    with_latency: bool,
) -> Result<std::collections::VecDeque<LandedVote>, VoteError> {
    let len = r.u64()? as usize;
    if len > MAX_LOCKOUT_HISTORY {
        return Err(VoteError::InvalidAccountData);
    }
    let mut votes = std::collections::VecDeque::with_capacity(len);
    for _ in 0..len {
        let latency = if with_latency { r.u8()? } else { 0 };
        let slot = r.u64()?;
        let confirmation_count = r.u32()?;
        votes.push_back(LandedVote {
            latency,
            lockout: VoteLockout {
                slot,
                confirmation_count,
            },
        });
    }
    Ok(votes)
}

fn read_authorized_voters(r: &mut Reader) -> Result<AuthorizedVoters, VoteError> {
    let len = r.u64()? as usize;
    if len > MAX_AUTHORIZED_VOTERS {
        return Err(VoteError::InvalidAccountData);
    }
    let mut entries = Vec::with_capacity(len);
    for _ in 0..len {
        let epoch = r.u64()?;
        let pubkey = r.pubkey()?;
        entries.push((epoch, pubkey));
    }
    Ok(AuthorizedVoters::from_entries(entries))
}

fn read_prior_voters(r: &mut Reader) -> Result<PriorVoters, VoteError> {
    let mut slots: Vec<(Pubkey, u64, u64)> = Vec::with_capacity(MAX_PRIOR_VOTERS);
    for _ in 0..MAX_PRIOR_VOTERS {
        let pubkey = r.pubkey()?;
        let start = r.u64()?;
        let end = r.u64()?;
        slots.push((pubkey, start, end));
    }
    let index = r.u64()? as usize;
    let is_empty = r.u8()? != 0;

    if is_empty {
        return Ok(PriorVoters::new());
    }
    // A populated buffer either wrapped (all 32 slots used) or is filled
    // contiguously from slot 0 up to `index`. A zeroed pubkey marks an unused
    // slot (a real voter pubkey is never all-zero).
    let all_used = slots.iter().all(|(pk, _, _)| *pk != Pubkey::default());
    let (entries, is_full) = if all_used {
        (slots, true)
    } else {
        let used = index.min(MAX_PRIOR_VOTERS);
        let mut e: Vec<(Pubkey, u64, u64)> = slots;
        e.truncate(used);
        (e, false)
    };
    Ok(PriorVoters::from_wire(entries, index, is_full))
}

fn read_epoch_credits(
    r: &mut Reader,
) -> Result<std::collections::VecDeque<EpochCredits>, VoteError> {
    let len = r.u64()? as usize;
    if len > MAX_EPOCH_CREDITS_HISTORY {
        return Err(VoteError::InvalidAccountData);
    }
    let mut credits = std::collections::VecDeque::with_capacity(len);
    for _ in 0..len {
        let epoch = r.u64()?;
        let c = r.u64()?;
        let prev = r.u64()?;
        credits.push_back(EpochCredits::new(epoch, c, prev));
    }
    Ok(credits)
}

fn read_block_timestamp(r: &mut Reader) -> Result<BlockTimestamp, VoteError> {
    let slot = r.u64()?;
    let timestamp = r.i64()?;
    Ok(BlockTimestamp::new(slot, timestamp))
}

fn read_option_bls(r: &mut Reader) -> Result<Option<[u8; 48]>, VoteError> {
    match r.u8()? {
        0 => Ok(None),
        1 => {
            let bytes = r.take(48)?;
            let mut arr = [0u8; 48];
            arr.copy_from_slice(bytes);
            Ok(Some(arr))
        }
        _ => Err(VoteError::InvalidAccountData),
    }
}

/// Bounds-checked little-endian byte reader.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VoteError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(VoteError::InvalidAccountData)?;
        if end > self.data.len() {
            return Err(VoteError::InvalidAccountData);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, VoteError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, VoteError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, VoteError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, VoteError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, VoteError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn pubkey(&mut self) -> Result<Pubkey, VoteError> {
        Ok(Pubkey::new_from_array(self.take(32)?.try_into().unwrap()))
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, VoteError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(VoteError::InvalidAccountData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v3() -> VoteState {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut vs = VoteState::new(node, voter, withdrawer, 7);
        vs.process_vote(100, 1_000, 2).unwrap();
        vs.process_vote(101, 1_010, 1).unwrap();
        vs.set_root(50);
        vs.add_epoch_credits(0, 100);
        vs.add_epoch_credits(1, 150);
        vs
    }

    #[test]
    fn v3_round_trips() {
        let vs = sample_v3();
        let bytes = vs.serialize_versioned(VoteStateVersion::V3);
        let back = VoteState::deserialize_versioned(&bytes).unwrap();
        assert_eq!(vs, back);
    }

    #[test]
    fn v1_14_11_round_trips() {
        let vs = sample_v3();
        let bytes = vs.serialize_versioned(VoteStateVersion::V1_14_11);
        let back = VoteState::deserialize_versioned(&bytes).unwrap();
        // V1_14_11 drops vote latency; compare everything else field-by-field.
        assert_eq!(back.node_pubkey, vs.node_pubkey);
        assert_eq!(back.authorized_withdrawer, vs.authorized_withdrawer);
        assert_eq!(back.commission, vs.commission);
        assert_eq!(back.root_slot, vs.root_slot);
        assert_eq!(back.votes.len(), vs.votes.len());
        for (b, v) in back.votes.iter().zip(vs.votes.iter()) {
            assert_eq!(b.lockout, v.lockout);
            assert_eq!(b.latency, 0);
        }
        assert_eq!(back.epoch_credits, vs.epoch_credits);
        assert_eq!(back.last_timestamp, vs.last_timestamp);
    }

    #[test]
    fn v4_round_trips_with_and_without_bls() {
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();
        let mut vs = VoteState::new_v4(
            node,
            voter,
            withdrawer,
            8_000,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            5_000,
            3,
        );
        vs.process_vote(200, 2_000, 1).unwrap();
        vs.add_epoch_credits(3, 42);

        // No BLS pubkey.
        let bytes = vs.serialize_versioned(VoteStateVersion::V4);
        let back = VoteState::deserialize_versioned(&bytes).unwrap();
        assert_eq!(vs, back);

        // With BLS pubkey.
        vs.bls_pubkey = Some([0xABu8; 48]);
        let bytes = vs.serialize_versioned(VoteStateVersion::V4);
        let back = VoteState::deserialize_versioned(&bytes).unwrap();
        assert_eq!(vs, back);
        assert_eq!(back.bls_pubkey, Some([0xABu8; 48]));
    }

    #[test]
    fn fixed_offsets_match_reference_layout() {
        let vs = sample_v3();

        // V3 / V1_14_11 fixed prefix: disc@0, node@4, withdrawer@36, commission@68, votes@69.
        let v3 = vs.serialize_versioned(VoteStateVersion::V3);
        assert_eq!(&v3[0..4], &VOTE_DISCRIMINANT_V3.to_le_bytes());
        assert_eq!(&v3[4..36], vs.node_pubkey.as_bytes());
        assert_eq!(&v3[36..68], vs.authorized_withdrawer.as_bytes());
        assert_eq!(v3[68], vs.commission);
        // votes vector length (u64) begins at offset 69.
        assert_eq!(
            u64::from_le_bytes(v3[69..77].try_into().unwrap()),
            vs.votes.len() as u64
        );

        // V4 fixed prefix: disc@0, node@4, withdrawer@36, inflation_collector@68,
        // revenue_collector@100, commission_bps@132, revenue_bps@134,
        // pending@136, bls option tag@144.
        let v4 = vs.serialize_versioned(VoteStateVersion::V4);
        assert_eq!(&v4[0..4], &VOTE_DISCRIMINANT_V4.to_le_bytes());
        assert_eq!(&v4[4..36], vs.node_pubkey.as_bytes());
        assert_eq!(&v4[36..68], vs.authorized_withdrawer.as_bytes());
        assert_eq!(&v4[68..100], vs.inflation_rewards_collector.as_bytes());
        assert_eq!(&v4[100..132], vs.block_revenue_collector.as_bytes());
        assert_eq!(
            u16::from_le_bytes(v4[132..134].try_into().unwrap()),
            vs.inflation_rewards_commission_bps
        );
        assert_eq!(
            u16::from_le_bytes(v4[134..136].try_into().unwrap()),
            vs.block_revenue_commission_bps
        );
        assert_eq!(
            u64::from_le_bytes(v4[136..144].try_into().unwrap()),
            vs.pending_delegator_rewards
        );
        assert_eq!(v4[144], 0); // bls option tag = None
    }

    #[test]
    fn to_account_data_pads_to_canonical_size() {
        let vs = sample_v3();
        let data = vs.to_account_data(VoteStateVersion::V3).unwrap();
        assert_eq!(data.len(), VOTE_STATE_V3_SIZE);
        // The populated prefix still decodes after padding.
        let back = VoteState::deserialize_versioned(&data).unwrap();
        assert_eq!(back.node_pubkey, vs.node_pubkey);
    }

    #[test]
    fn unknown_discriminant_is_rejected() {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 9; // invalid discriminant
        assert!(matches!(
            VoteState::deserialize_versioned(&bytes),
            Err(VoteError::InvalidAccountData)
        ));
    }

    #[test]
    fn truncated_input_is_rejected_not_panicking() {
        let vs = sample_v3();
        let bytes = vs.serialize_versioned(VoteStateVersion::V3);
        for cut in [4usize, 36, 69, 80] {
            assert!(VoteState::deserialize_versioned(&bytes[..cut]).is_err());
        }
    }
}
