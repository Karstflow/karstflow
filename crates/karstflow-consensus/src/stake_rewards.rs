/// Fork-aware partitioned stake rewards for epoch boundary distribution.
///
/// Stores pending stake rewards (pubkey, lamports, credits_observed) in a
/// shared index across forks. Each fork maintains its own partition layout
/// using singly-linked lists per partition, where entries are hashed into
/// partitions via SipHash-1-3 of (parent_blockhash || pubkey).
///
/// This structure supports multiple concurrent epoch boundary calculations
/// across forks while deduplicating identical reward entries.
use karstflow_types::Pubkey;
use std::collections::HashMap;
use std::hash::Hash;

/// Maximum partitions per epoch (protocol limit: ~43200 slots).
const MAX_PARTITIONS_PER_EPOCH: usize = 43_200;

/// Compound key for deduplicating reward entries across forks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RewardKey {
    pubkey: Pubkey,
    lamports: u64,
    credits_observed: u64,
}

/// Shared reward index entry.
#[derive(Debug, Clone)]
struct RewardEntry {
    pubkey: Pubkey,
    lamports: u64,
    credits_observed: u64,
}

/// A per-fork partition element linking to the shared index.
#[derive(Debug, Clone)]
struct PartitionElement {
    /// Index into the shared reward index.
    reward_id: u32,
    /// Next element in the partition's linked list (u32::MAX = end).
    next: u32,
}

/// Per-fork reward partition metadata.
#[derive(Debug, Clone)]
struct ForkRewardInfo {
    /// Number of partitions for this fork.
    partition_count: u32,
    /// Starting block height for reward distribution.
    starting_block_height: u64,
    /// Total lamports across all stake rewards.
    total_rewards: u64,
    /// Head index per partition (into elements vec; u32::MAX = empty).
    partition_heads: Vec<u32>,
    /// Tail index per partition (into elements vec; u32::MAX = empty).
    partition_tails: Vec<u32>,
    /// Partition elements for this fork.
    elements: Vec<PartitionElement>,
}

/// Fork identifier for stake rewards (separate from VoteStakes ForkId).
pub type StakeRewardForkId = u8;

/// Fork-aware partitioned stake rewards tracker.
#[derive(Debug)]
pub struct StakeRewards {
    /// Shared reward index: id -> entry.
    index: Vec<RewardEntry>,
    /// Key -> index id mapping for deduplication.
    key_to_id: HashMap<RewardKey, u32>,
    /// Per-fork reward info.
    forks: HashMap<StakeRewardForkId, ForkRewardInfo>,
    /// Next fork ID.
    next_fork_id: StakeRewardForkId,
    /// Current epoch (resets shared index when epoch changes).
    current_epoch: Option<u64>,
    /// Parent blockhash used for partition hashing.
    parent_blockhash: [u8; 32],
}

impl StakeRewards {
    /// Create a new stake rewards tracker.
    pub fn new() -> Self {
        Self {
            index: Vec::new(),
            key_to_id: HashMap::new(),
            forks: HashMap::new(),
            next_fork_id: 0,
            current_epoch: None,
            parent_blockhash: [0u8; 32],
        }
    }

    /// Initialize a fork for reward distribution.
    ///
    /// If the epoch has changed since the last init, the shared index is reset.
    /// Returns a fork ID for subsequent operations.
    pub fn init_fork(
        &mut self,
        epoch: u64,
        parent_blockhash: &[u8; 32],
        starting_block_height: u64,
        partition_count: u32,
    ) -> StakeRewardForkId {
        // Reset shared state on epoch change.
        if self.current_epoch != Some(epoch) {
            self.index.clear();
            self.key_to_id.clear();
            self.forks.clear();
            self.next_fork_id = 0;
            self.current_epoch = Some(epoch);
        }

        self.parent_blockhash = *parent_blockhash;

        let fork_id = self.next_fork_id;
        self.next_fork_id = self.next_fork_id.checked_add(1).expect("fork ID overflow");

        let pc = partition_count.min(MAX_PARTITIONS_PER_EPOCH as u32) as usize;

        self.forks.insert(
            fork_id,
            ForkRewardInfo {
                partition_count,
                starting_block_height,
                total_rewards: 0,
                partition_heads: vec![u32::MAX; pc],
                partition_tails: vec![u32::MAX; pc],
                elements: Vec::new(),
            },
        );

        fork_id
    }

    /// Insert a stake reward entry for a fork.
    ///
    /// The entry is deduplicated against the shared index and hashed into
    /// the appropriate partition using SipHash-1-3(parent_blockhash || pubkey).
    pub fn insert(
        &mut self,
        fork_id: StakeRewardForkId,
        pubkey: &Pubkey,
        lamports: u64,
        credits_observed: u64,
    ) {
        // Deduplicate against shared index.
        let key = RewardKey {
            pubkey: *pubkey,
            lamports,
            credits_observed,
        };
        let reward_id = if let Some(&id) = self.key_to_id.get(&key) {
            id
        } else {
            let id = self.index.len() as u32;
            self.index.push(RewardEntry {
                pubkey: *pubkey,
                lamports,
                credits_observed,
            });
            self.key_to_id.insert(key, id);
            id
        };

        let partition_count = self.forks.get(&fork_id).expect("fork exists").partition_count;

        // Hash pubkey into partition using SipHash-1-3.
        let partition_idx = self.compute_partition(pubkey, partition_count);

        let fork = self.forks.get_mut(&fork_id).expect("fork exists");

        let ele_idx = fork.elements.len() as u32;
        fork.elements.push(PartitionElement {
            reward_id,
            next: u32::MAX,
        });

        // Append to partition linked list.
        if fork.partition_heads[partition_idx] == u32::MAX {
            fork.partition_heads[partition_idx] = ele_idx;
            fork.partition_tails[partition_idx] = ele_idx;
        } else {
            let tail = fork.partition_tails[partition_idx] as usize;
            fork.elements[tail].next = ele_idx;
            fork.partition_tails[partition_idx] = ele_idx;
        }

        fork.total_rewards += lamports;
    }

    /// Iterate over all rewards in a specific partition for a fork.
    pub fn partition_iter(
        &self,
        fork_id: StakeRewardForkId,
        partition_idx: u32,
    ) -> PartitionIter<'_> {
        let fork = self.forks.get(&fork_id).expect("fork exists");
        let current = if (partition_idx as usize) < fork.partition_heads.len() {
            fork.partition_heads[partition_idx as usize]
        } else {
            u32::MAX
        };
        PartitionIter {
            rewards: self,
            fork_id,
            current,
        }
    }

    /// Total rewards for a fork.
    pub fn total_rewards(&self, fork_id: StakeRewardForkId) -> u64 {
        self.forks
            .get(&fork_id)
            .map_or(0, |f| f.total_rewards)
    }

    /// Number of partitions for a fork.
    pub fn num_partitions(&self, fork_id: StakeRewardForkId) -> u32 {
        self.forks
            .get(&fork_id)
            .map_or(0, |f| f.partition_count)
    }

    /// Starting block height for a fork's reward distribution.
    pub fn starting_block_height(&self, fork_id: StakeRewardForkId) -> u64 {
        self.forks
            .get(&fork_id)
            .map_or(0, |f| f.starting_block_height)
    }

    /// Exclusive ending block height (start + partition_count).
    pub fn exclusive_ending_block_height(&self, fork_id: StakeRewardForkId) -> u64 {
        self.forks.get(&fork_id).map_or(0, |f| {
            f.starting_block_height + f.partition_count as u64
        })
    }

    /// Compute partition index for a pubkey using SipHash-1-3.
    fn compute_partition(&self, pubkey: &Pubkey, partition_count: u32) -> usize {
        let hash = siphash13(&self.parent_blockhash, pubkey.as_ref());
        // partition = (partition_count * hash) / (u64::MAX + 1)
        // Use u128 to avoid overflow.
        ((partition_count as u128 * hash as u128) / (u64::MAX as u128 + 1)) as usize
    }
}

impl Default for StakeRewards {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over rewards in a single partition.
pub struct PartitionIter<'a> {
    rewards: &'a StakeRewards,
    fork_id: StakeRewardForkId,
    current: u32,
}

/// A single reward element returned by the partition iterator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeRewardEntry {
    pub pubkey: Pubkey,
    pub lamports: u64,
    pub credits_observed: u64,
}

impl<'a> Iterator for PartitionIter<'a> {
    type Item = StakeRewardEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current == u32::MAX {
            return None;
        }
        let fork = self.rewards.forks.get(&self.fork_id)?;
        let ele = &fork.elements[self.current as usize];
        let entry = &self.rewards.index[ele.reward_id as usize];
        self.current = ele.next;
        Some(StakeRewardEntry {
            pubkey: entry.pubkey,
            lamports: entry.lamports,
            credits_observed: entry.credits_observed,
        })
    }
}

/// SipHash-1-3 implementation matching the reference fd_siphash13.
///
/// Hashes (key || data) where key is the parent blockhash (treated as
/// two u64 values k0=0, k1=0 per reference) and data is the pubkey.
fn siphash13(blockhash: &[u8; 32], pubkey: &[u8]) -> u64 {
    // The reference uses k0=0, k1=0 for SipHash keys and hashes
    // (parent_blockhash || pubkey) as data.
    let mut hasher = SipHasher13::new_with_keys(0, 0);
    hasher.write(blockhash);
    hasher.write(pubkey);
    hasher.finish()
}

/// Minimal SipHash-1-3 hasher (1 round of compression, 3 finalization rounds).
struct SipHasher13 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: [u8; 8],
    buf_len: usize,
    total_len: usize,
}

impl SipHasher13 {
    fn new_with_keys(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            buf: [0u8; 8],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn write(&mut self, data: &[u8]) {
        self.total_len += data.len();
        let mut offset = 0;

        // Fill buffer if partially full.
        if self.buf_len > 0 {
            let needed = 8 - self.buf_len;
            let take = needed.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset = take;

            if self.buf_len == 8 {
                let m = u64::from_le_bytes(self.buf);
                self.compress(m);
                self.buf_len = 0;
            }
        }

        // Process full 8-byte blocks.
        while offset + 8 <= data.len() {
            let m = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            self.compress(m);
            offset += 8;
        }

        // Buffer remaining.
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn finish(&self) -> u64 {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;

        // Last block: remaining bytes + length byte.
        let mut last = (self.total_len as u64 & 0xff) << 56;
        let mut buf = [0u8; 8];
        buf[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        last |= u64::from_le_bytes(buf) & ((1u64 << (self.buf_len * 8)) - 1);

        v3 ^= last;
        // 1 round for SipHash-1-3.
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= last;

        v2 ^= 0xff;
        // 3 finalization rounds for SipHash-1-3.
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

        v0 ^ v1 ^ v2 ^ v3
    }

    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        // 1 round for SipHash-1-3.
        sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }
}

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    #[test]
    fn basic_insert_and_iterate() {
        let mut sr = StakeRewards::new();
        let blockhash = [42u8; 32];
        let fork = sr.init_fork(1, &blockhash, 100, 4);

        sr.insert(fork, &pk(1), 1000, 50);
        sr.insert(fork, &pk(2), 2000, 100);
        sr.insert(fork, &pk(3), 3000, 150);

        assert_eq!(sr.total_rewards(fork), 6000);
        assert_eq!(sr.num_partitions(fork), 4);
        assert_eq!(sr.starting_block_height(fork), 100);
        assert_eq!(sr.exclusive_ending_block_height(fork), 104);

        // Collect all rewards across all partitions.
        let mut all: Vec<StakeRewardEntry> = Vec::new();
        for p in 0..4 {
            all.extend(sr.partition_iter(fork, p));
        }
        assert_eq!(all.len(), 3);

        let total: u64 = all.iter().map(|e| e.lamports).sum();
        assert_eq!(total, 6000);
    }

    #[test]
    fn deduplication_across_forks() {
        let mut sr = StakeRewards::new();
        let blockhash = [42u8; 32];

        let f1 = sr.init_fork(1, &blockhash, 100, 2);
        sr.insert(f1, &pk(1), 1000, 50);

        let f2 = sr.init_fork(1, &blockhash, 100, 2);
        sr.insert(f2, &pk(1), 1000, 50); // Same reward, should dedup.

        // Shared index should have only 1 entry.
        assert_eq!(sr.index.len(), 1);

        // Both forks should see the reward.
        let r1: Vec<_> = (0..2).flat_map(|p| sr.partition_iter(f1, p)).collect();
        let r2: Vec<_> = (0..2).flat_map(|p| sr.partition_iter(f2, p)).collect();
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
        assert_eq!(r1[0].lamports, 1000);
    }

    #[test]
    fn epoch_change_resets_state() {
        let mut sr = StakeRewards::new();
        let blockhash = [42u8; 32];

        let f1 = sr.init_fork(1, &blockhash, 100, 2);
        sr.insert(f1, &pk(1), 1000, 50);

        // New epoch resets everything.
        let f2 = sr.init_fork(2, &blockhash, 200, 3);
        assert_eq!(sr.index.len(), 0); // Reset on epoch change before new insert.
        sr.insert(f2, &pk(2), 2000, 100);
        assert_eq!(sr.index.len(), 1);
    }

    #[test]
    fn partition_distribution() {
        let mut sr = StakeRewards::new();
        let blockhash = [0u8; 32];
        let fork = sr.init_fork(1, &blockhash, 0, 10);

        // Insert many entries and verify they distribute across partitions.
        for i in 0..100u8 {
            sr.insert(fork, &pk(i), 100, 10);
        }

        let mut total_in_partitions = 0;
        for p in 0..10 {
            total_in_partitions += sr.partition_iter(fork, p).count();
        }
        assert_eq!(total_in_partitions, 100);
    }

    #[test]
    fn empty_partition_iterator() {
        let mut sr = StakeRewards::new();
        let blockhash = [0u8; 32];
        let fork = sr.init_fork(1, &blockhash, 0, 4);

        // No inserts — all partitions empty.
        for p in 0..4 {
            assert_eq!(sr.partition_iter(fork, p).count(), 0);
        }
    }

    #[test]
    fn siphash13_deterministic() {
        let bh = [1u8; 32];
        let data = [2u8; 32];
        let h1 = siphash13(&bh, &data);
        let h2 = siphash13(&bh, &data);
        assert_eq!(h1, h2);

        // Different input should give different hash.
        let data2 = [3u8; 32];
        let h3 = siphash13(&bh, &data2);
        assert_ne!(h1, h3);
    }
}
