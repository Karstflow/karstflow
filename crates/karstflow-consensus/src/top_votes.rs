/// Bounded top-K validator selection for VAT (Vote Account Threshold).
///
/// Maintains the top `max_validators` staked vote accounts using a min-heap.
/// Used for epoch rewards eligibility, clock calculation, and leader schedule
/// participation.
///
/// Key tiebreaking rule: if the minimum stake in a full set has a tie,
/// ALL accounts with that stake value are excluded and the stake value
/// is watermarked so future inserts at or below it are rejected.
use karstflow_types::Pubkey;
use std::collections::{BinaryHeap, HashMap};

/// Default maximum number of top validators (SIMD-0387 / VAT).
pub const DEFAULT_MAX_VALIDATORS: usize = 2_000;

/// A validator entry in the top set.
#[derive(Debug, Clone)]
pub struct TopVoteEntry {
    /// Vote account pubkey.
    pub pubkey: Pubkey,
    /// Validator node identity.
    pub node_account: Pubkey,
    /// Delegated stake.
    pub stake: u64,
}

/// Wrapper for min-heap ordering: lowest stake sorts first (is "greatest"
/// in `BinaryHeap`'s max-heap, so we reverse the comparison).
#[derive(Debug, Clone, Eq, PartialEq)]
struct HeapEntry {
    stake: u64,
    pubkey: Pubkey,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse: smallest stake = highest priority for removal.
        // On stake tie, compare pubkey bytes (smaller pubkey = higher priority).
        other
            .stake
            .cmp(&self.stake)
            .then_with(|| other.pubkey.as_ref().cmp(self.pubkey.as_ref()))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Bounded top-K validator set with min-heap eviction.
#[derive(Debug, Clone)]
pub struct TopVotes {
    /// Maximum number of validators in the set.
    max_validators: usize,
    /// Min-heap (smallest stake at top).
    heap: BinaryHeap<HeapEntry>,
    /// Fast lookup by vote account pubkey.
    map: HashMap<Pubkey, TopVoteEntry>,
    /// Watermark: stakes at or below this value are rejected.
    /// Set when a tie at the minimum causes mass eviction.
    min_stake_watermark: u64,
}

impl TopVotes {
    /// Create a new top votes tracker with the given capacity.
    pub fn new(max_validators: usize) -> Self {
        Self {
            max_validators,
            heap: BinaryHeap::with_capacity(max_validators + 1),
            map: HashMap::with_capacity(max_validators + 1),
            min_stake_watermark: 0,
        }
    }

    /// Create a top votes tracker with the default 2000 validator limit.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_MAX_VALIDATORS)
    }

    /// Reset the structure, clearing all entries and the watermark.
    pub fn reset(&mut self) {
        self.heap.clear();
        self.map.clear();
        self.min_stake_watermark = 0;
    }

    /// Update the set with a vote account's stake.
    ///
    /// If the set is not full, the entry is inserted directly.
    /// If the set is full:
    /// - Stakes below the current minimum (or watermark) are ignored.
    /// - If the new stake ties the minimum, ALL entries at that stake
    ///   are evicted, the new entry is NOT inserted, and the stake
    ///   value is watermarked.
    /// - If the new stake exceeds the minimum, all entries at the
    ///   minimum stake are evicted and the new entry is inserted.
    pub fn update(&mut self, pubkey: Pubkey, node_account: Pubkey, stake: u64) {
        // Reject if at or below watermark.
        if stake <= self.min_stake_watermark {
            return;
        }

        if self.map.len() >= self.max_validators {
            // Heap is full — check against current minimum.
            let min_stake = match self.heap.peek() {
                Some(entry) => entry.stake,
                None => return,
            };

            if stake < min_stake {
                return;
            }

            if stake == min_stake {
                // Tie with minimum: evict all at this stake, set watermark,
                // do NOT insert the new entry.
                self.min_stake_watermark = stake;
                self.evict_all_at_stake(stake);
                return;
            }

            // New stake exceeds minimum: evict all at minimum stake.
            self.evict_all_at_stake(min_stake);
        }

        // Insert the new entry.
        self.heap.push(HeapEntry {
            stake,
            pubkey,
        });
        self.map.insert(
            pubkey,
            TopVoteEntry {
                pubkey,
                node_account,
                stake,
            },
        );
    }

    /// Query whether a vote account is in the top set.
    ///
    /// Returns `Some` with node account and stake if present, `None` otherwise.
    pub fn query(&self, pubkey: &Pubkey) -> Option<(&Pubkey, u64)> {
        self.map
            .get(pubkey)
            .map(|entry| (&entry.node_account, entry.stake))
    }

    /// Check if a vote account is in the top set.
    pub fn contains(&self, pubkey: &Pubkey) -> bool {
        self.map.contains_key(pubkey)
    }

    /// Number of validators currently in the top set.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the top set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over all entries in the top set.
    pub fn iter(&self) -> impl Iterator<Item = &TopVoteEntry> {
        self.map.values()
    }

    /// Evict all entries with the given stake value from the heap and map.
    fn evict_all_at_stake(&mut self, stake: u64) {
        // Drain the heap, keeping entries that don't match the target stake.
        let mut keep = Vec::new();
        while let Some(entry) = self.heap.pop() {
            if entry.stake == stake {
                self.map.remove(&entry.pubkey);
            } else {
                keep.push(entry);
            }
        }
        // Re-insert kept entries.
        for entry in keep {
            self.heap.push(entry);
        }
    }
}

impl Default for TopVotes {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        Pubkey::new([seed; 32])
    }

    #[test]
    fn basic_insert_and_query() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 20);
        tv.update(pk(3), pk(103), 30);
        tv.update(pk(4), pk(104), 40);

        assert!(tv.contains(&pk(1)));
        assert!(tv.contains(&pk(2)));
        assert!(tv.contains(&pk(3)));
        assert!(tv.contains(&pk(4)));
        assert!(!tv.contains(&pk(5)));

        let (node, stake) = tv.query(&pk(1)).unwrap();
        assert_eq!(*node, pk(101));
        assert_eq!(stake, 10);
    }

    #[test]
    fn lower_than_min_rejected_when_full() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 20);
        tv.update(pk(3), pk(103), 30);
        tv.update(pk(4), pk(104), 40);

        // Stake 5 < min (10), should be rejected.
        tv.update(pk(5), pk(105), 5);
        assert!(!tv.contains(&pk(5)));
        assert!(tv.contains(&pk(1))); // min still present
    }

    #[test]
    fn higher_than_min_evicts_minimum() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 20);
        tv.update(pk(3), pk(103), 30);
        tv.update(pk(4), pk(104), 40);

        // Stake 50 > min (10), should evict pk(1).
        tv.update(pk(5), pk(105), 50);
        assert!(!tv.contains(&pk(1)));
        assert!(tv.contains(&pk(2)));
        assert!(tv.contains(&pk(3)));
        assert!(tv.contains(&pk(4)));
        assert!(tv.contains(&pk(5)));
    }

    #[test]
    fn tied_minimum_all_evicted_on_higher() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 10);
        tv.update(pk(3), pk(103), 20);
        tv.update(pk(4), pk(104), 30);

        // Stake 40 > min (10). Both pk(1) and pk(2) at min stake evicted.
        tv.update(pk(5), pk(105), 40);
        assert!(!tv.contains(&pk(1)));
        assert!(!tv.contains(&pk(2)));
        assert!(tv.contains(&pk(3)));
        assert!(tv.contains(&pk(4)));
        assert!(tv.contains(&pk(5)));
    }

    #[test]
    fn tie_with_min_evicts_all_and_watermarks() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 10);
        tv.update(pk(3), pk(103), 20);
        tv.update(pk(4), pk(104), 30);

        // Stake 10 ties the min when full: evict all at 10, don't insert new.
        tv.update(pk(5), pk(105), 10);
        assert!(!tv.contains(&pk(1)));
        assert!(!tv.contains(&pk(2)));
        assert!(!tv.contains(&pk(5)));
        assert!(tv.contains(&pk(3)));
        assert!(tv.contains(&pk(4)));
    }

    #[test]
    fn watermark_rejects_equal_and_below() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 10);
        tv.update(pk(3), pk(103), 20);
        tv.update(pk(4), pk(104), 30);

        // Trigger watermark at 10.
        tv.update(pk(5), pk(105), 10);

        // Equal to watermark: rejected.
        tv.update(pk(6), pk(106), 10);
        assert!(!tv.contains(&pk(6)));

        // Below watermark: rejected.
        tv.update(pk(7), pk(107), 9);
        assert!(!tv.contains(&pk(7)));

        // Above watermark: accepted.
        tv.update(pk(8), pk(108), 11);
        assert!(tv.contains(&pk(8)));
    }

    #[test]
    fn watermark_advances_on_repeated_ties() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 10);
        tv.update(pk(3), pk(103), 20);
        tv.update(pk(4), pk(104), 30);

        // Watermark at 10.
        tv.update(pk(5), pk(105), 10);

        // Fill back up: pk(8)=11, still have pk(3)=20, pk(4)=30.
        tv.update(pk(8), pk(108), 11);
        tv.update(pk(9), pk(109), 25); // now full: 11, 20, 25, 30

        // Tie with new min (11) advances watermark to 11.
        tv.update(pk(10), pk(110), 11);
        assert!(!tv.contains(&pk(8)));
        assert!(!tv.contains(&pk(10)));
        assert!(tv.contains(&pk(3)));
        assert!(tv.contains(&pk(4)));
        assert!(tv.contains(&pk(9)));

        // Watermark at 11: reject 11, accept 12.
        tv.update(pk(11), pk(111), 11);
        assert!(!tv.contains(&pk(11)));
        tv.update(pk(12), pk(112), 12);
        assert!(tv.contains(&pk(12)));
    }

    #[test]
    fn reset_clears_everything_including_watermark() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 10);
        tv.update(pk(3), pk(103), 20);
        tv.update(pk(4), pk(104), 30);
        tv.update(pk(5), pk(105), 10); // watermark at 10

        tv.reset();
        assert!(!tv.contains(&pk(3)));
        assert_eq!(tv.len(), 0);

        // After reset, watermark is cleared: stake 10 should be accepted.
        tv.update(pk(13), pk(113), 11);
        assert!(tv.contains(&pk(13)));
    }

    #[test]
    fn len_tracks_correctly() {
        let mut tv = TopVotes::new(4);
        assert_eq!(tv.len(), 0);
        assert!(tv.is_empty());

        tv.update(pk(1), pk(101), 10);
        assert_eq!(tv.len(), 1);

        tv.update(pk(2), pk(102), 20);
        tv.update(pk(3), pk(103), 30);
        tv.update(pk(4), pk(104), 40);
        assert_eq!(tv.len(), 4);

        // Evict min and insert new.
        tv.update(pk(5), pk(105), 50);
        assert_eq!(tv.len(), 4);
    }

    #[test]
    fn iter_returns_all_entries() {
        let mut tv = TopVotes::new(4);
        tv.update(pk(1), pk(101), 10);
        tv.update(pk(2), pk(102), 20);
        tv.update(pk(3), pk(103), 30);

        let mut stakes: Vec<u64> = tv.iter().map(|e| e.stake).collect();
        stakes.sort();
        assert_eq!(stakes, vec![10, 20, 30]);
    }
}
