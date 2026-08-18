//! Bloom filter for gossip pull requests.
//!
//! Uses FNV-1a hashing with multiple seeds for fast membership testing.
//! The filter supports mask-based load balancing: a pull request includes
//! a mask that partitions CRDS entries by hash prefix, so the responder
//! only needs to check entries in the matching partition.

use karstflow_constants::gossip;

/// Bloom filter for gossip pull request deduplication.
///
/// The filter uses FNV-1a hash with parameterized seeds for each
/// hash function. It supports configurable size and number of hash
/// functions, defaulting to values from the gossip constants.
#[derive(Debug, Clone)]
pub struct GossipBloomFilter {
    /// Bit vector stored as packed u64 words.
    bits: Vec<u64>,
    /// Number of bits in the filter.
    num_bits: u64,
    /// Hash function seeds (one per hash function).
    keys: Vec<u64>,
    /// Number of bits currently set.
    num_bits_set: u64,
}

impl GossipBloomFilter {
    /// Create a new bloom filter sized for the expected number of items.
    ///
    /// Uses the default false positive rate and max bits from constants.
    pub fn new(expected_items: usize) -> Self {
        Self::with_params(
            expected_items,
            gossip::BLOOM_FALSE_POSITIVE_RATE,
            gossip::BLOOM_MAX_BITS,
            gossip::BLOOM_NUM_KEYS,
        )
    }

    /// Create a bloom filter with custom parameters.
    pub fn with_params(
        expected_items: usize,
        false_positive_rate: f64,
        max_bits: usize,
        num_keys: usize,
    ) -> Self {
        let optimal_bits = optimal_num_bits(expected_items, false_positive_rate);
        let num_bits = optimal_bits.min(max_bits as u64).max(64);
        let num_words = num_bits.div_ceil(64) as usize;

        // Generate deterministic seeds for hash functions
        let keys: Vec<u64> = (0..num_keys).map(|i| fnv_seed(i as u64)).collect();

        Self {
            bits: vec![0u64; num_words],
            num_bits,
            keys,
            num_bits_set: 0,
        }
    }

    /// Insert a 32-byte hash into the filter.
    pub fn insert(&mut self, hash: &[u8; 32]) {
        for &seed in &self.keys {
            let bit_pos = self.hash_to_bit(hash, seed);
            let word_idx = (bit_pos / 64) as usize;
            let bit_offset = bit_pos % 64;
            if word_idx < self.bits.len() {
                let mask = 1u64 << bit_offset;
                if self.bits[word_idx] & mask == 0 {
                    self.num_bits_set += 1;
                }
                self.bits[word_idx] |= mask;
            }
        }
    }

    /// Test whether a 32-byte hash might be in the filter.
    ///
    /// Returns false if the hash is definitely not present.
    /// Returns true if the hash might be present (possible false positive).
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.keys.iter().all(|&seed| {
            let bit_pos = self.hash_to_bit(hash, seed);
            let word_idx = (bit_pos / 64) as usize;
            let bit_offset = bit_pos % 64;
            if word_idx < self.bits.len() {
                (self.bits[word_idx] & (1u64 << bit_offset)) != 0
            } else {
                false
            }
        })
    }

    /// Number of bits set in the filter.
    pub fn bits_set(&self) -> u64 {
        self.num_bits_set
    }

    /// Total number of bits in the filter.
    pub fn total_bits(&self) -> u64 {
        self.num_bits
    }

    /// Number of hash functions.
    pub fn num_keys(&self) -> usize {
        self.keys.len()
    }

    /// Clear all bits.
    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.num_bits_set = 0;
    }

    /// Get the underlying bit vector.
    pub fn bits(&self) -> &[u64] {
        &self.bits
    }

    /// Get the hash function seeds.
    pub fn keys(&self) -> &[u64] {
        &self.keys
    }

    /// Reconstruct a bloom filter from serialized parts.
    pub fn from_parts(bits: Vec<u64>, num_bits: u64, keys: Vec<u64>) -> Self {
        let num_bits_set = bits.iter().map(|w| w.count_ones() as u64).sum();
        Self {
            bits,
            num_bits,
            keys,
            num_bits_set,
        }
    }

    /// Hash a 32-byte value to a bit position using FNV-1a.
    fn hash_to_bit(&self, hash: &[u8; 32], seed: u64) -> u64 {
        fnv1a_hash(hash, seed) % self.num_bits
    }
}

/// FNV-1a hash of a 32-byte value with a seed.
///
/// This is the same algorithm used by the reference implementation for bloom filter hashing.
/// FNV-1a is chosen for its speed on short inputs (no need for
/// cryptographic security in bloom filters).
fn fnv1a_hash(data: &[u8; 32], seed: u64) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS ^ seed;
    for &byte in data.iter() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Generate a deterministic seed for the i-th hash function.
fn fnv_seed(index: u64) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in index.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Calculate optimal number of bits for a bloom filter.
fn optimal_num_bits(expected_items: usize, false_positive_rate: f64) -> u64 {
    if expected_items == 0 {
        return 64;
    }
    let m = -(expected_items as f64 * false_positive_rate.ln()) / (2.0_f64.ln().powi(2));
    (m.ceil() as u64).max(64)
}

/// Mask for partitioning CRDS entries in pull requests.
///
/// The mask partitions the hash-prefix space so that a pull request
/// only covers a portion of the CRDS table, enabling load balancing
/// across multiple pull requests.
#[derive(Debug, Clone, Copy)]
pub struct PullRequestMask {
    /// The mask value: top mask_bits bits are significant.
    pub mask: u64,
    /// Number of significant bits in the mask (0..64).
    pub mask_bits: u32,
}

impl PullRequestMask {
    /// Create a mask that covers the full hash space (no partitioning).
    pub fn full() -> Self {
        Self {
            mask: 0,
            mask_bits: 0,
        }
    }

    /// Create a mask for partitioning based on CRDS table size.
    ///
    /// `mask_bits` is `ceil(log2(total_entries / max_items_per_request))`, floored
    /// at [`MIN_PULL_REQUEST_MASK_BITS`]. The floor is not a tuning choice: peers
    /// reject a pull request whose `mask_bits` is below it, so a mask computed
    /// from a small table would produce a request every conforming peer drops.
    ///
    /// [`MIN_PULL_REQUEST_MASK_BITS`]: karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS
    pub fn for_partition(total_entries: usize, max_items: usize, random_value: u64) -> Self {
        let floor = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;
        let computed = if total_entries <= max_items || max_items == 0 {
            0
        } else {
            let partitions = total_entries.div_ceil(max_items);
            64 - (partitions as u64).leading_zeros()
        };
        let mask_bits = computed.clamp(floor, 63);
        let mask = random_value | (!0u64 >> mask_bits);
        Self { mask, mask_bits }
    }

    /// Create the mask for an outbound pull request asking for one bucket.
    ///
    /// `seed` selects which of the `2^mask_bits` buckets to request; vary it
    /// between requests so successive rounds sweep the whole hash space.
    pub fn for_pull_request(seed: u64) -> Self {
        let mask_bits = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;
        let bucket = seed & ((1u64 << mask_bits) - 1);
        let mask = (bucket << (64 - mask_bits)) | (!0u64 >> mask_bits);
        Self { mask, mask_bits }
    }

    /// Check if a hash prefix falls within this mask's partition.
    pub fn matches(&self, hash_prefix: u64) -> bool {
        if self.mask_bits == 0 {
            return true;
        }
        let significant_mask = !0u64 << (64 - self.mask_bits);
        (hash_prefix & significant_mask) == (self.mask & significant_mask)
    }

    /// Get the lower bound of the hash prefix range.
    pub fn range_start(&self) -> u64 {
        if self.mask_bits == 0 {
            return 0;
        }
        let significant_mask = !0u64 << (64 - self.mask_bits);
        self.mask & significant_mask
    }

    /// Get the upper bound (exclusive) of the hash prefix range.
    pub fn range_end(&self) -> u64 {
        if self.mask_bits == 0 {
            return u64::MAX;
        }
        let fill_mask = !0u64 >> self.mask_bits;
        self.range_start() | fill_mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = GossipBloomFilter::new(100);

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        assert!(!filter.contains(&hash1));
        filter.insert(&hash1);
        assert!(filter.contains(&hash1));
        assert!(!filter.contains(&hash2));
    }

    #[test]
    fn test_bloom_filter_multiple_items() {
        let mut filter = GossipBloomFilter::new(1000);
        let items: Vec<[u8; 32]> = (0..100)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h[1] = (i >> 8) as u8;
                h
            })
            .collect();

        for item in &items {
            filter.insert(item);
        }

        for item in &items {
            assert!(filter.contains(item), "missing item {:?}", item[0]);
        }
    }

    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let mut filter = GossipBloomFilter::new(100);

        // Insert 100 items
        for i in 0u16..100 {
            let mut h = [0u8; 32];
            h[..2].copy_from_slice(&i.to_le_bytes());
            filter.insert(&h);
        }

        // Test 1000 non-inserted items for false positives
        let mut false_positives = 0;
        for i in 1000u16..2000 {
            let mut h = [0u8; 32];
            h[..2].copy_from_slice(&i.to_le_bytes());
            if filter.contains(&h) {
                false_positives += 1;
            }
        }

        // With 10% target FPR, allow up to 20% as margin
        assert!(
            false_positives < 200,
            "too many false positives: {}/1000",
            false_positives
        );
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut filter = GossipBloomFilter::new(100);
        let hash = [1u8; 32];
        filter.insert(&hash);
        assert!(filter.contains(&hash));

        filter.clear();
        assert!(!filter.contains(&hash));
        assert_eq!(filter.bits_set(), 0);
    }

    #[test]
    fn test_bloom_filter_bits_set() {
        let mut filter = GossipBloomFilter::new(100);
        assert_eq!(filter.bits_set(), 0);

        let hash = [1u8; 32];
        filter.insert(&hash);
        assert!(filter.bits_set() > 0);
        assert!(filter.bits_set() <= filter.num_keys() as u64);
    }

    #[test]
    fn test_fnv1a_deterministic() {
        let data = [42u8; 32];
        let h1 = fnv1a_hash(&data, 0);
        let h2 = fnv1a_hash(&data, 0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a_different_seeds() {
        let data = [42u8; 32];
        let h1 = fnv1a_hash(&data, 0);
        let h2 = fnv1a_hash(&data, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_mask_full() {
        let mask = PullRequestMask::full();
        assert!(mask.matches(0));
        assert!(mask.matches(u64::MAX));
        assert_eq!(mask.range_start(), 0);
        assert_eq!(mask.range_end(), u64::MAX);
    }

    #[test]
    fn test_mask_partition() {
        let mask = PullRequestMask::for_partition(1000, 100, 0xABCD_0000_0000_0000);
        assert!(mask.mask_bits > 0);
        // Verify the mask matches its own range
        let start = mask.range_start();
        assert!(mask.matches(start));
    }

    #[test]
    fn test_mask_no_partition_needed() {
        // A table smaller than one request's capacity needs no partitioning on its
        // own merits, but the protocol floor still applies: peers reject a filter
        // below it, so an unpartitioned request would simply be dropped.
        let floor = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;
        let mask = PullRequestMask::for_partition(50, 100, 0);
        assert_eq!(mask.mask_bits, floor);

        // The bucket is still reachable — some hash matches it.
        let start = mask.range_start();
        assert!(mask.matches(start));
    }

    #[test]
    fn test_mask_range_consistency() {
        let mask = PullRequestMask::for_partition(10000, 100, 0x8000_0000_0000_0000);
        let start = mask.range_start();
        let end = mask.range_end();
        assert!(start <= end);
        assert!(mask.matches(start));
        assert!(mask.matches(end));
    }

    #[test]
    fn outbound_pull_masks_meet_the_protocol_floor() {
        let floor = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;

        // A request built for a tiny table would compute mask_bits below the floor;
        // peers reject that, so the constructor must lift it.
        for (entries, max_items) in [(0usize, 100usize), (1, 100), (1000, 100), (10_000, 100)] {
            let mask = PullRequestMask::for_partition(entries, max_items, 0xDEAD_BEEF_0000_0000);
            assert!(
                mask.mask_bits >= floor,
                "for_partition({entries}, {max_items}) produced mask_bits={} below the floor",
                mask.mask_bits
            );
        }

        for seed in [0u64, 1, 63, 64, u64::MAX] {
            let mask = PullRequestMask::for_pull_request(seed);
            assert_eq!(mask.mask_bits, floor);
        }
    }

    #[test]
    fn pull_request_buckets_partition_the_hash_space() {
        let floor = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;
        let buckets = 1u64 << floor;

        // Every hash falls in exactly one bucket, and every bucket is reachable.
        for probe in [0u64, 1, u64::MAX / 3, u64::MAX / 2, u64::MAX] {
            let hits = (0..buckets)
                .filter(|&seed| PullRequestMask::for_pull_request(seed).matches(probe))
                .count();
            assert_eq!(
                hits, 1,
                "hash {probe:#x} matched {hits} buckets, expected 1"
            );
        }

        let distinct: std::collections::HashSet<u64> = (0..buckets)
            .map(|seed| PullRequestMask::for_pull_request(seed).mask)
            .collect();
        assert_eq!(distinct.len() as u64, buckets, "buckets are not distinct");
    }
}
