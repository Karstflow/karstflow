//! Wire-compatible bloom filter types for the gossip protocol.
//!
//! These types serialize identically to the Solana gossip protocol's
//! bloom filter and CRDS filter formats using standard bincode.
//! The `bv::BitVec<u64>` crate provides serde compatibility with
//! the bit vector layout used by Solana validators.

use bv::{BitVec, Bits, BitsMut};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::super::crds::{GossipBloomFilter, PullRequestMask};

/// Wire-format bloom filter.
///
/// Matches the Solana `Bloom<Hash>` struct layout for bincode serialization.
/// Field order is significant: keys, bits, num_bits_set, phantom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBloom {
    pub keys: Vec<u64>,
    pub bits: BitVec<u64>,
    pub num_bits_set: u64,
    pub _phantom: PhantomData<[u8; 32]>,
}

/// Wire-format CRDS pull request filter.
///
/// Combines a bloom filter (for known-value exclusion) with a mask
/// (for hash-prefix partitioning) to limit pull response size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCrdsFilter {
    pub filter: WireBloom,
    pub mask: u64,
    pub mask_bits: u32,
}

impl WireCrdsFilter {
    /// Whether an inbound filter is well-formed enough to answer.
    ///
    /// Peers reject pull requests below the protocol's `mask_bits` floor, so a
    /// request under it is malformed rather than merely greedy: answering it
    /// would both diverge from peers on well-formedness and let one request
    /// sweep a large share of the CRDS table.
    pub fn is_acceptable(&self) -> bool {
        self.mask_bits >= karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS
    }
}

impl WireBloom {
    /// Convert from the internal bloom filter representation.
    pub fn from_internal(bloom: &GossipBloomFilter) -> Self {
        let num_bits = bloom.total_bits();
        let internal_bits = bloom.bits();
        let mut bits = BitVec::new_fill(false, num_bits);
        for (i, &word) in internal_bits.iter().enumerate() {
            bits.set_block(i, word);
        }

        Self {
            keys: bloom.keys().to_vec(),
            bits,
            num_bits_set: bloom.bits_set(),
            _phantom: PhantomData,
        }
    }

    /// Convert to the internal bloom filter representation.
    pub fn to_internal(&self) -> GossipBloomFilter {
        let num_bits = self.bits.len();
        let block_count = self.bits.block_len();
        let mut words = Vec::with_capacity(block_count);
        for i in 0..block_count {
            words.push(self.bits.get_block(i));
        }
        GossipBloomFilter::from_parts(words, num_bits, self.keys.clone())
    }

    /// Create an empty wire bloom filter.
    pub fn empty() -> Self {
        Self {
            keys: Vec::new(),
            bits: BitVec::new(),
            num_bits_set: 0,
            _phantom: PhantomData,
        }
    }
}

impl WireCrdsFilter {
    /// Convert from internal bloom filter and pull request mask.
    pub fn from_internal(bloom: &GossipBloomFilter, mask: &PullRequestMask) -> Self {
        Self {
            filter: WireBloom::from_internal(bloom),
            mask: mask.mask,
            mask_bits: mask.mask_bits,
        }
    }

    /// Convert to internal bloom filter and pull request mask.
    pub fn to_internal(&self) -> (GossipBloomFilter, PullRequestMask) {
        let bloom = self.filter.to_internal();
        let mask = PullRequestMask {
            mask: self.mask,
            mask_bits: self.mask_bits,
        };
        (bloom, mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bloom_round_trip() {
        let mut internal = GossipBloomFilter::new(100);
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        internal.insert(&hash1);
        internal.insert(&hash2);

        let wire = WireBloom::from_internal(&internal);
        let restored = wire.to_internal();

        assert!(restored.contains(&hash1));
        assert!(restored.contains(&hash2));
        assert_eq!(restored.bits_set(), internal.bits_set());
        assert_eq!(restored.total_bits(), internal.total_bits());
        assert_eq!(restored.keys(), internal.keys());
    }

    #[test]
    fn wire_bloom_bincode_round_trip() {
        let mut internal = GossipBloomFilter::new(50);
        for i in 0u8..20 {
            let mut h = [0u8; 32];
            h[0] = i;
            internal.insert(&h);
        }

        let wire = WireBloom::from_internal(&internal);
        let bytes = bincode::serialize(&wire).unwrap();
        let decoded: WireBloom = bincode::deserialize(&bytes).unwrap();
        let restored = decoded.to_internal();

        for i in 0u8..20 {
            let mut h = [0u8; 32];
            h[0] = i;
            assert!(restored.contains(&h), "missing item {i}");
        }
    }

    #[test]
    fn wire_crds_filter_round_trip() {
        let bloom = GossipBloomFilter::new(200);
        let mask = PullRequestMask::for_partition(1000, 100, 0xABCD_0000_0000_0000);

        let wire_filter = WireCrdsFilter::from_internal(&bloom, &mask);
        let (restored_bloom, restored_mask) = wire_filter.to_internal();

        assert_eq!(restored_bloom.total_bits(), bloom.total_bits());
        assert_eq!(restored_mask.mask, mask.mask);
        assert_eq!(restored_mask.mask_bits, mask.mask_bits);
    }

    #[test]
    fn wire_crds_filter_bincode_round_trip() {
        let mut bloom = GossipBloomFilter::new(100);
        bloom.insert(&[42u8; 32]);
        let mask = PullRequestMask::for_partition(500, 50, 0x1234_0000_0000_0000);

        let wire_filter = WireCrdsFilter::from_internal(&bloom, &mask);
        let bytes = bincode::serialize(&wire_filter).unwrap();
        let decoded: WireCrdsFilter = bincode::deserialize(&bytes).unwrap();

        let (restored_bloom, restored_mask) = decoded.to_internal();
        assert!(restored_bloom.contains(&[42u8; 32]));
        assert_eq!(restored_mask.mask, mask.mask);
        assert_eq!(restored_mask.mask_bits, mask.mask_bits);
    }

    #[test]
    fn wire_bloom_empty() {
        let wire = WireBloom::empty();
        assert_eq!(wire.num_bits_set, 0);
        assert!(wire.keys.is_empty());
        assert_eq!(wire.bits.len(), 0);

        let bytes = bincode::serialize(&wire).unwrap();
        let decoded: WireBloom = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.num_bits_set, 0);
    }

    #[test]
    fn wire_bloom_preserves_membership() {
        let mut internal = GossipBloomFilter::new(500);
        let items: Vec<[u8; 32]> = (0u16..200)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..2].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        for item in &items {
            internal.insert(item);
        }

        // Convert to wire, serialize, deserialize, convert back
        let wire = WireBloom::from_internal(&internal);
        let bytes = bincode::serialize(&wire).unwrap();
        let decoded: WireBloom = bincode::deserialize(&bytes).unwrap();
        let restored = decoded.to_internal();

        // All inserted items must still be found
        for item in &items {
            assert!(restored.contains(item));
        }

        // Non-inserted items should mostly NOT be found
        let mut false_positives = 0;
        for i in 1000u16..2000 {
            let mut h = [0u8; 32];
            h[..2].copy_from_slice(&i.to_le_bytes());
            if restored.contains(&h) {
                false_positives += 1;
            }
        }
        assert!(
            false_positives < 200,
            "too many false positives: {false_positives}"
        );
    }

    #[test]
    fn pull_filter_below_mask_bits_floor_is_rejected() {
        let internal = GossipBloomFilter::new(64);
        let mut filter = WireBloom::from_internal(&internal);
        filter.num_bits_set = 0;
        let floor = karstflow_constants::gossip::MIN_PULL_REQUEST_MASK_BITS;

        for bits in 0..floor {
            let f = WireCrdsFilter {
                filter: filter.clone(),
                mask: !0u64,
                mask_bits: bits,
            };
            assert!(
                !f.is_acceptable(),
                "mask_bits={bits} is below the floor and must be rejected"
            );
        }

        for bits in [floor, floor + 1, 63] {
            let f = WireCrdsFilter {
                filter: filter.clone(),
                mask: !0u64,
                mask_bits: bits,
            };
            assert!(f.is_acceptable(), "mask_bits={bits} must be accepted");
        }
    }
}
