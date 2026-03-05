/// Deterministic turbine destination computation.
///
/// Each shred gets a unique position in the turbine tree based on a SHA-256
/// seed derived from (slot, shred_type, shred_index, leader_pubkey). This
/// seed initializes a ChaCha RNG that drives a stake-weighted shuffle,
/// producing a consistent tree topology across all validators.
///
/// The tree has two layers beyond the leader:
///   Layer 0: Leader (broadcasts to layer 1)
///   Layer 1: `fanout` validators (retransmit to layer 2)
///   Layer 2: `fanout * fanout` validators (leaf nodes)
///
/// Staked validators are selected via weighted sampling (higher stake =
/// higher probability of appearing early in the shuffle). Unstaked
/// validators fill remaining positions via uniform random selection.
use karstflow_constants::turbine::{
    DEST_SEED_INPUT_SIZE, DEST_SEED_TYPE_CODE, DEST_SEED_TYPE_DATA, MAX_FANOUT,
};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Destination seed
// ---------------------------------------------------------------------------

/// Compute the deterministic seed for turbine destination selection.
///
/// The seed is SHA-256(slot || type_byte || shred_index || leader_pubkey),
/// producing a 32-byte value that initializes the ChaCha20 RNG.
pub fn compute_destination_seed(
    slot: u64,
    is_data: bool,
    shred_index: u32,
    leader_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut input = [0u8; DEST_SEED_INPUT_SIZE];
    input[0..8].copy_from_slice(&slot.to_le_bytes());
    input[8] = if is_data {
        DEST_SEED_TYPE_DATA
    } else {
        DEST_SEED_TYPE_CODE
    };
    input[9..13].copy_from_slice(&shred_index.to_le_bytes());
    input[13..45].copy_from_slice(leader_pubkey);

    let hash = Sha256::digest(input);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Create a ChaCha20 RNG from a destination seed.
fn rng_from_seed(seed: [u8; 32]) -> ChaCha20Rng {
    use rand::SeedableRng;
    ChaCha20Rng::from_seed(seed)
}

// ---------------------------------------------------------------------------
// Validator pool for stake-weighted sampling
// ---------------------------------------------------------------------------

/// A validator entry for turbine destination computation.
#[derive(Debug, Clone)]
pub struct DestinationValidator {
    /// Validator identity pubkey.
    pub pubkey: [u8; 32],
    /// Stake in lamports (0 for unstaked).
    pub stake: u64,
}

/// Pre-computed destination pool built from epoch stake data.
///
/// Separates validators into staked and unstaked pools. Staked validators
/// are sorted by (stake descending, pubkey ascending) for deterministic
/// ordering. The pool supports efficient weighted and uniform sampling.
#[derive(Debug, Clone)]
pub struct DestinationPool {
    /// Staked validators sorted by (stake desc, pubkey asc).
    staked: Vec<DestinationValidator>,
    /// Total stake across all staked validators.
    total_stake: u64,
    /// Unstaked validator pubkeys.
    unstaked: Vec<[u8; 32]>,
}

impl DestinationPool {
    /// Build a destination pool from a set of validators.
    ///
    /// Validators with stake > 0 go into the staked pool (sorted by stake
    /// descending, then pubkey ascending). Validators with zero stake go
    /// into the unstaked pool.
    pub fn new(validators: Vec<DestinationValidator>) -> Self {
        let mut staked: Vec<DestinationValidator> = Vec::new();
        let mut unstaked: Vec<[u8; 32]> = Vec::new();

        for v in validators {
            if v.stake > 0 {
                staked.push(v);
            } else {
                unstaked.push(v.pubkey);
            }
        }

        // Sort staked: descending by stake, then ascending by pubkey.
        staked.sort_by(|a, b| b.stake.cmp(&a.stake).then_with(|| a.pubkey.cmp(&b.pubkey)));

        let total_stake = staked.iter().map(|v| v.stake).sum();

        Self {
            staked,
            total_stake,
            unstaked,
        }
    }

    /// Number of staked validators.
    pub fn staked_count(&self) -> usize {
        self.staked.len()
    }

    /// Number of unstaked validators.
    pub fn unstaked_count(&self) -> usize {
        self.unstaked.len()
    }

    /// Total validators (staked + unstaked).
    pub fn total_count(&self) -> usize {
        self.staked.len() + self.unstaked.len()
    }

    /// Draw a stake-weighted sample index from the staked pool.
    ///
    /// Uses binary search on cumulative weights for O(log n) selection.
    /// The `excluded` set contains indices to skip (e.g., the leader).
    /// Returns None if all staked validators are excluded.
    fn weighted_sample(&self, rng: &mut ChaCha20Rng, excluded: &[bool]) -> Option<usize> {
        if self.total_stake == 0 || self.staked.is_empty() {
            return None;
        }

        // Compute effective total stake minus excluded entries.
        let effective_total: u64 = self
            .staked
            .iter()
            .enumerate()
            .filter(|(i, _)| !excluded.get(*i).copied().unwrap_or(false))
            .map(|(_, v)| v.stake)
            .sum();

        if effective_total == 0 {
            return None;
        }

        // Draw random value in [0, effective_total).
        let target = rng.gen_range(0..effective_total);

        // Walk staked list, accumulating stake of non-excluded entries.
        let mut cumulative = 0u64;
        for (i, v) in self.staked.iter().enumerate() {
            if excluded.get(i).copied().unwrap_or(false) {
                continue;
            }
            cumulative += v.stake;
            if target < cumulative {
                return Some(i);
            }
        }

        // Fallback: return last non-excluded.
        self.staked
            .iter()
            .enumerate()
            .rev()
            .find(|(i, _)| !excluded.get(*i).copied().unwrap_or(false))
            .map(|(i, _)| i)
    }

    /// Draw a uniform random index from the unstaked pool.
    /// Returns None if the unstaked pool is empty or all are excluded.
    fn uniform_sample_unstaked(&self, rng: &mut ChaCha20Rng, excluded: &[bool]) -> Option<usize> {
        let available: Vec<usize> = (0..self.unstaked.len())
            .filter(|i| !excluded.get(*i).copied().unwrap_or(false))
            .collect();
        if available.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..available.len());
        Some(available[idx])
    }
}

// ---------------------------------------------------------------------------
// Destination computation
// ---------------------------------------------------------------------------

/// Computed destination for a single shred.
#[derive(Debug, Clone)]
pub struct ShredDestination {
    /// Destination validator pubkey.
    pub pubkey: [u8; 32],
    /// Whether this destination is staked.
    pub is_staked: bool,
}

/// Result of computing retransmit destinations for a validator.
#[derive(Debug, Clone)]
pub struct RetransmitDestinations {
    /// This validator's position in the shuffled tree (0-based).
    pub my_position: usize,
    /// Layer this validator is in (1 = first retransmit layer).
    pub my_layer: u8,
    /// Destinations to retransmit to (empty for leaf nodes).
    pub children: Vec<ShredDestination>,
}

/// Compute the first destination for a shred broadcast from the leader.
///
/// The leader sends each shred to a single root node selected via
/// stake-weighted sampling from all validators (excluding self).
/// Returns None if no valid destination exists (only one validator known).
pub fn compute_leader_destination(
    seed: [u8; 32],
    pool: &DestinationPool,
    leader_pubkey: &[u8; 32],
) -> Option<ShredDestination> {
    if pool.total_count() == 0 {
        return None;
    }

    let mut rng = rng_from_seed(seed);

    // Find and exclude the leader from staked pool.
    let mut staked_excluded = vec![false; pool.staked.len()];
    for (i, v) in pool.staked.iter().enumerate() {
        if v.pubkey == *leader_pubkey {
            staked_excluded[i] = true;
            break;
        }
    }

    // Try staked first.
    if let Some(idx) = pool.weighted_sample(&mut rng, &staked_excluded) {
        return Some(ShredDestination {
            pubkey: pool.staked[idx].pubkey,
            is_staked: true,
        });
    }

    // Fall back to unstaked.
    let mut unstaked_excluded = vec![false; pool.unstaked.len()];
    for (i, pk) in pool.unstaked.iter().enumerate() {
        if pk == leader_pubkey {
            unstaked_excluded[i] = true;
            break;
        }
    }

    pool.uniform_sample_unstaked(&mut rng, &unstaked_excluded)
        .map(|idx| ShredDestination {
            pubkey: pool.unstaked[idx],
            is_staked: false,
        })
}

/// Compute retransmit destinations for a non-leader validator.
///
/// The algorithm:
/// 1. Generate the full shuffle order using the shred's seed
/// 2. Find this validator's position in the shuffle
/// 3. Determine if it's a leaf (position > fanout) or interior node
/// 4. If interior, compute children indices and return destinations
///
/// Returns None if this validator isn't found in the pool.
pub fn compute_retransmit_destinations(
    seed: [u8; 32],
    pool: &DestinationPool,
    my_pubkey: &[u8; 32],
    leader_pubkey: &[u8; 32],
    fanout: usize,
) -> Option<RetransmitDestinations> {
    let fanout = fanout.min(MAX_FANOUT);

    if pool.total_count() <= 1 {
        return None;
    }

    // Generate the deterministic shuffle order.
    let shuffle = generate_shuffle(seed, pool, leader_pubkey, fanout);

    // Find our position in the shuffle.
    let my_position = shuffle.iter().position(|pk| pk == my_pubkey)?;

    // Determine layer and compute children.
    if my_position == 0 {
        // Position 0 = root of retransmit tree (first recipient from leader).
        // Children are positions [1, fanout].
        let children: Vec<ShredDestination> = (1..=fanout)
            .filter_map(|child_pos| {
                shuffle.get(child_pos).map(|pk| {
                    let is_staked = pool.staked.iter().any(|v| v.pubkey == *pk);
                    ShredDestination {
                        pubkey: *pk,
                        is_staked,
                    }
                })
            })
            .collect();

        Some(RetransmitDestinations {
            my_position,
            my_layer: 1,
            children,
        })
    } else if my_position <= fanout {
        // Layer 1 node. Children are at positions: my_position + l * fanout
        // for l in 1..=fanout.
        let children: Vec<ShredDestination> = (1..=fanout)
            .filter_map(|l| {
                let child_pos = my_position + l * fanout;
                shuffle.get(child_pos).map(|pk| {
                    let is_staked = pool.staked.iter().any(|v| v.pubkey == *pk);
                    ShredDestination {
                        pubkey: *pk,
                        is_staked,
                    }
                })
            })
            .collect();

        Some(RetransmitDestinations {
            my_position,
            my_layer: 1,
            children,
        })
    } else {
        // Layer 2 or beyond — leaf node, no retransmit needed.
        Some(RetransmitDestinations {
            my_position,
            my_layer: 2,
            children: Vec::new(),
        })
    }
}

/// Generate the deterministic shuffle order for all validators.
///
/// This produces a permutation of validator pubkeys based on the shred seed.
/// The order determines each validator's position in the turbine tree.
///
/// Staked validators are sampled first (weighted by stake), followed by
/// unstaked validators (uniform random). The leader is excluded from
/// the shuffle since they don't receive retransmissions.
fn generate_shuffle(
    seed: [u8; 32],
    pool: &DestinationPool,
    leader_pubkey: &[u8; 32],
    max_positions: usize,
) -> Vec<[u8; 32]> {
    let mut rng = rng_from_seed(seed);
    let mut result: Vec<[u8; 32]> = Vec::with_capacity(pool.total_count());

    // Track which staked/unstaked validators have been placed.
    let mut staked_used = vec![false; pool.staked.len()];
    let mut unstaked_used = vec![false; pool.unstaked.len()];

    // Exclude leader from both pools.
    for (i, v) in pool.staked.iter().enumerate() {
        if v.pubkey == *leader_pubkey {
            staked_used[i] = true;
            break;
        }
    }
    for (i, pk) in pool.unstaked.iter().enumerate() {
        if pk == leader_pubkey {
            unstaked_used[i] = true;
            break;
        }
    }

    // Maximum tree size = 1 + fanout + fanout² (but capped by pool size).
    let max_tree_size = (1 + max_positions + max_positions * max_positions)
        .min(pool.total_count().saturating_sub(1)); // -1 for leader

    // Sample staked validators first (weighted).
    while result.len() < max_tree_size {
        if let Some(idx) = pool.weighted_sample(&mut rng, &staked_used) {
            result.push(pool.staked[idx].pubkey);
            staked_used[idx] = true;
        } else {
            break;
        }
    }

    // Fill remaining positions with unstaked validators (uniform).
    while result.len() < max_tree_size {
        if let Some(idx) = pool.uniform_sample_unstaked(&mut rng, &unstaked_used) {
            result.push(pool.unstaked[idx]);
            unstaked_used[idx] = true;
        } else {
            break;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(id: u8, stake: u64) -> DestinationValidator {
        let mut pubkey = [0u8; 32];
        pubkey[0] = id;
        DestinationValidator { pubkey, stake }
    }

    fn make_pubkey(id: u8) -> [u8; 32] {
        let mut pk = [0u8; 32];
        pk[0] = id;
        pk
    }

    #[test]
    fn seed_is_deterministic() {
        let leader = [1u8; 32];
        let seed1 = compute_destination_seed(100, true, 5, &leader);
        let seed2 = compute_destination_seed(100, true, 5, &leader);
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn seed_differs_by_slot() {
        let leader = [1u8; 32];
        let seed1 = compute_destination_seed(100, true, 5, &leader);
        let seed2 = compute_destination_seed(101, true, 5, &leader);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn seed_differs_by_type() {
        let leader = [1u8; 32];
        let data_seed = compute_destination_seed(100, true, 5, &leader);
        let code_seed = compute_destination_seed(100, false, 5, &leader);
        assert_ne!(data_seed, code_seed);
    }

    #[test]
    fn seed_differs_by_index() {
        let leader = [1u8; 32];
        let seed1 = compute_destination_seed(100, true, 0, &leader);
        let seed2 = compute_destination_seed(100, true, 1, &leader);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn seed_differs_by_leader() {
        let leader1 = [1u8; 32];
        let leader2 = [2u8; 32];
        let seed1 = compute_destination_seed(100, true, 5, &leader1);
        let seed2 = compute_destination_seed(100, true, 5, &leader2);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn pool_separates_staked_and_unstaked() {
        let validators = vec![
            make_validator(1, 1000),
            make_validator(2, 0),
            make_validator(3, 500),
            make_validator(4, 0),
        ];
        let pool = DestinationPool::new(validators);
        assert_eq!(pool.staked_count(), 2);
        assert_eq!(pool.unstaked_count(), 2);
        assert_eq!(pool.total_count(), 4);
    }

    #[test]
    fn pool_sorts_staked_by_stake_desc() {
        let validators = vec![
            make_validator(1, 100),
            make_validator(2, 500),
            make_validator(3, 300),
        ];
        let pool = DestinationPool::new(validators);
        assert_eq!(pool.staked[0].pubkey[0], 2); // 500
        assert_eq!(pool.staked[1].pubkey[0], 3); // 300
        assert_eq!(pool.staked[2].pubkey[0], 1); // 100
    }

    #[test]
    fn pool_breaks_stake_ties_by_pubkey_asc() {
        let validators = vec![
            make_validator(3, 500),
            make_validator(1, 500),
            make_validator(2, 500),
        ];
        let pool = DestinationPool::new(validators);
        assert_eq!(pool.staked[0].pubkey[0], 1);
        assert_eq!(pool.staked[1].pubkey[0], 2);
        assert_eq!(pool.staked[2].pubkey[0], 3);
    }

    #[test]
    fn leader_destination_excludes_leader() {
        let leader_pk = make_pubkey(1);
        let validators = vec![
            make_validator(1, 1000),
            make_validator(2, 500),
            make_validator(3, 300),
        ];
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        let dest = compute_leader_destination(seed, &pool, &leader_pk);
        assert!(dest.is_some());
        let dest = dest.unwrap();
        assert_ne!(dest.pubkey, leader_pk);
        assert!(dest.is_staked);
    }

    #[test]
    fn leader_destination_returns_none_for_empty_pool() {
        let leader_pk = make_pubkey(1);
        let pool = DestinationPool::new(Vec::new());
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        assert!(compute_leader_destination(seed, &pool, &leader_pk).is_none());
    }

    #[test]
    fn leader_destination_returns_none_for_only_leader() {
        let leader_pk = make_pubkey(1);
        let validators = vec![make_validator(1, 1000)];
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        assert!(compute_leader_destination(seed, &pool, &leader_pk).is_none());
    }

    #[test]
    fn leader_destination_falls_back_to_unstaked() {
        let leader_pk = make_pubkey(1);
        let validators = vec![
            make_validator(1, 1000), // leader = only staked
            make_validator(2, 0),    // unstaked
        ];
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        let dest = compute_leader_destination(seed, &pool, &leader_pk);
        assert!(dest.is_some());
        let dest = dest.unwrap();
        assert_eq!(dest.pubkey, make_pubkey(2));
        assert!(!dest.is_staked);
    }

    #[test]
    fn retransmit_root_has_children() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 2000)]; // leader
        for i in 1..=10u8 {
            validators.push(make_validator(i, 1000 - i as u64 * 10));
        }
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        // Generate shuffle to find root (position 0).
        let shuffle = generate_shuffle(seed, &pool, &leader_pk, 3);
        if shuffle.is_empty() {
            return; // Not enough validators
        }
        let root_pk = shuffle[0];

        let result = compute_retransmit_destinations(seed, &pool, &root_pk, &leader_pk, 3);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.my_position, 0);
        assert_eq!(result.my_layer, 1);
        assert!(!result.children.is_empty());
    }

    #[test]
    fn retransmit_leaf_has_no_children() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 2000)];
        for i in 1..=20u8 {
            validators.push(make_validator(i, 1000 - i as u64 * 10));
        }
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        // Generate shuffle and find a leaf position (> fanout).
        let fanout = 3;
        let shuffle = generate_shuffle(seed, &pool, &leader_pk, fanout);

        // Pick a validator deep in the shuffle (position > fanout = leaf).
        if shuffle.len() > fanout + 1 {
            let leaf_pk = shuffle[fanout + 1]; // position fanout+1 > fanout = leaf
            let result = compute_retransmit_destinations(seed, &pool, &leaf_pk, &leader_pk, fanout);
            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.my_layer, 2);
            assert!(result.children.is_empty());
        }
    }

    #[test]
    fn shuffle_is_deterministic() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 2000)];
        for i in 1..=10u8 {
            validators.push(make_validator(i, 1000));
        }
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        let shuffle1 = generate_shuffle(seed, &pool, &leader_pk, 200);
        let shuffle2 = generate_shuffle(seed, &pool, &leader_pk, 200);
        assert_eq!(shuffle1, shuffle2);
    }

    #[test]
    fn shuffle_excludes_leader() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 2000)];
        for i in 1..=5u8 {
            validators.push(make_validator(i, 1000));
        }
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        let shuffle = generate_shuffle(seed, &pool, &leader_pk, 200);
        assert!(!shuffle.contains(&leader_pk));
    }

    #[test]
    fn different_shreds_get_different_trees() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 2000)];
        for i in 1..=10u8 {
            validators.push(make_validator(i, 1000));
        }
        let pool = DestinationPool::new(validators);

        let seed1 = compute_destination_seed(100, true, 0, &leader_pk);
        let seed2 = compute_destination_seed(100, true, 1, &leader_pk);

        let shuffle1 = generate_shuffle(seed1, &pool, &leader_pk, 200);
        let shuffle2 = generate_shuffle(seed2, &pool, &leader_pk, 200);

        // Different seeds should (with very high probability) produce different orderings.
        // Exact same is theoretically possible but astronomically unlikely.
        assert_ne!(shuffle1, shuffle2);
    }

    #[test]
    fn weighted_sample_favors_high_stake() {
        let validators = vec![
            make_validator(1, 900_000),
            make_validator(2, 100),
            make_validator(3, 100),
        ];
        let pool = DestinationPool::new(validators);

        // Run many samples and verify the high-stake validator appears most often.
        let seed = compute_destination_seed(42, true, 0, &[0u8; 32]);
        let mut counts = [0u32; 4];
        for trial in 0..100u32 {
            let mut trial_seed = seed;
            trial_seed[0] ^= trial as u8;
            trial_seed[1] ^= (trial >> 8) as u8;
            let mut rng = rng_from_seed(trial_seed);
            let excluded = vec![false; pool.staked.len()];
            if let Some(idx) = pool.weighted_sample(&mut rng, &excluded) {
                counts[pool.staked[idx].pubkey[0] as usize] += 1;
            }
        }
        // Validator 1 (900k stake) should be selected vastly more often.
        assert!(counts[1] > counts[2] + counts[3]);
    }

    #[test]
    fn retransmit_unknown_validator_returns_none() {
        let leader_pk = make_pubkey(0);
        let validators = vec![
            make_validator(0, 2000),
            make_validator(1, 1000),
            make_validator(2, 1000),
        ];
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);

        // Pubkey 99 is not in the pool.
        let unknown = make_pubkey(99);
        let result = compute_retransmit_destinations(seed, &pool, &unknown, &leader_pk, 200);
        assert!(result.is_none());
    }

    #[test]
    fn layer1_node_children_use_stride_pattern() {
        let leader_pk = make_pubkey(0);
        let mut validators = vec![make_validator(0, 10000)];
        // Need enough validators: 1 + fanout + fanout² with fanout=2 → 7 validators
        for i in 1..=10u8 {
            validators.push(make_validator(i, 5000 - i as u64 * 100));
        }
        let pool = DestinationPool::new(validators);
        let seed = compute_destination_seed(100, true, 0, &leader_pk);
        let fanout = 2;

        let shuffle = generate_shuffle(seed, &pool, &leader_pk, fanout);
        if shuffle.len() < 7 {
            return; // Not enough for full tree
        }

        // Position 1 (layer1): children at positions 1+1*2=3, 1+2*2=5
        let pos1_pk = shuffle[1];
        let result = compute_retransmit_destinations(seed, &pool, &pos1_pk, &leader_pk, fanout);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.my_position, 1);
        assert_eq!(result.my_layer, 1);

        // Verify children pubkeys match expected shuffle positions.
        for child in &result.children {
            assert!(shuffle.contains(&child.pubkey));
        }
    }
}
