use paradencer_constants::consensus::{LEADER_SCHEDULE_ROTATION, MAX_VALIDATORS_IN_SCHEDULE};
use paradencer_storage::Pubkey;
use rand::distributions::{Distribution, WeightedIndex};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderScheduleError {
    NoValidators,
    TooManyValidators,
}

#[derive(Debug, Clone)]
pub struct LeaderSchedule {
    slot_leaders: Vec<Pubkey>,
    epoch: u64,
}

impl LeaderSchedule {
    /// Generate a deterministic stake-weighted leader schedule for an epoch.
    ///
    /// Validators are sorted by (stake desc, pubkey desc) for determinism.
    /// A ChaCha20 PRNG seeded by epoch number produces a weighted random
    /// sample every `LEADER_SCHEDULE_ROTATION` slots (4 by default),
    /// giving each sampled leader a consecutive run of slots.
    pub fn new(epoch: u64, validators: &[(Pubkey, u64)]) -> Result<Self, LeaderScheduleError> {
        if validators.is_empty() {
            return Err(LeaderScheduleError::NoValidators);
        }

        if validators.len() > MAX_VALIDATORS_IN_SCHEDULE {
            return Err(LeaderScheduleError::TooManyValidators);
        }

        let total_stake: u64 = validators.iter().map(|(_, stake)| stake).sum();
        if total_stake == 0 {
            return Err(LeaderScheduleError::NoValidators);
        }

        let slot_leaders = Self::generate_schedule(
            epoch,
            validators,
            paradencer_constants::ledger::SLOTS_PER_EPOCH,
        );

        Ok(Self {
            slot_leaders,
            epoch,
        })
    }

    /// Generate the schedule using ChaCha20 weighted sampling with rotation.
    fn generate_schedule(epoch: u64, validators: &[(Pubkey, u64)], slots: u64) -> Vec<Pubkey> {
        // Sort by (stake desc, pubkey desc) for determinism, then dedup
        let mut sorted: Vec<(&Pubkey, u64)> = validators.iter().map(|(pk, s)| (pk, *s)).collect();
        sort_stakes(&mut sorted);

        let (keys, stakes): (Vec<&Pubkey>, Vec<u64>) = sorted.into_iter().unzip();
        let weighted_index = WeightedIndex::new(stakes).unwrap();

        // Seed ChaCha20 with epoch in first 8 bytes, rest zero
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&epoch.to_le_bytes());
        let rng = &mut ChaChaRng::from_seed(seed);

        let rotation = LEADER_SCHEDULE_ROTATION;
        let mut current_leader = Pubkey::default();

        (0..slots)
            .map(|i| {
                if i % rotation == 0 {
                    current_leader = *keys[weighted_index.sample(rng)];
                }
                current_leader
            })
            .collect()
    }

    pub fn get_leader(&self, slot_index: u64) -> Option<Pubkey> {
        self.slot_leaders.get(slot_index as usize).copied()
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> usize {
        self.slot_leaders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slot_leaders.is_empty()
    }

    pub fn validator_slot_counts(&self) -> HashMap<Pubkey, usize> {
        let mut counts = HashMap::new();
        for leader in &self.slot_leaders {
            *counts.entry(*leader).or_insert(0) += 1;
        }
        counts
    }
}

/// Sort validators by stake descending, then by pubkey descending for
/// determinism when stakes are equal. Dedup identical entries.
fn sort_stakes(stakes: &mut Vec<(&Pubkey, u64)>) {
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });
    stakes.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_schedule_rejects_empty_validators() {
        let result = LeaderSchedule::new(0, &[]);
        assert!(matches!(result, Err(LeaderScheduleError::NoValidators)));
    }

    #[test]
    fn leader_schedule_rejects_zero_total_stake() {
        let validators = vec![(Pubkey::new_unique(), 0), (Pubkey::new_unique(), 0)];
        let result = LeaderSchedule::new(0, &validators);
        assert!(matches!(result, Err(LeaderScheduleError::NoValidators)));
    }

    #[test]
    fn leader_schedule_creates_valid_schedule_for_single_validator() {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let schedule = LeaderSchedule::new(0, &validators).unwrap();

        assert_eq!(schedule.get_epoch(), 0);
        assert_eq!(
            schedule.len(),
            paradencer_constants::ledger::SLOTS_PER_EPOCH as usize
        );

        for slot_index in 0..100 {
            assert_eq!(schedule.get_leader(slot_index), Some(validator));
        }
    }

    #[test]
    fn leader_schedule_distributes_slots_proportionally() {
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let validators = vec![(validator_a, 7000), (validator_b, 3000)];

        let schedule = LeaderSchedule::new(0, &validators).unwrap();

        let counts = schedule.validator_slot_counts();
        let count_a = counts.get(&validator_a).copied().unwrap_or(0);
        let count_b = counts.get(&validator_b).copied().unwrap_or(0);

        let ratio_a = count_a as f64 / schedule.len() as f64;
        let ratio_b = count_b as f64 / schedule.len() as f64;

        assert!(
            (ratio_a - 0.7).abs() < 0.05,
            "Expected ~70% for validator_a, got {:.1}%",
            ratio_a * 100.0
        );
        assert!(
            (ratio_b - 0.3).abs() < 0.05,
            "Expected ~30% for validator_b, got {:.1}%",
            ratio_b * 100.0
        );
    }

    #[test]
    fn leader_schedule_changes_with_epoch() {
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let validators = vec![(validator_a, 5000), (validator_b, 5000)];

        let schedule_epoch_0 = LeaderSchedule::new(0, &validators).unwrap();
        let schedule_epoch_1 = LeaderSchedule::new(1, &validators).unwrap();

        let mut differences = 0;
        for slot_index in 0..1000 {
            if schedule_epoch_0.get_leader(slot_index) != schedule_epoch_1.get_leader(slot_index) {
                differences += 1;
            }
        }

        assert!(differences > 0, "Schedules should differ across epochs");
    }

    #[test]
    fn leader_schedule_returns_none_for_out_of_bounds_slot() {
        let validator = Pubkey::new_unique();
        let validators = vec![(validator, 1000)];
        let schedule = LeaderSchedule::new(0, &validators).unwrap();

        let max_slot = paradencer_constants::ledger::SLOTS_PER_EPOCH;
        assert!(schedule.get_leader(max_slot).is_none());
        assert!(schedule.get_leader(max_slot + 100).is_none());
    }

    #[test]
    fn leader_schedule_is_deterministic() {
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let validators = vec![(validator_a, 5000), (validator_b, 5000)];

        let schedule_1 = LeaderSchedule::new(42, &validators).unwrap();
        let schedule_2 = LeaderSchedule::new(42, &validators).unwrap();

        for slot_index in 0..schedule_1.len() as u64 {
            assert_eq!(
                schedule_1.get_leader(slot_index),
                schedule_2.get_leader(slot_index),
                "Schedules must be identical for same epoch and validators"
            );
        }
    }

    #[test]
    fn leader_schedule_uses_4_slot_rotation() {
        let validator_a = Pubkey::new_unique();
        let validator_b = Pubkey::new_unique();
        let validators = vec![(validator_a, 5000), (validator_b, 5000)];

        let schedule = LeaderSchedule::new(0, &validators).unwrap();

        // Each leader rotation is 4 consecutive slots
        let rotation = LEADER_SCHEDULE_ROTATION as usize;
        for chunk_start in (0..100).step_by(rotation) {
            let leader = schedule.get_leader(chunk_start as u64).unwrap();
            for offset in 1..rotation {
                let slot = chunk_start + offset;
                assert_eq!(
                    schedule.get_leader(slot as u64),
                    Some(leader),
                    "Slots {}-{} should have the same leader",
                    chunk_start,
                    chunk_start + rotation - 1
                );
            }
        }
    }

    #[test]
    fn sort_stakes_orders_by_stake_desc_then_pubkey_desc() {
        let pk_a = Pubkey::from([1u8; 32]);
        let pk_b = Pubkey::from([2u8; 32]);
        let pk_c = Pubkey::from([3u8; 32]);

        let mut stakes = vec![(&pk_a, 100), (&pk_b, 200), (&pk_c, 100)];
        sort_stakes(&mut stakes);

        // pk_b (200) first, then pk_c (100) before pk_a (100) because 3 > 1
        assert_eq!(stakes[0], (&pk_b, 200));
        assert_eq!(stakes[1], (&pk_c, 100));
        assert_eq!(stakes[2], (&pk_a, 100));
    }
}
