use crate::EpochSchedule;
use karstflow_constants::consensus::{LEADER_SCHEDULE_ROTATION, MAX_VALIDATORS_IN_SCHEDULE};
use karstflow_storage::Pubkey;
use rand::distributions::{Distribution, WeightedIndex};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::collections::HashMap;
use std::sync::Arc;

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
            karstflow_constants::ledger::SLOTS_PER_EPOCH,
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
        let weighted_index =
            WeightedIndex::new(stakes).expect("non-empty stakes for leader schedule");

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

    /// Get the leader for an absolute slot, resolving epoch internally.
    ///
    /// Returns `None` if the slot does not belong to this schedule's epoch.
    pub fn leader_for_absolute_slot(
        &self,
        slot: u64,
        epoch_schedule: &EpochSchedule,
    ) -> Option<Pubkey> {
        let (epoch, slot_index) = epoch_schedule.get_epoch_and_slot_index(slot);
        if epoch != self.epoch {
            return None;
        }
        self.get_leader(slot_index)
    }
}

/// Multi-epoch leader schedule cache supporting absolute slot queries.
///
/// Holds the current and optionally the next epoch's schedule, enabling
/// seamless leader lookups across epoch boundaries. This mirrors the
/// dual-epoch approach where the next epoch's schedule is pre-computed
/// before the epoch transition occurs.
#[derive(Debug, Clone)]
pub struct EpochLeaders {
    current: Arc<LeaderSchedule>,
    next: Option<Arc<LeaderSchedule>>,
    epoch_schedule: EpochSchedule,
}

impl EpochLeaders {
    /// Create a new epoch leader cache with the current schedule.
    pub fn new(current: Arc<LeaderSchedule>, epoch_schedule: EpochSchedule) -> Self {
        Self {
            current,
            next: None,
            epoch_schedule,
        }
    }

    /// Set the pre-computed schedule for the next epoch.
    pub fn set_next(&mut self, schedule: Arc<LeaderSchedule>) {
        self.next = Some(schedule);
    }

    /// Advance to the next epoch, promoting the next schedule to current.
    ///
    /// Returns `true` if the advance succeeded (next schedule was available),
    /// `false` if no next schedule was set.
    pub fn advance_epoch(&mut self) -> bool {
        if let Some(next) = self.next.take() {
            self.current = next;
            true
        } else {
            false
        }
    }

    /// Look up the leader for an absolute slot number.
    ///
    /// Checks the current epoch first, then the next epoch schedule if
    /// available. Returns `None` for slots outside both epochs.
    pub fn get_leader(&self, slot: u64) -> Option<Pubkey> {
        let (epoch, slot_index) = self.epoch_schedule.get_epoch_and_slot_index(slot);

        if epoch == self.current.get_epoch() {
            return self.current.get_leader(slot_index);
        }

        if let Some(ref next) = self.next {
            if epoch == next.get_epoch() {
                return next.get_leader(slot_index);
            }
        }

        None
    }

    /// Get leaders for a range of absolute slots.
    ///
    /// Returns a vec of `(slot, Option<Pubkey>)` tuples for each slot
    /// in `[start_slot, start_slot + count)`.
    pub fn get_leaders_range(&self, start_slot: u64, count: u64) -> Vec<(u64, Option<Pubkey>)> {
        (0..count)
            .map(|i| {
                let slot = start_slot.saturating_add(i);
                (slot, self.get_leader(slot))
            })
            .collect()
    }

    /// Check whether a given validator is the leader for a specific slot.
    pub fn is_leader(&self, slot: u64, validator: &Pubkey) -> bool {
        self.get_leader(slot)
            .map(|leader| leader == *validator)
            .unwrap_or(false)
    }

    /// Get the current epoch schedule.
    pub fn epoch_schedule(&self) -> &EpochSchedule {
        &self.epoch_schedule
    }

    /// Get a reference to the current epoch's schedule.
    pub fn current_schedule(&self) -> &Arc<LeaderSchedule> {
        &self.current
    }

    /// Get a reference to the next epoch's schedule, if available.
    pub fn next_schedule(&self) -> Option<&Arc<LeaderSchedule>> {
        self.next.as_ref()
    }

    /// Build a leader schedule map for the current epoch, grouped by validator.
    ///
    /// Returns a map from validator pubkey to the list of absolute slot
    /// numbers where that validator is the leader. Used by the
    /// `getLeaderSchedule` RPC method.
    pub fn schedule_by_validator(&self) -> HashMap<Pubkey, Vec<u64>> {
        let first_slot = self
            .epoch_schedule
            .get_first_slot_in_epoch(self.current.get_epoch());
        let mut result: HashMap<Pubkey, Vec<u64>> = HashMap::new();

        for i in 0..self.current.len() as u64 {
            if let Some(leader) = self.current.get_leader(i) {
                result.entry(leader).or_default().push(first_slot + i);
            }
        }

        result
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
            karstflow_constants::ledger::SLOTS_PER_EPOCH as usize
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

        let max_slot = karstflow_constants::ledger::SLOTS_PER_EPOCH;
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

    #[test]
    fn absolute_slot_leader_returns_leader_for_matching_epoch() {
        let validator = Pubkey::new_unique();
        let schedule = LeaderSchedule::new(0, &[(validator, 1000)]).unwrap();
        let epoch_schedule = EpochSchedule::default();

        // Slot 0 is in epoch 0 — should return the validator
        assert_eq!(
            schedule.leader_for_absolute_slot(0, &epoch_schedule),
            Some(validator)
        );
        assert_eq!(
            schedule.leader_for_absolute_slot(100, &epoch_schedule),
            Some(validator)
        );
    }

    #[test]
    fn absolute_slot_leader_returns_none_for_wrong_epoch() {
        let validator = Pubkey::new_unique();
        let schedule = LeaderSchedule::new(0, &[(validator, 1000)]).unwrap();
        let epoch_schedule = EpochSchedule::default();

        // Slot in epoch 1 — should return None
        let first_slot_epoch_1 = epoch_schedule.get_first_slot_in_epoch(1);
        assert_eq!(
            schedule.leader_for_absolute_slot(first_slot_epoch_1, &epoch_schedule),
            None
        );
    }

    #[test]
    fn epoch_leaders_queries_current_epoch() {
        let validator = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let leaders = EpochLeaders::new(schedule, epoch_schedule);

        assert_eq!(leaders.get_leader(0), Some(validator));
        assert_eq!(leaders.get_leader(100), Some(validator));
    }

    #[test]
    fn epoch_leaders_queries_next_epoch() {
        let v_a = Pubkey::new_unique();
        let v_b = Pubkey::new_unique();
        let epoch_schedule = EpochSchedule::default();

        let current = Arc::new(LeaderSchedule::new(0, &[(v_a, 1000)]).unwrap());
        let next = Arc::new(LeaderSchedule::new(1, &[(v_b, 1000)]).unwrap());

        let mut leaders = EpochLeaders::new(current, epoch_schedule);
        leaders.set_next(next);

        // Current epoch -> v_a
        assert_eq!(leaders.get_leader(0), Some(v_a));

        // Next epoch -> v_b
        let first_next = epoch_schedule.get_first_slot_in_epoch(1);
        assert_eq!(leaders.get_leader(first_next), Some(v_b));
    }

    #[test]
    fn epoch_leaders_returns_none_for_unknown_epoch() {
        let validator = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let leaders = EpochLeaders::new(schedule, epoch_schedule);

        // Epoch 2 — neither current nor next
        let far_slot = epoch_schedule.get_first_slot_in_epoch(2);
        assert_eq!(leaders.get_leader(far_slot), None);
    }

    #[test]
    fn epoch_leaders_advance_promotes_next_to_current() {
        let v_a = Pubkey::new_unique();
        let v_b = Pubkey::new_unique();
        let epoch_schedule = EpochSchedule::default();

        let current = Arc::new(LeaderSchedule::new(0, &[(v_a, 1000)]).unwrap());
        let next = Arc::new(LeaderSchedule::new(1, &[(v_b, 1000)]).unwrap());

        let mut leaders = EpochLeaders::new(current, epoch_schedule);
        leaders.set_next(next);

        assert!(leaders.advance_epoch());

        // After advance, epoch 1 is now current
        let first_next = epoch_schedule.get_first_slot_in_epoch(1);
        assert_eq!(leaders.get_leader(first_next), Some(v_b));

        // Old epoch 0 is no longer available
        assert_eq!(leaders.get_leader(0), None);

        // No next schedule after advance
        assert!(leaders.next_schedule().is_none());
    }

    #[test]
    fn epoch_leaders_advance_fails_without_next() {
        let validator = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let mut leaders = EpochLeaders::new(schedule, epoch_schedule);

        assert!(!leaders.advance_epoch());
        // Current schedule still valid
        assert_eq!(leaders.get_leader(0), Some(validator));
    }

    #[test]
    fn epoch_leaders_is_leader_checks_identity() {
        let leader = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(leader, 1000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let leaders = EpochLeaders::new(schedule, epoch_schedule);

        assert!(leaders.is_leader(0, &leader));
        assert!(!leaders.is_leader(0, &other));
    }

    #[test]
    fn epoch_leaders_range_returns_leaders_for_slot_range() {
        let validator = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(validator, 1000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let leaders = EpochLeaders::new(schedule, epoch_schedule);

        let range = leaders.get_leaders_range(0, 4);
        assert_eq!(range.len(), 4);
        for (slot, leader) in &range {
            assert!(leader.is_some(), "slot {slot} should have a leader");
            assert_eq!(leader.unwrap(), validator);
        }
    }

    #[test]
    fn epoch_leaders_schedule_by_validator_groups_slots() {
        let v_a = Pubkey::new_unique();
        let v_b = Pubkey::new_unique();
        let schedule = Arc::new(LeaderSchedule::new(0, &[(v_a, 5000), (v_b, 5000)]).unwrap());
        let epoch_schedule = EpochSchedule::default();
        let leaders = EpochLeaders::new(schedule, epoch_schedule);

        let by_validator = leaders.schedule_by_validator();
        assert!(by_validator.contains_key(&v_a));
        assert!(by_validator.contains_key(&v_b));

        let total_slots: usize = by_validator.values().map(|v| v.len()).sum();
        assert_eq!(
            total_slots,
            karstflow_constants::ledger::SLOTS_PER_EPOCH as usize
        );
    }
}
