use paradencer_constants::consensus::MAX_VALIDATORS_IN_SCHEDULE;
use paradencer_storage::Pubkey;
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

        let mut slot_leaders = Vec::new();
        let slots_per_epoch = paradencer_constants::ledger::SLOTS_PER_EPOCH;

        for slot_index in 0..slots_per_epoch {
            let leader = Self::select_leader_for_slot(slot_index, validators, total_stake, epoch);
            slot_leaders.push(leader);
        }

        Ok(Self {
            slot_leaders,
            epoch,
        })
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

    fn select_leader_for_slot(
        slot_index: u64,
        validators: &[(Pubkey, u64)],
        total_stake: u64,
        epoch: u64,
    ) -> Pubkey {
        let seed = Self::compute_seed(slot_index, epoch);
        let stake_target = (seed % total_stake) + 1;

        let mut cumulative_stake = 0_u64;
        for (pubkey, stake) in validators {
            cumulative_stake = cumulative_stake.saturating_add(*stake);
            if cumulative_stake >= stake_target {
                return *pubkey;
            }
        }

        validators[0].0
    }

    fn compute_seed(slot_index: u64, epoch: u64) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        slot_index.hash(&mut hasher);
        epoch.hash(&mut hasher);
        hasher.finish()
    }
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

        assert!((ratio_a - 0.7).abs() < 0.01);
        assert!((ratio_b - 0.3).abs() < 0.01);
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
}
