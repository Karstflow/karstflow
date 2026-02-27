use paradencer_constants::ledger::SLOTS_PER_EPOCH;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScheduleConfig {
    pub slots_per_epoch: u64,
    pub leader_schedule_slot_offset: u64,
    pub warmup: bool,
    pub first_normal_epoch: u64,
    pub first_normal_slot: u64,
}

impl Default for EpochScheduleConfig {
    fn default() -> Self {
        Self {
            slots_per_epoch: SLOTS_PER_EPOCH,
            leader_schedule_slot_offset: SLOTS_PER_EPOCH,
            warmup: false,
            first_normal_epoch: 0,
            first_normal_slot: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSchedule {
    config: EpochScheduleConfig,
}

impl EpochSchedule {
    pub fn new(config: EpochScheduleConfig) -> Self {
        Self { config }
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &EpochScheduleConfig {
        &self.config
    }

    pub fn get_epoch(&self, slot: u64) -> u64 {
        if !self.config.warmup || slot >= self.config.first_normal_slot {
            let normal_slot_index = slot.saturating_sub(self.config.first_normal_slot);
            self.config
                .first_normal_epoch
                .saturating_add(normal_slot_index / self.config.slots_per_epoch)
        } else {
            self.get_epoch_slow(slot)
        }
    }

    pub fn get_epoch_and_slot_index(&self, slot: u64) -> (u64, u64) {
        if !self.config.warmup || slot >= self.config.first_normal_slot {
            let normal_slot_index = slot.saturating_sub(self.config.first_normal_slot);
            let epoch = self
                .config
                .first_normal_epoch
                .saturating_add(normal_slot_index / self.config.slots_per_epoch);
            let slot_index = normal_slot_index % self.config.slots_per_epoch;
            (epoch, slot_index)
        } else {
            let epoch = self.get_epoch_slow(slot);
            let slot_index = slot.saturating_sub(self.get_first_slot_in_epoch(epoch));
            (epoch, slot_index)
        }
    }

    pub fn get_first_slot_in_epoch(&self, epoch: u64) -> u64 {
        if !self.config.warmup || epoch >= self.config.first_normal_epoch {
            let normal_epoch_index = epoch.saturating_sub(self.config.first_normal_epoch);
            self.config
                .first_normal_slot
                .saturating_add(normal_epoch_index.saturating_mul(self.config.slots_per_epoch))
        } else {
            self.get_first_slot_in_epoch_slow(epoch)
        }
    }

    pub fn get_last_slot_in_epoch(&self, epoch: u64) -> u64 {
        self.get_first_slot_in_epoch(epoch.saturating_add(1))
            .saturating_sub(1)
    }

    pub fn get_slots_in_epoch(&self, epoch: u64) -> u64 {
        if !self.config.warmup || epoch >= self.config.first_normal_epoch {
            self.config.slots_per_epoch
        } else {
            2_u64.saturating_pow(epoch.min(63) as u32)
        }
    }

    pub fn get_leader_schedule_epoch(&self, slot: u64) -> u64 {
        if slot < self.config.leader_schedule_slot_offset {
            0
        } else {
            self.get_epoch(slot.saturating_sub(self.config.leader_schedule_slot_offset))
        }
    }

    fn get_epoch_slow(&self, slot: u64) -> u64 {
        let mut epoch = 0_u64;
        let mut slot_index = 0_u64;
        while slot_index.saturating_add(self.get_slots_in_epoch(epoch)) <= slot {
            slot_index = slot_index.saturating_add(self.get_slots_in_epoch(epoch));
            epoch = epoch.saturating_add(1);
        }
        epoch
    }

    fn get_first_slot_in_epoch_slow(&self, epoch: u64) -> u64 {
        let mut slot = 0_u64;
        for e in 0..epoch {
            slot = slot.saturating_add(self.get_slots_in_epoch(e));
        }
        slot
    }
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self::new(EpochScheduleConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_schedule_computes_epoch_for_slot() {
        let schedule = EpochSchedule::default();
        assert_eq!(schedule.get_epoch(0), 0);
        assert_eq!(schedule.get_epoch(SLOTS_PER_EPOCH - 1), 0);
        assert_eq!(schedule.get_epoch(SLOTS_PER_EPOCH), 1);
        assert_eq!(schedule.get_epoch(SLOTS_PER_EPOCH * 2), 2);
    }

    #[test]
    fn epoch_schedule_computes_first_slot_in_epoch() {
        let schedule = EpochSchedule::default();
        assert_eq!(schedule.get_first_slot_in_epoch(0), 0);
        assert_eq!(schedule.get_first_slot_in_epoch(1), SLOTS_PER_EPOCH);
        assert_eq!(schedule.get_first_slot_in_epoch(2), SLOTS_PER_EPOCH * 2);
    }

    #[test]
    fn epoch_schedule_computes_last_slot_in_epoch() {
        let schedule = EpochSchedule::default();
        assert_eq!(schedule.get_last_slot_in_epoch(0), SLOTS_PER_EPOCH - 1);
        assert_eq!(schedule.get_last_slot_in_epoch(1), SLOTS_PER_EPOCH * 2 - 1);
    }

    #[test]
    fn epoch_schedule_computes_slots_in_epoch() {
        let schedule = EpochSchedule::default();
        assert_eq!(schedule.get_slots_in_epoch(0), SLOTS_PER_EPOCH);
        assert_eq!(schedule.get_slots_in_epoch(100), SLOTS_PER_EPOCH);
    }

    #[test]
    fn epoch_schedule_computes_leader_schedule_epoch() {
        let schedule = EpochSchedule::default();
        assert_eq!(schedule.get_leader_schedule_epoch(0), 0);
        assert_eq!(schedule.get_leader_schedule_epoch(SLOTS_PER_EPOCH - 1), 0);
        assert_eq!(schedule.get_leader_schedule_epoch(SLOTS_PER_EPOCH), 0);
        assert_eq!(
            schedule.get_leader_schedule_epoch(SLOTS_PER_EPOCH * 2 - 1),
            0
        );
        assert_eq!(schedule.get_leader_schedule_epoch(SLOTS_PER_EPOCH * 2), 1);
    }

    #[test]
    fn epoch_schedule_with_warmup_uses_exponential_growth() {
        let schedule = EpochSchedule::new(EpochScheduleConfig {
            slots_per_epoch: SLOTS_PER_EPOCH,
            leader_schedule_slot_offset: SLOTS_PER_EPOCH,
            warmup: true,
            first_normal_epoch: 10,
            first_normal_slot: (0..10).map(|e| 2_u64.pow(e)).sum(),
        });

        assert_eq!(schedule.get_slots_in_epoch(0), 1);
        assert_eq!(schedule.get_slots_in_epoch(1), 2);
        assert_eq!(schedule.get_slots_in_epoch(2), 4);
        assert_eq!(schedule.get_slots_in_epoch(9), 512);
        assert_eq!(schedule.get_slots_in_epoch(10), SLOTS_PER_EPOCH);

        assert_eq!(schedule.get_first_slot_in_epoch(0), 0);
        assert_eq!(schedule.get_first_slot_in_epoch(1), 1);
        assert_eq!(schedule.get_first_slot_in_epoch(2), 3);
        assert_eq!(schedule.get_first_slot_in_epoch(3), 7);
    }
}
