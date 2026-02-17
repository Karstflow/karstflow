/// EpochSchedule sysvar serialization wrapper.
///
/// Wraps the existing `EpochSchedule` type to provide account-level serialization.
/// The epoch schedule determines how slots map to epochs and controls
/// warmup behavior for new clusters.
use crate::{EpochSchedule, EpochScheduleConfig};

/// Serializable wrapper for the EpochSchedule sysvar.
///
/// Layout: slots_per_epoch(u64) + leader_schedule_slot_offset(u64)
///         + warmup(bool as u8) + first_normal_epoch(u64) + first_normal_slot(u64)
///         = 33 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochScheduleSysvar {
    pub schedule: EpochSchedule,
}

impl EpochScheduleSysvar {
    pub fn new(schedule: EpochSchedule) -> Self {
        Self { schedule }
    }

    /// Serialize to bytes for sysvar account data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let config = self.schedule.config();
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&config.slots_per_epoch.to_le_bytes());
        buf.extend_from_slice(&config.leader_schedule_slot_offset.to_le_bytes());
        buf.push(config.warmup as u8);
        buf.extend_from_slice(&config.first_normal_epoch.to_le_bytes());
        buf.extend_from_slice(&config.first_normal_slot.to_le_bytes());
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        let slots_per_epoch = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let leader_schedule_slot_offset = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let warmup = data[16] != 0;
        let first_normal_epoch = u64::from_le_bytes(data[17..25].try_into().ok()?);
        let first_normal_slot = u64::from_le_bytes(data[25..33].try_into().ok()?);

        let config = EpochScheduleConfig {
            slots_per_epoch,
            leader_schedule_slot_offset,
            warmup,
            first_normal_epoch,
            first_normal_slot,
        };
        Some(Self {
            schedule: EpochSchedule::new(config),
        })
    }
}

impl Default for EpochScheduleSysvar {
    fn default() -> Self {
        Self {
            schedule: EpochSchedule::default(),
        }
    }
}

impl From<EpochSchedule> for EpochScheduleSysvar {
    fn from(schedule: EpochSchedule) -> Self {
        Self::new(schedule)
    }
}
