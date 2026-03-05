/// Clock sysvar serialization wrapper.
///
/// Wraps the existing `Clock` type to provide account-level serialization
/// for the Clock sysvar. The clock tracks network time using slot numbers,
/// epoch boundaries, and stake-weighted timestamp estimates.
use crate::Clock;

/// Serializable wrapper around the consensus `Clock` type.
///
/// Provides binary serialization to and from the on-chain sysvar account
/// format (5 fields: slot, epoch_start_timestamp, epoch, leader_schedule_epoch,
/// unix_timestamp).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockSysvar {
    pub clock: Clock,
}

impl ClockSysvar {
    pub fn new(clock: Clock) -> Self {
        Self { clock }
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Layout: slot(u64) + epoch_start_timestamp(i64) + epoch(u64)
    ///         + leader_schedule_epoch(u64) + unix_timestamp(i64) = 40 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&self.clock.slot.to_le_bytes());
        buf.extend_from_slice(&self.clock.epoch_start_timestamp.to_le_bytes());
        buf.extend_from_slice(&self.clock.epoch.to_le_bytes());
        buf.extend_from_slice(&self.clock.leader_schedule_epoch.to_le_bytes());
        buf.extend_from_slice(&self.clock.unix_timestamp.to_le_bytes());
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let slot = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let epoch_start_timestamp = i64::from_le_bytes(data[8..16].try_into().ok()?);
        let epoch = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let leader_schedule_epoch = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let unix_timestamp = i64::from_le_bytes(data[32..40].try_into().ok()?);
        Some(Self {
            clock: Clock {
                slot,
                epoch_start_timestamp,
                epoch,
                leader_schedule_epoch,
                unix_timestamp,
            },
        })
    }
}

impl From<Clock> for ClockSysvar {
    fn from(clock: Clock) -> Self {
        Self::new(clock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_clock() -> Clock {
        Clock {
            slot: 12345,
            epoch_start_timestamp: -1_000_000,
            epoch: 42,
            leader_schedule_epoch: 43,
            unix_timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let sysvar = ClockSysvar::new(test_clock());
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes.len(), 40);
        let restored = ClockSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored, sysvar);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(ClockSysvar::from_bytes(&[0u8; 39]).is_none());
    }

    #[test]
    fn default_clock_roundtrip() {
        let sysvar = ClockSysvar::default();
        let bytes = sysvar.to_bytes();
        let restored = ClockSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.clock.slot, 0);
        assert_eq!(restored.clock.epoch, 0);
    }

    #[test]
    fn from_clock_conversion() {
        let clock = test_clock();
        let sysvar: ClockSysvar = clock.into();
        assert_eq!(sysvar.clock.slot, 12345);
    }

    #[test]
    fn negative_timestamps_preserved() {
        let mut clock = test_clock();
        clock.epoch_start_timestamp = -999_999_999;
        clock.unix_timestamp = -1;
        let sysvar = ClockSysvar::new(clock);
        let restored = ClockSysvar::from_bytes(&sysvar.to_bytes()).unwrap();
        assert_eq!(restored.clock.epoch_start_timestamp, -999_999_999);
        assert_eq!(restored.clock.unix_timestamp, -1);
    }
}
