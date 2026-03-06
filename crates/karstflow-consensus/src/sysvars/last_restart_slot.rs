//! LastRestartSlot sysvar.
//!
//! Records the slot at which the cluster was last restarted. Programs
//! can use this to detect when the cluster has undergone a restart and
//! adjust their behavior accordingly (e.g., resetting caches or
//! re-evaluating state).

/// Sysvar recording the most recent cluster restart slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LastRestartSlotSysvar {
    /// The slot number of the last cluster restart, or 0 if never restarted.
    pub slot: u64,
}

impl LastRestartSlotSysvar {
    pub fn new(slot: u64) -> Self {
        Self { slot }
    }

    /// Serialize to bytes for sysvar account data.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.slot.to_le_bytes().to_vec()
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let slot = u64::from_le_bytes(data[0..8].try_into().ok()?);
        Some(Self { slot })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serialization() {
        let sysvar = LastRestartSlotSysvar::new(42);
        let bytes = sysvar.to_bytes();
        let decoded = LastRestartSlotSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.slot, 42);
    }

    #[test]
    fn from_bytes_too_short() {
        assert!(LastRestartSlotSysvar::from_bytes(&[1, 2, 3]).is_none());
    }

    #[test]
    fn from_bytes_empty() {
        assert!(LastRestartSlotSysvar::from_bytes(&[]).is_none());
    }

    #[test]
    fn default_is_zero() {
        let sysvar = LastRestartSlotSysvar::default();
        assert_eq!(sysvar.slot, 0);
    }

    #[test]
    fn roundtrip_max_value() {
        let sysvar = LastRestartSlotSysvar::new(u64::MAX);
        let bytes = sysvar.to_bytes();
        let decoded = LastRestartSlotSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.slot, u64::MAX);
    }

    #[test]
    fn from_bytes_extra_data_accepted() {
        let mut data = 99u64.to_le_bytes().to_vec();
        data.extend_from_slice(&[0xFF; 8]); // extra trailing bytes
        let decoded = LastRestartSlotSysvar::from_bytes(&data).unwrap();
        assert_eq!(decoded.slot, 99);
    }
}
