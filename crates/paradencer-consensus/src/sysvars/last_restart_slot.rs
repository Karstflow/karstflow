/// LastRestartSlot sysvar.
///
/// Records the slot at which the cluster was last restarted. Programs
/// can use this to detect when the cluster has undergone a restart and
/// adjust their behavior accordingly (e.g., resetting caches or
/// re-evaluating state).

/// Sysvar recording the most recent cluster restart slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Default for LastRestartSlotSysvar {
    fn default() -> Self {
        Self { slot: 0 }
    }
}
