/// StakeHistory sysvar serialization wrapper.
///
/// Wraps the existing `StakeHistory` type to provide account-level
/// serialization. The stake history records the network-wide activation
/// and deactivation state across recent epochs, used for warmup/cooldown
/// rate calculations when delegating or withdrawing stake.
use crate::{EpochStakeEntry, StakeHistory, StakeHistoryEntry};

/// Serializable wrapper for the StakeHistory sysvar.
#[derive(Debug, Clone, Default)]
pub struct StakeHistorySysvar {
    pub history: StakeHistory,
}

impl StakeHistorySysvar {
    pub fn new(history: StakeHistory) -> Self {
        Self { history }
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Format: entry_count(u64) + entries(epoch(u64) + effective(u64)
    ///         + activating(u64) + deactivating(u64)) each.
    pub fn to_bytes(&self) -> Vec<u8> {
        let entries: Vec<&EpochStakeEntry> = self.history.iter().collect();
        let entry_size = 8 + 8 + 8 + 8; // epoch + 3 stake fields
        let mut buf = Vec::with_capacity(8 + entries.len() * entry_size);
        buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for entry in &entries {
            buf.extend_from_slice(&entry.epoch.to_le_bytes());
            buf.extend_from_slice(&entry.entry.effective.to_le_bytes());
            buf.extend_from_slice(&entry.entry.activating.to_le_bytes());
            buf.extend_from_slice(&entry.entry.deactivating.to_le_bytes());
        }
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let count = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let entry_size = 32; // 4 * u64
        if data.len() < 8 + count * entry_size {
            return None;
        }
        let mut history = StakeHistory::new();
        let mut offset = 8;
        for _ in 0..count {
            let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
            let effective = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().ok()?);
            let activating = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().ok()?);
            let deactivating = u64::from_le_bytes(data[offset + 24..offset + 32].try_into().ok()?);
            history.add(
                epoch,
                StakeHistoryEntry::new(effective, activating, deactivating),
            );
            offset += entry_size;
        }
        Some(Self { history })
    }
}

impl From<StakeHistory> for StakeHistorySysvar {
    fn from(history: StakeHistory) -> Self {
        Self::new(history)
    }
}
