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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_history() -> StakeHistory {
        let mut h = StakeHistory::new();
        h.add(10, StakeHistoryEntry::new(1000, 200, 50));
        h.add(11, StakeHistoryEntry::new(1100, 100, 30));
        h
    }

    #[test]
    fn serialization_roundtrip_empty() {
        let sysvar = StakeHistorySysvar::new(StakeHistory::new());
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes.len(), 8); // just the count
        let restored = StakeHistorySysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.history.iter().count(), 0);
    }

    #[test]
    fn serialization_roundtrip_with_entries() {
        let sysvar = StakeHistorySysvar::new(test_history());
        let bytes = sysvar.to_bytes();
        // 8 (count) + 2 * 32 (entries) = 72
        assert_eq!(bytes.len(), 72);
        let restored = StakeHistorySysvar::from_bytes(&bytes).unwrap();
        let entries: Vec<_> = restored.history.iter().collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(StakeHistorySysvar::from_bytes(&[0u8; 7]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_entries() {
        let mut data = vec![0u8; 8];
        // Say 1 entry exists
        data[0..8].copy_from_slice(&1u64.to_le_bytes());
        // But no entry data follows
        assert!(StakeHistorySysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn from_stake_history_conversion() {
        let h = test_history();
        let sysvar: StakeHistorySysvar = h.into();
        assert_eq!(sysvar.history.iter().count(), 2);
    }

    #[test]
    fn entry_values_preserved() {
        let mut h = StakeHistory::new();
        h.add(99, StakeHistoryEntry::new(5000, 300, 100));
        let sysvar = StakeHistorySysvar::new(h);
        let restored = StakeHistorySysvar::from_bytes(&sysvar.to_bytes()).unwrap();
        let entry = restored.history.iter().next().unwrap();
        assert_eq!(entry.epoch, 99);
        assert_eq!(entry.entry.effective, 5000);
        assert_eq!(entry.entry.activating, 300);
        assert_eq!(entry.entry.deactivating, 100);
    }
}
