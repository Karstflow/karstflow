/// RecentBlockhashes sysvar (deprecated).
///
/// Maintains a list of recent blockhashes paired with fee calculator data.
/// This sysvar is deprecated in favor of direct blockhash age checks,
/// but it must remain available for backward compatibility with older programs.
use karstflow_constants::sysvars::MAX_RECENT_BLOCKHASHES;

/// Entry pairing a blockhash with its associated fee rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentBlockhashEntry {
    pub blockhash: [u8; 32],
    pub lamports_per_signature: u64,
}

/// Deprecated sysvar containing recent blockhashes and their fee rates.
///
/// New programs should query blockhash age via the runtime instead.
#[derive(Debug, Clone)]
pub struct RecentBlockhashesSysvar {
    entries: Vec<RecentBlockhashEntry>,
}

impl RecentBlockhashesSysvar {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_RECENT_BLOCKHASHES),
        }
    }

    /// Add a blockhash to the front (most recent position).
    ///
    /// Evicts the oldest entry if at capacity.
    pub fn add(&mut self, blockhash: [u8; 32], lamports_per_signature: u64) {
        self.entries.insert(
            0,
            RecentBlockhashEntry {
                blockhash,
                lamports_per_signature,
            },
        );
        if self.entries.len() > MAX_RECENT_BLOCKHASHES {
            self.entries.truncate(MAX_RECENT_BLOCKHASHES);
        }
    }

    /// Get number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries (most recent first).
    pub fn iter(&self) -> impl Iterator<Item = &RecentBlockhashEntry> {
        self.entries.iter()
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Format: entry_count(u64) + entries(blockhash([u8;32]) + lamports_per_signature(u64)).
    pub fn to_bytes(&self) -> Vec<u8> {
        let entry_size = 32 + 8;
        let mut buf = Vec::with_capacity(8 + self.entries.len() * entry_size);
        buf.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.blockhash);
            buf.extend_from_slice(&entry.lamports_per_signature.to_le_bytes());
        }
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let count = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let entry_size = 32 + 8;
        if data.len() < 8 + count * entry_size {
            return None;
        }
        let mut entries = Vec::with_capacity(count);
        let mut offset = 8;
        for _ in 0..count {
            let mut blockhash = [0u8; 32];
            blockhash.copy_from_slice(&data[offset..offset + 32]);
            let lamports_per_signature =
                u64::from_le_bytes(data[offset + 32..offset + 40].try_into().ok()?);
            entries.push(RecentBlockhashEntry {
                blockhash,
                lamports_per_signature,
            });
            offset += entry_size;
        }
        Some(Self { entries })
    }
}

impl Default for RecentBlockhashesSysvar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bh(b: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    #[test]
    fn new_is_empty() {
        let rbs = RecentBlockhashesSysvar::new();
        assert!(rbs.is_empty());
        assert_eq!(rbs.len(), 0);
    }

    #[test]
    fn add_and_iterate() {
        let mut rbs = RecentBlockhashesSysvar::new();
        rbs.add(bh(1), 5000);
        rbs.add(bh(2), 6000);

        assert_eq!(rbs.len(), 2);
        let entries: Vec<_> = rbs.iter().collect();
        // Most recent first
        assert_eq!(entries[0].blockhash, bh(2));
        assert_eq!(entries[0].lamports_per_signature, 6000);
        assert_eq!(entries[1].blockhash, bh(1));
    }

    #[test]
    fn eviction_at_capacity() {
        let mut rbs = RecentBlockhashesSysvar::new();
        for i in 0..MAX_RECENT_BLOCKHASHES {
            rbs.add(bh(i as u8), 5000);
        }
        assert_eq!(rbs.len(), MAX_RECENT_BLOCKHASHES);

        // Add one more — oldest should be evicted
        rbs.add(bh(255), 9999);
        assert_eq!(rbs.len(), MAX_RECENT_BLOCKHASHES);

        // Most recent is bh(255)
        let first = rbs.iter().next().unwrap();
        assert_eq!(first.blockhash, bh(255));
        assert_eq!(first.lamports_per_signature, 9999);
    }

    #[test]
    fn serialization_roundtrip_empty() {
        let rbs = RecentBlockhashesSysvar::new();
        let bytes = rbs.to_bytes();
        let restored = RecentBlockhashesSysvar::from_bytes(&bytes).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn serialization_roundtrip_with_entries() {
        let mut rbs = RecentBlockhashesSysvar::new();
        rbs.add(bh(10), 5000);
        rbs.add(bh(20), 7000);
        rbs.add(bh(30), 9000);

        let bytes = rbs.to_bytes();
        let restored = RecentBlockhashesSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 3);

        let entries: Vec<_> = restored.iter().collect();
        assert_eq!(entries[0].blockhash, bh(30));
        assert_eq!(entries[0].lamports_per_signature, 9000);
        assert_eq!(entries[2].blockhash, bh(10));
        assert_eq!(entries[2].lamports_per_signature, 5000);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(RecentBlockhashesSysvar::from_bytes(&[0; 4]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_entries() {
        let mut data = vec![0u8; 8];
        data[0..8].copy_from_slice(&1u64.to_le_bytes()); // says 1 entry
                                                         // but no entry data
        assert!(RecentBlockhashesSysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn default_equals_new() {
        let d = RecentBlockhashesSysvar::default();
        let n = RecentBlockhashesSysvar::new();
        assert_eq!(d.len(), n.len());
    }
}
