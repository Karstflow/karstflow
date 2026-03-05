/// SlotHashes sysvar for recent slot-hash pairs.
///
/// Maintains an ordered list of the most recent slot numbers paired with
/// their corresponding bank hashes. Programs can verify that a specific
/// slot was processed and retrieve its hash for proof-of-history validation.
use karstflow_constants::sysvars::MAX_SLOT_HASHES;

/// Entry pairing a slot number with its bank hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotHashEntry {
    pub slot: u64,
    pub hash: [u8; 32],
}

/// Ordered collection of recent slot-hash pairs.
///
/// Entries are sorted by slot in descending order (most recent first).
/// When capacity is reached, the oldest entry is evicted.
#[derive(Debug, Clone)]
pub struct SlotHashesSysvar {
    entries: Vec<SlotHashEntry>,
}

impl SlotHashesSysvar {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_SLOT_HASHES),
        }
    }

    /// Insert a new slot-hash pair at the front (most recent position).
    ///
    /// The new slot must be greater than all existing slots. If the
    /// collection is at capacity, the oldest entry is removed.
    pub fn add(&mut self, slot: u64, hash: [u8; 32]) {
        // Insert at front (descending order by slot)
        self.entries.insert(0, SlotHashEntry { slot, hash });

        // Evict oldest if at capacity
        if self.entries.len() > MAX_SLOT_HASHES {
            self.entries.truncate(MAX_SLOT_HASHES);
        }
    }

    /// Look up the hash for a given slot.
    pub fn get(&self, slot: u64) -> Option<&[u8; 32]> {
        self.entries
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| &e.hash)
    }

    /// Get the most recent slot-hash entry.
    pub fn most_recent(&self) -> Option<&SlotHashEntry> {
        self.entries.first()
    }

    /// Get the oldest slot-hash entry.
    pub fn oldest(&self) -> Option<&SlotHashEntry> {
        self.entries.last()
    }

    /// Get number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries in descending slot order.
    pub fn iter(&self) -> impl Iterator<Item = &SlotHashEntry> {
        self.entries.iter()
    }

    /// Check whether a slot exists in the history.
    pub fn contains(&self, slot: u64) -> bool {
        self.entries.iter().any(|e| e.slot == slot)
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Format: entry_count(u64) + entries(slot(u64) + hash([u8;32])) each.
    pub fn to_bytes(&self) -> Vec<u8> {
        let entry_size = 8 + 32; // u64 slot + 32-byte hash
        let mut buf = Vec::with_capacity(8 + self.entries.len() * entry_size);
        buf.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.slot.to_le_bytes());
            buf.extend_from_slice(&entry.hash);
        }
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let count = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;
        let entry_size = 8 + 32;
        if data.len() < 8 + count * entry_size {
            return None;
        }
        let mut entries = Vec::with_capacity(count);
        let mut offset = 8;
        for _ in 0..count {
            let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset + 8..offset + 40]);
            entries.push(SlotHashEntry { slot, hash });
            offset += entry_size;
        }
        Some(Self { entries })
    }
}

impl Default for SlotHashesSysvar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_for(slot: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&slot.to_le_bytes());
        h
    }

    #[test]
    fn new_is_empty() {
        let sh = SlotHashesSysvar::new();
        assert!(sh.is_empty());
        assert_eq!(sh.len(), 0);
        assert!(sh.most_recent().is_none());
        assert!(sh.oldest().is_none());
    }

    #[test]
    fn add_and_get() {
        let mut sh = SlotHashesSysvar::new();
        sh.add(100, hash_for(100));
        assert_eq!(sh.len(), 1);
        assert_eq!(sh.get(100), Some(&hash_for(100)));
        assert!(sh.get(99).is_none());
    }

    #[test]
    fn most_recent_and_oldest() {
        let mut sh = SlotHashesSysvar::new();
        sh.add(10, hash_for(10));
        sh.add(20, hash_for(20));
        sh.add(30, hash_for(30));

        let most = sh.most_recent().unwrap();
        assert_eq!(most.slot, 30);
        assert_eq!(most.hash, hash_for(30));

        let old = sh.oldest().unwrap();
        assert_eq!(old.slot, 10);
        assert_eq!(old.hash, hash_for(10));
    }

    #[test]
    fn descending_order() {
        let mut sh = SlotHashesSysvar::new();
        sh.add(10, hash_for(10));
        sh.add(20, hash_for(20));
        sh.add(30, hash_for(30));

        let slots: Vec<u64> = sh.iter().map(|e| e.slot).collect();
        assert_eq!(slots, vec![30, 20, 10]);
    }

    #[test]
    fn contains() {
        let mut sh = SlotHashesSysvar::new();
        sh.add(50, hash_for(50));
        assert!(sh.contains(50));
        assert!(!sh.contains(51));
    }

    #[test]
    fn eviction_at_capacity() {
        let mut sh = SlotHashesSysvar::new();
        for i in 0..MAX_SLOT_HASHES as u64 {
            sh.add(i, hash_for(i));
        }
        assert_eq!(sh.len(), MAX_SLOT_HASHES);

        // Oldest is slot 0
        assert!(sh.contains(0));

        // Add one more — slot 0 should be evicted
        sh.add(MAX_SLOT_HASHES as u64, hash_for(MAX_SLOT_HASHES as u64));
        assert_eq!(sh.len(), MAX_SLOT_HASHES);
        assert!(!sh.contains(0));
        assert!(sh.contains(1));
        assert!(sh.contains(MAX_SLOT_HASHES as u64));
    }

    #[test]
    fn serialization_roundtrip_empty() {
        let sh = SlotHashesSysvar::new();
        let bytes = sh.to_bytes();
        let restored = SlotHashesSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 0);
    }

    #[test]
    fn serialization_roundtrip_with_entries() {
        let mut sh = SlotHashesSysvar::new();
        sh.add(10, hash_for(10));
        sh.add(20, hash_for(20));
        sh.add(30, hash_for(30));

        let bytes = sh.to_bytes();
        let restored = SlotHashesSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 3);
        assert_eq!(restored.get(10), Some(&hash_for(10)));
        assert_eq!(restored.get(20), Some(&hash_for(20)));
        assert_eq!(restored.get(30), Some(&hash_for(30)));

        let slots: Vec<u64> = restored.iter().map(|e| e.slot).collect();
        assert_eq!(slots, vec![30, 20, 10]);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(SlotHashesSysvar::from_bytes(&[0; 4]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_entries() {
        let mut data = vec![0u8; 8];
        data[0..8].copy_from_slice(&2u64.to_le_bytes()); // says 2 entries
                                                         // but no entry data follows
        assert!(SlotHashesSysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn default_equals_new() {
        let d = SlotHashesSysvar::default();
        let n = SlotHashesSysvar::new();
        assert_eq!(d.len(), n.len());
    }
}
