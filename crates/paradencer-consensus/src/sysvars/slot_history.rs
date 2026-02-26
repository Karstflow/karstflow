/// SlotHistory sysvar bitvector tracking processed slots.
///
/// Maintains a compact bitvector indicating which slots have been processed.
/// This allows programs and the runtime to verify whether a given slot
/// was included in the chain without storing full block data.
use paradencer_constants::sysvars::SLOT_HISTORY_BITS;

/// Number of u64 words needed to hold the bitvector.
const BITVEC_WORDS: usize = SLOT_HISTORY_BITS / 64;

/// Bitvector tracking which slots have been processed.
///
/// Uses a flat bitvector approach: `base_slot` indicates the first slot
/// represented by bit index 0. Slots below `base_slot` have been evicted.
/// The bitvector covers `SLOT_HISTORY_BITS` consecutive slots starting
/// from `base_slot`.
#[derive(Debug, Clone)]
pub struct SlotHistorySysvar {
    /// Packed bitvector of processed slot flags.
    bits: Vec<u64>,
    /// Lowest slot represented in the bitvector (bit 0).
    base_slot: u64,
    /// Highest slot that has been set plus one.
    next_slot: u64,
}

impl SlotHistorySysvar {
    pub fn new() -> Self {
        Self {
            bits: vec![0u64; BITVEC_WORDS],
            base_slot: 0,
            next_slot: 0,
        }
    }

    /// Mark a slot as processed.
    ///
    /// If the slot is ahead of the current window, the base advances
    /// forward, clearing old bits.
    pub fn set(&mut self, slot: u64) {
        if slot < self.base_slot {
            // Slot already evicted; ignore.
            return;
        }

        let offset = slot - self.base_slot;

        // If slot exceeds the current window, advance base.
        if offset >= SLOT_HISTORY_BITS as u64 {
            let advance = offset - SLOT_HISTORY_BITS as u64 + 1;
            self.advance_base(advance);
        }

        let index = (slot - self.base_slot) as usize;
        let word = index / 64;
        let bit = index % 64;
        if word < self.bits.len() {
            self.bits[word] |= 1u64 << bit;
        }

        if slot >= self.next_slot {
            self.next_slot = slot + 1;
        }
    }

    /// Check whether a slot is marked as processed.
    pub fn check(&self, slot: u64) -> bool {
        if slot < self.base_slot {
            return false;
        }
        let index = (slot - self.base_slot) as usize;
        if index >= SLOT_HISTORY_BITS {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        if word < self.bits.len() {
            (self.bits[word] >> bit) & 1 == 1
        } else {
            false
        }
    }

    /// Get the lowest slot tracked in the bitvector.
    pub fn base_slot(&self) -> u64 {
        self.base_slot
    }

    /// Get the slot just past the highest set slot.
    pub fn next_slot(&self) -> u64 {
        self.next_slot
    }

    /// Advance the base slot, clearing words that fall out of range.
    ///
    /// Shifts the conceptual window forward by `advance` slots. Bits
    /// representing slots that fall below the new `base_slot` are zeroed.
    fn advance_base(&mut self, advance: u64) {
        let advance_words = (advance as usize) / 64;
        let advance_bits = (advance as usize) % 64;

        if advance_words >= self.bits.len() {
            // Complete reset -- all existing data evicted.
            for word in self.bits.iter_mut() {
                *word = 0;
            }
        } else {
            // Shift whole words: move data from higher words to lower positions.
            // Word at index `advance_words` becomes new word 0, etc.
            self.bits.rotate_left(advance_words);
            let len = self.bits.len();
            // Clear the words that rotated from the front to the back.
            for word in &mut self.bits[len - advance_words..] {
                *word = 0;
            }

            // Shift remaining bits within words.
            if advance_bits > 0 {
                let complement = 64 - advance_bits;
                for i in 0..self.bits.len() - 1 {
                    self.bits[i] =
                        (self.bits[i] >> advance_bits) | (self.bits[i + 1] << complement);
                }
                let last = self.bits.len() - 1;
                self.bits[last] >>= advance_bits;
            }
        }

        self.base_slot += advance;
    }

    /// Serialize to bytes for sysvar account data.
    ///
    /// Format: base_slot(u64) + next_slot(u64) + bitvector_len(u64) + bitvector words.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + self.bits.len() * 8);
        buf.extend_from_slice(&self.base_slot.to_le_bytes());
        buf.extend_from_slice(&self.next_slot.to_le_bytes());
        buf.extend_from_slice(&(self.bits.len() as u64).to_le_bytes());
        for word in &self.bits {
            buf.extend_from_slice(&word.to_le_bytes());
        }
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let base_slot = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let next_slot = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let word_count = u64::from_le_bytes(data[16..24].try_into().ok()?) as usize;
        if data.len() < 24 + word_count * 8 {
            return None;
        }
        let mut bits = Vec::with_capacity(word_count);
        let mut offset = 24;
        for _ in 0..word_count {
            bits.push(u64::from_le_bytes(
                data[offset..offset + 8].try_into().ok()?,
            ));
            offset += 8;
        }
        Some(Self {
            bits,
            base_slot,
            next_slot,
        })
    }
}

impl Default for SlotHistorySysvar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_empty_state() {
        let sh = SlotHistorySysvar::new();
        assert_eq!(sh.base_slot(), 0);
        assert_eq!(sh.next_slot(), 0);
        assert!(!sh.check(0));
    }

    #[test]
    fn set_and_check_single_slot() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(42);
        assert!(sh.check(42));
        assert!(!sh.check(41));
        assert!(!sh.check(43));
        assert_eq!(sh.next_slot(), 43);
    }

    #[test]
    fn set_multiple_slots() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(10);
        sh.set(20);
        sh.set(30);
        assert!(sh.check(10));
        assert!(sh.check(20));
        assert!(sh.check(30));
        assert!(!sh.check(15));
        assert_eq!(sh.next_slot(), 31);
    }

    #[test]
    fn set_slot_zero() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(0);
        assert!(sh.check(0));
        assert_eq!(sh.next_slot(), 1);
    }

    #[test]
    fn check_returns_false_for_unset_slot() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(100);
        assert!(!sh.check(99));
        assert!(!sh.check(101));
    }

    #[test]
    fn set_beyond_window_advances_base() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(5);
        assert!(sh.check(5));

        // Set a slot far beyond the window
        let far_slot = SLOT_HISTORY_BITS as u64 + 100;
        sh.set(far_slot);

        // The old slot should be evicted
        assert!(!sh.check(5));
        // The new slot should be present
        assert!(sh.check(far_slot));
        // Base should have advanced
        assert!(sh.base_slot() > 0);
    }

    #[test]
    fn evicted_slot_returns_false() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(0);
        sh.set(1);

        // Force base to advance past slot 0 and 1
        let new_slot = SLOT_HISTORY_BITS as u64 + 10;
        sh.set(new_slot);

        assert!(!sh.check(0));
        assert!(!sh.check(1));
    }

    #[test]
    fn set_slot_below_base_is_ignored() {
        let mut sh = SlotHistorySysvar::new();
        // Advance the base
        let far = SLOT_HISTORY_BITS as u64 + 50;
        sh.set(far);
        let base = sh.base_slot();

        // Try setting a slot below the base
        sh.set(0);
        // Should not crash and base shouldn't change
        assert_eq!(sh.base_slot(), base);
        assert!(!sh.check(0));
    }

    #[test]
    fn next_slot_tracks_highest_set() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(100);
        assert_eq!(sh.next_slot(), 101);

        // Setting a lower slot doesn't decrease next_slot
        sh.set(50);
        assert_eq!(sh.next_slot(), 101);

        // Setting higher slot updates next_slot
        sh.set(200);
        assert_eq!(sh.next_slot(), 201);
    }

    #[test]
    fn check_beyond_window_returns_false() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(0);
        // Check slot way beyond the window
        assert!(!sh.check(SLOT_HISTORY_BITS as u64 + 100));
    }

    #[test]
    fn serialization_roundtrip_empty() {
        let sh = SlotHistorySysvar::new();
        let bytes = sh.to_bytes();
        let restored = SlotHistorySysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.base_slot(), 0);
        assert_eq!(restored.next_slot(), 0);
    }

    #[test]
    fn serialization_roundtrip_with_data() {
        let mut sh = SlotHistorySysvar::new();
        sh.set(10);
        sh.set(100);
        sh.set(1000);

        let bytes = sh.to_bytes();
        let restored = SlotHistorySysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.base_slot(), sh.base_slot());
        assert_eq!(restored.next_slot(), sh.next_slot());
        assert!(restored.check(10));
        assert!(restored.check(100));
        assert!(restored.check(1000));
        assert!(!restored.check(50));
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(SlotHistorySysvar::from_bytes(&[0; 10]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_words() {
        // Header says 2 words but data only has 1
        let mut data = vec![0u8; 24 + 8]; // header + 1 word
        data[16..24].copy_from_slice(&2u64.to_le_bytes()); // word_count = 2
        assert!(SlotHistorySysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn advance_base_partial_bits() {
        let mut sh = SlotHistorySysvar::new();
        // Set several consecutive slots
        for i in 0..128 {
            sh.set(i);
        }
        // Now advance by setting a slot that's exactly at the window boundary + some bits
        let new_slot = SLOT_HISTORY_BITS as u64 + 33; // 33 forces partial bit shift
        sh.set(new_slot);
        assert!(sh.check(new_slot));
        // Earlier slots should be evicted
        assert!(!sh.check(0));
    }

    #[test]
    fn default_equals_new() {
        let d = SlotHistorySysvar::default();
        let n = SlotHistorySysvar::new();
        assert_eq!(d.base_slot(), n.base_slot());
        assert_eq!(d.next_slot(), n.next_slot());
    }
}
