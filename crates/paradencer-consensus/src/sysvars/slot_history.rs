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
