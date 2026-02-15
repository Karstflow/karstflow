//! Slot and erasure metadata types.

use super::BlockstoreError;

/// Status of a slot in the blockstore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatus {
    /// Receiving shreds, not yet complete.
    Incomplete,
    /// All data shreds received.
    Complete,
    /// Block assembled and verified.
    Confirmed,
    /// Slot is dead (unrecoverable).
    Dead,
    /// Duplicate slot detected.
    Duplicate,
}

impl SlotStatus {
    fn to_byte(self) -> u8 {
        match self {
            Self::Incomplete => 0,
            Self::Complete => 1,
            Self::Confirmed => 2,
            Self::Dead => 3,
            Self::Duplicate => 4,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, BlockstoreError> {
        match byte {
            0 => Ok(Self::Incomplete),
            1 => Ok(Self::Complete),
            2 => Ok(Self::Confirmed),
            3 => Ok(Self::Dead),
            4 => Ok(Self::Duplicate),
            _ => Err(BlockstoreError::DeserializationError(format!(
                "invalid slot status byte: {}",
                byte
            ))),
        }
    }
}

/// Metadata for a slot in the blockstore.
#[derive(Debug, Clone)]
pub struct SlotMeta {
    /// Slot number.
    pub slot: u64,
    /// Parent slot number.
    pub parent_slot: Option<u64>,
    /// Number of data shreds received.
    pub received_data_shreds: u32,
    /// Number of coding shreds received.
    pub received_coding_shreds: u32,
    /// Expected total data shreds (set when last shred received).
    pub expected_data_shreds: Option<u32>,
    /// Current slot status.
    pub status: SlotStatus,
    /// Unix timestamp when first shred was received.
    pub first_shred_timestamp: i64,
    /// Unix timestamp when slot was completed.
    pub completion_timestamp: Option<i64>,
    /// Next slots (children).
    pub next_slots: Vec<u64>,
    /// Whether this slot is connected to a root through parent chain.
    pub is_connected: bool,
}

impl SlotMeta {
    /// Create a new SlotMeta for a slot.
    pub fn new(slot: u64, parent_slot: Option<u64>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            slot,
            parent_slot,
            received_data_shreds: 0,
            received_coding_shreds: 0,
            expected_data_shreds: None,
            status: SlotStatus::Incomplete,
            first_shred_timestamp: now,
            completion_timestamp: None,
            next_slots: Vec::new(),
            is_connected: false,
        }
    }

    /// Check if the slot has received all expected data shreds.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, SlotStatus::Complete | SlotStatus::Confirmed)
            || self
                .expected_data_shreds
                .map(|expected| self.received_data_shreds >= expected)
                .unwrap_or(false)
    }

    /// Check if the slot is dead.
    pub fn is_dead(&self) -> bool {
        self.status == SlotStatus::Dead
    }

    /// Serialize the slot meta to bytes for storage.
    ///
    /// Format:
    ///   slot: 8 bytes (BE)
    ///   parent_slot_present: 1 byte
    ///   parent_slot: 8 bytes (BE) if present
    ///   received_data_shreds: 4 bytes (BE)
    ///   received_coding_shreds: 4 bytes (BE)
    ///   expected_data_shreds_present: 1 byte
    ///   expected_data_shreds: 4 bytes (BE) if present
    ///   status: 1 byte
    ///   first_shred_timestamp: 8 bytes (BE)
    ///   completion_timestamp_present: 1 byte
    ///   completion_timestamp: 8 bytes (BE) if present
    ///   next_slots_count: 4 bytes (BE)
    ///   next_slots: 8 bytes (BE) each
    ///   is_connected: 1 byte
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        buf.extend_from_slice(&self.slot.to_be_bytes());

        match self.parent_slot {
            Some(ps) => {
                buf.push(1);
                buf.extend_from_slice(&ps.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }

        buf.extend_from_slice(&self.received_data_shreds.to_be_bytes());
        buf.extend_from_slice(&self.received_coding_shreds.to_be_bytes());

        match self.expected_data_shreds {
            Some(ed) => {
                buf.push(1);
                buf.extend_from_slice(&ed.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }

        buf.push(self.status.to_byte());
        buf.extend_from_slice(&self.first_shred_timestamp.to_be_bytes());

        match self.completion_timestamp {
            Some(ct) => {
                buf.push(1);
                buf.extend_from_slice(&ct.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }

        buf.extend_from_slice(&(self.next_slots.len() as u32).to_be_bytes());
        for ns in &self.next_slots {
            buf.extend_from_slice(&ns.to_be_bytes());
        }

        buf.push(if self.is_connected { 1 } else { 0 });

        buf
    }

    /// Deserialize a slot meta from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, BlockstoreError> {
        let mut pos = 0;

        let read_u64 = |data: &[u8], pos: &mut usize| -> Result<u64, BlockstoreError> {
            if *pos + 8 > data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "unexpected end of data reading u64".to_string(),
                ));
            }
            let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(val)
        };

        let read_u32 = |data: &[u8], pos: &mut usize| -> Result<u32, BlockstoreError> {
            if *pos + 4 > data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "unexpected end of data reading u32".to_string(),
                ));
            }
            let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            Ok(val)
        };

        let read_i64 = |data: &[u8], pos: &mut usize| -> Result<i64, BlockstoreError> {
            if *pos + 8 > data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "unexpected end of data reading i64".to_string(),
                ));
            }
            let val = i64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(val)
        };

        let read_u8 = |data: &[u8], pos: &mut usize| -> Result<u8, BlockstoreError> {
            if *pos >= data.len() {
                return Err(BlockstoreError::DeserializationError(
                    "unexpected end of data reading u8".to_string(),
                ));
            }
            let val = data[*pos];
            *pos += 1;
            Ok(val)
        };

        let slot = read_u64(data, &mut pos)?;

        let parent_slot = if read_u8(data, &mut pos)? == 1 {
            Some(read_u64(data, &mut pos)?)
        } else {
            None
        };

        let received_data_shreds = read_u32(data, &mut pos)?;
        let received_coding_shreds = read_u32(data, &mut pos)?;

        let expected_data_shreds = if read_u8(data, &mut pos)? == 1 {
            Some(read_u32(data, &mut pos)?)
        } else {
            None
        };

        let status = SlotStatus::from_byte(read_u8(data, &mut pos)?)?;
        let first_shred_timestamp = read_i64(data, &mut pos)?;

        let completion_timestamp = if read_u8(data, &mut pos)? == 1 {
            Some(read_i64(data, &mut pos)?)
        } else {
            None
        };

        let next_slots_count = read_u32(data, &mut pos)?;
        let mut next_slots = Vec::with_capacity(next_slots_count as usize);
        for _ in 0..next_slots_count {
            next_slots.push(read_u64(data, &mut pos)?);
        }

        let is_connected = read_u8(data, &mut pos)? == 1;

        Ok(Self {
            slot,
            parent_slot,
            received_data_shreds,
            received_coding_shreds,
            expected_data_shreds,
            status,
            first_shred_timestamp,
            completion_timestamp,
            next_slots,
            is_connected,
        })
    }
}

/// Erasure coding metadata for a set of shreds.
#[derive(Debug, Clone)]
pub struct ErasureMeta {
    /// Slot number.
    pub slot: u64,
    /// Index of the FEC set within the slot.
    pub fec_set_index: u32,
    /// Number of data shreds in this FEC set.
    pub num_data_shreds: u32,
    /// Number of coding shreds in this FEC set.
    pub num_coding_shreds: u32,
}

impl ErasureMeta {
    /// Create new erasure metadata.
    pub fn new(slot: u64, fec_set_index: u32, num_data: u32, num_coding: u32) -> Self {
        Self {
            slot,
            fec_set_index,
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
        }
    }

    /// Total number of shreds in the FEC set.
    pub fn total_shreds(&self) -> u32 {
        self.num_data_shreds + self.num_coding_shreds
    }
}
