/// Instructions sysvar for per-transaction instruction introspection.
///
/// Unlike other sysvars which are cached per-bank, the Instructions sysvar
/// is populated per-transaction. It allows a program to inspect the other
/// instructions within the same transaction, enabling cross-program
/// verification patterns.
use paradencer_constants::sysvars::MAX_INSTRUCTIONS_PER_TRANSACTION;

/// Single serialized instruction within the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedInstruction {
    /// Index of the program account in the transaction account list.
    pub program_id_index: u8,
    /// Indices into the transaction account list for each instruction account.
    pub account_indices: Vec<u8>,
    /// Opaque instruction data.
    pub data: Vec<u8>,
}

/// Per-transaction view of all instructions for introspection.
///
/// Not persisted in the sysvar account between transactions. Instead, the
/// runtime populates this before each transaction and clears it afterward.
#[derive(Debug, Clone, Default)]
pub struct InstructionsSysvar {
    instructions: Vec<SerializedInstruction>,
    /// Index of the currently executing instruction.
    current_index: u16,
}

impl InstructionsSysvar {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            current_index: 0,
        }
    }

    /// Load instructions for a new transaction.
    ///
    /// Returns `None` if the instruction count exceeds the maximum.
    pub fn load(instructions: Vec<SerializedInstruction>) -> Option<Self> {
        if instructions.len() > MAX_INSTRUCTIONS_PER_TRANSACTION {
            return None;
        }
        Some(Self {
            instructions,
            current_index: 0,
        })
    }

    /// Set the index of the instruction currently being executed.
    pub fn set_current_index(&mut self, index: u16) {
        self.current_index = index;
    }

    /// Get the index of the instruction currently being executed.
    pub fn current_index(&self) -> u16 {
        self.current_index
    }

    /// Get an instruction by its position in the transaction.
    pub fn get(&self, index: usize) -> Option<&SerializedInstruction> {
        self.instructions.get(index)
    }

    /// Get the total number of instructions.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Serialize to bytes for the sysvar account data.
    ///
    /// Format: instruction_count(u16) + current_index(u16) +
    ///         for each instruction: program_id_index(u8) +
    ///         account_count(u16) + account_indices + data_len(u16) + data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.instructions.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.current_index.to_le_bytes());
        for ix in &self.instructions {
            buf.push(ix.program_id_index);
            buf.extend_from_slice(&(ix.account_indices.len() as u16).to_le_bytes());
            buf.extend_from_slice(&ix.account_indices);
            buf.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
            buf.extend_from_slice(&ix.data);
        }
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let count = u16::from_le_bytes(data[0..2].try_into().ok()?) as usize;
        let current_index = u16::from_le_bytes(data[2..4].try_into().ok()?);
        let mut instructions = Vec::with_capacity(count);
        let mut offset = 4;
        for _ in 0..count {
            if offset >= data.len() {
                return None;
            }
            let program_id_index = data[offset];
            offset += 1;
            if offset + 2 > data.len() {
                return None;
            }
            let acct_count = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if offset + acct_count > data.len() {
                return None;
            }
            let account_indices = data[offset..offset + acct_count].to_vec();
            offset += acct_count;
            if offset + 2 > data.len() {
                return None;
            }
            let data_len = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if offset + data_len > data.len() {
                return None;
            }
            let ix_data = data[offset..offset + data_len].to_vec();
            offset += data_len;
            instructions.push(SerializedInstruction {
                program_id_index,
                account_indices,
                data: ix_data,
            });
        }
        Some(Self {
            instructions,
            current_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ix(pid: u8, accounts: &[u8], data: &[u8]) -> SerializedInstruction {
        SerializedInstruction {
            program_id_index: pid,
            account_indices: accounts.to_vec(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn new_is_empty() {
        let sysvar = InstructionsSysvar::new();
        assert!(sysvar.is_empty());
        assert_eq!(sysvar.len(), 0);
        assert_eq!(sysvar.current_index(), 0);
    }

    #[test]
    fn load_single_instruction() {
        let ix = sample_ix(3, &[0, 1, 2], &[0xAA, 0xBB]);
        let sysvar = InstructionsSysvar::load(vec![ix.clone()]).unwrap();
        assert_eq!(sysvar.len(), 1);
        assert_eq!(sysvar.get(0), Some(&ix));
        assert!(sysvar.get(1).is_none());
    }

    #[test]
    fn load_multiple_instructions() {
        let ixs = vec![
            sample_ix(0, &[1], &[0x01]),
            sample_ix(2, &[3, 4], &[0x02, 0x03]),
            sample_ix(5, &[], &[]),
        ];
        let sysvar = InstructionsSysvar::load(ixs).unwrap();
        assert_eq!(sysvar.len(), 3);
        assert_eq!(sysvar.get(2).unwrap().program_id_index, 5);
    }

    #[test]
    fn load_rejects_exceeding_max() {
        let ixs: Vec<SerializedInstruction> = (0..=MAX_INSTRUCTIONS_PER_TRANSACTION)
            .map(|i| sample_ix(i as u8, &[], &[]))
            .collect();
        assert!(InstructionsSysvar::load(ixs).is_none());
    }

    #[test]
    fn load_accepts_exactly_max() {
        let ixs: Vec<SerializedInstruction> = (0..MAX_INSTRUCTIONS_PER_TRANSACTION)
            .map(|i| sample_ix(i as u8, &[], &[]))
            .collect();
        let sysvar = InstructionsSysvar::load(ixs).unwrap();
        assert_eq!(sysvar.len(), MAX_INSTRUCTIONS_PER_TRANSACTION);
    }

    #[test]
    fn current_index_tracking() {
        let ixs = vec![sample_ix(0, &[], &[]), sample_ix(1, &[], &[])];
        let mut sysvar = InstructionsSysvar::load(ixs).unwrap();
        assert_eq!(sysvar.current_index(), 0);

        sysvar.set_current_index(1);
        assert_eq!(sysvar.current_index(), 1);
    }

    #[test]
    fn serialization_roundtrip_empty() {
        let sysvar = InstructionsSysvar::new();
        let bytes = sysvar.to_bytes();
        let restored = InstructionsSysvar::from_bytes(&bytes).unwrap();
        assert!(restored.is_empty());
        assert_eq!(restored.current_index(), 0);
    }

    #[test]
    fn serialization_roundtrip_with_instructions() {
        let ixs = vec![
            sample_ix(3, &[0, 1, 2], &[0xAA, 0xBB]),
            sample_ix(7, &[4], &[0xCC, 0xDD, 0xEE]),
        ];
        let mut sysvar = InstructionsSysvar::load(ixs).unwrap();
        sysvar.set_current_index(1);

        let bytes = sysvar.to_bytes();
        let restored = InstructionsSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.current_index(), 1);

        let ix0 = restored.get(0).unwrap();
        assert_eq!(ix0.program_id_index, 3);
        assert_eq!(ix0.account_indices, vec![0, 1, 2]);
        assert_eq!(ix0.data, vec![0xAA, 0xBB]);

        let ix1 = restored.get(1).unwrap();
        assert_eq!(ix1.program_id_index, 7);
        assert_eq!(ix1.account_indices, vec![4]);
        assert_eq!(ix1.data, vec![0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(InstructionsSysvar::from_bytes(&[0; 2]).is_none());
    }

    #[test]
    fn from_bytes_rejects_truncated_instruction() {
        // Header: count=1, current_index=0
        let mut data = vec![0u8; 4];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // count = 1
                                                         // But no instruction data follows
        assert!(InstructionsSysvar::from_bytes(&data).is_none());
    }

    #[test]
    fn serialization_empty_instruction() {
        let ixs = vec![sample_ix(0, &[], &[])];
        let sysvar = InstructionsSysvar::load(ixs).unwrap();
        let bytes = sysvar.to_bytes();
        let restored = InstructionsSysvar::from_bytes(&bytes).unwrap();
        let ix = restored.get(0).unwrap();
        assert_eq!(ix.program_id_index, 0);
        assert!(ix.account_indices.is_empty());
        assert!(ix.data.is_empty());
    }

    #[test]
    fn default_is_empty() {
        let d: InstructionsSysvar = Default::default();
        assert!(d.is_empty());
        assert_eq!(d.current_index(), 0);
    }
}
