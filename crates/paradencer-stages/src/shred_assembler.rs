//! Shred assembler for reconstructing blocks from complete shred sets
//!
//! This module takes complete shred sets from the window store and reconstructs
//! entries and blocks.

use paradencer_types::shred::{Shred, ShredVariant};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can occur during shred assembly
#[derive(Debug, Error)]
pub enum ShredAssemblyError {
    #[error("No shreds provided for assembly")]
    NoShreds,

    #[error("Shreds from different slots: expected {expected}, got {actual}")]
    SlotMismatch { expected: u64, actual: u64 },

    #[error("Invalid shred sequence: missing index {0}")]
    MissingIndex(u32),

    #[error("Entry deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Invalid entry data: {0}")]
    InvalidEntryData(String),

    #[error("Block boundary detection failed")]
    BlockBoundaryFailed,

    #[error("No data shreds in set")]
    NoDataShreds,

    #[error("Payload too short: expected at least {expected}, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },
}

/// Result type for shred assembly operations
pub type ShredAssemblyResult<T> = Result<T, ShredAssemblyError>;

/// A transaction entry reconstructed from shreds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Number of hashes since previous entry
    pub num_hashes: u64,

    /// Hash of the entry
    pub hash: [u8; 32],

    /// Transactions in this entry
    pub transactions: Vec<Vec<u8>>,
}

/// A complete block assembled from shreds
#[derive(Debug, Clone)]
pub struct AssembledBlock {
    /// Slot number
    pub slot: u64,

    /// Parent slot
    pub parent_slot: u64,

    /// Entries in this block
    pub entries: Vec<Entry>,

    /// Total number of transactions
    pub transaction_count: usize,

    /// Total size of block data in bytes
    pub total_bytes: usize,

    /// Number of shreds used to build this block
    pub shred_count: usize,
}

/// Statistics for shred assembly
#[derive(Debug, Clone, Default)]
pub struct ShredAssemblyStats {
    /// Total blocks assembled
    pub blocks_assembled: u64,

    /// Total entries extracted
    pub entries_extracted: u64,

    /// Total transactions extracted
    pub transactions_extracted: u64,

    /// Total bytes processed
    pub bytes_processed: u64,

    /// Total shreds processed
    pub shreds_processed: u64,
}

/// Shred assembler for reconstructing blocks from shreds
pub struct ShredAssembler {
    /// Statistics
    stats: ShredAssemblyStats,
}

impl ShredAssembler {
    /// Create a new shred assembler
    pub fn new() -> Self {
        Self {
            stats: ShredAssemblyStats::default(),
        }
    }

    /// Assemble a block from a set of data shreds
    pub fn assemble_block(&mut self, mut shreds: Vec<Shred>) -> ShredAssemblyResult<AssembledBlock> {
        if shreds.is_empty() {
            return Err(ShredAssemblyError::NoShreds);
        }

        // Filter to only data shreds and sort by index
        shreds.retain(|s| s.is_data());
        if shreds.is_empty() {
            return Err(ShredAssemblyError::NoDataShreds);
        }

        shreds.sort_by_key(|s| s.index());

        // Verify all shreds are from the same slot
        let slot = shreds[0].slot();
        for shred in &shreds {
            if shred.slot() != slot {
                return Err(ShredAssemblyError::SlotMismatch {
                    expected: slot,
                    actual: shred.slot(),
                });
            }
        }

        // Extract parent slot from first shred
        let parent_slot = shreds[0]
            .data_header()
            .map(|h| slot.saturating_sub(h.parent_offset as u64))
            .unwrap_or(slot.saturating_sub(1));

        // Concatenate all payloads
        let mut combined_data = Vec::new();
        let mut total_bytes = 0;

        for shred in &shreds {
            if let Some(size) = shred.data_size() {
                let data = &shred.payload[..size.min(shred.payload.len())];
                combined_data.extend_from_slice(data);
                total_bytes += data.len();
            }
        }

        // Parse entries from combined data
        let entries = self.parse_entries(&combined_data)?;
        let transaction_count: usize = entries.iter().map(|e| e.transactions.len()).sum();

        self.stats.blocks_assembled += 1;
        self.stats.entries_extracted += entries.len() as u64;
        self.stats.transactions_extracted += transaction_count as u64;
        self.stats.bytes_processed += total_bytes as u64;
        self.stats.shreds_processed += shreds.len() as u64;

        Ok(AssembledBlock {
            slot,
            parent_slot,
            entries,
            transaction_count,
            total_bytes,
            shred_count: shreds.len(),
        })
    }

    /// Parse entries from raw entry data
    fn parse_entries(&self, data: &[u8]) -> ShredAssemblyResult<Vec<Entry>> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            // Check if we have enough data for entry header
            if offset + 40 > data.len() {
                // Not enough data for another entry, stop parsing
                break;
            }

            // Parse entry header
            let entry = self.parse_single_entry(data, &mut offset)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Parse a single entry from data at the given offset
    fn parse_single_entry(&self, data: &[u8], offset: &mut usize) -> ShredAssemblyResult<Entry> {
        // Entry format:
        // - num_hashes: u64 (8 bytes)
        // - hash: [u8; 32] (32 bytes)
        // - num_transactions: u64 (8 bytes)
        // - transactions: variable length

        if *offset + 48 > data.len() {
            return Err(ShredAssemblyError::PayloadTooShort {
                expected: 48,
                actual: data.len() - *offset,
            });
        }

        // Parse num_hashes
        let num_hashes = u64::from_le_bytes(
            data[*offset..*offset + 8]
                .try_into()
                .map_err(|_| ShredAssemblyError::InvalidEntryData("Failed to parse num_hashes".to_string()))?,
        );
        *offset += 8;

        // Parse hash
        let hash: [u8; 32] = data[*offset..*offset + 32]
            .try_into()
            .map_err(|_| ShredAssemblyError::InvalidEntryData("Failed to parse hash".to_string()))?;
        *offset += 32;

        // Parse number of transactions
        let num_transactions = u64::from_le_bytes(
            data[*offset..*offset + 8]
                .try_into()
                .map_err(|_| ShredAssemblyError::InvalidEntryData("Failed to parse num_transactions".to_string()))?,
        );
        *offset += 8;

        // Parse transactions
        let mut transactions = Vec::new();
        for _ in 0..num_transactions {
            if *offset + 8 > data.len() {
                break; // Not enough data for transaction length
            }

            // Read transaction length
            let tx_len = u64::from_le_bytes(
                data[*offset..*offset + 8]
                    .try_into()
                    .map_err(|_| ShredAssemblyError::InvalidEntryData("Failed to parse transaction length".to_string()))?,
            ) as usize;
            *offset += 8;

            if *offset + tx_len > data.len() {
                break; // Not enough data for transaction
            }

            // Read transaction data
            let tx_data = data[*offset..*offset + tx_len].to_vec();
            *offset += tx_len;

            transactions.push(tx_data);
        }

        Ok(Entry {
            num_hashes,
            hash,
            transactions,
        })
    }

    /// Get assembly statistics
    pub fn stats(&self) -> &ShredAssemblyStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = ShredAssemblyStats::default();
    }
}

impl Default for ShredAssembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to detect block boundaries in a sequence of shreds
pub fn detect_block_boundary(shreds: &[Shred]) -> Option<usize> {
    for (i, shred) in shreds.iter().enumerate() {
        if shred.is_last_in_slot() {
            return Some(i + 1);
        }
    }
    None
}

/// Helper function to group shreds by slot
pub fn group_shreds_by_slot(shreds: Vec<Shred>) -> BTreeMap<u64, Vec<Shred>> {
    let mut grouped: BTreeMap<u64, Vec<Shred>> = BTreeMap::new();

    for shred in shreds {
        grouped.entry(shred.slot()).or_default().push(shred);
    }

    grouped
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_types::shred::*;

    fn create_test_shred(slot: u64, index: u32, payload: Vec<u8>) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_DATA_FLAG,
                slot,
                index,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: payload.len() as u16,
            }),
            payload,
        )
    }

    fn create_entry_bytes(num_hashes: u64, hash: [u8; 32], transactions: Vec<Vec<u8>>) -> Vec<u8> {
        let mut bytes = Vec::new();

        // num_hashes
        bytes.extend_from_slice(&num_hashes.to_le_bytes());

        // hash
        bytes.extend_from_slice(&hash);

        // num_transactions
        bytes.extend_from_slice(&(transactions.len() as u64).to_le_bytes());

        // transactions
        for tx in transactions {
            bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&tx);
        }

        bytes
    }

    #[test]
    fn test_assembler_creation() {
        let assembler = ShredAssembler::new();
        assert_eq!(assembler.stats().blocks_assembled, 0);
    }

    #[test]
    fn test_assemble_empty_shreds() {
        let mut assembler = ShredAssembler::new();
        let result = assembler.assemble_block(vec![]);
        assert!(matches!(result, Err(ShredAssemblyError::NoShreds)));
    }

    #[test]
    fn test_assemble_single_entry() {
        let mut assembler = ShredAssembler::new();

        // Create entry data
        let tx1 = vec![1, 2, 3, 4, 5];
        let tx2 = vec![6, 7, 8, 9, 10];
        let entry_data = create_entry_bytes(10, [0xAB; 32], vec![tx1.clone(), tx2.clone()]);

        // Create shred with entry data
        let shred = create_test_shred(100, 0, entry_data);

        let block = assembler.assemble_block(vec![shred]).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.entries[0].num_hashes, 10);
        assert_eq!(block.entries[0].hash, [0xAB; 32]);
        assert_eq!(block.entries[0].transactions.len(), 2);
        assert_eq!(block.entries[0].transactions[0], tx1);
        assert_eq!(block.entries[0].transactions[1], tx2);
        assert_eq!(block.transaction_count, 2);
    }

    #[test]
    fn test_assemble_multiple_entries() {
        let mut assembler = ShredAssembler::new();

        // Create multiple entries
        let entry1 = create_entry_bytes(10, [0xAA; 32], vec![vec![1, 2, 3]]);
        let entry2 = create_entry_bytes(20, [0xBB; 32], vec![vec![4, 5, 6], vec![7, 8, 9]]);

        let mut combined = Vec::new();
        combined.extend_from_slice(&entry1);
        combined.extend_from_slice(&entry2);

        let shred = create_test_shred(100, 0, combined);

        let block = assembler.assemble_block(vec![shred]).unwrap();

        assert_eq!(block.entries.len(), 2);
        assert_eq!(block.entries[0].num_hashes, 10);
        assert_eq!(block.entries[1].num_hashes, 20);
        assert_eq!(block.transaction_count, 3);
    }

    #[test]
    fn test_assemble_multiple_shreds() {
        let mut assembler = ShredAssembler::new();

        // Split entry across multiple shreds
        let entry_data = create_entry_bytes(10, [0xAB; 32], vec![vec![1, 2, 3, 4, 5]]);

        let mid = entry_data.len() / 2;
        let shred1 = create_test_shred(100, 0, entry_data[..mid].to_vec());
        let shred2 = create_test_shred(100, 1, entry_data[mid..].to_vec());

        let block = assembler.assemble_block(vec![shred1, shred2]).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.shred_count, 2);
        assert_eq!(block.entries.len(), 1);
    }

    #[test]
    fn test_slot_mismatch() {
        let mut assembler = ShredAssembler::new();

        let shred1 = create_test_shred(100, 0, vec![1, 2, 3]);
        let shred2 = create_test_shred(101, 1, vec![4, 5, 6]);

        let result = assembler.assemble_block(vec![shred1, shred2]);
        assert!(matches!(result, Err(ShredAssemblyError::SlotMismatch { .. })));
    }

    #[test]
    fn test_detect_block_boundary() {
        let shred1 = create_test_shred(100, 0, vec![]);
        let mut shred2 = create_test_shred(100, 1, vec![]);

        // Mark shred2 as last in slot
        if let ShredVariant::LegacyData(ref mut header) = shred2.variant {
            header.flags |= SHRED_LAST_IN_SLOT;
        }

        let shred3 = create_test_shred(100, 2, vec![]);

        let boundary = detect_block_boundary(&[shred1, shred2, shred3]);
        assert_eq!(boundary, Some(2));
    }

    #[test]
    fn test_group_shreds_by_slot() {
        let shreds = vec![
            create_test_shred(100, 0, vec![]),
            create_test_shred(101, 0, vec![]),
            create_test_shred(100, 1, vec![]),
            create_test_shred(102, 0, vec![]),
        ];

        let grouped = group_shreds_by_slot(shreds);

        assert_eq!(grouped.len(), 3);
        assert_eq!(grouped.get(&100).unwrap().len(), 2);
        assert_eq!(grouped.get(&101).unwrap().len(), 1);
        assert_eq!(grouped.get(&102).unwrap().len(), 1);
    }

    #[test]
    fn test_stats_tracking() {
        let mut assembler = ShredAssembler::new();

        let entry_data = create_entry_bytes(10, [0xAB; 32], vec![vec![1, 2, 3]]);
        let shred = create_test_shred(100, 0, entry_data);

        assembler.assemble_block(vec![shred]).unwrap();

        let stats = assembler.stats();
        assert_eq!(stats.blocks_assembled, 1);
        assert_eq!(stats.entries_extracted, 1);
        assert_eq!(stats.transactions_extracted, 1);
        assert!(stats.bytes_processed > 0);
    }
}
