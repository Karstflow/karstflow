//! Block assembly from stored shreds.
//!
//! Reassembles a complete block from stored data shreds once a slot
//! is marked complete. Includes entry parsing to extract transaction
//! data from the assembled block.

use super::meta::SlotMeta;
use super::shred_store::ShredStore;
use super::BlockstoreError;

/// Assembles complete blocks from stored data shreds.
pub struct BlockAssembler;

impl BlockAssembler {
    /// Attempt to assemble a block from stored shreds for a slot.
    ///
    /// Returns an error if the slot is not complete or shreds are missing.
    pub fn assemble(
        store: &ShredStore,
        slot: u64,
        meta: &SlotMeta,
    ) -> Result<AssembledBlock, BlockstoreError> {
        if !meta.is_complete() {
            return Err(BlockstoreError::SlotNotFound(slot));
        }

        let shreds = store.get_slot_data_shreds(slot)?;
        if shreds.is_empty() {
            return Err(BlockstoreError::SlotNotFound(slot));
        }

        // Concatenate all data shreds in order to produce the raw entry data
        let total_size: usize = shreds.iter().map(|(_, data)| data.len()).sum();
        let mut entries = Vec::with_capacity(total_size);
        for (_, data) in &shreds {
            entries.extend_from_slice(data);
        }

        let parent_slot = meta.parent_slot.unwrap_or(0);

        Ok(AssembledBlock {
            slot,
            parent_slot,
            data_size: entries.len(),
            entries,
        })
    }

    /// Parse entries from raw assembled block data.
    ///
    /// The raw bytes are bincode-serialized `Vec<PohEntry>` where each
    /// entry contains a PoH hash chain element and optional transactions.
    pub fn parse_entries(raw: &[u8]) -> Result<Vec<ParsedEntry>, BlockstoreError> {
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let wire_entries: Vec<WireEntry> = bincode::deserialize(raw)
            .map_err(|e| BlockstoreError::DeserializationError(e.to_string()))?;
        Ok(wire_entries
            .into_iter()
            .map(|we| ParsedEntry {
                num_hashes: we.num_hashes,
                hash: we.hash,
                transactions: we.transactions,
            })
            .collect())
    }
}

/// A fully assembled block ready for replay.
#[derive(Debug)]
pub struct AssembledBlock {
    /// Slot number.
    pub slot: u64,
    /// Parent slot number.
    pub parent_slot: u64,
    /// Raw entry data assembled from shreds.
    pub entries: Vec<u8>,
    /// Total size of assembled data in bytes.
    pub data_size: usize,
}

/// A parsed entry from an assembled block.
#[derive(Debug, Clone)]
pub struct ParsedEntry {
    /// Number of PoH hashes since previous entry.
    pub num_hashes: u64,
    /// PoH hash at this entry.
    pub hash: [u8; 32],
    /// Raw transaction bytes for each transaction in this entry.
    pub transactions: Vec<Vec<u8>>,
}

/// Wire format entry matching Solana's bincode-serialized PoH entry.
#[derive(serde::Deserialize)]
struct WireEntry {
    num_hashes: u64,
    hash: [u8; 32],
    transactions: Vec<Vec<u8>>,
}

/// Extract transaction signatures from raw transaction bytes.
///
/// The wire format starts with a compact-u16 signature count followed
/// by 64-byte Ed25519 signatures. Returns `None` if the data is too
/// short or the compact-u16 encoding is invalid.
pub fn extract_signatures(tx_bytes: &[u8]) -> Option<Vec<[u8; 64]>> {
    if tx_bytes.is_empty() {
        return None;
    }
    // Compact-u16 encoding: 1 byte if < 0x80, 2 bytes if < 0x4000, 3 bytes otherwise
    let (num_sigs, offset) = decode_compact_u16(tx_bytes)?;
    if num_sigs == 0 {
        return Some(Vec::new());
    }
    let needed = offset + (num_sigs as usize) * 64;
    if tx_bytes.len() < needed {
        return None;
    }
    let mut sigs = Vec::with_capacity(num_sigs as usize);
    for i in 0..num_sigs as usize {
        let start = offset + i * 64;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&tx_bytes[start..start + 64]);
        sigs.push(sig);
    }
    Some(sigs)
}

fn decode_compact_u16(data: &[u8]) -> Option<(u16, usize)> {
    if data.is_empty() {
        return None;
    }
    let b0 = data[0] as u16;
    if b0 < 0x80 {
        return Some((b0, 1));
    }
    if data.len() < 2 {
        return None;
    }
    let b1 = data[1] as u16;
    if b1 < 0x80 {
        return Some(((b0 & 0x7F) | (b1 << 7), 2));
    }
    if data.len() < 3 {
        return None;
    }
    let b2 = data[2] as u16;
    Some(((b0 & 0x7F) | ((b1 & 0x7F) << 7) | (b2 << 14), 3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_entries() {
        let entries = BlockAssembler::parse_entries(&[]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn extract_single_signature() {
        // Build a minimal tx: 1 signature (compact-u16: 0x01) + 64 bytes
        let mut tx = vec![1u8]; // compact-u16 = 1
        let sig = [0xAB; 64];
        tx.extend_from_slice(&sig);
        tx.extend_from_slice(&[0; 32]); // some message bytes

        let sigs = extract_signatures(&tx).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], sig);
    }

    #[test]
    fn extract_multiple_signatures() {
        let mut tx = vec![2u8]; // compact-u16 = 2
        let sig1 = [0xAA; 64];
        let sig2 = [0xBB; 64];
        tx.extend_from_slice(&sig1);
        tx.extend_from_slice(&sig2);
        tx.extend_from_slice(&[0; 32]);

        let sigs = extract_signatures(&tx).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0], sig1);
        assert_eq!(sigs[1], sig2);
    }

    #[test]
    fn extract_signatures_too_short() {
        let tx = vec![1u8, 0xAA]; // claims 1 sig but only 1 byte of data
        assert!(extract_signatures(&tx).is_none());
    }

    #[test]
    fn extract_signatures_empty() {
        assert!(extract_signatures(&[]).is_none());
    }

    #[test]
    fn compact_u16_decode() {
        assert_eq!(decode_compact_u16(&[0]), Some((0, 1)));
        assert_eq!(decode_compact_u16(&[1]), Some((1, 1)));
        assert_eq!(decode_compact_u16(&[127]), Some((127, 1)));
        // 128 = 0x80 | 0x00, 0x01 => (0x00 | (1 << 7)) = 128
        assert_eq!(decode_compact_u16(&[0x80, 0x01]), Some((128, 2)));
    }
}
