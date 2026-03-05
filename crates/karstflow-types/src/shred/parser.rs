//! Shred parsing and deserialization
//!
//! This module handles parsing raw network packets into structured shred types.

use super::types::*;
use std::io::{Cursor, Read};
use thiserror::Error;

/// Errors that can occur during shred parsing
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShredParseError {
    #[error("Shred too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("Invalid shred variant: {0:#x}")]
    InvalidVariant(u8),

    #[error("Invalid data shred size: {0}")]
    InvalidDataSize(u16),

    #[error("Invalid coding shred parameters: data={data}, coding={coding}")]
    InvalidCodingParams { data: u16, coding: u16 },

    #[error("Merkle proof parsing failed")]
    InvalidMerkleProof,

    #[error("IO error during parsing: {0}")]
    IoError(String),

    #[error("Payload size mismatch: expected {expected}, got {actual}")]
    PayloadSizeMismatch { expected: usize, actual: usize },
}

/// Result type for shred parsing operations
pub type ShredParseResult<T> = Result<T, ShredParseError>;

/// Shred parser for converting raw bytes into structured shreds
pub struct ShredParser;

impl ShredParser {
    /// Parse a raw byte buffer into a Shred.
    ///
    /// Preserves the original wire-format bytes in `Shred::raw` for
    /// Merkle signature verification.
    pub fn parse(data: &[u8]) -> ShredParseResult<Shred> {
        // Minimum shred size check
        if data.len() < SHRED_HEADER_SIZE {
            return Err(ShredParseError::TooShort {
                expected: SHRED_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);

        // Parse common header
        let common_header = Self::parse_common_header(&mut cursor)?;

        // Parse variant-specific data (Merkle proof is extracted from raw tail)
        let variant = Self::parse_variant(&mut cursor, common_header.variant, data)?;

        // Extract payload: bytes between the header and the Merkle proof tail.
        let header_end = cursor.position() as usize;
        let shred_type = common_header.variant & SHRED_TYPE_MASK;
        let is_legacy =
            shred_type == SHRED_TYPE_LEGACY_DATA || shred_type == SHRED_TYPE_LEGACY_CODE;

        let payload = if is_legacy {
            data[header_end..].to_vec()
        } else {
            // For Merkle shreds, payload ends where the Merkle proof begins.
            let proof_count = (common_header.variant & SHRED_PROOF_COUNT_MASK) as usize;
            let merkle_sz = proof_count * MERKLE_PROOF_NODE_BYTES;
            let is_resigned = matches!(
                shred_type,
                SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED | SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED
            );
            let resign_sz = if is_resigned { SIGNATURE_SIZE } else { 0 };
            let proof_start = data.len().saturating_sub(merkle_sz + resign_sz);
            let end = proof_start.max(header_end);
            data[header_end..end].to_vec()
        };

        Ok(Shred::with_raw(
            common_header,
            variant,
            payload,
            data.to_vec(),
        ))
    }

    /// Parse the common header present in all shreds
    fn parse_common_header(cursor: &mut Cursor<&[u8]>) -> ShredParseResult<ShredCommonHeader> {
        let mut signature = [0u8; SIGNATURE_SIZE];
        cursor
            .read_exact(&mut signature)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;

        let mut variant_buf = [0u8; 1];
        cursor
            .read_exact(&mut variant_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let variant = variant_buf[0];

        let mut slot_buf = [0u8; 8];
        cursor
            .read_exact(&mut slot_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let slot = u64::from_le_bytes(slot_buf);

        let mut index_buf = [0u8; 4];
        cursor
            .read_exact(&mut index_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let index = u32::from_le_bytes(index_buf);

        let mut version_buf = [0u8; 2];
        cursor
            .read_exact(&mut version_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let version = u16::from_le_bytes(version_buf);

        let mut fec_buf = [0u8; 4];
        cursor
            .read_exact(&mut fec_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let fec_set_index = u32::from_le_bytes(fec_buf);

        Ok(ShredCommonHeader {
            signature,
            variant,
            slot,
            index,
            version,
            fec_set_index,
        })
    }

    /// Parse variant-specific header based on variant byte.
    ///
    /// The variant byte encodes the shred type in the upper nibble and
    /// the Merkle proof depth (node count) in the lower nibble.
    fn parse_variant(
        cursor: &mut Cursor<&[u8]>,
        variant_byte: u8,
        raw_data: &[u8],
    ) -> ShredParseResult<ShredVariant> {
        let shred_type = variant_byte & SHRED_TYPE_MASK;
        let is_data = shred_type & SHRED_TYPEMASK_DATA != 0;
        let is_code = shred_type & SHRED_TYPEMASK_CODE != 0;
        let is_legacy =
            shred_type == SHRED_TYPE_LEGACY_DATA || shred_type == SHRED_TYPE_LEGACY_CODE;

        if is_data {
            let data_header = Self::parse_data_header(cursor)?;
            if is_legacy {
                Ok(ShredVariant::LegacyData(data_header))
            } else {
                let proof = Self::extract_merkle_proof(variant_byte, raw_data, true)?;
                Ok(ShredVariant::MerkleData(data_header, proof))
            }
        } else if is_code {
            let coding_header = Self::parse_coding_header(cursor)?;
            if is_legacy {
                Ok(ShredVariant::LegacyCoding(coding_header))
            } else {
                let proof = Self::extract_merkle_proof(variant_byte, raw_data, false)?;
                Ok(ShredVariant::MerkleCoding(coding_header, proof))
            }
        } else {
            Err(ShredParseError::InvalidVariant(variant_byte))
        }
    }

    /// Parse data shred specific header
    fn parse_data_header(cursor: &mut Cursor<&[u8]>) -> ShredParseResult<DataShredHeader> {
        let mut parent_buf = [0u8; 2];
        cursor
            .read_exact(&mut parent_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let parent_offset = u16::from_le_bytes(parent_buf);

        let mut flags_buf = [0u8; 1];
        cursor
            .read_exact(&mut flags_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let flags = flags_buf[0];

        let mut size_buf = [0u8; 2];
        cursor
            .read_exact(&mut size_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let size = u16::from_le_bytes(size_buf);

        // Validate size
        if size as usize > DATA_SHRED_PAYLOAD_SIZE {
            return Err(ShredParseError::InvalidDataSize(size));
        }

        Ok(DataShredHeader {
            parent_offset,
            flags,
            size,
        })
    }

    /// Parse coding shred specific header
    fn parse_coding_header(cursor: &mut Cursor<&[u8]>) -> ShredParseResult<CodingShredHeader> {
        let mut num_data_buf = [0u8; 2];
        cursor
            .read_exact(&mut num_data_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let num_data_shreds = u16::from_le_bytes(num_data_buf);

        let mut num_coding_buf = [0u8; 2];
        cursor
            .read_exact(&mut num_coding_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let num_coding_shreds = u16::from_le_bytes(num_coding_buf);

        let mut position_buf = [0u8; 2];
        cursor
            .read_exact(&mut position_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let position = u16::from_le_bytes(position_buf);

        // Validate parameters
        if num_data_shreds as usize > MAX_DATA_SHREDS_PER_FEC_BLOCK
            || num_coding_shreds as usize > MAX_CODING_SHREDS_PER_FEC_BLOCK
        {
            return Err(ShredParseError::InvalidCodingParams {
                data: num_data_shreds,
                coding: num_coding_shreds,
            });
        }

        Ok(CodingShredHeader {
            num_data_shreds,
            num_coding_shreds,
            position,
        })
    }

    /// Extract Merkle proof nodes from the tail of the raw shred bytes.
    ///
    /// The proof sits at the end of the shred (before any retransmitter signature).
    /// The number of proof nodes is encoded in the lower nibble of the variant byte.
    fn extract_merkle_proof(
        variant_byte: u8,
        raw: &[u8],
        is_data: bool,
    ) -> ShredParseResult<MerkleProof> {
        let proof_count = (variant_byte & SHRED_PROOF_COUNT_MASK) as usize;
        if proof_count > MERKLE_MAX_PROOF_DEPTH {
            return Err(ShredParseError::InvalidMerkleProof);
        }
        if proof_count == 0 {
            return Ok(MerkleProof { proof: Vec::new() });
        }

        let merkle_sz = proof_count * MERKLE_PROOF_NODE_BYTES;
        let shred_type = variant_byte & SHRED_TYPE_MASK;
        let is_resigned = matches!(
            shred_type,
            SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED | SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED
        );
        let resign_sz = if is_resigned { SIGNATURE_SIZE } else { 0 };

        // Merkle proof offset: shred_size - merkle_sz - resign_sz
        let shred_sz = if is_data { SHRED_MIN_SIZE } else { SHRED_SIZE };
        let shred_end = raw.len().min(shred_sz);
        let proof_start = shred_end
            .checked_sub(merkle_sz + resign_sz)
            .ok_or(ShredParseError::InvalidMerkleProof)?;

        if proof_start + merkle_sz > raw.len() {
            return Err(ShredParseError::InvalidMerkleProof);
        }

        let mut proof = Vec::with_capacity(proof_count);
        for i in 0..proof_count {
            let off = proof_start + i * MERKLE_PROOF_NODE_BYTES;
            let mut node = [0u8; MERKLE_PROOF_NODE_BYTES];
            node.copy_from_slice(&raw[off..off + MERKLE_PROOF_NODE_BYTES]);
            proof.push(node);
        }

        Ok(MerkleProof { proof })
    }

    /// Serialize a shred into wire-format bytes.
    ///
    /// For Merkle shreds, the proof is written at the tail of the shred
    /// with zero-padding between the payload and proof as needed.
    pub fn serialize(shred: &Shred) -> ShredParseResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(SHRED_SIZE);

        // Write common header
        Self::write_common_header(&mut buffer, &shred.common_header)?;

        // Write variant-specific header (NOT the proof yet)
        Self::write_variant_header(&mut buffer, &shred.variant)?;

        // Write payload
        buffer.extend_from_slice(&shred.payload);

        // For Merkle shreds, pad to target size then append proof at tail.
        match &shred.variant {
            ShredVariant::MerkleData(_, proof) | ShredVariant::MerkleCoding(_, proof) => {
                let is_data = matches!(&shred.variant, ShredVariant::MerkleData(_, _));
                let target_sz = if is_data { SHRED_MIN_SIZE } else { SHRED_SIZE };
                let merkle_sz = proof.proof.len() * MERKLE_PROOF_NODE_BYTES;
                let needed = target_sz.saturating_sub(merkle_sz);
                if buffer.len() < needed {
                    buffer.resize(needed, 0);
                }
                Self::write_merkle_proof(&mut buffer, proof)?;
            }
            _ => {}
        }

        Ok(buffer)
    }

    /// Write common header to buffer
    fn write_common_header(
        buffer: &mut Vec<u8>,
        header: &ShredCommonHeader,
    ) -> ShredParseResult<()> {
        buffer.extend_from_slice(&header.signature);
        buffer.push(header.variant);
        buffer.extend_from_slice(&header.slot.to_le_bytes());
        buffer.extend_from_slice(&header.index.to_le_bytes());
        buffer.extend_from_slice(&header.version.to_le_bytes());
        buffer.extend_from_slice(&header.fec_set_index.to_le_bytes());
        Ok(())
    }

    /// Write variant-specific header fields (not the Merkle proof).
    fn write_variant_header(buffer: &mut Vec<u8>, variant: &ShredVariant) -> ShredParseResult<()> {
        match variant {
            ShredVariant::LegacyData(header) | ShredVariant::MerkleData(header, _) => {
                Self::write_data_header(buffer, header)
            }
            ShredVariant::LegacyCoding(header) | ShredVariant::MerkleCoding(header, _) => {
                Self::write_coding_header(buffer, header)
            }
        }
    }

    /// Write data header to buffer
    fn write_data_header(buffer: &mut Vec<u8>, header: &DataShredHeader) -> ShredParseResult<()> {
        buffer.extend_from_slice(&header.parent_offset.to_le_bytes());
        buffer.push(header.flags);
        buffer.extend_from_slice(&header.size.to_le_bytes());
        Ok(())
    }

    /// Write coding header to buffer
    fn write_coding_header(
        buffer: &mut Vec<u8>,
        header: &CodingShredHeader,
    ) -> ShredParseResult<()> {
        buffer.extend_from_slice(&header.num_data_shreds.to_le_bytes());
        buffer.extend_from_slice(&header.num_coding_shreds.to_le_bytes());
        buffer.extend_from_slice(&header.position.to_le_bytes());
        Ok(())
    }

    /// Append Merkle proof nodes to buffer.
    ///
    /// Proof nodes are 20-byte truncated SHA-256 hashes. They are written
    /// at the tail of the shred, so the caller must pad the payload to the
    /// appropriate offset before calling this.
    fn write_merkle_proof(buffer: &mut Vec<u8>, proof: &MerkleProof) -> ShredParseResult<()> {
        for node in &proof.proof {
            buffer.extend_from_slice(node);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wire-format legacy data shred.
    fn build_legacy_data_wire(slot: u64, index: u32, fec_set: u32, payload: &[u8]) -> Vec<u8> {
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE; // 0xA5
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        buf.push(variant_byte);
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // version
        buf.extend_from_slice(&fec_set.to_le_bytes());
        // Data header
        buf.extend_from_slice(&1u16.to_le_bytes()); // parent_offset
        buf.push(0); // flags
        buf.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // size
                                                                      // Payload
        buf.extend_from_slice(payload);
        buf
    }

    /// Build a wire-format legacy coding shred.
    fn build_legacy_code_wire(slot: u64, index: u32, fec_set: u32, payload: &[u8]) -> Vec<u8> {
        let variant_byte = SHRED_TYPE_LEGACY_CODE | SHRED_LEGACY_CODE_NIBBLE; // 0x5A
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        buf.push(variant_byte);
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // version
        buf.extend_from_slice(&fec_set.to_le_bytes());
        // Coding header
        buf.extend_from_slice(&32u16.to_le_bytes()); // num_data
        buf.extend_from_slice(&32u16.to_le_bytes()); // num_coding
        buf.extend_from_slice(&10u16.to_le_bytes()); // position
                                                     // Payload
        buf.extend_from_slice(payload);
        buf
    }

    /// Build a wire-format Merkle data shred.
    fn build_merkle_data_wire(
        slot: u64,
        index: u32,
        fec_set: u32,
        proof_depth: u8,
        proof_fill: u8,
    ) -> Vec<u8> {
        let variant_byte = SHRED_TYPE_MERKLE_DATA | proof_depth;
        let merkle_sz = proof_depth as usize * MERKLE_PROOF_NODE_BYTES;
        let mut buf = vec![0u8; SHRED_MIN_SIZE];
        // Signature
        buf[..SIGNATURE_SIZE].fill(0x01);
        // Common header
        buf[SIGNATURE_SIZE] = variant_byte;
        buf[0x41..0x49].copy_from_slice(&slot.to_le_bytes());
        buf[0x49..0x4d].copy_from_slice(&index.to_le_bytes());
        buf[0x4d..0x4f].copy_from_slice(&1u16.to_le_bytes()); // version
        buf[0x4f..0x53].copy_from_slice(&fec_set.to_le_bytes());
        // Data header
        buf[0x53..0x55].copy_from_slice(&1u16.to_le_bytes()); // parent_offset
        buf[0x55] = 0; // flags
        buf[0x56..0x58].copy_from_slice(&512u16.to_le_bytes()); // size
                                                                // Payload at 0x58
        buf[0x58..0x58 + 128].fill(0xAB);
        // Merkle proof at tail
        let proof_start = SHRED_MIN_SIZE - merkle_sz;
        buf[proof_start..].fill(proof_fill);
        buf
    }

    #[test]
    fn test_parse_legacy_data_shred() {
        let wire = build_legacy_data_wire(100, 5, 0, &vec![0xAB; 512]);
        let shred = ShredParser::parse(&wire).unwrap();

        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 5);
        assert!(shred.is_data());
        assert!(!shred.is_coding());
        assert!(!shred.is_merkle());
        assert_eq!(shred.data_size(), Some(512));
        assert!(shred.raw.is_some());
    }

    #[test]
    fn test_parse_legacy_coding_shred() {
        let wire = build_legacy_code_wire(100, 5, 0, &vec![0xCD; 512]);
        let shred = ShredParser::parse(&wire).unwrap();

        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 5);
        assert!(!shred.is_data());
        assert!(shred.is_coding());
        assert!(!shred.is_merkle());

        let coding_header = shred.coding_header().unwrap();
        assert_eq!(coding_header.num_data_shreds, 32);
        assert_eq!(coding_header.num_coding_shreds, 32);
        assert_eq!(coding_header.position, 10);
    }

    #[test]
    fn test_parse_merkle_data_shred() {
        let proof_depth = 3u8;
        let wire = build_merkle_data_wire(100, 5, 0, proof_depth, 0xFF);
        let shred = ShredParser::parse(&wire).unwrap();

        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 5);
        assert!(shred.is_data());
        assert!(shred.is_merkle());
        assert_eq!(shred.merkle_proof_count(), 3);

        match &shred.variant {
            ShredVariant::MerkleData(_, proof) => {
                assert_eq!(proof.proof.len(), 3);
                for node in &proof.proof {
                    assert_eq!(*node, [0xFF; MERKLE_PROOF_NODE_BYTES]);
                }
            }
            _ => panic!("Expected MerkleData variant"),
        }
    }

    #[test]
    fn test_serialize_roundtrip_legacy() {
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        let common_header = ShredCommonHeader {
            signature: [0xAB; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 100,
            index: 5,
            version: 1,
            fec_set_index: 0,
        };

        let data_header = DataShredHeader {
            parent_offset: 1,
            flags: 0,
            size: 512,
        };

        let original = Shred::new(
            common_header,
            ShredVariant::LegacyData(data_header),
            vec![0xCD; 512],
        );

        let serialized = ShredParser::serialize(&original).unwrap();
        let parsed = ShredParser::parse(&serialized).unwrap();

        assert_eq!(parsed.slot(), original.slot());
        assert_eq!(parsed.index(), original.index());
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_parse_too_short() {
        let buffer = vec![0u8; 10];
        let result = ShredParser::parse(&buffer);
        assert!(matches!(result, Err(ShredParseError::TooShort { .. })));
    }

    #[test]
    fn test_parse_invalid_variant() {
        // Variant 0x30 has upper nibble 0x30, which is neither data nor code.
        let mut buffer = vec![0u8; SHRED_HEADER_SIZE];
        buffer[SIGNATURE_SIZE] = 0x30;

        let result = ShredParser::parse(&buffer);
        assert!(matches!(result, Err(ShredParseError::InvalidVariant(_))));
    }
}
