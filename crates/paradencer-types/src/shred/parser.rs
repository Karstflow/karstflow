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
    /// Parse a raw byte buffer into a Shred
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

        // Parse variant-specific data
        let variant = Self::parse_variant(&mut cursor, common_header.variant)?;

        // Extract remaining payload
        let position = cursor.position() as usize;
        let payload = data[position..].to_vec();

        Ok(Shred::new(common_header, variant, payload))
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

    /// Parse variant-specific header based on variant byte
    fn parse_variant(
        cursor: &mut Cursor<&[u8]>,
        variant_byte: u8,
    ) -> ShredParseResult<ShredVariant> {
        let is_merkle = (variant_byte & SHRED_MERKLE_FLAG) != 0;
        let variant_type = variant_byte & SHRED_VARIANT_MASK;

        match variant_type {
            SHRED_DATA_FLAG => {
                let data_header = Self::parse_data_header(cursor)?;
                if is_merkle {
                    let proof = Self::parse_merkle_proof(cursor)?;
                    Ok(ShredVariant::MerkleData(data_header, proof))
                } else {
                    Ok(ShredVariant::LegacyData(data_header))
                }
            }
            SHRED_CODE_FLAG => {
                let coding_header = Self::parse_coding_header(cursor)?;
                if is_merkle {
                    let proof = Self::parse_merkle_proof(cursor)?;
                    Ok(ShredVariant::MerkleCoding(coding_header, proof))
                } else {
                    Ok(ShredVariant::LegacyCoding(coding_header))
                }
            }
            _ => Err(ShredParseError::InvalidVariant(variant_byte)),
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

    /// Parse Merkle proof
    fn parse_merkle_proof(cursor: &mut Cursor<&[u8]>) -> ShredParseResult<MerkleProof> {
        // Read number of proof nodes (typically 20 for Solana)
        let mut num_nodes_buf = [0u8; 1];
        cursor
            .read_exact(&mut num_nodes_buf)
            .map_err(|e| ShredParseError::IoError(e.to_string()))?;
        let num_nodes = num_nodes_buf[0] as usize;

        if num_nodes > 32 {
            return Err(ShredParseError::InvalidMerkleProof);
        }

        let mut proof = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let mut node = [0u8; 32];
            cursor
                .read_exact(&mut node)
                .map_err(|e| ShredParseError::IoError(e.to_string()))?;
            proof.push(node);
        }

        Ok(MerkleProof { proof })
    }

    /// Serialize a shred into bytes
    pub fn serialize(shred: &Shred) -> ShredParseResult<Vec<u8>> {
        let mut buffer = Vec::with_capacity(SHRED_SIZE);

        // Write common header
        Self::write_common_header(&mut buffer, &shred.common_header)?;

        // Write variant-specific data
        Self::write_variant(&mut buffer, &shred.variant)?;

        // Write payload
        buffer.extend_from_slice(&shred.payload);

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

    /// Write variant-specific data to buffer
    fn write_variant(buffer: &mut Vec<u8>, variant: &ShredVariant) -> ShredParseResult<()> {
        match variant {
            ShredVariant::LegacyData(header) => Self::write_data_header(buffer, header),
            ShredVariant::LegacyCoding(header) => Self::write_coding_header(buffer, header),
            ShredVariant::MerkleData(header, proof) => {
                Self::write_data_header(buffer, header)?;
                Self::write_merkle_proof(buffer, proof)
            }
            ShredVariant::MerkleCoding(header, proof) => {
                Self::write_coding_header(buffer, header)?;
                Self::write_merkle_proof(buffer, proof)
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

    /// Write Merkle proof to buffer
    fn write_merkle_proof(buffer: &mut Vec<u8>, proof: &MerkleProof) -> ShredParseResult<()> {
        buffer.push(proof.proof.len() as u8);
        for node in &proof.proof {
            buffer.extend_from_slice(node);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_legacy_data_shred() {
        let mut buffer = Vec::new();

        // Signature
        buffer.extend_from_slice(&[0u8; SIGNATURE_SIZE]);

        // Variant (data, no merkle)
        buffer.push(SHRED_DATA_FLAG);

        // Slot
        buffer.extend_from_slice(&100u64.to_le_bytes());

        // Index
        buffer.extend_from_slice(&5u32.to_le_bytes());

        // Version
        buffer.extend_from_slice(&1u16.to_le_bytes());

        // FEC set index
        buffer.extend_from_slice(&0u32.to_le_bytes());

        // Data header
        buffer.extend_from_slice(&1u16.to_le_bytes()); // parent_offset
        buffer.push(0); // flags
        buffer.extend_from_slice(&512u16.to_le_bytes()); // size

        // Payload
        buffer.extend_from_slice(&vec![0xAB; 512]);

        let shred = ShredParser::parse(&buffer).unwrap();

        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 5);
        assert!(shred.is_data());
        assert!(!shred.is_coding());
        assert!(!shred.is_merkle());
        assert_eq!(shred.data_size(), Some(512));
    }

    #[test]
    fn test_parse_legacy_coding_shred() {
        let mut buffer = Vec::new();

        // Signature
        buffer.extend_from_slice(&[0u8; SIGNATURE_SIZE]);

        // Variant (coding, no merkle)
        buffer.push(SHRED_CODE_FLAG);

        // Slot
        buffer.extend_from_slice(&100u64.to_le_bytes());

        // Index
        buffer.extend_from_slice(&5u32.to_le_bytes());

        // Version
        buffer.extend_from_slice(&1u16.to_le_bytes());

        // FEC set index
        buffer.extend_from_slice(&0u32.to_le_bytes());

        // Coding header
        buffer.extend_from_slice(&32u16.to_le_bytes()); // num_data_shreds
        buffer.extend_from_slice(&32u16.to_le_bytes()); // num_coding_shreds
        buffer.extend_from_slice(&10u16.to_le_bytes()); // position

        // Payload
        buffer.extend_from_slice(&vec![0xCD; 512]);

        let shred = ShredParser::parse(&buffer).unwrap();

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
        let mut buffer = Vec::new();

        // Signature
        buffer.extend_from_slice(&[0u8; SIGNATURE_SIZE]);

        // Variant (data + merkle)
        buffer.push(SHRED_DATA_FLAG | SHRED_MERKLE_FLAG);

        // Slot
        buffer.extend_from_slice(&100u64.to_le_bytes());

        // Index
        buffer.extend_from_slice(&5u32.to_le_bytes());

        // Version
        buffer.extend_from_slice(&1u16.to_le_bytes());

        // FEC set index
        buffer.extend_from_slice(&0u32.to_le_bytes());

        // Data header
        buffer.extend_from_slice(&1u16.to_le_bytes()); // parent_offset
        buffer.push(0); // flags
        buffer.extend_from_slice(&512u16.to_le_bytes()); // size

        // Merkle proof (3 nodes)
        buffer.push(3);
        for _ in 0..3 {
            buffer.extend_from_slice(&[0xFF; 32]);
        }

        // Payload
        buffer.extend_from_slice(&vec![0xAB; 512]);

        let shred = ShredParser::parse(&buffer).unwrap();

        assert_eq!(shred.slot(), 100);
        assert!(shred.is_data());
        assert!(shred.is_merkle());

        match &shred.variant {
            ShredVariant::MerkleData(_, proof) => {
                assert_eq!(proof.proof.len(), 3);
            }
            _ => panic!("Expected MerkleData variant"),
        }
    }

    #[test]
    fn test_serialize_roundtrip() {
        let common_header = ShredCommonHeader {
            signature: [0xAB; SIGNATURE_SIZE],
            variant: SHRED_DATA_FLAG,
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
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        buffer.push(0xFF); // Invalid variant
        buffer.extend_from_slice(&[0u8; 18]); // Rest of header

        let result = ShredParser::parse(&buffer);
        assert!(matches!(result, Err(ShredParseError::InvalidVariant(_))));
    }
}
