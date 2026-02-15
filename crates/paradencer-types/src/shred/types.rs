//! Shred type definitions and data structures
//!
//! This module contains the core data structures for Solana shreds,
//! which are the atomic units of block propagation in the network.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde helper for large arrays
mod serde_arrays {
    use super::*;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(data)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor;

        impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (i, item) in arr.iter_mut().enumerate() {
                    *item = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(ArrayVisitor)
    }
}

/// Size of a complete shred packet in bytes
pub const SHRED_SIZE: usize = 1228;

/// Size of the shred header in bytes
pub const SHRED_HEADER_SIZE: usize = 88;

/// Maximum number of data shreds per FEC block
pub const MAX_DATA_SHREDS_PER_FEC_BLOCK: usize = 67;

/// Maximum number of coding shreds per FEC block
pub const MAX_CODING_SHREDS_PER_FEC_BLOCK: usize = 67;

/// Signature size in bytes (Ed25519)
pub const SIGNATURE_SIZE: usize = 64;

/// Shred payload size (SHRED_SIZE - SHRED_HEADER_SIZE)
pub const SHRED_PAYLOAD_SIZE: usize = SHRED_SIZE - SHRED_HEADER_SIZE;

/// Data shred payload size (includes data-specific header)
pub const DATA_SHRED_PAYLOAD_SIZE: usize = 1051;

/// Coding shred payload size
pub const CODING_SHRED_PAYLOAD_SIZE: usize = 1139;

/// Size of Merkle proof in bytes
pub const MERKLE_PROOF_SIZE: usize = 20 * 32; // 20 hashes

/// Shred variant bit flags
pub const SHRED_VARIANT_MASK: u8 = 0x0F;
pub const SHRED_DATA_FLAG: u8 = 0b0101;
pub const SHRED_CODE_FLAG: u8 = 0b1010;

/// Merkle variant flag
pub const SHRED_MERKLE_FLAG: u8 = 0x40;

/// Last shred in slot flag
pub const SHRED_LAST_IN_SLOT: u8 = 0x80;

/// A complete shred with all its components
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shred {
    /// Common header present in all shreds
    pub common_header: ShredCommonHeader,

    /// Variant-specific data
    pub variant: ShredVariant,

    /// Raw payload bytes
    pub payload: Vec<u8>,
}

/// Common header present in all shred types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShredCommonHeader {
    /// Ed25519 signature (64 bytes)
    #[serde(with = "serde_arrays")]
    pub signature: [u8; SIGNATURE_SIZE],

    /// Shred variant and flags
    pub variant: u8,

    /// Slot number this shred belongs to
    pub slot: u64,

    /// Index of this shred within the slot
    pub index: u32,

    /// Shred version for replay protection
    pub version: u16,

    /// FEC set index (used for erasure coding)
    pub fec_set_index: u32,
}

/// Shred variant enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShredVariant {
    /// Legacy data shred (pre-Merkle)
    LegacyData(DataShredHeader),

    /// Legacy coding shred (pre-Merkle)
    LegacyCoding(CodingShredHeader),

    /// Merkle-proof data shred
    MerkleData(DataShredHeader, MerkleProof),

    /// Merkle-proof coding shred
    MerkleCoding(CodingShredHeader, MerkleProof),
}

/// Data shred specific header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataShredHeader {
    /// Parent slot (for chaining)
    pub parent_offset: u16,

    /// Flags (last shred in slot, etc.)
    pub flags: u8,

    /// Size of actual data in payload
    pub size: u16,
}

/// Coding shred specific header
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingShredHeader {
    /// Number of data shreds in this FEC set
    pub num_data_shreds: u16,

    /// Number of coding shreds in this FEC set
    pub num_coding_shreds: u16,

    /// Position of this coding shred in the FEC set
    pub position: u16,
}

/// Merkle proof for shred authentication
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Merkle tree proof nodes
    pub proof: Vec<[u8; 32]>,
}

/// FEC set identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FecSetId {
    /// Slot number
    pub slot: u64,

    /// FEC set index within the slot
    pub index: u32,
}

/// Metadata for a shred stored in the window
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShredMetadata {
    /// Slot number
    pub slot: u64,

    /// Shred index
    pub index: u32,

    /// FEC set index
    pub fec_set_index: u32,

    /// Whether this is a data shred
    pub is_data: bool,

    /// Whether this is a coding shred
    pub is_coding: bool,

    /// Size of the shred
    pub size: usize,

    /// Timestamp when shred was received
    pub received_at: u64,
}

impl Shred {
    /// Create a new shred with the given components
    pub fn new(common_header: ShredCommonHeader, variant: ShredVariant, payload: Vec<u8>) -> Self {
        Self {
            common_header,
            variant,
            payload,
        }
    }

    /// Get the slot number
    pub fn slot(&self) -> u64 {
        self.common_header.slot
    }

    /// Get the shred index
    pub fn index(&self) -> u32 {
        self.common_header.index
    }

    /// Get the FEC set index
    pub fn fec_set_index(&self) -> u32 {
        self.common_header.fec_set_index
    }

    /// Check if this is a data shred
    pub fn is_data(&self) -> bool {
        matches!(self.variant, ShredVariant::LegacyData(_) | ShredVariant::MerkleData(_, _))
    }

    /// Check if this is a coding shred
    pub fn is_coding(&self) -> bool {
        matches!(self.variant, ShredVariant::LegacyCoding(_) | ShredVariant::MerkleCoding(_, _))
    }

    /// Check if this shred uses Merkle proofs
    pub fn is_merkle(&self) -> bool {
        matches!(self.variant, ShredVariant::MerkleData(_, _) | ShredVariant::MerkleCoding(_, _))
    }

    /// Check if this is the last shred in a slot
    pub fn is_last_in_slot(&self) -> bool {
        match &self.variant {
            ShredVariant::LegacyData(header) | ShredVariant::MerkleData(header, _) => {
                header.flags & SHRED_LAST_IN_SLOT != 0
            }
            _ => false,
        }
    }

    /// Get the FEC set ID
    pub fn fec_set_id(&self) -> FecSetId {
        FecSetId {
            slot: self.slot(),
            index: self.fec_set_index(),
        }
    }

    /// Get data shred header if this is a data shred
    pub fn data_header(&self) -> Option<&DataShredHeader> {
        match &self.variant {
            ShredVariant::LegacyData(header) | ShredVariant::MerkleData(header, _) => Some(header),
            _ => None,
        }
    }

    /// Get coding shred header if this is a coding shred
    pub fn coding_header(&self) -> Option<&CodingShredHeader> {
        match &self.variant {
            ShredVariant::LegacyCoding(header) | ShredVariant::MerkleCoding(header, _) => Some(header),
            _ => None,
        }
    }

    /// Get the actual data size (for data shreds)
    pub fn data_size(&self) -> Option<usize> {
        self.data_header().map(|h| h.size as usize)
    }

    /// Extract metadata from this shred
    pub fn metadata(&self) -> ShredMetadata {
        ShredMetadata {
            slot: self.slot(),
            index: self.index(),
            fec_set_index: self.fec_set_index(),
            is_data: self.is_data(),
            is_coding: self.is_coding(),
            size: self.payload.len(),
            received_at: 0, // Set by window store
        }
    }
}

impl FecSetId {
    /// Create a new FEC set ID
    pub fn new(slot: u64, index: u32) -> Self {
        Self { slot, index }
    }
}

impl std::fmt::Display for FecSetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FecSet(slot={}, index={})", self.slot, self.index)
    }
}

impl ShredMetadata {
    /// Check if this represents a data shred
    pub fn is_data_shred(&self) -> bool {
        self.is_data
    }

    /// Check if this represents a coding shred
    pub fn is_coding_shred(&self) -> bool {
        self.is_coding
    }

    /// Get the FEC set ID
    pub fn fec_set_id(&self) -> FecSetId {
        FecSetId {
            slot: self.slot,
            index: self.fec_set_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shred_constants() {
        assert_eq!(SHRED_SIZE, 1228);
        assert_eq!(SHRED_HEADER_SIZE, 88);
        assert_eq!(MAX_DATA_SHREDS_PER_FEC_BLOCK, 67);
        assert_eq!(SHRED_PAYLOAD_SIZE, SHRED_SIZE - SHRED_HEADER_SIZE);
    }

    #[test]
    fn test_shred_variant_flags() {
        assert_eq!(SHRED_DATA_FLAG & SHRED_VARIANT_MASK, SHRED_DATA_FLAG);
        assert_eq!(SHRED_CODE_FLAG & SHRED_VARIANT_MASK, SHRED_CODE_FLAG);
    }

    #[test]
    fn test_fec_set_id() {
        let id1 = FecSetId::new(100, 5);
        let id2 = FecSetId::new(100, 5);
        let id3 = FecSetId::new(100, 6);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_shred_type_checks() {
        let common_header = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: SHRED_DATA_FLAG,
            slot: 100,
            index: 0,
            version: 1,
            fec_set_index: 0,
        };

        let data_header = DataShredHeader {
            parent_offset: 1,
            flags: 0,
            size: 512,
        };

        let shred = Shred::new(
            common_header,
            ShredVariant::LegacyData(data_header),
            vec![0; 512],
        );

        assert!(shred.is_data());
        assert!(!shred.is_coding());
        assert!(!shred.is_merkle());
        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 0);
        assert_eq!(shred.data_size(), Some(512));
    }
}
