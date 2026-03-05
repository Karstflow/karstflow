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
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(ArrayVisitor)
    }
}

// Re-export wire-format constants from karstflow-constants for backward compat.
pub use karstflow_constants::shred::{
    MERKLE_MAX_PROOF_DEPTH, MERKLE_PROOF_NODE_BYTES, SHRED_CODE_HEADER_BYTES,
    SHRED_DATA_HEADER_BYTES, SHRED_MAX_SIZE, SHRED_MIN_SIZE, SHRED_SIGNATURE_BYTES,
};

/// Size of a complete shred packet in bytes (alias for SHRED_MAX_SIZE).
pub const SHRED_SIZE: usize = SHRED_MAX_SIZE;

/// Size of the data shred header in bytes.
pub const SHRED_HEADER_SIZE: usize = SHRED_DATA_HEADER_BYTES;

/// Maximum number of data shreds per FEC block.
pub const MAX_DATA_SHREDS_PER_FEC_BLOCK: usize = karstflow_constants::shred::MAX_FEC_DATA_SHREDS;

/// Maximum number of coding shreds per FEC block.
pub const MAX_CODING_SHREDS_PER_FEC_BLOCK: usize =
    karstflow_constants::shred::MAX_FEC_CODING_SHREDS;

/// Signature size in bytes (Ed25519).
pub const SIGNATURE_SIZE: usize = SHRED_SIGNATURE_BYTES;

/// Data shred payload size (SHRED_MIN_SIZE - SHRED_DATA_HEADER_BYTES).
pub const DATA_SHRED_PAYLOAD_SIZE: usize = SHRED_MIN_SIZE - SHRED_DATA_HEADER_BYTES;

/// Coding shred payload size (SHRED_MAX_SIZE - SHRED_CODE_HEADER_BYTES).
pub const CODING_SHRED_PAYLOAD_SIZE: usize = SHRED_MAX_SIZE - SHRED_CODE_HEADER_BYTES;

/// Shred payload size for legacy data (no Merkle overhead).
pub const SHRED_PAYLOAD_SIZE: usize = SHRED_SIZE - SHRED_HEADER_SIZE;

// Re-export variant byte constants.
pub use karstflow_constants::shred::{
    SHRED_LEGACY_CODE_NIBBLE, SHRED_LEGACY_DATA_NIBBLE, SHRED_PROOF_COUNT_MASK,
    SHRED_TYPEMASK_CODE, SHRED_TYPEMASK_DATA, SHRED_TYPE_LEGACY_CODE, SHRED_TYPE_LEGACY_DATA,
    SHRED_TYPE_MASK, SHRED_TYPE_MERKLE_CODE, SHRED_TYPE_MERKLE_CODE_CHAINED,
    SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED, SHRED_TYPE_MERKLE_DATA,
    SHRED_TYPE_MERKLE_DATA_CHAINED, SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED,
};

// Backward compat aliases (used widely in existing code).
/// Lower nibble value for legacy data variant byte.
pub const SHRED_DATA_FLAG: u8 = SHRED_LEGACY_DATA_NIBBLE;
/// Lower nibble value for legacy code variant byte.
pub const SHRED_CODE_FLAG: u8 = SHRED_LEGACY_CODE_NIBBLE;

/// Last shred in slot flag (bit in data shred flags byte).
pub const SHRED_LAST_IN_SLOT: u8 = 0x80;

/// A complete shred with all its components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shred {
    /// Common header present in all shreds.
    pub common_header: ShredCommonHeader,

    /// Variant-specific data.
    pub variant: ShredVariant,

    /// Payload bytes (after header, before Merkle proof for Merkle shreds).
    pub payload: Vec<u8>,

    /// Original wire-format bytes when parsed from the network.
    /// Used for Merkle signature verification which hashes over raw bytes.
    #[serde(skip)]
    pub raw: Option<Vec<u8>>,
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

/// Merkle proof for shred authentication.
///
/// Each node is a 20-byte truncated SHA-256 hash. The proof contains
/// sibling hashes needed to reconstruct the Merkle root from a leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Merkle tree proof nodes (truncated 20-byte SHA-256 hashes).
    pub proof: Vec<[u8; MERKLE_PROOF_NODE_BYTES]>,
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
    /// Create a new shred with the given components.
    pub fn new(common_header: ShredCommonHeader, variant: ShredVariant, payload: Vec<u8>) -> Self {
        Self {
            common_header,
            variant,
            payload,
            raw: None,
        }
    }

    /// Create a new shred preserving original wire-format bytes.
    pub fn with_raw(
        common_header: ShredCommonHeader,
        variant: ShredVariant,
        payload: Vec<u8>,
        raw: Vec<u8>,
    ) -> Self {
        Self {
            common_header,
            variant,
            payload,
            raw: Some(raw),
        }
    }

    /// Get the slot number.
    pub fn slot(&self) -> u64 {
        self.common_header.slot
    }

    /// Compute the parent slot from the data shred header's parent offset.
    ///
    /// Returns `None` for coding shreds (which don't carry parent info).
    pub fn parent_slot(&self) -> Option<u64> {
        self.data_header().map(|h| {
            self.common_header
                .slot
                .saturating_sub(h.parent_offset as u64)
        })
    }

    /// Get the shred index.
    pub fn index(&self) -> u32 {
        self.common_header.index
    }

    /// Get the FEC set index.
    pub fn fec_set_index(&self) -> u32 {
        self.common_header.fec_set_index
    }

    /// Extract the shred type from the variant byte (upper nibble).
    pub fn shred_type(&self) -> u8 {
        self.common_header.variant & SHRED_TYPE_MASK
    }

    /// Check if this is a data shred (from the parsed variant enum).
    pub fn is_data(&self) -> bool {
        matches!(
            self.variant,
            ShredVariant::LegacyData(_) | ShredVariant::MerkleData(_, _)
        )
    }

    /// Check if this is a coding shred (from the parsed variant enum).
    pub fn is_coding(&self) -> bool {
        matches!(
            self.variant,
            ShredVariant::LegacyCoding(_) | ShredVariant::MerkleCoding(_, _)
        )
    }

    /// Check if this shred uses Merkle proofs (from the parsed variant enum).
    pub fn is_merkle(&self) -> bool {
        matches!(
            self.variant,
            ShredVariant::MerkleData(_, _) | ShredVariant::MerkleCoding(_, _)
        )
    }

    /// Check if this is a chained Merkle shred (from variant byte).
    pub fn is_chained(&self) -> bool {
        let t = self.shred_type();
        t == SHRED_TYPE_MERKLE_DATA_CHAINED
            || t == SHRED_TYPE_MERKLE_CODE_CHAINED
            || t == SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED
            || t == SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED
    }

    /// Check if this is a resigned (retransmitter-signed) Merkle shred (from variant byte).
    pub fn is_resigned(&self) -> bool {
        let t = self.shred_type();
        t == SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED || t == SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED
    }

    /// Get the Merkle proof depth (number of proof nodes) from the variant byte.
    /// Returns 0 for legacy shreds.
    pub fn merkle_proof_count(&self) -> usize {
        let t = self.shred_type();
        if t == SHRED_TYPE_LEGACY_DATA || t == SHRED_TYPE_LEGACY_CODE {
            0
        } else {
            (self.common_header.variant & SHRED_PROOF_COUNT_MASK) as usize
        }
    }

    /// Check if this is the last shred in a slot.
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
            ShredVariant::LegacyCoding(header) | ShredVariant::MerkleCoding(header, _) => {
                Some(header)
            }
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
    fn test_variant_byte_encoding() {
        // Legacy data: 0xA5 → type=0xA0, nibble=5
        let v = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        assert_eq!(v, 0xA5);
        assert_eq!(v & SHRED_TYPE_MASK, SHRED_TYPE_LEGACY_DATA);
        assert_eq!(v & SHRED_TYPEMASK_DATA, SHRED_TYPEMASK_DATA);
        assert_eq!(v & SHRED_TYPEMASK_CODE, 0);

        // Legacy code: 0x5A → type=0x50, nibble=0xA
        let v = SHRED_TYPE_LEGACY_CODE | SHRED_LEGACY_CODE_NIBBLE;
        assert_eq!(v, 0x5A);
        assert_eq!(v & SHRED_TYPE_MASK, SHRED_TYPE_LEGACY_CODE);
        assert_eq!(v & SHRED_TYPEMASK_CODE, SHRED_TYPEMASK_CODE);

        // Merkle data with 5 proof nodes: 0x85
        let v = SHRED_TYPE_MERKLE_DATA | 5;
        assert_eq!(v, 0x85);
        assert_eq!(v & SHRED_TYPE_MASK, SHRED_TYPE_MERKLE_DATA);
        assert_eq!(v & SHRED_PROOF_COUNT_MASK, 5);
        assert_eq!(v & SHRED_TYPEMASK_DATA, SHRED_TYPEMASK_DATA);

        // Merkle code with 10 proof nodes: 0x4A
        let v = SHRED_TYPE_MERKLE_CODE | 10;
        assert_eq!(v, 0x4A);
        assert_eq!(v & SHRED_TYPE_MASK, SHRED_TYPE_MERKLE_CODE);
        assert_eq!(v & SHRED_PROOF_COUNT_MASK, 10);
        assert_eq!(v & SHRED_TYPEMASK_CODE, SHRED_TYPEMASK_CODE);
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
    fn test_shred_type_checks_legacy_data() {
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE; // 0xA5
        let common_header = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
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
        assert!(!shred.is_chained());
        assert!(!shred.is_resigned());
        assert_eq!(shred.merkle_proof_count(), 0);
        assert_eq!(shred.slot(), 100);
        assert_eq!(shred.index(), 0);
        assert_eq!(shred.data_size(), Some(512));
    }

    #[test]
    fn test_shred_type_checks_merkle_data() {
        let proof_depth = 5u8;
        let variant_byte = SHRED_TYPE_MERKLE_DATA | proof_depth; // 0x85
        let common_header = ShredCommonHeader {
            signature: [1; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 200,
            index: 3,
            version: 2,
            fec_set_index: 0,
        };

        let data_header = DataShredHeader {
            parent_offset: 1,
            flags: 0,
            size: 512,
        };

        let proof = MerkleProof {
            proof: vec![[0xAA; MERKLE_PROOF_NODE_BYTES]; proof_depth as usize],
        };

        let shred = Shred::new(
            common_header,
            ShredVariant::MerkleData(data_header, proof),
            vec![0; 512],
        );

        assert!(shred.is_data());
        assert!(!shred.is_coding());
        assert!(shred.is_merkle());
        assert!(!shred.is_chained());
        assert!(!shred.is_resigned());
        assert_eq!(shred.merkle_proof_count(), 5);
    }

    #[test]
    fn test_shred_type_checks_merkle_code_chained_resigned() {
        let proof_depth = 8u8;
        let variant_byte = SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED | proof_depth; // 0x78
        let common_header = ShredCommonHeader {
            signature: [1; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 300,
            index: 10,
            version: 1,
            fec_set_index: 5,
        };

        let coding_header = CodingShredHeader {
            num_data_shreds: 32,
            num_coding_shreds: 32,
            position: 3,
        };

        let proof = MerkleProof {
            proof: vec![[0xBB; MERKLE_PROOF_NODE_BYTES]; proof_depth as usize],
        };

        let shred = Shred::new(
            common_header,
            ShredVariant::MerkleCoding(coding_header, proof),
            vec![0; 256],
        );

        assert!(!shred.is_data());
        assert!(shred.is_coding());
        assert!(shred.is_merkle());
        assert!(shred.is_chained());
        assert!(shred.is_resigned());
        assert_eq!(shred.merkle_proof_count(), 8);
    }

    #[test]
    fn test_parent_slot_data_shred() {
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        let common = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 100,
            index: 0,
            version: 1,
            fec_set_index: 0,
        };
        let data_header = DataShredHeader {
            parent_offset: 3,
            flags: 0,
            size: 64,
        };
        let shred = Shred::new(common, ShredVariant::LegacyData(data_header), vec![0; 64]);

        assert_eq!(shred.parent_slot(), Some(97)); // 100 - 3
    }

    #[test]
    fn test_parent_slot_same_slot() {
        // parent_offset == 0 means parent is the same slot (genesis-like)
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
        let common = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 50,
            index: 0,
            version: 1,
            fec_set_index: 0,
        };
        let data_header = DataShredHeader {
            parent_offset: 0,
            flags: 0,
            size: 64,
        };
        let shred = Shred::new(common, ShredVariant::LegacyData(data_header), vec![0; 64]);

        assert_eq!(shred.parent_slot(), Some(50)); // 50 - 0
    }

    #[test]
    fn test_parent_slot_coding_shred_returns_none() {
        let variant_byte = SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED | 4;
        let common = ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 200,
            index: 5,
            version: 1,
            fec_set_index: 0,
        };
        let coding_header = CodingShredHeader {
            num_data_shreds: 32,
            num_coding_shreds: 32,
            position: 0,
        };
        let proof = MerkleProof {
            proof: vec![[0; MERKLE_PROOF_NODE_BYTES]; 4],
        };
        let shred = Shred::new(
            common,
            ShredVariant::MerkleCoding(coding_header, proof),
            vec![0; 256],
        );

        assert_eq!(shred.parent_slot(), None);
    }
}
