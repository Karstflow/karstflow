//! Integration tests for shred processing
//!
//! These tests verify the complete shred processing pipeline from raw packets
//! to reconstructed blocks.

use crate::shred::*;

/// Helper to create a test legacy data shred.
fn create_data_shred(slot: u64, index: u32, fec_set_index: u32, payload: Vec<u8>) -> Shred {
    let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE; // 0xA5
    Shred::new(
        ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot,
            index,
            version: 1,
            fec_set_index,
        },
        ShredVariant::LegacyData(DataShredHeader {
            parent_offset: 1,
            flags: 0,
            size: payload.len() as u16,
        }),
        payload,
    )
}

/// Helper to create a test legacy coding shred.
fn create_coding_shred(
    slot: u64,
    index: u32,
    fec_set_index: u32,
    num_data: u16,
    num_coding: u16,
    payload: Vec<u8>,
) -> Shred {
    let variant_byte = SHRED_TYPE_LEGACY_CODE | SHRED_LEGACY_CODE_NIBBLE; // 0x5A
    Shred::new(
        ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: variant_byte,
            slot,
            index,
            version: 1,
            fec_set_index,
        },
        ShredVariant::LegacyCoding(CodingShredHeader {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            position: index as u16,
        }),
        payload,
    )
}

#[test]
fn test_shred_parse_serialize_roundtrip() {
    let original = create_data_shred(100, 5, 0, vec![0xAB; 512]);
    let serialized = ShredParser::serialize(&original).unwrap();
    let parsed = ShredParser::parse(&serialized).unwrap();

    assert_eq!(parsed.slot(), original.slot());
    assert_eq!(parsed.index(), original.index());
    assert_eq!(parsed.fec_set_index(), original.fec_set_index());
    assert_eq!(parsed.is_data(), original.is_data());
    assert_eq!(parsed.payload.len(), original.payload.len());
}

#[test]
fn test_all_shred_variants() {
    let proof_depth = 5u8;
    let variant_byte = SHRED_TYPE_MERKLE_DATA | proof_depth;
    let merkle_data = Shred::new(
        ShredCommonHeader {
            signature: [1; SIGNATURE_SIZE],
            variant: variant_byte,
            slot: 100,
            index: 2,
            version: 1,
            fec_set_index: 0,
        },
        ShredVariant::MerkleData(
            DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: 256,
            },
            MerkleProof {
                proof: vec![[0xFF; MERKLE_PROOF_NODE_BYTES]; proof_depth as usize],
            },
        ),
        vec![3; 256],
    );

    let variants = vec![
        create_data_shred(100, 0, 0, vec![1; 256]),
        create_coding_shred(100, 1, 0, 4, 4, vec![2; 256]),
        merkle_data,
    ];

    for shred in &variants {
        assert!(shred.is_data() || shred.is_coding());
    }

    // Check type identification.
    assert!(variants[0].is_data());
    assert!(!variants[0].is_merkle());
    assert!(variants[1].is_coding());
    assert!(!variants[1].is_merkle());
    assert!(variants[2].is_data());
    assert!(variants[2].is_merkle());
    assert_eq!(variants[2].merkle_proof_count(), 5);
}

#[test]
fn test_fec_set_id() {
    let shred = create_data_shred(100, 5, 3, vec![0; 128]);
    let fec_id = shred.fec_set_id();

    assert_eq!(fec_id.slot, 100);
    assert_eq!(fec_id.index, 3);
}

#[test]
fn test_shred_metadata() {
    let shred = create_data_shred(100, 5, 0, vec![0; 512]);
    let metadata = shred.metadata();

    assert_eq!(metadata.slot, 100);
    assert_eq!(metadata.index, 5);
    assert_eq!(metadata.fec_set_index, 0);
    assert!(metadata.is_data);
    assert!(!metadata.is_coding);
}

#[test]
fn test_last_in_slot_flag() {
    let mut shred = create_data_shred(100, 10, 0, vec![0; 128]);

    // Initially not last.
    assert!(!shred.is_last_in_slot());

    // Set last in slot flag.
    if let ShredVariant::LegacyData(ref mut header) = shred.variant {
        header.flags |= SHRED_LAST_IN_SLOT;
    }

    assert!(shred.is_last_in_slot());
}

#[test]
fn test_parse_invalid_shred() {
    // Too short.
    let short_data = vec![0u8; 10];
    assert!(ShredParser::parse(&short_data).is_err());

    // Invalid variant: 0x30 has no data or code bit set.
    let mut invalid_variant = vec![0u8; SHRED_HEADER_SIZE + 100];
    invalid_variant[SIGNATURE_SIZE] = 0x30;
    assert!(ShredParser::parse(&invalid_variant).is_err());
}

#[test]
fn test_shred_size_constants() {
    assert_eq!(SHRED_SIZE, 1228);
    assert_eq!(SHRED_HEADER_SIZE, 88);
    assert_eq!(SHRED_PAYLOAD_SIZE, SHRED_SIZE - SHRED_HEADER_SIZE);
    assert_eq!(
        DATA_SHRED_PAYLOAD_SIZE,
        SHRED_MIN_SIZE - SHRED_DATA_HEADER_BYTES
    );
    assert_eq!(MAX_DATA_SHREDS_PER_FEC_BLOCK, 67);
}

#[test]
fn test_shred_ordering() {
    let mut shreds = [
        create_data_shred(100, 5, 0, vec![0; 64]),
        create_data_shred(100, 2, 0, vec![0; 64]),
        create_data_shred(100, 8, 0, vec![0; 64]),
        create_data_shred(100, 1, 0, vec![0; 64]),
    ];

    shreds.sort_by_key(|s| s.index());

    assert_eq!(shreds[0].index(), 1);
    assert_eq!(shreds[1].index(), 2);
    assert_eq!(shreds[2].index(), 5);
    assert_eq!(shreds[3].index(), 8);
}

#[test]
fn test_merkle_proof_20_byte_entries() {
    let proof = MerkleProof {
        proof: vec![[0xAB; MERKLE_PROOF_NODE_BYTES]; 10],
    };

    assert_eq!(proof.proof.len(), 10);
    assert_eq!(proof.proof[0].len(), 20);
}
