//! Integration tests for shred processing
//!
//! These tests verify the complete shred processing pipeline from raw packets
//! to reconstructed blocks.

#[cfg(test)]
mod integration_tests {
    use crate::shred::*;
    use paradencer_crypto::{FecReconstructor, reconstruct_fec_set};

    /// Helper to create a test data shred
    fn create_data_shred(slot: u64, index: u32, fec_set_index: u32, payload: Vec<u8>) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_DATA_FLAG,
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

    /// Helper to create a test coding shred
    fn create_coding_shred(
        slot: u64,
        index: u32,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
        payload: Vec<u8>,
    ) -> Shred {
        Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_CODE_FLAG,
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
        let variants = vec![
            create_data_shred(100, 0, 0, vec![1; 256]),
            create_coding_shred(100, 1, 0, 4, 4, vec![2; 256]),
            // Merkle variants
            Shred::new(
                ShredCommonHeader {
                    signature: [0; SIGNATURE_SIZE],
                    variant: SHRED_DATA_FLAG | SHRED_MERKLE_FLAG,
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
                        proof: vec![[0xFF; 32]; 5],
                    },
                ),
                vec![3; 256],
            ),
        ];

        for shred in variants {
            let serialized = ShredParser::serialize(&shred).unwrap();
            let parsed = ShredParser::parse(&serialized).unwrap();

            assert_eq!(parsed.slot(), shred.slot());
            assert_eq!(parsed.index(), shred.index());
            assert_eq!(parsed.is_data(), shred.is_data());
            assert_eq!(parsed.is_coding(), shred.is_coding());
            assert_eq!(parsed.is_merkle(), shred.is_merkle());
        }
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

        // Initially not last
        assert!(!shred.is_last_in_slot());

        // Set last in slot flag
        if let ShredVariant::LegacyData(ref mut header) = shred.variant {
            header.flags |= SHRED_LAST_IN_SLOT;
        }

        assert!(shred.is_last_in_slot());
    }

    #[test]
    fn test_parse_invalid_shred() {
        // Too short
        let short_data = vec![0u8; 10];
        assert!(ShredParser::parse(&short_data).is_err());

        // Invalid variant
        let mut invalid_variant = vec![0u8; SHRED_HEADER_SIZE + 100];
        invalid_variant[SIGNATURE_SIZE] = 0xFF; // Invalid variant byte
        assert!(ShredParser::parse(&invalid_variant).is_err());
    }

    #[test]
    fn test_shred_size_constants() {
        assert_eq!(SHRED_SIZE, 1228);
        assert_eq!(SHRED_HEADER_SIZE, 88);
        assert_eq!(SHRED_PAYLOAD_SIZE, SHRED_SIZE - SHRED_HEADER_SIZE);
        assert_eq!(DATA_SHRED_PAYLOAD_SIZE, 1051);
        assert_eq!(MAX_DATA_SHREDS_PER_FEC_BLOCK, 67);
    }

    #[test]
    fn test_shred_ordering() {
        let mut shreds = vec![
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
    fn test_parse_merkle_proof() {
        let proof = MerkleProof {
            proof: vec![[0xAB; 32]; 10],
        };

        let shred = Shred::new(
            ShredCommonHeader {
                signature: [0; SIGNATURE_SIZE],
                variant: SHRED_DATA_FLAG | SHRED_MERKLE_FLAG,
                slot: 100,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::MerkleData(
                DataShredHeader {
                    parent_offset: 1,
                    flags: 0,
                    size: 256,
                },
                proof.clone(),
            ),
            vec![0; 256],
        );

        let serialized = ShredParser::serialize(&shred).unwrap();
        let parsed = ShredParser::parse(&serialized).unwrap();

        match &parsed.variant {
            ShredVariant::MerkleData(_, parsed_proof) => {
                assert_eq!(parsed_proof.proof.len(), proof.proof.len());
            }
            _ => panic!("Expected MerkleData variant"),
        }
    }
}
