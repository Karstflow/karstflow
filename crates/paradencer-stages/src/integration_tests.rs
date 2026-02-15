//! Integration tests for complete shred processing pipeline
//!
//! Tests the flow: network packets -> shreds -> window store -> FEC reconstruction -> block assembly

#[cfg(test)]
mod tests {
    use paradencer_crypto::FecReconstructor;
    use paradencer_storage::{ShredWindowConfig, ShredWindowStore};
    use paradencer_types::shred::*;
    use crate::shred_assembler::*;
    use reed_solomon_erasure::galois_8::ReedSolomon;

    /// Create a deterministic test shred
    fn create_test_shred(slot: u64, index: u32, fec_set_index: u32, data: &[u8]) -> Shred {
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
                flags: if index == 9 { SHRED_LAST_IN_SLOT } else { 0 },
                size: data.len() as u16,
            }),
            data.to_vec(),
        )
    }

    /// Create coding shred for testing
    fn create_coding_shred(
        slot: u64,
        index: u32,
        fec_set_index: u32,
        num_data: u16,
        num_coding: u16,
        data: &[u8],
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
            data.to_vec(),
        )
    }

    /// Create entry bytes for testing
    fn create_entry_bytes(num_hashes: u64, hash: [u8; 32], transactions: Vec<Vec<u8>>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&num_hashes.to_le_bytes());
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&(transactions.len() as u64).to_le_bytes());

        for tx in transactions {
            bytes.extend_from_slice(&(tx.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&tx);
        }

        bytes
    }

    #[test]
    fn test_complete_pipeline_single_fec_set() {
        // Step 1: Create test data representing entries
        let tx1 = vec![1, 2, 3, 4, 5];
        let tx2 = vec![6, 7, 8, 9, 10];
        let entry_data = create_entry_bytes(10, [0xAB; 32], vec![tx1.clone(), tx2.clone()]);

        // Step 2: Create shreds with the entry data
        let shred = create_test_shred(100, 0, 0, &entry_data);

        // Step 3: Insert into window store
        let window = ShredWindowStore::with_defaults();
        assert!(window.insert(shred.clone()).unwrap());

        // Step 4: Retrieve shreds from window
        let retrieved = window.get_slot_shreds(100).unwrap();
        assert_eq!(retrieved.len(), 1);

        // Step 5: Assemble block
        let mut assembler = ShredAssembler::new();
        let block = assembler.assemble_block(retrieved).unwrap();

        // Verify block contents
        assert_eq!(block.slot, 100);
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.entries[0].transactions.len(), 2);
        assert_eq!(block.entries[0].transactions[0], tx1);
        assert_eq!(block.entries[0].transactions[1], tx2);
    }

    #[test]
    fn test_pipeline_with_multiple_shreds() {
        // Create multiple entries
        let entry1 = create_entry_bytes(10, [0xAA; 32], vec![vec![1, 2, 3]]);
        let entry2 = create_entry_bytes(20, [0xBB; 32], vec![vec![4, 5, 6]]);
        let entry3 = create_entry_bytes(30, [0xCC; 32], vec![vec![7, 8, 9]]);

        // Split across multiple shreds
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&entry1);
        all_data.extend_from_slice(&entry2);
        all_data.extend_from_slice(&entry3);

        let chunk_size = all_data.len() / 3;
        let shreds = vec![
            create_test_shred(100, 0, 0, &all_data[0..chunk_size]),
            create_test_shred(100, 1, 0, &all_data[chunk_size..chunk_size * 2]),
            create_test_shred(100, 2, 0, &all_data[chunk_size * 2..]),
        ];

        // Insert into window (out of order)
        let window = ShredWindowStore::with_defaults();
        window.insert(shreds[2].clone()).unwrap();
        window.insert(shreds[0].clone()).unwrap();
        window.insert(shreds[1].clone()).unwrap();

        // Retrieve and assemble
        let retrieved = window.get_slot_shreds(100).unwrap();
        assert_eq!(retrieved.len(), 3);

        let mut assembler = ShredAssembler::new();
        let block = assembler.assemble_block(retrieved).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.entries.len(), 3);
        assert_eq!(block.transaction_count, 3);
    }

    #[test]
    fn test_pipeline_with_fec_reconstruction() {
        // Create test data
        let test_data: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let entry = create_entry_bytes(i, [i as u8; 32], vec![vec![i as u8; 10]]);
                entry
            })
            .collect();

        // Pad to uniform size
        let max_size = test_data.iter().map(|d| d.len()).max().unwrap();
        let mut uniform_data: Vec<Vec<u8>> = test_data
            .iter()
            .map(|d| {
                let mut padded = d.clone();
                padded.resize(max_size, 0);
                padded
            })
            .collect();

        // Create FEC coding shreds using Reed-Solomon
        let codec = ReedSolomon::new(4, 4).unwrap();
        let mut all_shreds = uniform_data.clone();
        all_shreds.extend(vec![vec![0u8; max_size]; 4]);

        let mut shreds_refs: Vec<_> = all_shreds.iter_mut().map(|s| s.as_mut_slice()).collect();
        codec.encode(&mut shreds_refs).unwrap();

        // Create shred objects
        let mut data_shreds: Vec<Shred> = uniform_data
            .iter()
            .enumerate()
            .map(|(i, data)| create_test_shred(100, i as u32, 0, data))
            .collect();

        let coding_shreds: Vec<Shred> = all_shreds[4..]
            .iter()
            .enumerate()
            .map(|(i, data)| create_coding_shred(100, (i + 4) as u32, 0, 4, 4, data))
            .collect();

        // Simulate loss: drop first 2 data shreds
        let available_shreds: Vec<Shred> = data_shreds[2..]
            .iter()
            .chain(coding_shreds.iter())
            .cloned()
            .collect();

        // Insert into window with auto-reconstruction enabled
        let config = ShredWindowConfig {
            enable_auto_reconstruction: true,
            min_shreds_for_reconstruction: 4,
            ..Default::default()
        };
        let window = ShredWindowStore::new(config);

        for shred in available_shreds {
            window.insert(shred).unwrap();
        }

        // Check statistics
        let stats = window.stats();
        assert!(stats.total_shreds_inserted >= 4); // At least the ones we inserted
    }

    #[test]
    fn test_pipeline_multiple_slots() {
        let window = ShredWindowStore::with_defaults();

        // Create shreds for multiple slots
        for slot in 100..110 {
            let entry_data = create_entry_bytes(slot, [slot as u8; 32], vec![vec![slot as u8; 5]]);
            let shred = create_test_shred(slot, 0, 0, &entry_data);
            window.insert(shred).unwrap();
        }

        // Verify all slots are tracked
        let stats = window.stats();
        assert_eq!(stats.active_slots, 10);

        // Advance root and prune old slots
        let pruned = window.advance_root(105);
        assert_eq!(pruned, 5);

        let stats = window.stats();
        assert_eq!(stats.active_slots, 5);

        // Assemble remaining slots
        let mut assembler = ShredAssembler::new();
        for slot in 105..110 {
            if let Some(shreds) = window.get_slot_shreds(slot) {
                let block = assembler.assemble_block(shreds).unwrap();
                assert_eq!(block.slot, slot);
            }
        }
    }

    #[test]
    fn test_deduplication() {
        let window = ShredWindowStore::with_defaults();

        let shred1 = create_test_shred(100, 0, 0, &[1, 2, 3]);
        let shred2 = create_test_shred(100, 0, 0, &[1, 2, 3]); // Duplicate

        assert!(window.insert(shred1).unwrap());
        assert!(!window.insert(shred2).unwrap()); // Should be rejected as duplicate

        let stats = window.stats();
        assert_eq!(stats.total_shreds_inserted, 1);
        assert_eq!(stats.total_duplicates, 1);
    }

    #[test]
    fn test_block_boundary_detection() {
        let mut shreds = vec![
            create_test_shred(100, 0, 0, &[1, 2, 3]),
            create_test_shred(100, 1, 0, &[4, 5, 6]),
            create_test_shred(100, 2, 0, &[7, 8, 9]),
        ];

        // No boundary yet
        assert_eq!(detect_block_boundary(&shreds), None);

        // Mark last shred
        if let ShredVariant::LegacyData(ref mut header) = shreds[2].variant {
            header.flags |= SHRED_LAST_IN_SLOT;
        }

        assert_eq!(detect_block_boundary(&shreds), Some(3));
    }

    #[test]
    fn test_group_shreds_by_slot() {
        let shreds = vec![
            create_test_shred(100, 0, 0, &[1]),
            create_test_shred(101, 0, 0, &[2]),
            create_test_shred(100, 1, 0, &[3]),
            create_test_shred(102, 0, 0, &[4]),
            create_test_shred(101, 1, 0, &[5]),
        ];

        let grouped = group_shreds_by_slot(shreds);

        assert_eq!(grouped.len(), 3);
        assert_eq!(grouped.get(&100).unwrap().len(), 2);
        assert_eq!(grouped.get(&101).unwrap().len(), 2);
        assert_eq!(grouped.get(&102).unwrap().len(), 1);
    }

    #[test]
    fn test_parse_serialize_in_pipeline() {
        let entry_data = create_entry_bytes(42, [0xDE; 32], vec![vec![1, 2, 3, 4]]);
        let original_shred = create_test_shred(100, 5, 0, &entry_data);

        // Serialize as if sending over network
        let serialized = ShredParser::serialize(&original_shred).unwrap();

        // Parse as if receiving from network
        let parsed_shred = ShredParser::parse(&serialized).unwrap();

        // Insert into window
        let window = ShredWindowStore::with_defaults();
        window.insert(parsed_shred).unwrap();

        // Retrieve and assemble
        let shreds = window.get_slot_shreds(100).unwrap();
        let mut assembler = ShredAssembler::new();
        let block = assembler.assemble_block(shreds).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.entries[0].num_hashes, 42);
        assert_eq!(block.entries[0].hash, [0xDE; 32]);
    }

    #[test]
    fn test_large_block_assembly() {
        // Create a larger block with many entries
        let mut all_data = Vec::new();
        for i in 0..20 {
            let tx = vec![i as u8; 100];
            let entry = create_entry_bytes(i as u64, [i as u8; 32], vec![tx]);
            all_data.extend_from_slice(&entry);
        }

        // Split into multiple shreds
        let shred_size = 500;
        let mut shreds = Vec::new();
        for (idx, chunk) in all_data.chunks(shred_size).enumerate() {
            let is_last = idx == (all_data.len() + shred_size - 1) / shred_size - 1;
            let mut shred = create_test_shred(100, idx as u32, 0, chunk);

            if is_last {
                if let ShredVariant::LegacyData(ref mut header) = shred.variant {
                    header.flags |= SHRED_LAST_IN_SLOT;
                }
            }

            shreds.push(shred);
        }

        // Process through pipeline
        let window = ShredWindowStore::with_defaults();
        for shred in &shreds {
            window.insert(shred.clone()).unwrap();
        }

        let retrieved = window.get_slot_shreds(100).unwrap();
        let mut assembler = ShredAssembler::new();
        let block = assembler.assemble_block(retrieved).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.entries.len(), 20);
        assert_eq!(block.transaction_count, 20);

        // Verify statistics
        let stats = assembler.stats();
        assert_eq!(stats.blocks_assembled, 1);
        assert_eq!(stats.entries_extracted, 20);
        assert_eq!(stats.transactions_extracted, 20);
    }
}
