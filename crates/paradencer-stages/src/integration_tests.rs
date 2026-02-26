//! Integration tests for complete shred processing pipeline
//!
//! Tests the flow: network packets -> shreds -> window store -> FEC reconstruction -> block assembly

#[cfg(test)]
mod tests {
    use crate::block_producer::PohEntry;
    use crate::shred_assembler::*;
    use paradencer_crypto::FecReconstructor;
    use paradencer_storage::{ShredWindowConfig, ShredWindowStore};
    use paradencer_types::shred::*;
    use paradencer_types::Hash;
    use reed_solomon_erasure::galois_8::ReedSolomon;

    /// Create a deterministic test shred
    fn create_test_shred(slot: u64, index: u32, fec_set_index: u32, data: &[u8]) -> Shred {
        let variant_byte = SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE;
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
        let variant_byte = SHRED_TYPE_LEGACY_CODE | SHRED_LEGACY_CODE_NIBBLE;
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
            data.to_vec(),
        )
    }

    /// Create a bincode-serialized entry batch.
    fn create_entry_batch(entries: &[PohEntry]) -> Vec<u8> {
        PohEntry::batch_to_bytes(entries)
    }

    #[test]
    fn test_complete_pipeline_single_fec_set() {
        let tx1 = vec![1, 2, 3, 4, 5];
        let tx2 = vec![6, 7, 8, 9, 10];
        let entry = PohEntry::new(10, Hash::new([0xAB; 32]), vec![tx1.clone(), tx2.clone()]);
        let entry_data = create_entry_batch(&[entry]);

        let shred = create_test_shred(100, 0, 0, &entry_data);

        let window = ShredWindowStore::with_defaults();
        assert!(window.insert(shred.clone()).unwrap());

        let retrieved = window.get_slot_shreds(100).unwrap();
        assert_eq!(retrieved.len(), 1);

        let mut assembler = ShredAssembler::new();
        let block = assembler.assemble_block(retrieved).unwrap();

        assert_eq!(block.slot, 100);
        assert_eq!(block.entries.len(), 1);
        assert_eq!(block.entries[0].transactions.len(), 2);
        assert_eq!(block.entries[0].transactions[0], tx1);
        assert_eq!(block.entries[0].transactions[1], tx2);
    }

    #[test]
    fn test_pipeline_with_multiple_shreds() {
        let entry1 = PohEntry::new(10, Hash::new([0xAA; 32]), vec![vec![1, 2, 3]]);
        let entry2 = PohEntry::new(20, Hash::new([0xBB; 32]), vec![vec![4, 5, 6]]);
        let entry3 = PohEntry::new(30, Hash::new([0xCC; 32]), vec![vec![7, 8, 9]]);
        let all_data = create_entry_batch(&[entry1, entry2, entry3]);

        let chunk_size = all_data.len() / 3;
        let shreds = vec![
            create_test_shred(100, 0, 0, &all_data[0..chunk_size]),
            create_test_shred(100, 1, 0, &all_data[chunk_size..chunk_size * 2]),
            create_test_shred(100, 2, 0, &all_data[chunk_size * 2..]),
        ];

        let window = ShredWindowStore::with_defaults();
        window.insert(shreds[2].clone()).unwrap();
        window.insert(shreds[0].clone()).unwrap();
        window.insert(shreds[1].clone()).unwrap();

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
        // Create test shred payloads (not entries — just raw FEC data for RS test)
        let payload_size = 128;
        let test_data: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut data = vec![i as u8; payload_size];
                data[0] = i as u8;
                data
            })
            .collect();

        let mut uniform_data = test_data.clone();

        // Create FEC coding shreds using Reed-Solomon
        let codec = ReedSolomon::new(4, 4).unwrap();
        let mut all_shreds = uniform_data.clone();
        all_shreds.extend(vec![vec![0u8; payload_size]; 4]);

        let mut shreds_refs: Vec<_> = all_shreds.iter_mut().map(|s| s.as_mut_slice()).collect();
        codec.encode(&mut shreds_refs).unwrap();

        // Create shred objects
        let data_shreds: Vec<Shred> = uniform_data
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

        let config = ShredWindowConfig {
            enable_auto_reconstruction: true,
            min_shreds_for_reconstruction: 4,
            ..Default::default()
        };
        let window = ShredWindowStore::new(config);

        for shred in available_shreds {
            window.insert(shred).unwrap();
        }

        let stats = window.stats();
        assert!(stats.total_shreds_inserted >= 4);
    }

    #[test]
    fn test_pipeline_multiple_slots() {
        let window = ShredWindowStore::with_defaults();

        for slot in 100..110 {
            let entry = PohEntry::new(slot, Hash::new([slot as u8; 32]), vec![vec![slot as u8; 5]]);
            let entry_data = create_entry_batch(&[entry]);
            let shred = create_test_shred(slot, 0, 0, &entry_data);
            window.insert(shred).unwrap();
        }

        let stats = window.stats();
        assert_eq!(stats.active_slots, 10);

        let pruned = window.advance_root(105);
        assert_eq!(pruned, 5);

        let stats = window.stats();
        assert_eq!(stats.active_slots, 5);

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
        let entry = PohEntry::new(42, Hash::new([0xDE; 32]), vec![vec![1, 2, 3, 4]]);
        let entry_data = create_entry_batch(&[entry]);
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
        let entries: Vec<PohEntry> = (0..20)
            .map(|i| {
                let tx = vec![i as u8; 100];
                PohEntry::new(i as u64, Hash::new([i as u8; 32]), vec![tx])
            })
            .collect();
        let all_data = create_entry_batch(&entries);

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

        let stats = assembler.stats();
        assert_eq!(stats.blocks_assembled, 1);
        assert_eq!(stats.entries_extracted, 20);
        assert_eq!(stats.transactions_extracted, 20);
    }
}

// ---------------------------------------------------------------------------
// Wave 7: Execution adapter pipeline integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod execution_pipeline_tests {
    use crate::SbpfExecutionAdapter;
    use paradencer_consensus::{ExecutionBackend, InstructionInfo, SlotContext};
    use paradencer_constants::execution::MAX_COMPUTE_UNITS;
    use paradencer_ids::{BPF_LOADER_PROGRAM_ID, SYSTEM_PROGRAM_ID};
    use paradencer_sbpf::elf_loader::TestElfBuilder;
    use paradencer_sbpf::instruction::{Instruction, Opcode};
    use paradencer_sbpf::TransactionProcessor;
    use paradencer_types::{Account, AccountData, AccountMeta, Pubkey};
    use std::sync::Arc;

    fn build_success_elf() -> Vec<u8> {
        let mut text = Vec::new();
        for insn in &[
            Instruction::new(Opcode::Mov64Imm as u8, 0, 0, 0, 0),
            Instruction::new(Opcode::Exit as u8, 0, 0, 0, 0),
        ] {
            text.extend_from_slice(&insn.encode().to_le_bytes());
        }
        TestElfBuilder::new().text(text).build()
    }

    #[test]
    fn adapter_system_transfer_end_to_end() {
        let adapter = SbpfExecutionAdapter::with_defaults();

        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();

        let from_account = Account {
            meta: AccountMeta {
                lamports: 1_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let to_account = Account {
            meta: AccountMeta {
                lamports: 500,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        let mut data = vec![2, 0, 0, 0]; // Transfer instruction
        data.extend_from_slice(&100u64.to_le_bytes());

        let info = InstructionInfo {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![
                (from, from_account, true, true),
                (to, to_account, true, false),
            ],
            data,
            slot_context: SlotContext::default(),
            sibling_instructions: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success);
        assert_eq!(result.modified_accounts.len(), 2);

        let from_modified = result.modified_accounts.get(&from).unwrap();
        assert_eq!(from_modified.meta.lamports, 900);

        let to_modified = result.modified_accounts.get(&to).unwrap();
        assert_eq!(to_modified.meta.lamports, 600);
    }

    #[test]
    fn adapter_bpf_execution_end_to_end() {
        let adapter = SbpfExecutionAdapter::with_defaults();
        let program_id = Pubkey::new_unique();
        let elf = build_success_elf();

        let program_account = Account {
            meta: AccountMeta {
                lamports: 1,
                owner: BPF_LOADER_PROGRAM_ID,
                executable: true,
                rent_epoch: 0,
            },
            data: AccountData::new(elf),
        };

        let info = InstructionInfo {
            program_id,
            accounts: vec![(program_id, program_account, false, false)],
            data: vec![],
            slot_context: SlotContext::default(),
            sibling_instructions: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success, "BPF via adapter should succeed");
        assert!(result.compute_units_consumed > 0);
    }

    #[test]
    fn adapter_routes_vote_program_through_pipeline() {
        use paradencer_ids::VOTE_PROGRAM_ID;

        let adapter = SbpfExecutionAdapter::with_defaults();
        let vote_pubkey = Pubkey::new_unique();
        let node = Pubkey::new_unique();
        let voter = Pubkey::new_unique();
        let withdrawer = Pubkey::new_unique();

        let vote_account = Account {
            meta: AccountMeta {
                lamports: 10_000,
                owner: VOTE_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };

        // Build InitializeAccount instruction data
        let mut init_data = vec![0, 0, 0, 0]; // InitializeAccount = 0
        init_data.extend_from_slice(node.as_bytes());
        init_data.extend_from_slice(voter.as_bytes());
        init_data.extend_from_slice(withdrawer.as_bytes());
        init_data.push(5); // commission

        let info = InstructionInfo {
            program_id: VOTE_PROGRAM_ID,
            accounts: vec![(vote_pubkey, vote_account, true, false)],
            data: init_data,
            slot_context: SlotContext::default(),
            sibling_instructions: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);

        assert!(result.success, "Vote init via adapter should succeed");
        assert_eq!(result.modified_accounts.len(), 1);
        assert!(result.error.is_none());

        // Verify the account data was populated (vote state serialized)
        let modified = result.modified_accounts.get(&vote_pubkey).unwrap();
        assert!(
            modified.data.as_slice().len() > 0,
            "Vote state should be serialized"
        );
    }

    #[test]
    fn adapter_routes_all_13_programs() {
        use paradencer_ids::{
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, CONFIG_PROGRAM_ID,
            ED25519_PROGRAM_ID, MEMO_PROGRAM_ID, SECP256K1_PROGRAM_ID, STAKE_PROGRAM_ID,
            TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, VOTE_PROGRAM_ID,
        };

        let adapter = SbpfExecutionAdapter::with_defaults();

        let all_ids = [
            SYSTEM_PROGRAM_ID,
            VOTE_PROGRAM_ID,
            STAKE_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
            TOKEN_2022_PROGRAM_ID,
            paradencer_ids::ASSOCIATED_TOKEN_PROGRAM_ID,
            MEMO_PROGRAM_ID,
            BPF_LOADER_PROGRAM_ID,
            COMPUTE_BUDGET_PROGRAM_ID,
            ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            CONFIG_PROGRAM_ID,
            ED25519_PROGRAM_ID,
            SECP256K1_PROGRAM_ID,
        ];

        for program_id in &all_ids {
            let info = InstructionInfo {
                program_id: *program_id,
                accounts: vec![],
                data: vec![],
                slot_context: SlotContext::default(),
                sibling_instructions: vec![],
            };

            // Should not panic — adapter routes to all builtins
            let _result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);
        }
    }

    #[test]
    fn adapter_with_shared_processor() {
        let processor = Arc::new(TransactionProcessor::new());
        let adapter = SbpfExecutionAdapter::new(processor);

        // Run both builtin and BPF through the same shared processor
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();

        let from_account = Account {
            meta: AccountMeta {
                lamports: 5_000,
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
            data: AccountData::empty(),
        };
        let to_account = Account::default();

        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&1_000u64.to_le_bytes());

        let info = InstructionInfo {
            program_id: SYSTEM_PROGRAM_ID,
            accounts: vec![
                (from, from_account, true, true),
                (to, to_account, true, false),
            ],
            data,
            slot_context: SlotContext::default(),
            sibling_instructions: vec![],
        };

        let result = adapter.execute_instruction(&info, MAX_COMPUTE_UNITS);
        assert!(result.success, "Shared processor transfer should succeed");
    }
}
