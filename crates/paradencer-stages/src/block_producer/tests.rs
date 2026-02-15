//! Comprehensive tests for block producer pipeline
//!
//! These tests verify the entire block production flow including:
//! - PoH service hash chain generation
//! - Entry creation from transactions
//! - Entry shredding with FEC encoding
//! - Integration with leader schedule
//! - End-to-end block production

use super::*;
use paradencer_consensus::{Hash, LeaderSchedule};
use paradencer_mesh::bounded_link;
use paradencer_storage::Pubkey;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ============================================================================
// PoH Service Tests
// ============================================================================

#[test]
fn test_poh_hash_chain_continuity() {
    let mut poh = PohService::new(Hash::new_unique());
    let start_hash = poh.current_hash();

    // Hash several times and verify chain
    let hash1 = poh.hash(b"data1");
    let hash2 = poh.hash(b"data2");
    let hash3 = poh.hash(b"data3");

    assert_ne!(hash1, start_hash);
    assert_ne!(hash2, hash1);
    assert_ne!(hash3, hash2);
    assert_eq!(poh.current_hash(), hash3);
}

#[test]
fn test_poh_deterministic_hashing() {
    let seed = Hash::new_unique();

    let mut poh1 = PohService::new(seed);
    let mut poh2 = PohService::new(seed);

    // Same inputs should produce same outputs
    let hash1_a = poh1.hash(b"test");
    let hash1_b = poh2.hash(b"test");
    assert_eq!(hash1_a, hash1_b);

    let hash2_a = poh1.hash(b"data");
    let hash2_b = poh2.hash(b"data");
    assert_eq!(hash2_a, hash2_b);
}

#[test]
fn test_poh_tick_generation() {
    let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 10);

    let entry = poh.tick();

    assert!(entry.is_tick());
    assert_eq!(entry.num_hashes, 10);
    assert_eq!(entry.transactions.len(), 0);
    assert_eq!(poh.tick_count(), 1);
}

#[test]
fn test_poh_record_transactions() {
    let mut poh = PohService::new_random();

    let tx1 = b"transaction 1".to_vec();
    let tx2 = b"transaction 2".to_vec();
    let txs = vec![tx1.clone(), tx2.clone()];

    let entry = poh.record(txs);

    assert!(!entry.is_tick());
    assert_eq!(entry.transactions.len(), 2);
    assert_eq!(entry.transactions[0], tx1);
    assert_eq!(entry.transactions[1], tx2);
}

#[test]
fn test_poh_stats_accumulation() {
    let mut poh = PohService::with_hashes_per_tick(Hash::new_unique(), 5);

    // Generate some activity
    poh.tick();
    poh.record(vec![b"tx1".to_vec(), b"tx2".to_vec()]);
    poh.tick();

    let stats = poh.stats();
    assert_eq!(stats.total_ticks, 2);
    assert_eq!(stats.total_entries, 1);
    assert_eq!(stats.total_transactions, 2);
    assert!(stats.total_hashes > 0);
}

#[test]
fn test_poh_entry_serialization() {
    let tx1 = b"first transaction".to_vec();
    let tx2 = b"second transaction".to_vec();
    let entry = PohEntry::new(100, Hash::new_unique(), vec![tx1.clone(), tx2.clone()]);

    let bytes = entry.to_bytes();

    // Verify size calculation
    assert_eq!(bytes.len(), entry.size_bytes());

    // Verify structure (num_hashes + hash + num_txs + tx lengths + tx data)
    assert!(bytes.len() > 48); // At least header size
}

// ============================================================================
// Entry Creator Tests
// ============================================================================

#[test]
fn test_entry_creator_batching() {
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let config = EntryCreatorConfig {
        max_txs_per_entry: 3,
        max_bytes_per_entry: 1000,
        ticks_per_slot: 64,
    };
    let mut creator = EntryCreator::new(poh, config);

    // Add transactions one by one
    creator.add_transaction(b"tx1".to_vec());
    assert_eq!(creator.buffered_count(), 1);
    assert!(!creator.should_flush());

    creator.add_transaction(b"tx2".to_vec());
    assert_eq!(creator.buffered_count(), 2);
    assert!(!creator.should_flush());

    creator.add_transaction(b"tx3".to_vec());
    assert_eq!(creator.buffered_count(), 3);
    assert!(creator.should_flush()); // Hit max_txs_per_entry

    let entry = creator.create_entry().unwrap();
    assert_eq!(entry.transactions.len(), 3);
    assert_eq!(creator.buffered_count(), 0);
}

#[test]
fn test_entry_creator_byte_limit() {
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let config = EntryCreatorConfig {
        max_txs_per_entry: 100,
        max_bytes_per_entry: 100, // Small byte limit
        ticks_per_slot: 64,
    };
    let mut creator = EntryCreator::new(poh, config);

    // Add a large transaction
    let large_tx = vec![0u8; 60];
    creator.add_transaction(large_tx);
    assert!(!creator.should_flush());

    // Add another, should trigger flush
    let another_tx = vec![0u8; 50];
    creator.add_transaction(another_tx);
    assert!(creator.should_flush()); // Over byte limit
}

#[test]
fn test_entry_creator_tick_generation() {
    let poh = Arc::new(Mutex::new(PohService::with_hashes_per_tick(
        Hash::new_unique(),
        100,
    )));
    let mut creator = EntryCreator::with_poh(poh);

    let entry = creator.create_tick_entry();

    assert!(entry.is_tick());
    assert_eq!(entry.num_hashes, 100);
    assert_eq!(creator.entries_created(), 1);
}

#[test]
fn test_entry_creator_flush() {
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let mut creator = EntryCreator::with_poh(poh);

    creator.add_transaction(b"tx1".to_vec());
    creator.add_transaction(b"tx2".to_vec());

    let entry = creator.flush().unwrap();
    assert_eq!(entry.transactions.len(), 2);
    assert_eq!(creator.buffered_count(), 0);
}

#[test]
fn test_entry_creator_empty_flush() {
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let mut creator = EntryCreator::with_poh(poh);

    let result = creator.flush();
    assert!(result.is_none());
}

#[test]
fn test_entry_creator_clear_buffer() {
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let mut creator = EntryCreator::with_poh(poh);

    creator.add_transaction(b"tx1".to_vec());
    creator.add_transaction(b"tx2".to_vec());
    assert_eq!(creator.buffered_count(), 2);

    creator.clear_buffer();
    assert_eq!(creator.buffered_count(), 0);
    assert_eq!(creator.buffered_bytes(), 0);
}

// ============================================================================
// Entry Shredder Tests
// ============================================================================

#[test]
fn test_shredder_data_shred_creation() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry = create_test_entry_with_txs(5);
    let shreds = shredder.create_data_shreds(&[entry]).unwrap();

    assert!(!shreds.is_empty());
    for shred in &shreds {
        assert!(shred.is_data());
        assert_eq!(shred.slot(), 100);
    }
}

#[test]
fn test_shredder_coding_shred_creation() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry = create_test_entry_with_txs(3);
    let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
    let coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

    assert!(!coding_shreds.is_empty());
    for shred in &coding_shreds {
        assert!(shred.is_coding());
        assert_eq!(shred.slot(), 100);
    }
}

#[test]
fn test_shredder_index_sequencing() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry1 = create_test_entry_with_txs(2);
    let shreds1 = shredder.create_data_shreds(&[entry1]).unwrap();

    let entry2 = create_test_entry_with_txs(2);
    let shreds2 = shredder.create_data_shreds(&[entry2]).unwrap();

    // Indices should be sequential across entries
    if let (Some(last1), Some(first2)) = (shreds1.last(), shreds2.first()) {
        assert!(first2.index() > last1.index());
    }
}

#[test]
fn test_shredder_slot_reset() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry = create_test_entry_with_txs(2);
    shredder.create_data_shreds(&[entry]).unwrap();
    assert!(shredder.next_index() > 0);

    shredder.reset_for_slot(200);
    assert_eq!(shredder.slot(), 200);
    assert_eq!(shredder.next_index(), 0);
}

#[test]
fn test_shredder_last_shred_marking() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    // Create a tick entry (should be marked as last)
    let tick_entry = PohEntry::new(100, Hash::new_unique(), vec![]);
    let shreds = shredder.create_data_shreds(&[tick_entry]).unwrap();

    if let Some(last_shred) = shreds.last() {
        assert!(last_shred.is_last_in_slot());
    }
}

#[test]
fn test_shredder_fec_block_structure() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry = create_test_entry_with_txs(10);
    let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
    let coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

    // All shreds in a FEC block should have the same FEC set index
    let fec_set_index = data_shreds[0].fec_set_index();
    for shred in &data_shreds {
        assert_eq!(shred.fec_set_index(), fec_set_index);
    }
    for shred in &coding_shreds {
        assert_eq!(shred.fec_set_index(), fec_set_index);
    }
}

#[test]
fn test_shredder_stats() {
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entry = create_test_entry_with_txs(5);
    let data_shreds = shredder.create_data_shreds(&[entry]).unwrap();
    let _coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

    let (data_count, coding_count) = shredder.stats();
    assert_eq!(data_count, data_shreds.len() as u64);
    assert!(coding_count > 0);

    shredder.reset_stats();
    let (data_count, coding_count) = shredder.stats();
    assert_eq!(data_count, 0);
    assert_eq!(coding_count, 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_poh_to_entry_to_shred_pipeline() {
    // Full pipeline: PoH -> Entry -> Shreds
    let poh = Arc::new(Mutex::new(PohService::with_hashes_per_tick(
        Hash::new_unique(),
        100,
    )));
    let mut creator = EntryCreator::with_poh(poh.clone());

    // Create entries with transactions
    creator.add_transaction(b"tx1".to_vec());
    creator.add_transaction(b"tx2".to_vec());
    let entry1 = creator.create_entry().unwrap();

    creator.add_transaction(b"tx3".to_vec());
    let entry2 = creator.create_entry().unwrap();

    let tick_entry = creator.create_tick_entry();

    // Shred the entries
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    let entries = vec![entry1, entry2, tick_entry];
    let data_shreds = shredder.create_data_shreds(&entries).unwrap();
    let coding_shreds = shredder.create_coding_shreds(&data_shreds).unwrap();

    // Verify output
    assert!(!data_shreds.is_empty());
    assert!(!coding_shreds.is_empty());
    assert!(data_shreds.last().unwrap().is_last_in_slot());
}

#[test]
fn test_leader_schedule_integration() {
    // Test that block producer respects leader schedule
    let validator_a = Pubkey::new_unique();
    let validator_b = Pubkey::new_unique();
    let validators = vec![(validator_a, 5000), (validator_b, 5000)];
    let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

    // Count slots for each validator
    let mut slots_a = 0;
    let mut slots_b = 0;
    for slot in 0..1000 {
        match leader_schedule.get_leader(slot) {
            Some(leader) if leader == validator_a => slots_a += 1,
            Some(leader) if leader == validator_b => slots_b += 1,
            _ => {}
        }
    }

    // Both should get roughly equal slots (50/50 stake)
    let ratio_a = slots_a as f64 / 1000.0;
    let ratio_b = slots_b as f64 / 1000.0;
    assert!((ratio_a - 0.5).abs() < 0.1);
    assert!((ratio_b - 0.5).abs() < 0.1);
}

#[test]
fn test_block_producer_channels() {
    // Test block producer with real channels
    let validator = Pubkey::new_unique();
    let validators = vec![(validator, 1000)];
    let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

    let (tx_sender, tx_receiver) = bounded_link(100);
    let (shred_sender, shred_receiver) = bounded_link(1000);

    let config = BlockProducerConfig {
        ticks_per_slot: 8, // Short for testing
        tick_duration: Duration::from_millis(10),
        ..Default::default()
    };

    let mut producer = BlockProducer::new(
        config,
        leader_schedule,
        validator,
        None,
        tx_receiver,
        shred_sender,
    );

    // Start producer
    producer.start(0).unwrap();

    // Send some transactions
    for i in 0..10 {
        let tx = format!("transaction_{}", i).into_bytes();
        tx_sender.send(tx).unwrap();
    }

    // Let it run briefly
    thread::sleep(Duration::from_millis(200));

    // Stop producer
    producer.stop().unwrap();

    // Check that shreds were produced
    let mut shred_count = 0;
    while shred_receiver.try_recv().is_ok() {
        shred_count += 1;
    }

    assert!(shred_count > 0, "Should have produced some shreds");

    // Check stats
    let stats = producer.stats();
    assert!(stats.slots_produced > 0);
}

#[test]
fn test_multi_slot_production() {
    // Test producing multiple slots
    let validator = Pubkey::new_unique();
    let validators = vec![(validator, 1000)];
    let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

    let (_tx_sender, tx_receiver) = bounded_link(100);
    let (shred_sender, shred_receiver) = bounded_link(1000);

    let config = BlockProducerConfig {
        ticks_per_slot: 4, // Very short for testing
        tick_duration: Duration::from_millis(5),
        verbose: false,
        ..Default::default()
    };

    let mut producer = BlockProducer::new(
        config,
        leader_schedule,
        validator,
        None,
        tx_receiver,
        shred_sender,
    );

    producer.start(0).unwrap();
    thread::sleep(Duration::from_millis(150)); // Let it produce a few slots
    producer.stop().unwrap();

    let stats = producer.stats();
    assert!(stats.slots_produced >= 1);
    assert!(stats.total_ticks >= 4); // At least one full slot

    // Verify shreds were sent
    let mut shred_count = 0;
    while shred_receiver.try_recv().is_ok() {
        shred_count += 1;
    }
    assert!(shred_count > 0);
}

#[test]
fn test_non_leader_validator() {
    // Test that non-leader validators don't produce blocks
    let validator_a = Pubkey::new_unique();
    let validator_b = Pubkey::new_unique();
    let validators = vec![(validator_a, 10000), (validator_b, 1)]; // A has most stake
    let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

    let (_tx_sender, tx_receiver) = bounded_link(100);
    let (shred_sender, shred_receiver) = bounded_link(1000);

    let config = BlockProducerConfig {
        ticks_per_slot: 4,
        tick_duration: Duration::from_millis(5),
        ..Default::default()
    };

    // Create producer for validator_b (who is rarely leader)
    let mut producer = BlockProducer::new(
        config,
        leader_schedule,
        validator_b,
        None,
        tx_receiver,
        shred_sender,
    );

    producer.start(0).unwrap();
    thread::sleep(Duration::from_millis(100));
    producer.stop().unwrap();

    // validator_b should produce very few or no blocks
    let stats = producer.stats();
    // With stake ratio 10000:1, validator_b should rarely be leader
    assert!(stats.slots_produced < 5);
}

#[test]
fn test_empty_slot_production() {
    // Test producing a slot with no transactions (only ticks)
    let validator = Pubkey::new_unique();
    let validators = vec![(validator, 1000)];
    let leader_schedule = LeaderSchedule::new(0, &validators).unwrap();

    let (_tx_sender, tx_receiver) = bounded_link(100);
    let (shred_sender, shred_receiver) = bounded_link(1000);

    let config = BlockProducerConfig {
        ticks_per_slot: 8,
        tick_duration: Duration::from_millis(5),
        ..Default::default()
    };

    let mut producer = BlockProducer::new(
        config,
        leader_schedule,
        validator,
        None,
        tx_receiver,
        shred_sender,
    );

    producer.start(0).unwrap();
    thread::sleep(Duration::from_millis(100));
    producer.stop().unwrap();

    let stats = producer.stats();
    assert!(stats.slots_produced >= 1);
    assert_eq!(stats.total_transactions, 0); // No transactions sent
    assert!(stats.total_ticks >= 8); // But ticks were generated

    // Should still produce shreds (for tick entries)
    let mut shred_count = 0;
    while shred_receiver.try_recv().is_ok() {
        shred_count += 1;
    }
    assert!(shred_count > 0, "Even empty slots should produce shreds");
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_entry_with_txs(num_txs: usize) -> PohEntry {
    let transactions: Vec<Vec<u8>> = (0..num_txs)
        .map(|i| format!("transaction_{}", i).into_bytes())
        .collect();

    PohEntry::new(100, Hash::new_unique(), transactions)
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

#[test]
fn test_high_throughput_entry_creation() {
    // Test creating many entries rapidly
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let mut creator = EntryCreator::with_poh(poh);

    let start = std::time::Instant::now();
    for i in 0..1000 {
        creator.add_transaction(format!("tx{}", i).into_bytes());
        if creator.should_flush() {
            creator.create_entry();
        }
    }
    let duration = start.elapsed();

    assert!(
        duration.as_millis() < 1000,
        "Should create 1000 entries in < 1s"
    );
    assert!(creator.entries_created() > 0);
}

#[test]
fn test_large_entry_shredding() {
    // Test shredding a large entry that spans multiple shreds
    let pubkey = Pubkey::new_unique();
    let mut shredder = EntryShredder::with_defaults(pubkey, None, 100).unwrap();

    // Create an entry with many large transactions
    let large_txs: Vec<Vec<u8>> = (0..50).map(|i| vec![i as u8; 500]).collect();
    let entry = PohEntry::new(100, Hash::new_unique(), large_txs);

    let shreds = shredder.create_data_shreds(&[entry]).unwrap();

    // Should create multiple shreds
    assert!(shreds.len() > 1);
    assert!(shreds.len() < paradencer_types::shred::MAX_DATA_SHREDS_PER_FEC_BLOCK);
}

#[test]
fn test_concurrent_poh_access() {
    // Test that PoH service can handle concurrent access safely
    let poh = Arc::new(Mutex::new(PohService::new_random()));

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let poh = poh.clone();
            thread::spawn(move || {
                for j in 0..100 {
                    let mut poh = poh.lock().unwrap();
                    poh.hash(format!("thread{}_{}", i, j).as_bytes());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let poh = poh.lock().unwrap();
    assert_eq!(poh.stats().total_hashes, 400); // 4 threads * 100 hashes
}

#[test]
fn test_entry_creator_concurrent_access() {
    // Test concurrent access to entry creator
    let poh = Arc::new(Mutex::new(PohService::new_random()));
    let creator = Arc::new(Mutex::new(EntryCreator::with_poh(poh)));

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let creator = creator.clone();
            thread::spawn(move || {
                for j in 0..50 {
                    let mut creator = creator.lock().unwrap();
                    creator.add_transaction(format!("tx_{}_{}", i, j).into_bytes());
                    if creator.should_flush() {
                        creator.create_entry();
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let creator = creator.lock().unwrap();
    assert!(creator.entries_created() > 0);
}
