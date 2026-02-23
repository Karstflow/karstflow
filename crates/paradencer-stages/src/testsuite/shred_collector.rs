use super::*;
use crate::shred_assembler::AssembledBlock;
use crate::{ShredCollector, ShredCollectorConfig};
use paradencer_types::shred::{
    DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SHRED_DATA_FLAG, SHRED_LAST_IN_SLOT,
    SIGNATURE_SIZE,
};

fn create_test_shred(slot: u64, index: u32, last_in_slot: bool) -> Shred {
    let mut flags = 0u8;
    if last_in_slot {
        flags |= SHRED_LAST_IN_SLOT;
    }
    // Build a minimal entry payload: num_hashes(8) + hash(32) + num_transactions(8) = 48 bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u64.to_le_bytes()); // num_hashes
    payload.extend_from_slice(&[0xABu8; 32]); // hash
    payload.extend_from_slice(&0u64.to_le_bytes()); // num_transactions = 0

    Shred::new(
        ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: SHRED_DATA_FLAG,
            slot,
            index,
            version: 1,
            fec_set_index: 0,
        },
        ShredVariant::LegacyData(DataShredHeader {
            parent_offset: 1,
            flags,
            size: payload.len() as u16,
        }),
        payload,
    )
}

#[test]
fn collector_emits_block_when_last_in_slot_received() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(16);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);
    let mut collector = ShredCollector::new(shred_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Send two shreds for slot 10, second is last-in-slot.
    shred_tx.try_send(create_test_shred(10, 0, false)).unwrap();
    shred_tx.try_send(create_test_shred(10, 1, true)).unwrap();

    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.shreds_received, 2);
    assert_eq!(stats.blocks_emitted, 1);

    let block = block_rx.try_recv().unwrap();
    assert!(block.is_some());
    let block = block.unwrap();
    assert_eq!(block.slot, 10);
    assert_eq!(block.shred_count, 2);
}

#[test]
fn collector_buffers_incomplete_slot() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(16);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);
    let mut collector = ShredCollector::new(shred_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Send shred without last-in-slot flag.
    shred_tx.try_send(create_test_shred(20, 0, false)).unwrap();

    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.shreds_received, 1);
    assert_eq!(stats.blocks_emitted, 0);

    // No block emitted yet.
    let block = block_rx.try_recv().unwrap();
    assert!(block.is_none());
}

#[test]
fn collector_handles_multiple_slots_independently() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(32);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);
    let mut collector = ShredCollector::new(shred_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Slot 30: complete (last-in-slot).
    shred_tx.try_send(create_test_shred(30, 0, true)).unwrap();
    // Slot 31: incomplete.
    shred_tx.try_send(create_test_shred(31, 0, false)).unwrap();
    // Slot 32: complete.
    shred_tx.try_send(create_test_shred(32, 0, true)).unwrap();

    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.shreds_received, 3);
    assert_eq!(stats.blocks_emitted, 2);

    // Both complete slots emitted.
    let block_a = block_rx.try_recv().unwrap().unwrap();
    let block_b = block_rx.try_recv().unwrap().unwrap();
    let emitted_slots: Vec<u64> = vec![block_a.slot, block_b.slot];
    assert!(emitted_slots.contains(&30));
    assert!(emitted_slots.contains(&32));

    // Slot 31 still buffered — no third block.
    let no_block = block_rx.try_recv().unwrap();
    assert!(no_block.is_none());
}

#[test]
fn collector_evicts_old_slots() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(16);
    let (block_tx, _block_rx) = bounded_link::<AssembledBlock>(16);
    let config = ShredCollectorConfig {
        max_slot_age_ticks: 3,
        ..ShredCollectorConfig::default()
    };
    let mut collector = ShredCollector::with_config(shred_rx, block_tx, config);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Send an incomplete slot.
    shred_tx.try_send(create_test_shred(40, 0, false)).unwrap();
    collector.tick(&context).unwrap();

    // Tick several more times to age it out.
    collector.tick(&context).unwrap();
    collector.tick(&context).unwrap();
    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.slots_evicted_age, 1);
}

#[test]
fn collector_evicts_overflow_slots() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(64);
    let (block_tx, _block_rx) = bounded_link::<AssembledBlock>(16);
    let config = ShredCollectorConfig {
        max_buffered_slots: 2,
        max_slot_age_ticks: 1000,
        ..ShredCollectorConfig::default()
    };
    let mut collector = ShredCollector::with_config(shred_rx, block_tx, config);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Send 4 different incomplete slots.
    for slot in 50..54 {
        shred_tx
            .try_send(create_test_shred(slot, 0, false))
            .unwrap();
    }

    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.shreds_received, 4);
    assert_eq!(stats.slots_evicted_overflow, 2);
}
