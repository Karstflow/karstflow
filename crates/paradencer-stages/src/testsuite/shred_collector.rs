use super::*;
use crate::block_producer::PohEntry;
use crate::shred_assembler::AssembledBlock;
use crate::shred_network::{CompletedFecSet, ShredNetworkConfig, ShredNetworkService};
use crate::{ShredCollector, ShredCollectorConfig};
use paradencer_types::shred::{
    DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SHRED_LAST_IN_SLOT,
    SHRED_LEGACY_DATA_NIBBLE, SHRED_TYPE_LEGACY_DATA, SIGNATURE_SIZE,
};
use paradencer_types::Hash;

/// Create a valid bincode batch payload for a single tick entry.
fn make_entry_batch_payload() -> Vec<u8> {
    let entry = PohEntry::new(1, Hash::new([0xAB; 32]), vec![]);
    PohEntry::batch_to_bytes(&[entry])
}

/// Create a shred from a raw payload slice.
fn make_shred(slot: u64, index: u32, last_in_slot: bool, payload: Vec<u8>) -> Shred {
    let mut flags = 0u8;
    if last_in_slot {
        flags |= SHRED_LAST_IN_SLOT;
    }
    Shred::new(
        ShredCommonHeader {
            signature: [0; SIGNATURE_SIZE],
            variant: SHRED_TYPE_LEGACY_DATA | SHRED_LEGACY_DATA_NIBBLE,
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

/// Create a single-shred slot (complete entry in one shred).
fn create_test_shred(slot: u64, index: u32, last_in_slot: bool) -> Shred {
    make_shred(slot, index, last_in_slot, make_entry_batch_payload())
}

#[test]
fn collector_emits_block_when_last_in_slot_received() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(16);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);
    let mut collector = ShredCollector::new(shred_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Split one entry batch across two shreds for slot 10.
    let batch = make_entry_batch_payload();
    let mid = batch.len() / 2;
    shred_tx
        .try_send(make_shred(10, 0, false, batch[..mid].to_vec()))
        .unwrap();
    shred_tx
        .try_send(make_shred(10, 1, true, batch[mid..].to_vec()))
        .unwrap();

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

#[test]
fn collector_receives_fec_sets_from_channel() {
    let (shred_tx, shred_rx) = bounded_link::<Shred>(16);
    let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);

    let mut collector = ShredCollector::with_fec_input(shred_rx, fec_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Send a CompletedFecSet with a last-in-slot shred.
    let payload = make_entry_batch_payload();
    let mut shred = make_shred(50, 0, true, payload);

    let fec_set = CompletedFecSet {
        slot: 50,
        fec_set_index: 0,
        data_shreds: vec![shred],
        was_recovered: false,
    };
    fec_tx.try_send(fec_set).unwrap();

    // Tick to drain FEC sets and emit block.
    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.fec_sets_received, 1);
    assert_eq!(stats.blocks_emitted, 1);

    let block = block_rx.try_recv().unwrap().unwrap();
    assert_eq!(block.slot, 50);
}

#[test]
fn full_pipeline_filter_to_fec_to_collector_to_block() {
    // End-to-end: shreds → ShredNetworkService → ShredCollector → AssembledBlock.
    let (filter_tx, filter_rx) = bounded_link::<Shred>(64);
    let (fec_tx, fec_rx) = bounded_link::<CompletedFecSet>(16);
    let (shred_direct_tx, shred_direct_rx) = bounded_link::<Shred>(16);
    let (block_tx, block_rx) = bounded_link::<AssembledBlock>(16);

    let config = ShredNetworkConfig {
        turbine_neighbor_count: 0,
        ..Default::default()
    };
    let mut network_svc = ShredNetworkService::new(config, filter_rx, fec_tx);
    let mut collector = ShredCollector::with_fec_input(shred_direct_rx, fec_rx, block_tx);
    let context = ServiceContext::new(ShutdownSwitch::new());

    // Create a simple FEC set: 2 data + 2 coding.
    // Data shreds carry a valid entry batch payload.
    let entry = PohEntry::new(42, Hash::new([0xEE; 32]), vec![vec![1, 2, 3]]);
    let batch_bytes = PohEntry::batch_to_bytes(&[entry]);

    // Create data shreds with unique signatures.
    let data0 = {
        let mut sig = [0u8; 64];
        sig[0] = 1;
        Shred::new(
            ShredCommonHeader {
                signature: sig,
                variant: paradencer_types::shred::SHRED_DATA_FLAG,
                slot: 100,
                index: 0,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: SHRED_LAST_IN_SLOT,
                size: batch_bytes.len() as u16,
            }),
            batch_bytes.clone(),
        )
    };
    let data1 = {
        let mut sig = [0u8; 64];
        sig[0] = 2;
        Shred::new(
            ShredCommonHeader {
                signature: sig,
                variant: paradencer_types::shred::SHRED_DATA_FLAG,
                slot: 100,
                index: 1,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyData(DataShredHeader {
                parent_offset: 1,
                flags: 0,
                size: batch_bytes.len() as u16,
            }),
            batch_bytes.clone(),
        )
    };
    // One coding shred to learn FEC params (num_data=2, num_coding=2).
    let coding0 = {
        let mut sig = [0u8; 64];
        sig[0] = 3;
        Shred::new(
            ShredCommonHeader {
                signature: sig,
                variant: paradencer_types::shred::SHRED_CODE_FLAG,
                slot: 100,
                index: 2,
                version: 1,
                fec_set_index: 0,
            },
            ShredVariant::LegacyCoding(paradencer_types::shred::CodingShredHeader {
                num_data_shreds: 2,
                num_coding_shreds: 2,
                position: 0,
            }),
            vec![0u8; batch_bytes.len()],
        )
    };

    // Send shreds through the filter channel.
    filter_tx.try_send(data0).unwrap();
    filter_tx.try_send(data1).unwrap();
    filter_tx.try_send(coding0).unwrap();

    // Tick network service → produces CompletedFecSet.
    network_svc.tick(&context).unwrap();

    // Tick collector → drains FEC sets, assembles block.
    collector.tick(&context).unwrap();

    let stats = collector.stats();
    assert_eq!(stats.fec_sets_received, 1);
    assert_eq!(stats.blocks_emitted, 1);

    let block = block_rx.try_recv().unwrap().unwrap();
    assert_eq!(block.slot, 100);
    assert!(block.entries.len() >= 1);
    assert_eq!(block.entries[0].num_hashes, 42);
}
