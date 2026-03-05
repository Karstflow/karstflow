use super::*;
use karstflow_constants::blockstore::*;
use karstflow_types::shred::{
    CodingShredHeader, DataShredHeader, Shred, ShredCommonHeader, ShredVariant, SHRED_LAST_IN_SLOT,
    SIGNATURE_SIZE,
};

fn make_shred_data(index: u32) -> Vec<u8> {
    let mut data = vec![0xDE, 0xAD];
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&[0xBE; 10]);
    data
}

#[test]
fn create_in_memory_blockstore() {
    let bs = Blockstore::in_memory();
    assert!(bs.latest_root().is_none());
    assert!(bs.roots().is_empty());
}

#[test]
fn insert_and_retrieve_data_shred() {
    let bs = Blockstore::in_memory();
    let data = make_shred_data(0);
    bs.insert_data_shred(100, 0, &data).unwrap();

    let retrieved = bs.get_data_shred(100, 0).unwrap();
    assert_eq!(retrieved, Some(data));
}

#[test]
fn insert_and_retrieve_coding_shred() {
    let bs = Blockstore::in_memory();
    let data = vec![0xCC; 64];
    bs.insert_coding_shred(100, 0, &data).unwrap();

    // Coding shreds are stored separately; data shred retrieval should be None
    let data_shred = bs.get_data_shred(100, 0).unwrap();
    assert!(data_shred.is_none());
}

#[test]
fn slot_meta_tracks_received_shreds() {
    let bs = Blockstore::in_memory();
    bs.insert_data_shred(50, 0, &[1, 2, 3]).unwrap();
    bs.insert_data_shred(50, 1, &[4, 5, 6]).unwrap();
    bs.insert_coding_shred(50, 0, &[7, 8, 9]).unwrap();

    let meta = bs.get_slot_meta(50).unwrap().unwrap();
    assert_eq!(meta.received_data_shreds, 2);
    assert_eq!(meta.received_coding_shreds, 1);
    assert_eq!(meta.slot, 50);
}

#[test]
fn slot_completion_detection() {
    let bs = Blockstore::in_memory();
    bs.insert_data_shred(10, 0, &[1]).unwrap();

    // Not complete yet since expected_data_shreds isn't set
    assert!(!bs.is_slot_complete(10));

    // Manually set expected via slot meta manipulation
    let mut meta = bs.get_slot_meta(10).unwrap().unwrap();
    meta.expected_data_shreds = Some(1);
    meta.status = SlotStatus::Complete;
    // Save it back via backend
    let key = 10u64.to_be_bytes();
    bs.backend
        .put(CF_SLOT_META, &key, &meta.serialize())
        .unwrap();

    assert!(bs.is_slot_complete(10));
}

#[test]
fn mark_slot_as_dead() {
    let bs = Blockstore::in_memory();
    bs.insert_data_shred(20, 0, &[1]).unwrap();
    bs.mark_dead(20).unwrap();

    let meta = bs.get_slot_meta(20).unwrap().unwrap();
    assert!(meta.is_dead());
    assert_eq!(meta.status, SlotStatus::Dead);
}

#[test]
fn mark_already_dead_slot_returns_error() {
    let bs = Blockstore::in_memory();
    bs.mark_dead(30).unwrap();

    let result = bs.mark_dead(30);
    assert!(result.is_err());
    match result.unwrap_err() {
        BlockstoreError::SlotAlreadyDead(slot) => assert_eq!(slot, 30),
        other => panic!("expected SlotAlreadyDead, got: {:?}", other),
    }
}

#[test]
fn mark_slot_as_duplicate() {
    let bs = Blockstore::in_memory();
    bs.insert_data_shred(40, 0, &[1]).unwrap();
    bs.mark_duplicate(40).unwrap();

    let meta = bs.get_slot_meta(40).unwrap().unwrap();
    assert_eq!(meta.status, SlotStatus::Duplicate);
}

#[test]
fn root_tracking_set_and_query() {
    let bs = Blockstore::in_memory();
    assert!(!bs.is_root(100));

    bs.set_root(100).unwrap();
    assert!(bs.is_root(100));
    assert!(!bs.is_root(101));
}

#[test]
fn latest_root_tracking() {
    let bs = Blockstore::in_memory();
    assert!(bs.latest_root().is_none());

    bs.set_root(10).unwrap();
    assert_eq!(bs.latest_root(), Some(10));

    bs.set_root(20).unwrap();
    assert_eq!(bs.latest_root(), Some(20));

    bs.set_root(15).unwrap();
    // Latest root should still be 20 (it's the highest)
    assert_eq!(bs.latest_root(), Some(20));
}

#[test]
fn roots_returns_all_roots_sorted() {
    let bs = Blockstore::in_memory();
    bs.set_root(30).unwrap();
    bs.set_root(10).unwrap();
    bs.set_root(20).unwrap();

    let roots = bs.roots();
    assert_eq!(roots, vec![10, 20, 30]);
}

#[test]
fn purge_slots_below_threshold() {
    let bs = Blockstore::in_memory();

    // Insert shreds in several slots
    for slot in 0..5 {
        bs.insert_data_shred(slot, 0, &make_shred_data(0)).unwrap();
        bs.set_root(slot).unwrap();
    }

    let purged = bs.purge_slots_below(3).unwrap();
    assert!(purged > 0);

    // Slots 0, 1, 2 should be gone
    for slot in 0..3 {
        assert!(bs.get_slot_meta(slot).unwrap().is_none());
        assert!(bs.get_data_shred(slot, 0).unwrap().is_none());
        assert!(!bs.is_root(slot));
    }

    // Slots 3, 4 should still exist
    assert!(bs.get_slot_meta(3).unwrap().is_some());
    assert!(bs.get_data_shred(3, 0).unwrap().is_some());
    assert!(bs.is_root(3));
}

#[test]
fn multiple_slots_independent() {
    let bs = Blockstore::in_memory();
    let data_a = vec![0xAA; 8];
    let data_b = vec![0xBB; 8];

    bs.insert_data_shred(100, 0, &data_a).unwrap();
    bs.insert_data_shred(200, 0, &data_b).unwrap();

    assert_eq!(bs.get_data_shred(100, 0).unwrap(), Some(data_a));
    assert_eq!(bs.get_data_shred(200, 0).unwrap(), Some(data_b));

    let meta_a = bs.get_slot_meta(100).unwrap().unwrap();
    let meta_b = bs.get_slot_meta(200).unwrap().unwrap();
    assert_eq!(meta_a.slot, 100);
    assert_eq!(meta_b.slot, 200);
}

#[test]
fn empty_shred_data_rejected() {
    let bs = Blockstore::in_memory();
    let result = bs.insert_data_shred(1, 0, &[]);
    assert!(result.is_err());
    match result.unwrap_err() {
        BlockstoreError::InvalidShredData => {}
        other => panic!("expected InvalidShredData, got: {:?}", other),
    }
}

#[test]
fn shred_index_out_of_range() {
    let bs = Blockstore::in_memory();
    let result = bs.insert_data_shred(1, MAX_DATA_SHREDS_PER_SLOT as u32, &[1]);
    assert!(result.is_err());
    match result.unwrap_err() {
        BlockstoreError::ShredIndexOutOfRange { slot, index } => {
            assert_eq!(slot, 1);
            assert_eq!(index, MAX_DATA_SHREDS_PER_SLOT as u32);
        }
        other => panic!("expected ShredIndexOutOfRange, got: {:?}", other),
    }
}

#[test]
fn backend_get_put_delete() {
    let backend = backend::BlockstoreBackend::in_memory();

    // Put and get
    backend.put(CF_SLOT_META, b"key1", b"value1").unwrap();
    assert_eq!(
        backend.get(CF_SLOT_META, b"key1").unwrap(),
        Some(b"value1".to_vec())
    );

    // Delete
    backend.delete(CF_SLOT_META, b"key1").unwrap();
    assert_eq!(backend.get(CF_SLOT_META, b"key1").unwrap(), None);
}

#[test]
fn backend_prefix_scan() {
    let backend = backend::BlockstoreBackend::in_memory();

    let prefix = 42u64.to_be_bytes();
    let mut key1 = prefix.to_vec();
    key1.extend_from_slice(&0u32.to_be_bytes());
    let mut key2 = prefix.to_vec();
    key2.extend_from_slice(&1u32.to_be_bytes());
    let other_prefix = 99u64.to_be_bytes();
    let mut key3 = other_prefix.to_vec();
    key3.extend_from_slice(&0u32.to_be_bytes());

    backend.put(CF_DATA_SHRED, &key1, b"shred_0").unwrap();
    backend.put(CF_DATA_SHRED, &key2, b"shred_1").unwrap();
    backend.put(CF_DATA_SHRED, &key3, b"other").unwrap();

    let results = backend.prefix_scan(CF_DATA_SHRED, &prefix).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn slot_meta_serialization_round_trip() {
    let mut meta = SlotMeta::new(42, Some(41));
    meta.received_data_shreds = 10;
    meta.received_coding_shreds = 5;
    meta.expected_data_shreds = Some(10);
    meta.status = SlotStatus::Complete;
    meta.next_slots = vec![43, 44];
    meta.is_connected = true;
    meta.completion_timestamp = Some(1700000000);

    let bytes = meta.serialize();
    let restored = SlotMeta::deserialize(&bytes).unwrap();

    assert_eq!(restored.slot, 42);
    assert_eq!(restored.parent_slot, Some(41));
    assert_eq!(restored.received_data_shreds, 10);
    assert_eq!(restored.received_coding_shreds, 5);
    assert_eq!(restored.expected_data_shreds, Some(10));
    assert_eq!(restored.status, SlotStatus::Complete);
    assert_eq!(restored.next_slots, vec![43, 44]);
    assert!(restored.is_connected);
    assert_eq!(restored.completion_timestamp, Some(1700000000));
}

#[test]
fn cleanup_threshold_calculation() {
    assert_eq!(BlockstoreCleanup::cleanup_threshold(2000), 1000);
    assert_eq!(BlockstoreCleanup::cleanup_threshold(500), 0);
    assert_eq!(BlockstoreCleanup::cleanup_threshold(0), 0);
}

#[test]
fn blockstore_error_display() {
    let err = BlockstoreError::SlotNotFound(42);
    assert!(err.to_string().contains("42"));

    let err = BlockstoreError::ShredIndexOutOfRange { slot: 1, index: 99 };
    assert!(err.to_string().contains("1"));
    assert!(err.to_string().contains("99"));

    let err = BlockstoreError::InvalidShredData;
    assert!(err.to_string().contains("Invalid"));
}

#[test]
fn erasure_meta_basic() {
    let em = ErasureMeta::new(100, 0, 32, 16);
    assert_eq!(em.total_shreds(), 48);
    assert_eq!(em.slot, 100);
    assert_eq!(em.fec_set_index, 0);
}

#[test]
fn nonexistent_slot_meta_returns_none() {
    let bs = Blockstore::in_memory();
    assert!(bs.get_slot_meta(999).unwrap().is_none());
}

#[test]
fn nonexistent_data_shred_returns_none() {
    let bs = Blockstore::in_memory();
    assert!(bs.get_data_shred(999, 0).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Typed shred insertion and FEC tracking tests
// ---------------------------------------------------------------------------

fn make_data_shred(slot: u64, index: u32, last_in_slot: bool, parent_offset: u16) -> Shred {
    let flags = if last_in_slot { SHRED_LAST_IN_SLOT } else { 0 };
    Shred::new(
        ShredCommonHeader {
            signature: [0u8; SIGNATURE_SIZE],
            variant: 0x05,
            slot,
            index,
            version: 1,
            fec_set_index: 0,
        },
        ShredVariant::LegacyData(DataShredHeader {
            parent_offset,
            flags,
            size: 100,
        }),
        vec![0xAA; 100],
    )
}

fn make_coding_shred(
    slot: u64,
    index: u32,
    fec_set_index: u32,
    num_data: u16,
    num_coding: u16,
) -> Shred {
    Shred::new(
        ShredCommonHeader {
            signature: [0u8; SIGNATURE_SIZE],
            variant: 0x0A,
            slot,
            index,
            version: 1,
            fec_set_index,
        },
        ShredVariant::LegacyCoding(CodingShredHeader {
            num_data_shreds: num_data,
            num_coding_shreds: num_coding,
            position: 0,
        }),
        vec![0xCC; 100],
    )
}

#[test]
fn insert_typed_data_shred() {
    let bs = Blockstore::in_memory();
    let shred = make_data_shred(100, 0, false, 1);
    let result = bs.insert_shred(&shred).unwrap();

    assert!(!result.slot_complete);
    assert!(!result.is_last_in_slot);

    // Verify the shred was stored.
    let data = bs.get_data_shred(100, 0).unwrap();
    assert!(data.is_some());
    assert_eq!(data.unwrap().len(), 100);
}

#[test]
fn insert_last_data_shred_completes_slot() {
    let bs = Blockstore::in_memory();

    // Insert shred 0 (not last).
    let s0 = make_data_shred(10, 0, false, 1);
    let r0 = bs.insert_shred(&s0).unwrap();
    assert!(!r0.slot_complete);

    // Insert shred 1 (last in slot: expected = 2, received = 2).
    let s1 = make_data_shred(10, 1, true, 1);
    let r1 = bs.insert_shred(&s1).unwrap();
    assert!(r1.slot_complete);
    assert!(r1.is_last_in_slot);

    let meta = bs.get_slot_meta(10).unwrap().unwrap();
    assert_eq!(meta.expected_data_shreds, Some(2));
    assert_eq!(meta.status, SlotStatus::Complete);
    assert!(meta.completion_timestamp.is_some());
}

#[test]
fn insert_typed_coding_shred() {
    let bs = Blockstore::in_memory();
    let shred = make_coding_shred(50, 0, 0, 4, 2);
    let result = bs.insert_shred(&shred).unwrap();

    assert!(!result.slot_complete);
    assert_eq!(result.fec_result, FecInsertResult::Incomplete);
}

#[test]
fn parent_slot_set_from_shred_header() {
    let bs = Blockstore::in_memory();
    let shred = make_data_shred(100, 0, false, 1);
    bs.insert_shred(&shred).unwrap();

    let meta = bs.get_slot_meta(100).unwrap().unwrap();
    assert_eq!(meta.parent_slot, Some(99));
}

#[test]
fn parent_child_linkage() {
    let bs = Blockstore::in_memory();

    // Insert a shred for parent slot first so its meta exists.
    let parent_shred = make_data_shred(99, 0, false, 1);
    bs.insert_shred(&parent_shred).unwrap();

    // Insert child slot shred with parent_offset = 1.
    let child_shred = make_data_shred(100, 0, false, 1);
    bs.insert_shred(&child_shred).unwrap();

    let parent_meta = bs.get_slot_meta(99).unwrap().unwrap();
    assert!(parent_meta.next_slots.contains(&100));
}

#[test]
fn fec_tracker_integration() {
    let bs = Blockstore::in_memory();

    // Query FEC state through blockstore.
    let shred = make_data_shred(10, 0, false, 1);
    bs.insert_shred(&shred).unwrap();

    let tracker = bs.fec_tracker();
    let meta = tracker.get_erasure_meta(10, 0).unwrap();
    assert!(meta.is_some());
}

#[test]
fn set_roots_batch() {
    let bs = Blockstore::in_memory();
    bs.set_roots(&[10, 20, 30]).unwrap();

    assert!(bs.is_root(10));
    assert!(bs.is_root(20));
    assert!(bs.is_root(30));
    assert!(!bs.is_root(15));
    assert_eq!(bs.latest_root(), Some(30));
}

#[test]
fn slot_range_query() {
    let bs = Blockstore::in_memory();
    for slot in [5, 7, 10, 15] {
        bs.insert_data_shred(slot, 0, &[1]).unwrap();
    }

    let range = bs.slot_range(5, 12).unwrap();
    assert_eq!(range, vec![5, 7, 10]);
}

// -----------------------------------------------------------------------
// Persistent backend tests
// -----------------------------------------------------------------------

#[test]
fn persistent_open_and_write() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_test");

    let bs = Blockstore::open(&path).unwrap();
    bs.insert_data_shred(100, 0, &[1, 2, 3]).unwrap();

    let data = bs.get_data_shred(100, 0).unwrap();
    assert_eq!(data, Some(vec![1, 2, 3]));
}

#[test]
fn persistent_data_survives_reopen() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_persist");

    // Write data.
    {
        let bs = Blockstore::open(&path).unwrap();
        bs.insert_data_shred(50, 0, &[0xAA; 16]).unwrap();
        bs.insert_data_shred(50, 1, &[0xBB; 16]).unwrap();
        bs.backend.flush().unwrap();
    }

    // Reopen and verify.
    {
        let bs = Blockstore::open(&path).unwrap();
        assert_eq!(bs.get_data_shred(50, 0).unwrap(), Some(vec![0xAA; 16]));
        assert_eq!(bs.get_data_shred(50, 1).unwrap(), Some(vec![0xBB; 16]));
    }
}

#[test]
fn persistent_slot_meta_survives_reopen() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_meta");

    {
        let bs = Blockstore::open(&path).unwrap();
        bs.insert_data_shred(42, 0, &[1]).unwrap();
        bs.insert_data_shred(42, 1, &[2]).unwrap();
        bs.backend.flush().unwrap();
    }

    {
        let bs = Blockstore::open(&path).unwrap();
        let meta = bs.get_slot_meta(42).unwrap().expect("should exist");
        assert_eq!(meta.slot, 42);
        assert_eq!(meta.received_data_shreds, 2);
    }
}

#[test]
fn persistent_roots_survive_reopen() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_roots");

    {
        let bs = Blockstore::open(&path).unwrap();
        bs.set_roots(&[10, 20, 30]).unwrap();
        bs.backend.flush().unwrap();
    }

    {
        let bs = Blockstore::open(&path).unwrap();
        assert!(bs.is_root(10));
        assert!(bs.is_root(20));
        assert!(bs.is_root(30));
        assert!(!bs.is_root(15));
        assert_eq!(bs.latest_root(), Some(30));
    }
}

#[test]
fn persistent_purge_removes_from_disk() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_purge");

    {
        let bs = Blockstore::open(&path).unwrap();
        bs.insert_data_shred(5, 0, &[1]).unwrap();
        bs.insert_data_shred(10, 0, &[2]).unwrap();
        bs.insert_data_shred(15, 0, &[3]).unwrap();
        bs.set_roots(&[5, 10, 15]).unwrap();
        bs.purge_slots_below(12).unwrap();
        bs.backend.flush().unwrap();
    }

    {
        let bs = Blockstore::open(&path).unwrap();
        // Slots 5 and 10 should be purged.
        assert!(bs.get_slot_meta(5).unwrap().is_none());
        assert!(bs.get_slot_meta(10).unwrap().is_none());
        // Slot 15 should remain.
        assert!(bs.get_slot_meta(15).unwrap().is_some());
        // Roots 5 and 10 should be gone from disk.
        assert!(!bs.is_root(5));
        assert!(!bs.is_root(10));
        assert!(bs.is_root(15));
    }
}

#[test]
fn persistent_dead_slot_survives_reopen() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_dead");

    {
        let bs = Blockstore::open(&path).unwrap();
        bs.insert_data_shred(99, 0, &[1]).unwrap();
        bs.mark_dead(99).unwrap();
        bs.backend.flush().unwrap();
    }

    {
        let bs = Blockstore::open(&path).unwrap();
        let meta = bs.get_slot_meta(99).unwrap().expect("should exist");
        assert_eq!(meta.status, SlotStatus::Dead);
    }
}

#[test]
fn persistent_backend_is_persistent() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("blockstore_check");
    let bs = Blockstore::open(&path).unwrap();
    assert!(bs.backend.is_persistent());
}

#[test]
fn in_memory_backend_is_not_persistent() {
    let bs = Blockstore::in_memory();
    assert!(!bs.backend.is_persistent());
}

// ---------------------------------------------------------------------------
// Block stream event publishing tests
// ---------------------------------------------------------------------------

#[test]
fn event_published_on_set_root() {
    let mut bs = Blockstore::in_memory();
    let (pub_, sub) = block_stream::block_stream(16);
    bs.set_event_publisher(pub_);

    bs.set_root(42).unwrap();
    let event = sub.try_recv().unwrap();
    assert_eq!(event, block_stream::SlotEvent::Rooted { slot: 42 });
}

#[test]
fn event_published_on_set_roots() {
    let mut bs = Blockstore::in_memory();
    let (pub_, sub) = block_stream::block_stream(16);
    bs.set_event_publisher(pub_);

    bs.set_roots(&[10, 20, 30]).unwrap();
    let events = sub.drain();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], block_stream::SlotEvent::Rooted { slot: 10 });
    assert_eq!(events[2], block_stream::SlotEvent::Rooted { slot: 30 });
}

#[test]
fn event_published_on_mark_dead() {
    let mut bs = Blockstore::in_memory();
    let (pub_, sub) = block_stream::block_stream(16);
    bs.set_event_publisher(pub_);

    bs.mark_dead(5).unwrap();
    let event = sub.try_recv().unwrap();
    assert_eq!(event, block_stream::SlotEvent::Dead { slot: 5 });
}

#[test]
fn event_published_on_mark_duplicate() {
    let mut bs = Blockstore::in_memory();
    let (pub_, sub) = block_stream::block_stream(16);
    bs.set_event_publisher(pub_);

    bs.mark_duplicate(7).unwrap();
    let event = sub.try_recv().unwrap();
    assert_eq!(event, block_stream::SlotEvent::Duplicate { slot: 7 });
}

#[test]
fn no_event_without_publisher() {
    let bs = Blockstore::in_memory();
    // Should not panic even without a publisher.
    bs.set_root(42).unwrap();
    bs.mark_dead(99).unwrap_or(()); // Slot already dead is ok.
}

// --- Block height index ---

#[test]
fn set_and_get_block_height() {
    let bs = Blockstore::in_memory();
    bs.set_block_height(100, 50).unwrap();
    bs.set_block_height(200, 99).unwrap();

    assert_eq!(bs.get_block_height(100).unwrap(), Some(50));
    assert_eq!(bs.get_block_height(200).unwrap(), Some(99));
    assert_eq!(bs.get_block_height(300).unwrap(), None);
}

#[test]
fn block_height_overwrite() {
    let bs = Blockstore::in_memory();
    bs.set_block_height(100, 50).unwrap();
    bs.set_block_height(100, 51).unwrap();
    assert_eq!(bs.get_block_height(100).unwrap(), Some(51));
}

#[test]
fn slot_for_block_height_found() {
    let bs = Blockstore::in_memory();
    bs.set_block_height(10, 5).unwrap();
    bs.set_block_height(20, 10).unwrap();
    bs.set_block_height(30, 15).unwrap();

    assert_eq!(bs.slot_for_block_height(10).unwrap(), Some(20));
    assert_eq!(bs.slot_for_block_height(15).unwrap(), Some(30));
}

#[test]
fn slot_for_block_height_not_found() {
    let bs = Blockstore::in_memory();
    bs.set_block_height(10, 5).unwrap();
    assert_eq!(bs.slot_for_block_height(999).unwrap(), None);
}

#[test]
fn block_height_zero_values() {
    let bs = Blockstore::in_memory();
    // Slot 0 with height 0 (genesis).
    bs.set_block_height(0, 0).unwrap();
    assert_eq!(bs.get_block_height(0).unwrap(), Some(0));
    assert_eq!(bs.slot_for_block_height(0).unwrap(), Some(0));
}

#[test]
fn highest_block_height_tracks_latest_root() {
    let bs = Blockstore::in_memory();
    assert_eq!(bs.highest_block_height().unwrap(), None);

    bs.set_root(10).unwrap();
    bs.set_block_height(10, 5).unwrap();
    assert_eq!(bs.highest_block_height().unwrap(), Some(5));

    bs.set_root(20).unwrap();
    bs.set_block_height(20, 12).unwrap();
    assert_eq!(bs.highest_block_height().unwrap(), Some(12));
}

// --- Block time ---

#[test]
fn set_and_get_block_time() {
    let bs = Blockstore::in_memory();
    bs.set_block_time(100, 1_700_000_000).unwrap();
    bs.set_block_time(200, 1_700_000_400).unwrap();

    assert_eq!(bs.get_block_time(100).unwrap(), Some(1_700_000_000));
    assert_eq!(bs.get_block_time(200).unwrap(), Some(1_700_000_400));
    assert_eq!(bs.get_block_time(300).unwrap(), None);
}

#[test]
fn block_time_recorded_on_slot_completion() {
    let bs = Blockstore::in_memory();
    let shred = make_data_shred(42, 0, true, 1);
    bs.insert_shred(&shred).unwrap();

    // Slot should be complete (last_in_slot flag set).
    assert!(bs.is_slot_complete(42));

    // Block time should have been recorded.
    let block_time = bs.get_block_time(42).unwrap();
    assert!(block_time.is_some());
    let ts = block_time.unwrap();
    // Should be a recent unix timestamp (after 2024).
    assert!(ts > 1_700_000_000);
}

#[test]
fn block_time_overwrite() {
    let bs = Blockstore::in_memory();
    bs.set_block_time(50, 1000).unwrap();
    bs.set_block_time(50, 2000).unwrap();
    assert_eq!(bs.get_block_time(50).unwrap(), Some(2000));
}

// --- Blockstore stats ---

#[test]
fn stats_track_shred_inserts_and_slot_lifecycle() {
    let bs = Blockstore::in_memory();

    // No activity yet.
    let snap = bs.stats().snapshot();
    assert_eq!(snap.shreds_inserted, 0);
    assert_eq!(snap.slots_completed, 0);

    // Insert a data shred (not last in slot).
    let shred = make_data_shred(100, 0, false, 1);
    bs.insert_shred(&shred).unwrap();
    assert_eq!(bs.stats().snapshot().shreds_inserted, 1);
    assert_eq!(bs.stats().snapshot().slots_completed, 0);

    // Insert last-in-slot shred → slot completes.
    let last_shred = make_data_shred(100, 1, true, 1);
    bs.insert_shred(&last_shred).unwrap();
    assert_eq!(bs.stats().snapshot().shreds_inserted, 2);
    assert_eq!(bs.stats().snapshot().slots_completed, 1);

    // Mark dead / duplicate / root.
    bs.mark_dead(200).unwrap();
    bs.mark_duplicate(300).unwrap();
    bs.set_root(100).unwrap();

    let snap = bs.stats().snapshot();
    assert_eq!(snap.slots_dead, 1);
    assert_eq!(snap.slots_duplicate, 1);
    assert_eq!(snap.slots_rooted, 1);
}
