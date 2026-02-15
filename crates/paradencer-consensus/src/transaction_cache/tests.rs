use super::*;

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h[31] = seed.wrapping_mul(7);
    h
}

// ── basic insert and query ──────────────────────────────────────────

#[test]
fn insert_and_query_single_entry() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);
    let mh = make_hash(2);

    assert!(cache.insert(&bh, &mh, 100, 0));
    assert!(cache.contains(&bh, &mh, 0));
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn detect_duplicate_same_fork() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);
    let mh = make_hash(2);

    assert!(cache.insert(&bh, &mh, 100, 0));
    // Second insert of the exact same tx on the same fork is a duplicate.
    assert!(!cache.insert(&bh, &mh, 100, 0));
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn allow_same_tx_on_different_forks() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);
    let mh = make_hash(2);

    assert!(cache.insert(&bh, &mh, 100, 0));
    // Same transaction on a different fork should be accepted.
    assert!(cache.insert(&bh, &mh, 100, 1));

    assert!(cache.contains(&bh, &mh, 0));
    assert!(cache.contains(&bh, &mh, 1));
    // The entry count stays 1 because it is the same (blockhash, message_hash) pair.
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn not_found_returns_false() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);
    let mh = make_hash(2);

    assert!(!cache.contains(&bh, &mh, 0));
}

// ── purge by slot ───────────────────────────────────────────────────

#[test]
fn purge_by_slot_removes_target() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);
    let mh1 = make_hash(10);
    let mh2 = make_hash(20);

    cache.insert(&bh, &mh1, 100, 0);
    cache.insert(&bh, &mh2, 200, 0);
    assert_eq!(cache.entry_count(), 2);

    cache.purge_slot(100);
    assert!(!cache.contains(&bh, &mh1, 0));
    assert!(cache.contains(&bh, &mh2, 0));
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn purge_before_slot_removes_old_entries() {
    let cache = TransactionCache::new();
    let bh = make_hash(1);

    for i in 0u8..5 {
        let mh = make_hash(100 + i);
        cache.insert(&bh, &mh, i as u64, 0);
    }
    assert_eq!(cache.entry_count(), 5);

    cache.purge_before_slot(3);
    // Slots 0, 1, 2 removed; slots 3, 4 remain.
    assert_eq!(cache.entry_count(), 2);
}

// ── capacity ────────────────────────────────────────────────────────

#[test]
fn capacity_limits_reject_inserts() {
    let cache = TransactionCache::with_capacity(3);

    for i in 0u8..3 {
        let bh = make_hash(i);
        let mh = make_hash(i + 100);
        assert!(cache.insert(&bh, &mh, i as u64, 0));
    }
    assert_eq!(cache.entry_count(), 3);

    // Fourth insert should be rejected (at capacity).
    let bh = make_hash(50);
    let mh = make_hash(51);
    assert!(!cache.insert(&bh, &mh, 10, 0));
    assert_eq!(cache.entry_count(), 3);
}

// ── entry count across shards ───────────────────────────────────────

#[test]
fn entry_count_across_shards() {
    let cache = TransactionCache::new();
    let count = 200;

    for i in 0..count {
        let mut bh = [0u8; 32];
        bh[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        let mh = make_hash((i % 256) as u8);
        cache.insert(&bh, &mh, i as u64, 0);
    }
    assert_eq!(cache.entry_count(), count);
}

// ── shard distribution ──────────────────────────────────────────────

#[test]
fn shard_index_is_deterministic() {
    let cache = TransactionCache::new();
    let hash = make_hash(42);

    let idx1 = cache.shard_for_hash(&hash);
    let idx2 = cache.shard_for_hash(&hash);
    assert_eq!(idx1, idx2);
}

#[test]
fn shard_index_within_bounds() {
    let cache = TransactionCache::new();
    for seed in 0u8..=255 {
        let hash = make_hash(seed);
        let idx = cache.shard_for_hash(&hash);
        assert!(idx < TRANSACTION_CACHE_SHARDS);
    }
}

// ── concurrent inserts ──────────────────────────────────────────────

#[test]
fn concurrent_inserts_from_multiple_threads() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(TransactionCache::new());
    let num_threads = 8;
    let entries_per_thread = 500;

    let mut handles = Vec::new();
    for t in 0..num_threads {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            for i in 0..entries_per_thread {
                let mut bh = [0u8; 32];
                bh[0..8].copy_from_slice(&((t * entries_per_thread + i) as u64).to_le_bytes());
                let mut mh = [0u8; 32];
                mh[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                mh[8] = t as u8;
                cache.insert(&bh, &mh, i as u64, t as u64);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        cache.entry_count(),
        (num_threads * entries_per_thread) as usize
    );
}

// ── nonce utilities ─────────────────────────────────────────────────

#[test]
fn nonce_detection_via_public_api() {
    // AdvanceNonceAccount discriminant is 4.
    let advance_data = 4u32.to_le_bytes();
    assert!(is_nonce_instruction(&advance_data));

    let transfer_data = 2u32.to_le_bytes();
    assert!(!is_nonce_instruction(&transfer_data));
}

#[test]
fn nonce_key_extraction() {
    let accounts = [5u8, 3, 1];
    assert_eq!(extract_nonce_key_index(&accounts), Some(5));
    assert_eq!(extract_nonce_key_index(&[]), None);
}
