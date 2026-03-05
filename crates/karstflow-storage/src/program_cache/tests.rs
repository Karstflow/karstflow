use super::*;
use karstflow_types::Pubkey;

fn test_pubkey(seed: u8) -> Pubkey {
    Pubkey::new([seed; 32])
}

fn test_loaded_program(seed: u8) -> CachedProgram {
    CachedProgram::loaded(vec![seed; 64], Pubkey::zeroed(), seed as u64)
}

#[test]
fn insert_and_retrieve_program() {
    let cache = ProgramCache::new();
    let id = test_pubkey(1);
    let program = test_loaded_program(1);

    cache.insert(id, program, 100);
    let result = cache.get(&id, 100);

    assert!(result.is_some());
    let cached = result.unwrap();
    assert!(cached.is_executable());
    assert_eq!(cached.data_size, 64);
}

#[test]
fn cache_hit_increments_stats() {
    let cache = ProgramCache::new();
    let id = test_pubkey(2);
    cache.insert(id, test_loaded_program(2), 100);

    cache.get(&id, 101);
    cache.get(&id, 102);

    assert_eq!(cache.stats().hit_count(), 2);
}

#[test]
fn cache_miss_increments_stats() {
    let cache = ProgramCache::new();
    let missing = test_pubkey(99);

    let result = cache.get(&missing, 100);
    assert!(result.is_none());
    assert_eq!(cache.stats().miss_count(), 1);
}

#[test]
fn invalidate_removes_entry() {
    let cache = ProgramCache::new();
    let id = test_pubkey(3);
    cache.insert(id, test_loaded_program(3), 100);
    assert_eq!(cache.len(), 1);

    cache.invalidate(&id);
    assert_eq!(cache.len(), 0);
    assert!(cache.get(&id, 100).is_none());
}

#[test]
fn lru_eviction_when_at_capacity() {
    let cache = ProgramCache::with_capacity(3);

    // Insert 3 programs
    for i in 0..3u8 {
        cache.insert(test_pubkey(i), test_loaded_program(i), i as u64);
    }
    assert_eq!(cache.len(), 3);

    // Access program 0 and 2 to make program 1 the LRU
    cache.get(&test_pubkey(0), 10);
    cache.get(&test_pubkey(2), 10);

    // Insert a 4th program, triggering eviction
    cache.insert(test_pubkey(10), test_loaded_program(10), 10);

    // Program 1 (LRU) should have been evicted
    assert_eq!(cache.len(), 3);
    assert!(cache.get(&test_pubkey(1), 11).is_none());

    // Programs 0, 2, and 10 should still be present
    assert!(cache.get(&test_pubkey(0), 11).is_some());
    assert!(cache.get(&test_pubkey(2), 11).is_some());
    assert!(cache.get(&test_pubkey(10), 11).is_some());

    assert!(cache.stats().eviction_count() > 0);
}

#[test]
fn builtin_programs_not_evicted() {
    let cache = ProgramCache::with_capacity(2);

    // Insert a builtin (protected from eviction)
    let builtin_id = test_pubkey(100);
    let builtin = CachedProgram::builtin(Pubkey::zeroed());
    cache.insert_builtin(builtin_id, builtin, 0);

    // Insert a regular program
    cache.insert(test_pubkey(1), test_loaded_program(1), 1);

    // Insert another regular program (should trigger eviction of program 1, not builtin)
    cache.insert(test_pubkey(2), test_loaded_program(2), 2);

    // Builtin should still be present
    assert!(cache.get(&builtin_id, 10).is_some());

    // The regular program with older access should be evicted
    // Program 1 was LRU and has ref_count == 0
    assert!(cache.get(&test_pubkey(1), 10).is_none());
    assert!(cache.get(&test_pubkey(2), 10).is_some());
}

#[test]
fn clear_removes_all_entries() {
    let cache = ProgramCache::new();
    for i in 0..5u8 {
        cache.insert(test_pubkey(i), test_loaded_program(i), i as u64);
    }
    assert_eq!(cache.len(), 5);

    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn concurrent_read_access() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(ProgramCache::new());
    let id = test_pubkey(42);
    cache.insert(id, test_loaded_program(42), 100);

    let mut handles = vec![];
    for _ in 0..8 {
        let cache_clone = Arc::clone(&cache);
        let handle = thread::spawn(move || {
            for slot in 0..100u64 {
                let result = cache_clone.get(&id, slot);
                assert!(result.is_some());
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(cache.stats().hit_count(), 800);
}

#[test]
fn failed_to_load_tombstone() {
    let cache = ProgramCache::new();
    let id = test_pubkey(50);
    let program = CachedProgram::failed("invalid ELF".to_string(), Pubkey::zeroed());

    cache.insert(id, program, 100);
    let result = cache.get(&id, 100).unwrap();

    assert!(!result.is_executable());
    match &result.program_type {
        ProgramType::FailedToLoad(reason) => {
            assert_eq!(reason, "invalid ELF");
        }
        other => panic!("expected FailedToLoad, got: {:?}", other),
    }
}

#[test]
fn program_redeployment_updates_cache() {
    let cache = ProgramCache::new();
    let id = test_pubkey(60);

    // Deploy v1
    let v1 = CachedProgram::loaded(vec![1; 32], Pubkey::zeroed(), 100);
    cache.insert(id, v1, 100);

    let result = cache.get(&id, 100).unwrap();
    assert_eq!(result.data_size, 32);

    // Redeploy v2
    let v2 = CachedProgram::loaded(vec![2; 64], Pubkey::zeroed(), 200);
    cache.insert(id, v2, 200);

    let result = cache.get(&id, 200).unwrap();
    assert_eq!(result.data_size, 64);
    assert_eq!(result.deployment_slot, 200);

    // Only one entry in cache for this program
    assert_eq!(cache.len(), 1);
}

#[test]
fn cache_stats_accuracy() {
    let cache = ProgramCache::new();
    let id = test_pubkey(70);
    let missing = test_pubkey(71);

    // 1 insertion
    cache.insert(id, test_loaded_program(70), 100);
    assert_eq!(cache.stats().insertion_count(), 1);

    // 2 hits
    cache.get(&id, 101);
    cache.get(&id, 102);
    assert_eq!(cache.stats().hit_count(), 2);

    // 1 miss
    cache.get(&missing, 103);
    assert_eq!(cache.stats().miss_count(), 1);
}

#[test]
fn program_type_executable_check() {
    assert!(CachedProgram::builtin(Pubkey::zeroed()).is_executable());
    assert!(CachedProgram::loaded(vec![1], Pubkey::zeroed(), 0).is_executable());
    assert!(!CachedProgram::failed("err".to_string(), Pubkey::zeroed()).is_executable());

    let closing = CachedProgram {
        program_type: ProgramType::Closing,
        elf_bytes: None,
        data_size: 0,
        owner: Pubkey::zeroed(),
        deployment_slot: 0,
        expiration_slot: None,
    };
    assert!(!closing.is_executable());
}

#[test]
fn default_cache_is_empty() {
    let cache = ProgramCache::default();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}
