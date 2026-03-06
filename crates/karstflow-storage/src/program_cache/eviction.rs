//! LRU eviction policy for the program cache.
//!
//! Selects entries to evict based on last-accessed time, while protecting
//! entries with active references (ref_count > 0) from eviction.

use super::CacheSlot;
use karstflow_types::Pubkey;
use std::collections::HashMap;

/// LRU eviction policy for the program cache.
pub struct EvictionPolicy;

impl EvictionPolicy {
    /// Select entries to evict using LRU policy.
    ///
    /// Returns pubkeys of entries to remove. Entries with ref_count > 0
    /// (e.g., builtin programs) are never evicted.
    pub(crate) fn select_evictions(
        entries: &HashMap<Pubkey, CacheSlot>,
        target_count: usize,
    ) -> Vec<Pubkey> {
        if entries.len() <= target_count {
            return vec![];
        }

        let to_evict = entries.len() - target_count;

        // Sort candidates by last_accessed (ascending = least recently used first).
        // Only consider entries with ref_count == 0 as eviction candidates.
        let mut candidates: Vec<_> = entries
            .iter()
            .filter(|(_, slot)| slot.ref_count == 0)
            .map(|(k, v)| (*k, v.last_accessed))
            .collect();

        candidates.sort_by_key(|(_, accessed)| *accessed);

        candidates.iter().take(to_evict).map(|(k, _)| *k).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_slot(last_accessed: u64, ref_count: u64) -> CacheSlot {
        CacheSlot {
            program: Arc::new(super::super::CachedProgram::builtin(Pubkey::new([0; 32]))),
            last_accessed,
            deployment_slot: 0,
            ref_count,
        }
    }

    #[test]
    fn no_eviction_when_under_target() {
        let mut entries = HashMap::new();
        entries.insert(Pubkey::new_from_array([1; 32]), make_slot(100, 0));
        entries.insert(Pubkey::new_from_array([2; 32]), make_slot(200, 0));

        let evicted = EvictionPolicy::select_evictions(&entries, 5);
        assert!(evicted.is_empty());
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut entries = HashMap::new();
        let old_key = Pubkey::new_from_array([1; 32]);
        let new_key = Pubkey::new_from_array([2; 32]);
        entries.insert(old_key, make_slot(10, 0));
        entries.insert(new_key, make_slot(100, 0));

        let evicted = EvictionPolicy::select_evictions(&entries, 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0], old_key);
    }

    #[test]
    fn protects_referenced_entries() {
        let mut entries = HashMap::new();
        let protected = Pubkey::new_from_array([1; 32]);
        let evictable = Pubkey::new_from_array([2; 32]);
        entries.insert(protected, make_slot(10, 1)); // ref_count > 0
        entries.insert(evictable, make_slot(20, 0));

        let evicted = EvictionPolicy::select_evictions(&entries, 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0], evictable);
    }

    #[test]
    fn all_protected_means_no_eviction() {
        let mut entries = HashMap::new();
        entries.insert(Pubkey::new_from_array([1; 32]), make_slot(10, 1));
        entries.insert(Pubkey::new_from_array([2; 32]), make_slot(20, 1));

        let evicted = EvictionPolicy::select_evictions(&entries, 1);
        assert!(evicted.is_empty());
    }

    #[test]
    fn empty_entries_no_eviction() {
        let entries = HashMap::new();
        let evicted = EvictionPolicy::select_evictions(&entries, 0);
        assert!(evicted.is_empty());
    }

    #[test]
    fn exact_target_no_eviction() {
        let mut entries = HashMap::new();
        entries.insert(Pubkey::new_from_array([1; 32]), make_slot(10, 0));
        entries.insert(Pubkey::new_from_array([2; 32]), make_slot(20, 0));

        let evicted = EvictionPolicy::select_evictions(&entries, 2);
        assert!(evicted.is_empty());
    }
}
