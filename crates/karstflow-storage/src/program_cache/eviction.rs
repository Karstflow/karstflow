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
