//! Secondary index mapping program owners to their account pubkeys.
//!
//! Enables efficient `getProgramAccounts`-style queries without scanning
//! the entire account database. The index is maintained incrementally:
//! inserts and removals are O(1) per account. Owner lookups return all
//! accounts owned by a program in O(k) where k is the result set size.

use super::primitives::Pubkey;
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Secondary index that maps program owner pubkeys to the set of
/// account pubkeys they own.
///
/// Thread-safe via `DashMap` sharding. Statistics (total lamports,
/// account count) are maintained with atomic counters for O(1) queries.
pub struct OwnerIndex {
    /// Owner pubkey → set of account pubkeys owned by that program.
    by_owner: DashMap<Pubkey, HashSet<Pubkey>>,

    /// Account pubkey → current owner (for updating the index on owner change).
    current_owner: DashMap<Pubkey, Pubkey>,

    /// Account pubkey → last-modified slot.
    updated_slot: DashMap<Pubkey, u64>,

    /// Total lamports across all indexed accounts.
    total_lamports: AtomicU64,

    /// Number of indexed accounts.
    account_count: AtomicU64,
}

impl OwnerIndex {
    pub fn new() -> Self {
        Self {
            by_owner: DashMap::new(),
            current_owner: DashMap::new(),
            updated_slot: DashMap::new(),
            total_lamports: AtomicU64::new(0),
            account_count: AtomicU64::new(0),
        }
    }

    /// Insert or update an account in the index.
    ///
    /// If the account already exists, the old owner's entry is removed
    /// and the lamport delta is applied to the total.
    pub fn upsert(
        &self,
        pubkey: Pubkey,
        owner: Pubkey,
        lamports: u64,
        slot: u64,
        old_lamports: Option<u64>,
    ) {
        // Update owner index.
        if let Some(prev_owner) = self.current_owner.get(&pubkey) {
            let prev = *prev_owner;
            drop(prev_owner);
            if prev != owner {
                // Owner changed: remove from old owner's set.
                if let Some(mut set) = self.by_owner.get_mut(&prev) {
                    set.remove(&pubkey);
                    if set.is_empty() {
                        drop(set);
                        self.by_owner.remove(&prev);
                    }
                }
            }
        } else {
            // New account.
            self.account_count.fetch_add(1, Ordering::Relaxed);
        }

        self.current_owner.insert(pubkey, owner);
        self.by_owner.entry(owner).or_default().insert(pubkey);

        // Update slot tracking.
        self.updated_slot.insert(pubkey, slot);

        // Update lamport totals.
        if let Some(old) = old_lamports {
            // Existing account: adjust delta.
            if lamports >= old {
                self.total_lamports
                    .fetch_add(lamports - old, Ordering::Relaxed);
            } else {
                self.total_lamports
                    .fetch_sub(old - lamports, Ordering::Relaxed);
            }
        } else {
            // New account.
            self.total_lamports.fetch_add(lamports, Ordering::Relaxed);
        }
    }

    /// Remove an account from the index.
    #[allow(dead_code)]
    pub fn remove(&self, pubkey: &Pubkey, lamports: u64) {
        if let Some((_, owner)) = self.current_owner.remove(pubkey) {
            if let Some(mut set) = self.by_owner.get_mut(&owner) {
                set.remove(pubkey);
                if set.is_empty() {
                    drop(set);
                    self.by_owner.remove(&owner);
                }
            }
            self.updated_slot.remove(pubkey);
            self.account_count.fetch_sub(1, Ordering::Relaxed);
            self.total_lamports.fetch_sub(lamports, Ordering::Relaxed);
        }
    }

    /// Get all account pubkeys owned by a program.
    pub fn accounts_by_owner(&self, owner: &Pubkey) -> Vec<Pubkey> {
        self.by_owner
            .get(owner)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Number of distinct owners in the index.
    pub fn owner_count(&self) -> usize {
        self.by_owner.len()
    }

    /// Number of accounts owned by a specific program.
    pub fn accounts_owned_by(&self, owner: &Pubkey) -> usize {
        self.by_owner.get(owner).map(|set| set.len()).unwrap_or(0)
    }

    /// Total number of indexed accounts (O(1)).
    pub fn total_accounts(&self) -> u64 {
        self.account_count.load(Ordering::Relaxed)
    }

    /// Total lamports across all indexed accounts (O(1)).
    pub fn total_lamports(&self) -> u64 {
        self.total_lamports.load(Ordering::Relaxed)
    }

    /// Get the slot at which an account was last modified.
    pub fn last_updated_slot(&self, pubkey: &Pubkey) -> Option<u64> {
        self.updated_slot.get(pubkey).map(|v| *v)
    }

    /// Get all accounts modified at or after a given slot.
    pub fn accounts_modified_since(&self, min_slot: u64) -> Vec<Pubkey> {
        self.updated_slot
            .iter()
            .filter(|entry| *entry.value() >= min_slot)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Clear all entries from the index.
    pub fn clear(&self) {
        self.by_owner.clear();
        self.current_owner.clear();
        self.updated_slot.clear();
        self.total_lamports.store(0, Ordering::Relaxed);
        self.account_count.store(0, Ordering::Relaxed);
    }
}

impl Default for OwnerIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new([b; 32])
    }

    #[test]
    fn insert_and_lookup_by_owner() {
        let idx = OwnerIndex::new();
        let owner = pk(1);
        let acc_a = pk(10);
        let acc_b = pk(11);

        idx.upsert(acc_a, owner, 100, 1, None);
        idx.upsert(acc_b, owner, 200, 1, None);

        let mut result = idx.accounts_by_owner(&owner);
        result.sort_by_key(|p| p.as_bytes()[0]);
        assert_eq!(result, vec![acc_a, acc_b]);
    }

    #[test]
    fn owner_change_updates_index() {
        let idx = OwnerIndex::new();
        let owner_a = pk(1);
        let owner_b = pk(2);
        let acc = pk(10);

        idx.upsert(acc, owner_a, 100, 1, None);
        assert_eq!(idx.accounts_by_owner(&owner_a).len(), 1);
        assert_eq!(idx.accounts_by_owner(&owner_b).len(), 0);

        // Change owner.
        idx.upsert(acc, owner_b, 100, 2, Some(100));
        assert_eq!(idx.accounts_by_owner(&owner_a).len(), 0);
        assert_eq!(idx.accounts_by_owner(&owner_b).len(), 1);
    }

    #[test]
    fn remove_account() {
        let idx = OwnerIndex::new();
        let owner = pk(1);
        let acc = pk(10);

        idx.upsert(acc, owner, 500, 1, None);
        assert_eq!(idx.total_accounts(), 1);
        assert_eq!(idx.total_lamports(), 500);

        idx.remove(&acc, 500);
        assert_eq!(idx.total_accounts(), 0);
        assert_eq!(idx.total_lamports(), 0);
        assert_eq!(idx.accounts_by_owner(&owner).len(), 0);
    }

    #[test]
    fn lamport_tracking() {
        let idx = OwnerIndex::new();
        let owner = pk(1);

        idx.upsert(pk(10), owner, 100, 1, None);
        idx.upsert(pk(11), owner, 200, 1, None);
        assert_eq!(idx.total_lamports(), 300);
        assert_eq!(idx.total_accounts(), 2);

        // Update lamports for pk(10): 100 → 150.
        idx.upsert(pk(10), owner, 150, 2, Some(100));
        assert_eq!(idx.total_lamports(), 350);
        assert_eq!(idx.total_accounts(), 2);

        // Decrease lamports for pk(11): 200 → 50.
        idx.upsert(pk(11), owner, 50, 3, Some(200));
        assert_eq!(idx.total_lamports(), 200);
    }

    #[test]
    fn slot_tracking() {
        let idx = OwnerIndex::new();
        let owner = pk(1);
        let acc = pk(10);

        idx.upsert(acc, owner, 100, 5, None);
        assert_eq!(idx.last_updated_slot(&acc), Some(5));

        idx.upsert(acc, owner, 200, 10, Some(100));
        assert_eq!(idx.last_updated_slot(&acc), Some(10));
    }

    #[test]
    fn accounts_modified_since_slot() {
        let idx = OwnerIndex::new();
        let owner = pk(1);

        idx.upsert(pk(10), owner, 100, 5, None);
        idx.upsert(pk(11), owner, 200, 10, None);
        idx.upsert(pk(12), owner, 300, 15, None);

        let modified = idx.accounts_modified_since(10);
        assert_eq!(modified.len(), 2); // pk(11) and pk(12)
    }

    #[test]
    fn clear_resets_all() {
        let idx = OwnerIndex::new();
        let owner = pk(1);

        idx.upsert(pk(10), owner, 100, 1, None);
        idx.upsert(pk(11), owner, 200, 1, None);

        idx.clear();
        assert_eq!(idx.total_accounts(), 0);
        assert_eq!(idx.total_lamports(), 0);
        assert_eq!(idx.owner_count(), 0);
    }

    #[test]
    fn multiple_owners() {
        let idx = OwnerIndex::new();
        let owner_a = pk(1);
        let owner_b = pk(2);
        let owner_c = pk(3);

        idx.upsert(pk(10), owner_a, 100, 1, None);
        idx.upsert(pk(11), owner_a, 200, 1, None);
        idx.upsert(pk(12), owner_b, 300, 1, None);
        idx.upsert(pk(13), owner_c, 400, 1, None);

        assert_eq!(idx.owner_count(), 3);
        assert_eq!(idx.accounts_owned_by(&owner_a), 2);
        assert_eq!(idx.accounts_owned_by(&owner_b), 1);
        assert_eq!(idx.accounts_owned_by(&owner_c), 1);
        assert_eq!(idx.total_lamports(), 1000);
        assert_eq!(idx.total_accounts(), 4);
    }

    #[test]
    fn empty_owner_removed_from_index() {
        let idx = OwnerIndex::new();
        let owner = pk(1);
        let acc = pk(10);

        idx.upsert(acc, owner, 100, 1, None);
        assert_eq!(idx.owner_count(), 1);

        idx.remove(&acc, 100);
        assert_eq!(idx.owner_count(), 0);
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let idx = OwnerIndex::new();
        idx.remove(&pk(99), 0);
        assert_eq!(idx.total_accounts(), 0);
        assert_eq!(idx.total_lamports(), 0);
    }
}
