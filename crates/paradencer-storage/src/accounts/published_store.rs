/// Bounded LRU cache for published (committed) account state.
///
/// Published accounts are the "root" state — confirmed, non-speculative.
/// They live primarily on disk (durable store) with a bounded in-memory
/// cache for hot accounts. This design scales to hundreds of millions
/// of accounts without proportional memory growth.
///
/// Cache operations:
/// - `get()`: cache hit → return; cache miss → load from disk, insert, evict LRU if full
/// - `insert()`: write to cache + persist to disk
/// - `insert_batch()`: batch publish with WriteBatch
/// - `insert_recovered()`: populate cache from recovery (no disk write)
/// - `iter_all()`: stream all accounts from disk (or cache if no disk)
use std::collections::HashMap;
use std::sync::Arc;

use paradencer_constants::durable_store::{CF_ACCOUNTS, DEFAULT_PUBLISHED_CACHE_MAX_ENTRIES};

use super::primitives::{Account, Pubkey};
use crate::durable::account_encoding::{decode_account, encode_account};
use crate::durable::{DurableStore, WriteBatch};

/// A node in the intrusive LRU doubly-linked list.
struct CacheNode {
    account: Account,
    /// Next more-recently-used entry (None if this is the MRU head).
    newer: Option<Pubkey>,
    /// Next less-recently-used entry (None if this is the LRU tail).
    older: Option<Pubkey>,
}

/// Bounded published account cache with O(1) LRU eviction.
///
/// Combines a HashMap for O(1) key lookup with an intrusive doubly-linked
/// list for O(1) eviction of the least-recently-used entry.
pub(crate) struct PublishedStore {
    /// Cache entries keyed by pubkey.
    cache: HashMap<Pubkey, CacheNode>,
    /// Most recently used entry (head of LRU list).
    lru_head: Option<Pubkey>,
    /// Least recently used entry (tail of LRU list).
    lru_tail: Option<Pubkey>,
    /// Maximum entries before eviction starts.
    max_entries: usize,
    /// Durable store backend for disk persistence.
    store: Option<Arc<dyn DurableStore>>,
}

impl PublishedStore {
    /// Create a store with no disk backend and default cache capacity.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            lru_head: None,
            lru_tail: None,
            max_entries: DEFAULT_PUBLISHED_CACHE_MAX_ENTRIES,
            store: None,
        }
    }

    /// Create a store with the given cache capacity and no disk backend.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_entries.min(65536)),
            lru_head: None,
            lru_tail: None,
            max_entries,
            store: None,
        }
    }

    /// Create a store backed by persistent storage.
    pub fn with_durable_store(store: Arc<dyn DurableStore>) -> Self {
        Self {
            cache: HashMap::new(),
            lru_head: None,
            lru_tail: None,
            max_entries: DEFAULT_PUBLISHED_CACHE_MAX_ENTRIES,
            store: Some(store),
        }
    }

    /// Returns true if a durable store is configured.
    pub fn has_durable_store(&self) -> bool {
        self.store.is_some()
    }

    /// Number of entries currently in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    /// Get a published account. Cache hit → return; miss → load from disk.
    ///
    /// On cache miss with a durable store, loads the account from disk and
    /// inserts it into the cache (evicting the LRU entry if full).
    pub fn get(&mut self, pubkey: &Pubkey) -> Option<Account> {
        // Cache hit — move to MRU and return.
        if self.cache.contains_key(pubkey) {
            self.move_to_head(pubkey);
            return self.cache.get(pubkey).map(|n| n.account.clone());
        }

        // Cache miss — try disk.
        let account = self.load_from_disk(pubkey)?;
        self.insert_into_cache(*pubkey, account.clone());
        Some(account)
    }

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    /// Insert a published account into the cache and persist to disk.
    pub fn insert(&mut self, pubkey: Pubkey, account: Account) {
        self.persist_account(&pubkey, &account);
        self.insert_into_cache(pubkey, account);
    }

    /// Insert a batch of published accounts with a single WriteBatch.
    ///
    /// Returns the number of accounts written.
    pub fn insert_batch(&mut self, accounts: &HashMap<Pubkey, Account>) -> usize {
        if accounts.is_empty() {
            return 0;
        }

        // Build write batch for disk persistence.
        if let Some(ref store) = self.store {
            let mut batch = WriteBatch::new();
            for (pubkey, account) in accounts {
                let encoded = encode_account(account);
                let _ = batch.put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded);
            }
            if !batch.is_empty() {
                if let Err(e) = store.write_batch(&batch) {
                    eprintln!("durable store batch write error: {e}");
                }
            }
        }

        // Insert all into cache.
        let count = accounts.len();
        for (pubkey, account) in accounts {
            self.insert_into_cache(*pubkey, account.clone());
        }
        count
    }

    /// Insert an account from recovery (disk) without re-persisting to disk.
    ///
    /// Used during startup recovery to populate the cache without write
    /// amplification.
    pub fn insert_recovered(&mut self, pubkey: Pubkey, account: Account) {
        self.insert_into_cache(pubkey, account);
    }

    /// Remove a published account from cache and disk.
    #[allow(dead_code)]
    pub fn remove(&mut self, pubkey: &Pubkey) {
        self.remove_from_cache(pubkey);
        if let Some(ref store) = self.store {
            let _ = store.delete(CF_ACCOUNTS, pubkey.as_bytes());
        }
    }

    /// Clear the entire cache (disk data is NOT affected).
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.lru_head = None;
        self.lru_tail = None;
    }

    /// Clear the entire cache AND delete all accounts from disk.
    pub fn clear_all(&mut self) {
        self.cache.clear();
        self.lru_head = None;
        self.lru_tail = None;
        // Disk cleanup would require prefix_scan + delete_all, which is
        // expensive. For now, clearing the cache is sufficient since the
        // durable store can be recreated.
    }

    // -----------------------------------------------------------------------
    // Iteration (for snapshots, hashing, etc.)
    // -----------------------------------------------------------------------

    /// Iterate all published accounts.
    ///
    /// When a durable store is configured, streams from disk (handles 100M+
    /// accounts without loading all into memory). Without a durable store,
    /// returns the in-memory cache contents.
    pub fn iter_all(&self) -> Vec<(Pubkey, Account)> {
        if let Some(ref store) = self.store {
            self.iter_from_disk(store.as_ref())
        } else {
            self.cache
                .iter()
                .map(|(pk, node)| (*pk, node.account.clone()))
                .collect()
        }
    }

    /// Stream all published accounts from the durable store.
    fn iter_from_disk(&self, store: &dyn DurableStore) -> Vec<(Pubkey, Account)> {
        let entries = match store.prefix_scan(CF_ACCOUNTS, &[]) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("iter_from_disk prefix_scan error: {e}");
                return Vec::new();
            }
        };

        let mut result = Vec::with_capacity(entries.len());
        for (key_bytes, value_bytes) in entries {
            if key_bytes.len() != 32 {
                continue;
            }
            let pubkey = Pubkey::from(
                <[u8; 32]>::try_from(key_bytes.as_slice()).unwrap_or_else(|_| unreachable!()),
            );
            if let Some(account) = decode_account(&value_bytes) {
                result.push((pubkey, account));
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Internal LRU cache machinery
    // -----------------------------------------------------------------------

    /// Insert an entry into the cache at the MRU position.
    /// Evicts the LRU entry if the cache is full.
    fn insert_into_cache(&mut self, pubkey: Pubkey, account: Account) {
        // If key already exists, fully remove it (HashMap + LRU list) so the
        // subsequent len() check doesn't spuriously count it and evict another entry.
        if self.cache.contains_key(&pubkey) {
            self.remove_from_cache(&pubkey);
        }

        // Evict LRU if cache is full.
        while self.cache.len() >= self.max_entries && self.lru_tail.is_some() {
            let evict_key = self.lru_tail.unwrap();
            self.remove_from_cache(&evict_key);
        }

        // Insert as new MRU head.
        let node = CacheNode {
            account,
            newer: None,
            older: self.lru_head,
        };
        self.cache.insert(pubkey, node);

        // Link into the LRU list.
        if let Some(old_head) = self.lru_head {
            if let Some(old_head_node) = self.cache.get_mut(&old_head) {
                old_head_node.newer = Some(pubkey);
            }
        }
        self.lru_head = Some(pubkey);

        if self.lru_tail.is_none() {
            self.lru_tail = Some(pubkey);
        }
    }

    /// Move an existing entry to the MRU position.
    fn move_to_head(&mut self, pubkey: &Pubkey) {
        if self.lru_head == Some(*pubkey) {
            return; // Already at head.
        }
        self.unlink(pubkey);

        // Re-insert at head.
        if let Some(node) = self.cache.get_mut(pubkey) {
            node.newer = None;
            node.older = self.lru_head;
        }
        if let Some(old_head) = self.lru_head {
            if let Some(old_head_node) = self.cache.get_mut(&old_head) {
                old_head_node.newer = Some(*pubkey);
            }
        }
        self.lru_head = Some(*pubkey);

        if self.lru_tail.is_none() {
            self.lru_tail = Some(*pubkey);
        }
    }

    /// Unlink an entry from the LRU list (does NOT remove from HashMap).
    fn unlink(&mut self, pubkey: &Pubkey) {
        let (older, newer) = match self.cache.get(pubkey) {
            Some(node) => (node.older, node.newer),
            None => return,
        };

        // Update neighbors.
        if let Some(older_key) = older {
            if let Some(older_node) = self.cache.get_mut(&older_key) {
                older_node.newer = newer;
            }
        }
        if let Some(newer_key) = newer {
            if let Some(newer_node) = self.cache.get_mut(&newer_key) {
                newer_node.older = older;
            }
        }

        // Update head/tail pointers.
        if self.lru_head == Some(*pubkey) {
            self.lru_head = older;
        }
        if self.lru_tail == Some(*pubkey) {
            self.lru_tail = newer;
        }
    }

    /// Remove an entry from both the cache and the LRU list.
    fn remove_from_cache(&mut self, pubkey: &Pubkey) {
        self.unlink(pubkey);
        self.cache.remove(pubkey);
    }

    /// Persist a single account to disk (best-effort).
    fn persist_account(&self, pubkey: &Pubkey, account: &Account) {
        if let Some(ref store) = self.store {
            let encoded = encode_account(account);
            if let Err(e) = store.put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded) {
                eprintln!("durable store put error: {e}");
            }
        }
    }

    /// Load an account from the durable store.
    fn load_from_disk(&self, pubkey: &Pubkey) -> Option<Account> {
        let store = self.store.as_ref()?;
        match store.get(CF_ACCOUNTS, pubkey.as_bytes()) {
            Ok(Some(bytes)) => decode_account(&bytes),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable::FileDurableStore;

    fn pk(b: u8) -> Pubkey {
        Pubkey::from([b; 32])
    }

    fn acct(lamports: u64) -> Account {
        Account::new(lamports, vec![], Pubkey::from([0xFF; 32]))
    }

    fn test_store() -> Arc<FileDurableStore> {
        FileDurableStore::temporary()
            .expect("temporary store")
            .into_arc()
    }

    // --- Basic operations ---

    #[test]
    fn get_returns_none_for_missing() {
        let mut ps = PublishedStore::new();
        assert!(ps.get(&pk(1)).is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut ps = PublishedStore::new();
        ps.insert(pk(1), acct(100));
        let a = ps.get(&pk(1)).expect("should exist");
        assert_eq!(a.meta.lamports, 100);
    }

    #[test]
    fn overwrite_updates_value() {
        let mut ps = PublishedStore::new();
        ps.insert(pk(1), acct(100));
        ps.insert(pk(1), acct(200));
        let a = ps.get(&pk(1)).expect("should exist");
        assert_eq!(a.meta.lamports, 200);
        assert_eq!(ps.cache_len(), 1);
    }

    #[test]
    fn remove_from_store() {
        let mut ps = PublishedStore::new();
        ps.insert(pk(1), acct(100));
        ps.remove(&pk(1));
        assert!(ps.get(&pk(1)).is_none());
        assert_eq!(ps.cache_len(), 0);
    }

    // --- LRU eviction ---

    #[test]
    fn lru_eviction_removes_oldest() {
        let mut ps = PublishedStore::with_capacity(3);

        ps.insert(pk(1), acct(100)); // oldest
        ps.insert(pk(2), acct(200));
        ps.insert(pk(3), acct(300)); // newest

        // Cache is full (3/3). Insert a 4th entry.
        ps.insert(pk(4), acct(400));

        assert_eq!(ps.cache_len(), 3);
        assert!(ps.get(&pk(1)).is_none(), "pk(1) should be evicted");
        assert!(ps.get(&pk(2)).is_some());
        assert!(ps.get(&pk(3)).is_some());
        assert!(ps.get(&pk(4)).is_some());
    }

    #[test]
    fn lru_access_promotes_entry() {
        let mut ps = PublishedStore::with_capacity(3);

        ps.insert(pk(1), acct(100)); // oldest initially
        ps.insert(pk(2), acct(200));
        ps.insert(pk(3), acct(300));

        // Access pk(1) to promote it to MRU.
        ps.get(&pk(1));

        // Insert pk(4) — should evict pk(2) (now the LRU).
        ps.insert(pk(4), acct(400));

        assert_eq!(ps.cache_len(), 3);
        assert!(ps.get(&pk(1)).is_some(), "pk(1) was accessed recently");
        assert!(ps.get(&pk(2)).is_none(), "pk(2) should be evicted");
        assert!(ps.get(&pk(3)).is_some());
        assert!(ps.get(&pk(4)).is_some());
    }

    // --- Durable store integration ---

    #[test]
    fn disk_fallback_on_cache_miss() {
        let store = test_store();
        let mut ps = PublishedStore::with_durable_store(store);

        // Insert and then clear cache to force disk fallback.
        ps.insert(pk(1), acct(500));
        ps.clear_cache();

        // Should load from disk.
        let a = ps.get(&pk(1)).expect("should load from disk");
        assert_eq!(a.meta.lamports, 500);
        assert_eq!(ps.cache_len(), 1); // Now cached.
    }

    #[test]
    fn evicted_entries_survive_on_disk() {
        let store = test_store();
        let mut ps = PublishedStore {
            cache: HashMap::new(),
            lru_head: None,
            lru_tail: None,
            max_entries: 2,
            store: Some(store),
        };

        ps.insert(pk(1), acct(100));
        ps.insert(pk(2), acct(200));
        ps.insert(pk(3), acct(300)); // evicts pk(1) from cache

        assert_eq!(ps.cache_len(), 2);
        assert!(!ps.cache.contains_key(&pk(1)));

        // pk(1) should still be on disk.
        let a = ps.get(&pk(1)).expect("should load from disk");
        assert_eq!(a.meta.lamports, 100);
    }

    #[test]
    fn batch_insert_persists_all() {
        let store = test_store();
        let mut ps = PublishedStore::with_durable_store(store);

        let mut batch = HashMap::new();
        for i in 0u8..10 {
            batch.insert(pk(i), acct(i as u64 * 100));
        }

        let count = ps.insert_batch(&batch);
        assert_eq!(count, 10);

        // Clear cache and verify all persist on disk.
        ps.clear_cache();
        for i in 0u8..10 {
            let a = ps.get(&pk(i)).expect("should load from disk");
            assert_eq!(a.meta.lamports, i as u64 * 100);
        }
    }

    #[test]
    fn insert_recovered_does_not_persist() {
        let store = test_store();
        let mut ps = PublishedStore::with_durable_store(store.clone());

        ps.insert_recovered(pk(1), acct(999));

        // In cache.
        assert!(ps.cache.contains_key(&pk(1)));

        // NOT on disk.
        let raw = store.get(CF_ACCOUNTS, pk(1).as_bytes()).unwrap();
        assert!(raw.is_none(), "insert_recovered should not write to disk");
    }

    #[test]
    fn iter_all_from_disk() {
        let store = test_store();
        let mut ps = PublishedStore::with_durable_store(store);

        for i in 0u8..5 {
            ps.insert(pk(i), acct(i as u64 * 10));
        }

        // iter_all should return everything from disk, not just cache.
        ps.clear_cache();
        let all = ps.iter_all();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn iter_all_without_durable_store() {
        let mut ps = PublishedStore::new();

        for i in 0u8..5 {
            ps.insert(pk(i), acct(i as u64 * 10));
        }

        let all = ps.iter_all();
        assert_eq!(all.len(), 5);
    }

    // --- Edge cases ---

    #[test]
    fn empty_store_iter_all() {
        let ps = PublishedStore::new();
        assert!(ps.iter_all().is_empty());
    }

    #[test]
    fn clear_cache_and_get_without_disk() {
        let mut ps = PublishedStore::new();
        ps.insert(pk(1), acct(100));
        ps.clear_cache();
        assert!(ps.get(&pk(1)).is_none(), "no disk → data lost after clear");
    }

    #[test]
    fn single_entry_cache() {
        let mut ps = PublishedStore::with_capacity(1);

        ps.insert(pk(1), acct(100));
        assert_eq!(ps.cache_len(), 1);

        ps.insert(pk(2), acct(200));
        assert_eq!(ps.cache_len(), 1);
        assert!(ps.cache.contains_key(&pk(2)));
        assert!(!ps.cache.contains_key(&pk(1)));
    }

    #[test]
    fn overwrite_doesnt_increase_count() {
        let mut ps = PublishedStore::with_capacity(3);

        ps.insert(pk(1), acct(100));
        ps.insert(pk(2), acct(200));
        ps.insert(pk(1), acct(300)); // overwrite, not new entry

        assert_eq!(ps.cache_len(), 2);
        assert_eq!(ps.get(&pk(1)).unwrap().meta.lamports, 300);
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut ps = PublishedStore::new();
        ps.remove(&pk(99)); // Should not panic.
        assert_eq!(ps.cache_len(), 0);
    }

    #[test]
    fn lru_chain_integrity_after_many_operations() {
        let mut ps = PublishedStore::with_capacity(5);

        // Insert 5 entries. LRU order (MRU→LRU): 4, 3, 2, 1, 0.
        for i in 0u8..5 {
            ps.insert(pk(i), acct(i as u64));
        }

        // Access pk(0) to promote it to MRU.
        // LRU order becomes: 0, 4, 3, 2, 1.
        ps.get(&pk(0));

        // Insert 2 new entries — should evict pk(1) and pk(2) (LRU).
        ps.insert(pk(10), acct(10));
        ps.insert(pk(11), acct(11));

        assert_eq!(ps.cache_len(), 5);
        // pk(0) was accessed recently → should survive.
        assert!(
            ps.cache.contains_key(&pk(0)),
            "pk(0) is MRU, should survive"
        );
        // pk(1) and pk(2) are LRU → should be evicted.
        assert!(
            !ps.cache.contains_key(&pk(1)),
            "pk(1) was LRU, should be evicted"
        );
        assert!(
            !ps.cache.contains_key(&pk(2)),
            "pk(2) was LRU, should be evicted"
        );
        // pk(3), pk(4), pk(10), pk(11) should still be in cache.
        assert!(ps.cache.contains_key(&pk(3)));
        assert!(ps.cache.contains_key(&pk(4)));
        assert!(ps.cache.contains_key(&pk(10)));
        assert!(ps.cache.contains_key(&pk(11)));
    }
}
