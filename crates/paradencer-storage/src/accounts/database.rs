use super::fork_tree::ForkTree;
use super::owner_index::OwnerIndex;
use super::primitives::{Account, Pubkey};
use super::published_store::PublishedStore;
use super::record::{AccountRecord, RecordKey, TransactionId, VersionCounter};
use crate::durable::DurableStore;
use crate::StorageError;
use ahash::AHasher;
use dashmap::DashMap;
use paradencer_constants::durable_store::ACCOUNTS_HASH_FANOUT;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

/// Account database with fork-aware transaction tree.
///
/// Supports speculative execution across competing forks: each fork
/// is a transaction that inherits state from its parent. Reading an
/// account walks the ancestor chain until a record is found, then
/// falls back to published (root) state.
///
/// Publishing a transaction linearizes its entire ancestry chain,
/// merging all ancestor records into root and cancelling all
/// competing branches.
///
/// Published (root) accounts live in a bounded LRU cache backed by
/// persistent storage. Only transaction (in-preparation) records are
/// kept in the in-memory DashMap. This design scales to hundreds of
/// millions of accounts without proportional memory growth.
pub struct AccountDatabase {
    /// In-preparation transaction records only (no published records).
    records: Arc<DashMap<RecordKey, AccountRecord>>,
    versions: Arc<VersionCounter>,
    /// Bounded LRU cache + disk backend for published (root) accounts.
    published: Arc<Mutex<PublishedStore>>,
    fork_tree: Arc<RwLock<ForkTree>>,
    owner_index: Arc<OwnerIndex>,
    /// Tracks which pubkeys were modified at each slot (for incremental snapshots).
    dirty_set: Arc<RwLock<HashMap<u64, HashSet<Pubkey>>>>,
    /// Per-transaction record index: maps transaction ID → set of pubkeys
    /// modified in that transaction. Enables O(n_changed) publish/cancel
    /// instead of scanning the entire record map.
    txn_records: Arc<DashMap<TransactionId, HashSet<Pubkey>>>,
    /// Cached ancestor chains per transaction. Avoids repeated fork tree lock
    /// acquisitions when reading accounts from the same fork. Invalidated
    /// whenever the fork tree structure changes (prepare/publish/cancel).
    ancestor_cache: Arc<DashMap<TransactionId, Vec<TransactionId>>>,
}

impl AccountDatabase {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            published: Arc::new(Mutex::new(PublishedStore::new())),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            dirty_set: Arc::new(RwLock::new(HashMap::new())),
            txn_records: Arc::new(DashMap::new()),
            ancestor_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::with_capacity(capacity)),
            versions: Arc::new(VersionCounter::new()),
            published: Arc::new(Mutex::new(PublishedStore::with_capacity(capacity))),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            dirty_set: Arc::new(RwLock::new(HashMap::new())),
            txn_records: Arc::new(DashMap::new()),
            ancestor_cache: Arc::new(DashMap::new()),
        }
    }

    /// Create an AccountDatabase backed by persistent storage.
    ///
    /// Published account records are written to disk when transactions
    /// are published or accounts are stored directly. On read, if an
    /// account is not found in the cache, the durable store is queried
    /// as fallback.
    pub fn with_durable_store(store: Arc<dyn DurableStore>) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            published: Arc::new(Mutex::new(PublishedStore::with_durable_store(store))),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            dirty_set: Arc::new(RwLock::new(HashMap::new())),
            txn_records: Arc::new(DashMap::new()),
            ancestor_cache: Arc::new(DashMap::new()),
        }
    }

    /// Record a pubkey as modified at the given slot.
    #[inline]
    fn mark_dirty(&self, pubkey: Pubkey, slot: u64) {
        self.dirty_set
            .write()
            .unwrap()
            .entry(slot)
            .or_default()
            .insert(pubkey);
    }

    // -----------------------------------------------------------------------
    // Fork-aware transaction lifecycle
    // -----------------------------------------------------------------------

    /// Prepare a new transaction forked from `parent`.
    ///
    /// The child transaction inherits all state from the parent chain
    /// via copy-on-write semantics. Reads in the child first check the
    /// child's own records, then walk up to parent, grandparent, etc.
    pub fn prepare_transaction(
        &self,
        parent: TransactionId,
        child: TransactionId,
    ) -> Result<(), StorageError> {
        let mut tree = self.fork_tree.write().unwrap();
        tree.prepare(parent, child)
            .map_err(|e| StorageError::AccountDatabaseError {
                details: e.to_string(),
            })?;
        drop(tree);
        // Invalidate ancestor cache — tree structure changed.
        self.ancestor_cache.clear();
        Ok(())
    }

    /// Read an account, walking the ancestor chain.
    ///
    /// Lookup order: xid records → parent records → ... → published (root).
    /// This provides copy-on-write semantics: a child fork sees parent
    /// state unless it has written its own version.
    pub fn read_account(
        &self,
        xid: TransactionId,
        pubkey: &Pubkey,
    ) -> Result<Option<Account>, StorageError> {
        // Root reads go directly through the published store (cache + disk).
        if xid.is_root() {
            return Ok(self.published.lock().get(pubkey));
        }

        // Walk ancestor chain: check xid, then parent, grandparent, etc.
        // Use cached chain when available to avoid fork tree lock acquisition.
        let ancestors = if let Some(cached) = self.ancestor_cache.get(&xid) {
            cached.clone()
        } else {
            let tree = self.fork_tree.read().unwrap();
            let chain = tree.ancestors(xid);
            drop(tree);
            self.ancestor_cache.insert(xid, chain.clone());
            chain
        };

        for ancestor in &ancestors {
            let key = RecordKey::new(*ancestor, *pubkey);
            if let Some(entry) = self.records.get(&key) {
                return Ok(Some(entry.account.clone()));
            }
        }

        // Fall back to published (root) state (cache + disk).
        Ok(self.published.lock().get(pubkey))
    }

    /// Write an account within a transaction context.
    ///
    /// If the transaction is registered in the fork tree and is frozen
    /// (has children), the write is rejected.
    pub fn write_account(
        &self,
        xid: TransactionId,
        pubkey: Pubkey,
        account: Account,
    ) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotModifyPublished);
        }

        // Check frozen status (transactions with children are immutable).
        let tree = self.fork_tree.read().unwrap();
        if tree.is_frozen(xid) {
            return Err(StorageError::TransactionFrozen);
        }
        drop(tree);

        let version = self.versions.next();
        let key = RecordKey::new(xid, pubkey);
        let record = AccountRecord::new(xid, pubkey, account, version);
        self.records.insert(key, record);
        self.txn_records.entry(xid).or_default().insert(pubkey);
        Ok(())
    }

    /// Publish a transaction, linearizing its entire ancestry chain.
    ///
    /// All records from the transaction and its ancestors are merged
    /// into published (root) state. Child records override parent records
    /// for the same key. All competing branches (siblings and their
    /// descendants) are cancelled.
    pub fn publish_transaction(&self, xid: TransactionId) -> Result<(), StorageError> {
        self.publish_transaction_at_slot(xid, 0)
    }

    /// Publish a transaction into published state, recording dirty pubkeys at the given slot.
    pub fn publish_transaction_at_slot(
        &self,
        xid: TransactionId,
        slot: u64,
    ) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotPublishRoot);
        }

        let mut tree = self.fork_tree.write().unwrap();

        // Get ancestor chain (xid first, then parent, grandparent, ...).
        let chain = tree.ancestors(xid);

        // Collect competing branches to cancel.
        let competitors = tree.competing_branches(xid);

        // Merge records from chain into published state.
        // Walk from oldest ancestor to newest (xid) so child overrides parent.
        let mut published_updates: HashMap<Pubkey, Account> = HashMap::new();
        for &ancestor in chain.iter().rev() {
            if let Some(pubkeys) = self.txn_records.get(&ancestor) {
                for pubkey in pubkeys.value() {
                    let key = RecordKey::new(ancestor, *pubkey);
                    if let Some(entry) = self.records.get(&key) {
                        published_updates.insert(*pubkey, entry.account.clone());
                    }
                }
            }
        }

        // Update owner index and merge into published store.
        {
            let mut published = self.published.lock();
            for (pubkey, account) in &published_updates {
                let old_lamports = published.get(pubkey).map(|a| a.meta.lamports);
                self.owner_index.upsert(
                    *pubkey,
                    account.meta.owner,
                    account.meta.lamports,
                    0,
                    old_lamports,
                );
            }
            published.insert_batch(&published_updates);
        }

        // Mark all published pubkeys as dirty at this slot.
        {
            let mut dirty = self.dirty_set.write().unwrap();
            let set = dirty.entry(slot).or_default();
            for pubkey in published_updates.keys() {
                set.insert(*pubkey);
            }
        }

        // Remove records from published chain and competitors using targeted lookup.
        // O(n_changed) instead of O(total_records).
        let all_txns_to_remove: Vec<TransactionId> = chain
            .iter()
            .copied()
            .chain(competitors.iter().copied())
            .collect();
        for txn_id in &all_txns_to_remove {
            if let Some((_, pubkeys)) = self.txn_records.remove(txn_id) {
                for pubkey in pubkeys {
                    self.records.remove(&RecordKey::new(*txn_id, pubkey));
                }
            }
        }

        // Clean up tree.
        for &c in &competitors {
            tree.remove(c);
        }
        tree.remove_chain(&chain);
        drop(tree);

        // Invalidate ancestor cache — tree structure changed.
        self.ancestor_cache.clear();

        Ok(())
    }

    /// Cancel a transaction and all its descendants.
    ///
    /// All records belonging to the cancelled transactions are removed.
    pub fn cancel_transaction(&self, xid: TransactionId) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotCancelRoot);
        }

        let mut tree = self.fork_tree.write().unwrap();
        let descendants = tree.descendants(xid);

        // Collect all xids to remove: xid + descendants.
        let mut to_remove: Vec<TransactionId> = descendants;
        to_remove.push(xid);

        // Targeted removal: O(n_changed) instead of scanning entire record map.
        for txn_id in &to_remove {
            if let Some((_, pubkeys)) = self.txn_records.remove(txn_id) {
                for pubkey in pubkeys {
                    self.records.remove(&RecordKey::new(*txn_id, pubkey));
                }
            }
        }

        tree.remove(xid);
        drop(tree);

        // Invalidate ancestor cache — tree structure changed.
        self.ancestor_cache.clear();

        Ok(())
    }

    /// Number of in-preparation transactions in the fork tree.
    pub fn fork_count(&self) -> usize {
        self.fork_tree.read().unwrap().transaction_count()
    }

    /// Check if a transaction exists in the fork tree.
    pub fn has_fork(&self, xid: TransactionId) -> bool {
        self.fork_tree.read().unwrap().contains(xid)
    }

    /// Check if a transaction is frozen (has children).
    pub fn is_frozen(&self, xid: TransactionId) -> bool {
        self.fork_tree.read().unwrap().is_frozen(xid)
    }

    // -----------------------------------------------------------------------
    // Direct published-state operations (no fork tree involvement)
    // -----------------------------------------------------------------------

    pub fn get_published_account(&self, pubkey: &Pubkey) -> Option<Account> {
        self.published.lock().get(pubkey)
    }

    /// Store an account directly into published state.
    ///
    /// Used for protocol-level operations (e.g. epoch reward credits)
    /// that happen outside the normal transaction flow.
    pub fn store_published_account(&self, pubkey: Pubkey, account: Account) {
        self.store_published_account_at_slot(pubkey, account, 0);
    }

    /// Store an account into published state with slot tracking.
    pub fn store_published_account_at_slot(&self, pubkey: Pubkey, account: Account, slot: u64) {
        let old_lamports = {
            let mut published = self.published.lock();
            let old = published.get(&pubkey).map(|a| a.meta.lamports);
            published.insert(pubkey, account.clone());
            old
        };
        self.owner_index.upsert(
            pubkey,
            account.meta.owner,
            account.meta.lamports,
            slot,
            old_lamports,
        );
        self.mark_dirty(pubkey, slot);
    }

    /// Number of in-preparation transaction records in the DashMap.
    pub fn count_records(&self) -> usize {
        self.records.len()
    }

    pub fn count_transaction_records(&self, xid: TransactionId) -> usize {
        self.txn_records
            .get(&xid)
            .map(|entry| entry.value().len())
            .unwrap_or(0)
    }

    /// Iterate all published accounts from persistent storage.
    ///
    /// Streams accounts from the durable store without building a HashMap.
    /// Falls back to in-memory cache iteration when no durable store is configured.
    /// Prefer this over `get_all_published_accounts()` when key lookup is not needed.
    pub fn iter_published_accounts(&self) -> Vec<(Pubkey, Account)> {
        self.published.lock().iter_all()
    }

    /// Get all published accounts as a HashMap.
    ///
    /// Use `iter_published_accounts()` when key-based lookup is not needed,
    /// as it avoids building the HashMap.
    pub fn get_all_published_accounts(&self) -> HashMap<Pubkey, Account> {
        self.published.lock().iter_all().into_iter().collect()
    }

    pub fn bulk_insert_published_accounts(
        &self,
        accounts: HashMap<Pubkey, Account>,
    ) -> Result<(), StorageError> {
        self.bulk_insert_published_accounts_at_slot(accounts, 0)
    }

    /// Bulk insert with slot tracking.
    pub fn bulk_insert_published_accounts_at_slot(
        &self,
        accounts: HashMap<Pubkey, Account>,
        slot: u64,
    ) -> Result<(), StorageError> {
        {
            let mut published = self.published.lock();
            for (pubkey, account) in &accounts {
                self.owner_index.upsert(
                    *pubkey,
                    account.meta.owner,
                    account.meta.lamports,
                    slot,
                    None,
                );
            }
            published.insert_batch(&accounts);
        }

        // Mark all inserted pubkeys as dirty at this slot.
        {
            let mut dirty = self.dirty_set.write().unwrap();
            let set = dirty.entry(slot).or_default();
            for pubkey in accounts.keys() {
                set.insert(*pubkey);
            }
        }

        Ok(())
    }

    pub fn clear_all_accounts(&self) {
        self.records.clear();
        self.published.lock().clear_all();
        *self.fork_tree.write().unwrap() = ForkTree::new();
        self.owner_index.clear();
        self.dirty_set.write().unwrap().clear();
        self.txn_records.clear();
        self.ancestor_cache.clear();
    }

    /// Get the set of pubkeys modified at a specific slot.
    pub fn dirty_accounts_at_slot(&self, slot: u64) -> HashSet<Pubkey> {
        self.dirty_set
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .unwrap_or_default()
    }

    /// Get the total number of dirty pubkeys across all tracked slots.
    pub fn dirty_account_count(&self) -> usize {
        self.dirty_set
            .read()
            .unwrap()
            .values()
            .map(|set| set.len())
            .sum()
    }

    /// Drain dirty pubkeys for slots up to and including `max_slot`.
    ///
    /// Returns the union of all pubkeys from drained slots and removes
    /// those slots from tracking. Used after an incremental snapshot
    /// captures the delta.
    pub fn drain_dirty_slots_through(&self, max_slot: u64) -> HashSet<Pubkey> {
        let mut dirty = self.dirty_set.write().unwrap();
        let mut result = HashSet::new();
        let slots_to_drain: Vec<u64> = dirty.keys().filter(|&&s| s <= max_slot).copied().collect();
        for slot in slots_to_drain {
            if let Some(set) = dirty.remove(&slot) {
                result.extend(set);
            }
        }
        result
    }

    /// Get the range of slots with dirty tracking data.
    pub fn dirty_slot_range(&self) -> Option<(u64, u64)> {
        let dirty = self.dirty_set.read().unwrap();
        if dirty.is_empty() {
            return None;
        }
        let min = *dirty.keys().min().unwrap();
        let max = *dirty.keys().max().unwrap();
        Some((min, max))
    }

    /// Number of published accounts (O(1) via atomic counter).
    pub fn get_account_count(&self) -> usize {
        self.owner_index.total_accounts() as usize
    }

    /// Sum of lamports across all published accounts (O(1) via atomic counter).
    pub fn get_total_lamports(&self) -> u64 {
        self.owner_index.total_lamports()
    }

    // -----------------------------------------------------------------------
    // Owner index queries
    // -----------------------------------------------------------------------

    /// Get all published account pubkeys owned by a program.
    ///
    /// Uses the secondary owner index for O(k) lookups where k is the
    /// result set size, instead of scanning the entire database.
    pub fn get_accounts_by_owner(&self, owner: &Pubkey) -> Vec<(Pubkey, Account)> {
        self.owner_index
            .accounts_by_owner(owner)
            .into_iter()
            .filter_map(|pubkey| {
                self.get_published_account(&pubkey)
                    .map(|account| (pubkey, account))
            })
            .collect()
    }

    /// Get published account count from the index (O(1)).
    pub fn indexed_account_count(&self) -> u64 {
        self.owner_index.total_accounts()
    }

    /// Get total lamports from the index (O(1)).
    pub fn indexed_total_lamports(&self) -> u64 {
        self.owner_index.total_lamports()
    }

    /// Number of accounts owned by a specific program.
    pub fn accounts_owned_by(&self, owner: &Pubkey) -> usize {
        self.owner_index.accounts_owned_by(owner)
    }

    /// Number of distinct program owners in the index.
    pub fn owner_count(&self) -> usize {
        self.owner_index.owner_count()
    }

    /// Get the slot at which a published account was last modified.
    pub fn account_last_updated_slot(&self, pubkey: &Pubkey) -> Option<u64> {
        self.owner_index.last_updated_slot(pubkey)
    }

    /// Get all published accounts modified at or after a given slot.
    pub fn accounts_modified_since(&self, min_slot: u64) -> Vec<(Pubkey, Account)> {
        self.owner_index
            .accounts_modified_since(min_slot)
            .into_iter()
            .filter_map(|pubkey| {
                self.get_published_account(&pubkey)
                    .map(|account| (pubkey, account))
            })
            .collect()
    }

    pub fn invalidate_cache(&self) {
        self.published.lock().clear_cache();
    }

    pub fn cache_size(&self) -> usize {
        self.published.lock().cache_len()
    }

    /// Returns true if this database is backed by persistent storage.
    pub fn has_durable_store(&self) -> bool {
        self.published.lock().has_durable_store()
    }

    /// Insert an account from recovery (disk) without re-persisting to disk.
    ///
    /// Used during startup recovery to load accounts from the durable store
    /// into memory without writing them back out. Populates both the
    /// in-memory cache and the owner index.
    pub fn insert_recovered_account(&self, pubkey: Pubkey, account: Account) {
        self.published
            .lock()
            .insert_recovered(pubkey, account.clone());
        self.owner_index
            .upsert(pubkey, account.meta.owner, account.meta.lamports, 0, None);
    }

    /// Register a recovered account in the owner index only.
    ///
    /// Unlike `insert_recovered_account`, this does NOT populate the
    /// in-memory LRU cache. The account data lives on disk and will be
    /// loaded into the cache lazily on first access. This is the preferred
    /// path for parallel recovery at scale because:
    /// - The owner index uses DashMap (sharded, lock-free reads) and atomics,
    ///   so concurrent updates from multiple threads have minimal contention.
    /// - Skipping the PublishedStore Mutex avoids a serial bottleneck.
    /// - The LRU cache warms naturally during normal operation; pre-warming
    ///   it at startup wastes memory for accounts that won't be accessed soon.
    pub fn insert_recovered_index_only(&self, pubkey: Pubkey, account: &Account) {
        self.owner_index
            .upsert(pubkey, account.meta.owner, account.meta.lamports, 0, None);
    }

    pub fn compute_state_hash(&self) -> u64 {
        let mut hasher = AHasher::default();

        let mut published_accounts = self.published.lock().iter_all();
        published_accounts.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        for (pubkey, account) in &published_accounts {
            pubkey.hash(&mut hasher);
            account.meta.lamports.hash(&mut hasher);
            account.meta.owner.hash(&mut hasher);
            account.data.as_slice().hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Compute a SHA-256 Merkle hash over all published accounts.
    ///
    /// Each account is hashed as:
    ///   `SHA-256(lamports_le || rent_epoch_le || data || executable_byte || owner || pubkey)`
    ///
    /// All per-account hashes are sorted by pubkey and accumulated
    /// into a 16-way fanout Merkle hash. Accounts with zero lamports
    /// are excluded (matching the Solana protocol behavior).
    ///
    /// Returns `(hash, account_count)` where `account_count` is the
    /// number of non-zero-lamport accounts included.
    pub fn compute_accounts_hash(&self) -> ([u8; 32], usize) {
        use paradencer_crypto::sha256::Sha256StreamingHasher;

        let published_accounts = self.iter_published_accounts();

        // Compute per-account hashes, sorted by pubkey.
        let mut account_hashes: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (pubkey, account) in &published_accounts {
            if account.meta.lamports == 0 {
                continue;
            }
            let mut h = Sha256StreamingHasher::new();
            h.update(&account.meta.lamports.to_le_bytes());
            h.update(&account.meta.rent_epoch.to_le_bytes());
            h.update(account.data.as_ref());
            h.update(&[account.meta.executable as u8]);
            h.update(account.meta.owner.as_bytes());
            h.update(pubkey.as_bytes());
            account_hashes.push((*pubkey.as_bytes(), h.finalize()));
        }

        // Sort by pubkey bytes for deterministic ordering.
        account_hashes.sort_by(|a, b| a.0.cmp(&b.0));

        let count = account_hashes.len();

        if count == 0 {
            return ([0u8; 32], 0);
        }

        // 16-way fanout Merkle hash.
        let fanout = ACCOUNTS_HASH_FANOUT;
        let chunk_size = count.div_ceil(fanout);
        let mut chunk_hashes = Vec::with_capacity(fanout);

        for chunk in account_hashes.chunks(chunk_size.max(1)) {
            let mut h = Sha256StreamingHasher::new();
            for (_, account_hash) in chunk {
                h.update(account_hash);
            }
            chunk_hashes.push(h.finalize());
        }

        // Combine chunk hashes.
        let mut final_hash = Sha256StreamingHasher::new();
        for chunk_hash in &chunk_hashes {
            final_hash.update(chunk_hash);
        }

        (final_hash.finalize(), count)
    }
}

impl Default for AccountDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AccountDatabase {
    fn clone(&self) -> Self {
        Self {
            records: Arc::clone(&self.records),
            versions: Arc::clone(&self.versions),
            published: Arc::clone(&self.published),
            fork_tree: Arc::clone(&self.fork_tree),
            owner_index: Arc::clone(&self.owner_index),
            dirty_set: Arc::clone(&self.dirty_set),
            txn_records: Arc::clone(&self.txn_records),
            ancestor_cache: Arc::clone(&self.ancestor_cache),
        }
    }
}

impl std::fmt::Debug for AccountDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountDatabase")
            .field("records_count", &self.records.len())
            .field("version_counter", &self.versions)
            .field("fork_count", &self.fork_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable::account_encoding::{decode_account, encode_account};
    use crate::durable::FileDurableStore;
    use paradencer_constants::durable_store::CF_ACCOUNTS;

    fn test_store() -> Arc<dyn DurableStore> {
        FileDurableStore::temporary()
            .expect("temporary store")
            .into_arc()
    }

    // -----------------------------------------------------------------------
    // Basic persistence: new() without durable store (backward compat)
    // -----------------------------------------------------------------------

    #[test]
    fn new_without_durable_store() {
        let db = AccountDatabase::new();
        assert!(!db.has_durable_store());

        let pk = Pubkey::from([0x01; 32]);
        let acct = Account::new(100, vec![], Pubkey::from([0x02; 32]));
        db.store_published_account(pk, acct.clone());

        let read = db.get_published_account(&pk).expect("should exist");
        assert_eq!(read.meta.lamports, 100);
    }

    // -----------------------------------------------------------------------
    // store_published_account persists to disk
    // -----------------------------------------------------------------------

    #[test]
    fn store_published_persists_to_disk() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let pk = Pubkey::from([0xAA; 32]);
        let acct = Account::new(500, vec![1, 2, 3], Pubkey::from([0xBB; 32]));
        db.store_published_account(pk, acct);

        // Verify on disk directly.
        let raw = store
            .get(CF_ACCOUNTS, pk.as_bytes())
            .expect("get")
            .expect("should exist on disk");
        let decoded = decode_account(&raw).expect("decode");
        assert_eq!(decoded.meta.lamports, 500);
        assert_eq!(decoded.data.as_slice(), &[1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // publish_transaction persists to disk
    // -----------------------------------------------------------------------

    #[test]
    fn publish_transaction_persists_to_disk() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let xid = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid)
            .expect("prepare");

        let pk = Pubkey::from([0x01; 32]);
        let acct = Account::new(999, vec![0xFF; 8], Pubkey::from([0x02; 32]));
        db.write_account(xid, pk, acct).expect("write");

        db.publish_transaction(xid).expect("publish");

        // Verify persisted.
        let raw = store
            .get(CF_ACCOUNTS, pk.as_bytes())
            .expect("get")
            .expect("should exist on disk");
        let decoded = decode_account(&raw).expect("decode");
        assert_eq!(decoded.meta.lamports, 999);
    }

    // -----------------------------------------------------------------------
    // read_account falls back to disk
    // -----------------------------------------------------------------------

    #[test]
    fn read_account_disk_fallback() {
        let store = test_store();

        // Pre-populate disk with an account.
        let pk = Pubkey::from([0xCC; 32]);
        let acct = Account::new(777, vec![42], Pubkey::from([0xDD; 32]));
        let encoded = encode_account(&acct);
        store
            .put(CF_ACCOUNTS, pk.as_bytes(), &encoded)
            .expect("put");

        // Create a DB backed by the same store — no in-memory records.
        let db = AccountDatabase::with_durable_store(store);

        let read = db
            .read_account(TransactionId::root(), &pk)
            .expect("read")
            .expect("should find on disk");
        assert_eq!(read.meta.lamports, 777);
        assert_eq!(read.data.as_slice(), &[42]);

        // After fallback, should be in the published store's cache.
        assert!(db.cache_size() > 0);
    }

    // -----------------------------------------------------------------------
    // get_published_account falls back to disk
    // -----------------------------------------------------------------------

    #[test]
    fn get_published_account_disk_fallback() {
        let store = test_store();

        let pk = Pubkey::from([0xEE; 32]);
        let acct = Account::new(123, vec![], Pubkey::from([0xFF; 32]));
        store
            .put(CF_ACCOUNTS, pk.as_bytes(), &encode_account(&acct))
            .expect("put");

        let db = AccountDatabase::with_durable_store(store);
        let read = db.get_published_account(&pk).expect("should find");
        assert_eq!(read.meta.lamports, 123);
    }

    // -----------------------------------------------------------------------
    // cancel_transaction does NOT persist
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_transaction_does_not_persist() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let xid = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid)
            .expect("prepare");

        let pk = Pubkey::from([0x01; 32]);
        let acct = Account::new(999, vec![], Pubkey::from([0x02; 32]));
        db.write_account(xid, pk, acct).expect("write");

        db.cancel_transaction(xid).expect("cancel");

        // Should NOT be on disk.
        assert!(store
            .get(CF_ACCOUNTS, pk.as_bytes())
            .expect("get")
            .is_none());
    }

    // -----------------------------------------------------------------------
    // bulk_insert persists batch to disk
    // -----------------------------------------------------------------------

    #[test]
    fn bulk_insert_persists_to_disk() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let mut accounts = HashMap::new();
        for i in 0u8..5 {
            let pk = Pubkey::from([i; 32]);
            let acct = Account::new((i as u64 + 1) * 100, vec![], Pubkey::from([0xFF; 32]));
            accounts.insert(pk, acct);
        }

        db.bulk_insert_published_accounts_at_slot(accounts, 10)
            .expect("bulk insert");

        // Verify all on disk.
        for i in 0u8..5 {
            let pk = Pubkey::from([i; 32]);
            let raw = store
                .get(CF_ACCOUNTS, pk.as_bytes())
                .expect("get")
                .expect("should exist");
            let decoded = decode_account(&raw).expect("decode");
            assert_eq!(decoded.meta.lamports, (i as u64 + 1) * 100);
        }
    }

    // -----------------------------------------------------------------------
    // Overwrite in memory persists latest to disk
    // -----------------------------------------------------------------------

    #[test]
    fn overwrite_persists_latest() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let pk = Pubkey::from([0x01; 32]);
        let acct1 = Account::new(100, vec![], Pubkey::from([0x02; 32]));
        let acct2 = Account::new(200, vec![1], Pubkey::from([0x03; 32]));

        db.store_published_account(pk, acct1);
        db.store_published_account(pk, acct2);

        let raw = store
            .get(CF_ACCOUNTS, pk.as_bytes())
            .expect("get")
            .expect("should exist");
        let decoded = decode_account(&raw).expect("decode");
        assert_eq!(decoded.meta.lamports, 200);
        assert_eq!(decoded.meta.owner, Pubkey::from([0x03; 32]));
    }

    // -----------------------------------------------------------------------
    // Disk fallback for fork reads
    // -----------------------------------------------------------------------

    #[test]
    fn fork_read_falls_back_to_disk() {
        let store = test_store();

        // Pre-populate disk.
        let pk = Pubkey::from([0xAA; 32]);
        let acct = Account::new(555, vec![], Pubkey::from([0xBB; 32]));
        store
            .put(CF_ACCOUNTS, pk.as_bytes(), &encode_account(&acct))
            .expect("put");

        let db = AccountDatabase::with_durable_store(store);

        // Create a fork.
        let xid = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid)
            .expect("prepare");

        // Reading from fork should walk to root, then fall back to disk.
        let read = db
            .read_account(xid, &pk)
            .expect("read")
            .expect("should find");
        assert_eq!(read.meta.lamports, 555);
    }

    // -----------------------------------------------------------------------
    // Multiple publish transactions accumulate on disk
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_publishes_accumulate_on_disk() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        // First transaction.
        let xid1 = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid1)
            .expect("prepare");
        let pk1 = Pubkey::from([0x01; 32]);
        db.write_account(
            xid1,
            pk1,
            Account::new(100, vec![], Pubkey::from([0xFF; 32])),
        )
        .expect("write");
        db.publish_transaction(xid1).expect("publish");

        // Second transaction.
        let xid2 = TransactionId::from_slot(2);
        db.prepare_transaction(TransactionId::root(), xid2)
            .expect("prepare");
        let pk2 = Pubkey::from([0x02; 32]);
        db.write_account(
            xid2,
            pk2,
            Account::new(200, vec![], Pubkey::from([0xFF; 32])),
        )
        .expect("write");
        db.publish_transaction(xid2).expect("publish");

        // Both should be on disk.
        assert!(store
            .get(CF_ACCOUNTS, pk1.as_bytes())
            .expect("get")
            .is_some());
        assert!(store
            .get(CF_ACCOUNTS, pk2.as_bytes())
            .expect("get")
            .is_some());
        assert_eq!(store.count(CF_ACCOUNTS).expect("count"), 2);
    }

    // -----------------------------------------------------------------------
    // State hash consistency across persist + reload
    // -----------------------------------------------------------------------

    #[test]
    fn state_hash_consistent_after_reload() {
        let store = test_store();

        let pk1 = Pubkey::from([0x01; 32]);
        let pk2 = Pubkey::from([0x02; 32]);
        let acct1 = Account::new(100, vec![1, 2], Pubkey::from([0xFF; 32]));
        let acct2 = Account::new(200, vec![3, 4], Pubkey::from([0xEE; 32]));

        // Store and compute hash.
        let db1 = AccountDatabase::with_durable_store(store.clone());
        db1.store_published_account(pk1, acct1.clone());
        db1.store_published_account(pk2, acct2.clone());
        let hash1 = db1.compute_state_hash();

        // Reload into a fresh database.
        let db2 = AccountDatabase::new();
        db2.insert_recovered_account(pk1, acct1);
        db2.insert_recovered_account(pk2, acct2);
        let hash2 = db2.compute_state_hash();

        assert_eq!(hash1, hash2);
    }

    // -----------------------------------------------------------------------
    // Large batch persistence (1000 accounts)
    // -----------------------------------------------------------------------

    #[test]
    fn large_batch_persistence() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let mut accounts = HashMap::new();
        for i in 0u32..1000 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            let pk = Pubkey::from(bytes);
            let acct = Account::new(i as u64 * 10, vec![0u8; 64], Pubkey::from([0xFF; 32]));
            accounts.insert(pk, acct);
        }

        db.bulk_insert_published_accounts_at_slot(accounts, 0)
            .expect("bulk insert");

        assert_eq!(store.count(CF_ACCOUNTS).expect("count"), 1000);
    }

    // -----------------------------------------------------------------------
    // insert_recovered_account does NOT write to disk
    // -----------------------------------------------------------------------

    #[test]
    fn insert_recovered_does_not_persist() {
        let store = test_store();
        let db = AccountDatabase::with_durable_store(store.clone());

        let pk = Pubkey::from([0xAA; 32]);
        let acct = Account::new(100, vec![], Pubkey::from([0xBB; 32]));
        db.insert_recovered_account(pk, acct);

        // Should NOT be on disk.
        assert!(store
            .get(CF_ACCOUNTS, pk.as_bytes())
            .expect("get")
            .is_none());

        // But should be in memory.
        assert!(db.get_published_account(&pk).is_some());
    }

    // -----------------------------------------------------------------------
    // SHA-256 accounts hash
    // -----------------------------------------------------------------------

    #[test]
    fn accounts_hash_empty_db() {
        let db = AccountDatabase::new();
        let (hash, count) = db.compute_accounts_hash();
        assert_eq!(count, 0);
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn accounts_hash_deterministic() {
        let pk1 = Pubkey::from([0x01; 32]);
        let pk2 = Pubkey::from([0x02; 32]);
        let acct1 = Account::new(1000, vec![1, 2, 3], Pubkey::from([0xFF; 32]));
        let acct2 = Account::new(2000, vec![4, 5, 6], Pubkey::from([0xEE; 32]));

        // Two databases with same accounts should produce same hash.
        let db1 = AccountDatabase::new();
        db1.store_published_account(pk1, acct1.clone());
        db1.store_published_account(pk2, acct2.clone());

        let db2 = AccountDatabase::new();
        db2.store_published_account(pk1, acct1);
        db2.store_published_account(pk2, acct2);

        let (hash1, count1) = db1.compute_accounts_hash();
        let (hash2, count2) = db2.compute_accounts_hash();

        assert_eq!(hash1, hash2);
        assert_eq!(count1, 2);
        assert_eq!(count2, 2);
        // SHA-256 should produce a non-zero hash.
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn accounts_hash_excludes_zero_lamports() {
        let db = AccountDatabase::new();

        // Zero-lamport account should be excluded.
        let pk_zero = Pubkey::from([0x01; 32]);
        db.store_published_account(
            pk_zero,
            Account::new(0, vec![1, 2, 3], Pubkey::from([0xFF; 32])),
        );

        // Non-zero account should be included.
        let pk_nonzero = Pubkey::from([0x02; 32]);
        db.store_published_account(
            pk_nonzero,
            Account::new(1000, vec![4, 5, 6], Pubkey::from([0xFF; 32])),
        );

        let (hash, count) = db.compute_accounts_hash();
        assert_eq!(count, 1); // Only non-zero lamport account.
        assert_ne!(hash, [0u8; 32]);

        // Hash with zero-lamport only should equal empty hash.
        let db_zero_only = AccountDatabase::new();
        db_zero_only.store_published_account(
            pk_zero,
            Account::new(0, vec![1, 2, 3], Pubkey::from([0xFF; 32])),
        );
        let (hash_zero, count_zero) = db_zero_only.compute_accounts_hash();
        assert_eq!(count_zero, 0);
        assert_eq!(hash_zero, [0u8; 32]);
    }

    #[test]
    fn accounts_hash_different_data_different_hash() {
        let pk = Pubkey::from([0x42; 32]);

        let db1 = AccountDatabase::new();
        db1.store_published_account(pk, Account::new(1000, vec![1], Pubkey::from([0xFF; 32])));

        let db2 = AccountDatabase::new();
        db2.store_published_account(pk, Account::new(1000, vec![2], Pubkey::from([0xFF; 32])));

        let (hash1, _) = db1.compute_accounts_hash();
        let (hash2, _) = db2.compute_accounts_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn accounts_hash_insertion_order_independent() {
        let pk1 = Pubkey::from([0x01; 32]);
        let pk2 = Pubkey::from([0x02; 32]);
        let pk3 = Pubkey::from([0x03; 32]);
        let acct1 = Account::new(100, vec![1], Pubkey::from([0xAA; 32]));
        let acct2 = Account::new(200, vec![2], Pubkey::from([0xBB; 32]));
        let acct3 = Account::new(300, vec![3], Pubkey::from([0xCC; 32]));

        // Insert in forward order.
        let db_fwd = AccountDatabase::new();
        db_fwd.store_published_account(pk1, acct1.clone());
        db_fwd.store_published_account(pk2, acct2.clone());
        db_fwd.store_published_account(pk3, acct3.clone());

        // Insert in reverse order.
        let db_rev = AccountDatabase::new();
        db_rev.store_published_account(pk3, acct3);
        db_rev.store_published_account(pk2, acct2);
        db_rev.store_published_account(pk1, acct1);

        let (hash_fwd, _) = db_fwd.compute_accounts_hash();
        let (hash_rev, _) = db_rev.compute_accounts_hash();
        assert_eq!(hash_fwd, hash_rev);
    }

    // ── dirty set tracking tests ──────────────────────────────────────

    #[test]
    fn dirty_set_empty_by_default() {
        let db = AccountDatabase::new();
        assert_eq!(db.dirty_account_count(), 0);
        assert!(db.dirty_slot_range().is_none());
        assert!(db.dirty_accounts_at_slot(0).is_empty());
    }

    #[test]
    fn store_published_marks_dirty() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new_unique();
        let acct = Account::new(1000, vec![], Pubkey::from([1u8; 32]));
        db.store_published_account_at_slot(pk, acct, 42);

        assert_eq!(db.dirty_account_count(), 1);
        assert_eq!(db.dirty_slot_range(), Some((42, 42)));
        assert!(db.dirty_accounts_at_slot(42).contains(&pk));
        assert!(db.dirty_accounts_at_slot(0).is_empty());
    }

    #[test]
    fn store_published_no_slot_marks_at_zero() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new_unique();
        let acct = Account::new(1000, vec![], Pubkey::from([1u8; 32]));
        db.store_published_account(pk, acct);

        assert_eq!(db.dirty_account_count(), 1);
        assert!(db.dirty_accounts_at_slot(0).contains(&pk));
    }

    #[test]
    fn bulk_insert_marks_all_dirty() {
        let db = AccountDatabase::new();
        let mut accounts = HashMap::new();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let pk3 = Pubkey::new_unique();
        accounts.insert(pk1, Account::new(100, vec![], Pubkey::from([1u8; 32])));
        accounts.insert(pk2, Account::new(200, vec![], Pubkey::from([2u8; 32])));
        accounts.insert(pk3, Account::new(300, vec![], Pubkey::from([3u8; 32])));

        db.bulk_insert_published_accounts_at_slot(accounts, 10)
            .unwrap();

        assert_eq!(db.dirty_account_count(), 3);
        let dirty = db.dirty_accounts_at_slot(10);
        assert!(dirty.contains(&pk1));
        assert!(dirty.contains(&pk2));
        assert!(dirty.contains(&pk3));
    }

    #[test]
    fn publish_transaction_marks_dirty() {
        let db = AccountDatabase::new();
        let root = TransactionId::root();
        let xid = TransactionId::new([0x42; 16]);
        db.prepare_transaction(root, xid).unwrap();

        let pk = Pubkey::new_unique();
        let acct = Account::new(5000, vec![], Pubkey::from([0xAA; 32]));
        db.write_account(xid, pk, acct).unwrap();

        db.publish_transaction_at_slot(xid, 77).unwrap();

        assert_eq!(db.dirty_account_count(), 1);
        assert!(db.dirty_accounts_at_slot(77).contains(&pk));
    }

    #[test]
    fn dirty_set_tracks_multiple_slots() {
        let db = AccountDatabase::new();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();

        db.store_published_account_at_slot(
            pk1,
            Account::new(100, vec![], Pubkey::from([1u8; 32])),
            10,
        );
        db.store_published_account_at_slot(
            pk2,
            Account::new(200, vec![], Pubkey::from([2u8; 32])),
            20,
        );

        assert_eq!(db.dirty_account_count(), 2);
        assert_eq!(db.dirty_slot_range(), Some((10, 20)));
        assert_eq!(db.dirty_accounts_at_slot(10).len(), 1);
        assert_eq!(db.dirty_accounts_at_slot(20).len(), 1);
    }

    #[test]
    fn dirty_set_deduplicates_same_pubkey_same_slot() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new_unique();

        db.store_published_account_at_slot(
            pk,
            Account::new(100, vec![], Pubkey::from([1u8; 32])),
            5,
        );
        db.store_published_account_at_slot(
            pk,
            Account::new(200, vec![], Pubkey::from([1u8; 32])),
            5,
        );

        // Same pubkey at same slot should be counted once.
        assert_eq!(db.dirty_account_count(), 1);
        assert_eq!(db.dirty_accounts_at_slot(5).len(), 1);
    }

    #[test]
    fn drain_dirty_slots_removes_tracked_data() {
        let db = AccountDatabase::new();
        let pk1 = Pubkey::new_unique();
        let pk2 = Pubkey::new_unique();
        let pk3 = Pubkey::new_unique();

        db.store_published_account_at_slot(
            pk1,
            Account::new(100, vec![], Pubkey::from([1u8; 32])),
            10,
        );
        db.store_published_account_at_slot(
            pk2,
            Account::new(200, vec![], Pubkey::from([2u8; 32])),
            20,
        );
        db.store_published_account_at_slot(
            pk3,
            Account::new(300, vec![], Pubkey::from([3u8; 32])),
            30,
        );

        // Drain through slot 20 — should get pk1 and pk2.
        let drained = db.drain_dirty_slots_through(20);
        assert_eq!(drained.len(), 2);
        assert!(drained.contains(&pk1));
        assert!(drained.contains(&pk2));

        // Only slot 30 should remain.
        assert_eq!(db.dirty_account_count(), 1);
        assert_eq!(db.dirty_slot_range(), Some((30, 30)));
    }

    #[test]
    fn drain_all_dirty_slots() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new_unique();
        db.store_published_account_at_slot(
            pk,
            Account::new(100, vec![], Pubkey::from([1u8; 32])),
            5,
        );

        let drained = db.drain_dirty_slots_through(u64::MAX);
        assert_eq!(drained.len(), 1);
        assert_eq!(db.dirty_account_count(), 0);
        assert!(db.dirty_slot_range().is_none());
    }

    #[test]
    fn clear_all_accounts_clears_dirty_set() {
        let db = AccountDatabase::new();
        let pk = Pubkey::new_unique();
        db.store_published_account_at_slot(
            pk,
            Account::new(100, vec![], Pubkey::from([1u8; 32])),
            5,
        );
        assert_eq!(db.dirty_account_count(), 1);

        db.clear_all_accounts();
        assert_eq!(db.dirty_account_count(), 0);
    }

    // ── per-transaction record index tests ───────────────────────────

    #[test]
    fn publish_only_touches_changed_records() {
        let db = AccountDatabase::new();

        // Pre-populate 100 published accounts.
        for i in 0u8..100 {
            let pk = Pubkey::from([i; 32]);
            let acct = Account::new(i as u64 * 100, vec![], Pubkey::from([0xFF; 32]));
            db.store_published_account(pk, acct);
        }
        assert_eq!(db.get_account_count(), 100);

        // Create a fork that modifies only 3 accounts.
        let xid = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid).unwrap();

        let pk_a = Pubkey::from([0x01; 32]);
        let pk_b = Pubkey::from([0x02; 32]);
        let pk_c = Pubkey::from([0x03; 32]);
        db.write_account(
            xid,
            pk_a,
            Account::new(9999, vec![], Pubkey::from([0xAA; 32])),
        )
        .unwrap();
        db.write_account(
            xid,
            pk_b,
            Account::new(8888, vec![], Pubkey::from([0xBB; 32])),
        )
        .unwrap();
        db.write_account(
            xid,
            pk_c,
            Account::new(7777, vec![], Pubkey::from([0xCC; 32])),
        )
        .unwrap();

        assert_eq!(db.count_transaction_records(xid), 3);

        // Publish — should update only the 3 changed accounts.
        db.publish_transaction(xid).unwrap();

        // Verify the 3 changed accounts are updated.
        let a = db.get_published_account(&pk_a).unwrap();
        assert_eq!(a.meta.lamports, 9999);
        let b = db.get_published_account(&pk_b).unwrap();
        assert_eq!(b.meta.lamports, 8888);
        let c = db.get_published_account(&pk_c).unwrap();
        assert_eq!(c.meta.lamports, 7777);

        // Verify all other accounts are untouched.
        for i in 4u8..100 {
            let pk = Pubkey::from([i; 32]);
            let acct = db.get_published_account(&pk).unwrap();
            assert_eq!(acct.meta.lamports, i as u64 * 100);
        }

        // txn_records should be empty after publish.
        assert_eq!(db.count_transaction_records(xid), 0);
    }

    #[test]
    fn cancel_only_removes_changed_records() {
        let db = AccountDatabase::new();

        // Pre-populate 50 published accounts.
        for i in 0u8..50 {
            let pk = Pubkey::from([i; 32]);
            let acct = Account::new(i as u64 * 10, vec![], Pubkey::from([0xFF; 32]));
            db.store_published_account(pk, acct);
        }

        // Create a fork with 2 modified accounts.
        let xid = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid).unwrap();
        let pk_x = Pubkey::from([0xA0; 32]);
        let pk_y = Pubkey::from([0xB0; 32]);
        db.write_account(
            xid,
            pk_x,
            Account::new(111, vec![], Pubkey::from([0x01; 32])),
        )
        .unwrap();
        db.write_account(
            xid,
            pk_y,
            Account::new(222, vec![], Pubkey::from([0x02; 32])),
        )
        .unwrap();

        // Only transaction records in the DashMap (published are in the store).
        assert_eq!(db.count_records(), 2);

        // Cancel the fork.
        db.cancel_transaction(xid).unwrap();

        // All fork records removed.
        assert_eq!(db.count_records(), 0);
        assert_eq!(db.count_transaction_records(xid), 0);

        // Published accounts are intact.
        for i in 0u8..50 {
            let pk = Pubkey::from([i; 32]);
            assert!(db.get_published_account(&pk).is_some());
        }
    }

    #[test]
    fn publish_chain_with_overrides() {
        let db = AccountDatabase::new();
        let pk = Pubkey::from([0x42; 32]);

        // Root → slot 1: write before creating child.
        let xid1 = TransactionId::from_slot(1);
        db.prepare_transaction(TransactionId::root(), xid1).unwrap();
        db.write_account(
            xid1,
            pk,
            Account::new(100, vec![], Pubkey::from([0x01; 32])),
        )
        .unwrap();

        // slot 1 → slot 2: child overrides the same account.
        let xid2 = TransactionId::from_slot(2);
        db.prepare_transaction(xid1, xid2).unwrap();
        db.write_account(
            xid2,
            pk,
            Account::new(200, vec![], Pubkey::from([0x02; 32])),
        )
        .unwrap();

        // Publishing xid2 linearizes xid1→xid2; child (xid2) wins.
        db.publish_transaction(xid2).unwrap();

        let acct = db.get_published_account(&pk).unwrap();
        assert_eq!(acct.meta.lamports, 200);
        assert_eq!(acct.meta.owner, Pubkey::from([0x02; 32]));
    }

    #[test]
    fn ancestor_cache_avoids_repeated_fork_tree_lock() {
        let db = AccountDatabase::new();
        let pk = Pubkey::from([0x55; 32]);

        // Build chain: root → xid1 → xid2.
        let xid1 = TransactionId::from_slot(1);
        let xid2 = TransactionId::from_slot(2);
        db.prepare_transaction(TransactionId::root(), xid1).unwrap();
        db.write_account(
            xid1,
            pk,
            Account::new(100, vec![], Pubkey::from([0x01; 32])),
        )
        .unwrap();
        db.prepare_transaction(xid1, xid2).unwrap();

        // First read populates ancestor cache.
        let result = db.read_account(xid2, &pk).unwrap();
        assert_eq!(result.unwrap().meta.lamports, 100);

        // Verify cache is populated.
        assert!(db.ancestor_cache.get(&xid2).is_some());

        // Second read uses cache (no fork tree lock needed).
        let result2 = db.read_account(xid2, &pk).unwrap();
        assert_eq!(result2.unwrap().meta.lamports, 100);

        // Publishing invalidates cache.
        db.publish_transaction(xid2).unwrap();
        assert!(db.ancestor_cache.is_empty());
    }
}
