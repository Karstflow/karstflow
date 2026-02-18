use super::fork_tree::ForkTree;
use super::owner_index::OwnerIndex;
use super::primitives::{Account, Pubkey};
use super::record::{AccountRecord, RecordKey, TransactionId, VersionCounter};
use crate::durable::account_encoding::{decode_account, encode_account};
use crate::durable::{DurableStore, WriteBatch};
use crate::StorageError;
use ahash::AHasher;
use dashmap::DashMap;
use paradencer_constants::durable_store::{ACCOUNTS_HASH_FANOUT, CF_ACCOUNTS};
use std::collections::HashMap;
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
pub struct AccountDatabase {
    records: Arc<DashMap<RecordKey, AccountRecord>>,
    versions: Arc<VersionCounter>,
    account_cache: Arc<DashMap<Pubkey, (Account, u64)>>,
    fork_tree: Arc<RwLock<ForkTree>>,
    owner_index: Arc<OwnerIndex>,
    durable_store: Option<Arc<dyn DurableStore>>,
}

impl AccountDatabase {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::new()),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            durable_store: None,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::with_capacity(capacity)),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::with_capacity(capacity / 10)),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            durable_store: None,
        }
    }

    /// Create an AccountDatabase backed by persistent storage.
    ///
    /// Published account records are written to disk when transactions
    /// are published or accounts are stored directly. On read, if an
    /// account is not found in memory, the durable store is queried
    /// as fallback.
    pub fn with_durable_store(store: Arc<dyn DurableStore>) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::new()),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
            durable_store: Some(store),
        }
    }

    /// Persist a single account to the durable store (if configured).
    #[inline]
    fn persist_account(&self, pubkey: &Pubkey, account: &Account) {
        if let Some(ref store) = self.durable_store {
            let encoded = encode_account(account);
            // Best-effort persist — log errors but don't propagate to callers.
            if let Err(e) = store.put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded) {
                eprintln!("durable store put error: {e}");
            }
        }
    }

    /// Load an account from the durable store (if configured).
    fn load_from_disk(&self, pubkey: &Pubkey) -> Option<Account> {
        let store = self.durable_store.as_ref()?;
        match store.get(CF_ACCOUNTS, pubkey.as_bytes()) {
            Ok(Some(bytes)) => decode_account(&bytes),
            _ => None,
        }
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
            })
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
        // Fast path: published (root) reads go through cache first.
        if xid.is_root() {
            if let Some(entry) = self.account_cache.get(pubkey) {
                return Ok(Some(entry.0.clone()));
            }
            let key = RecordKey::published(*pubkey);
            if let Some(entry) = self.records.get(&key) {
                return Ok(Some(entry.account.clone()));
            }
            // Disk fallback for root reads.
            if let Some(account) = self.load_from_disk(pubkey) {
                let version = self.versions.next();
                let published_key = RecordKey::published(*pubkey);
                let record =
                    AccountRecord::new(TransactionId::root(), *pubkey, account.clone(), version);
                self.records.insert(published_key, record);
                self.account_cache
                    .insert(*pubkey, (account.clone(), version));
                return Ok(Some(account));
            }
            return Ok(None);
        }

        // Walk ancestor chain: check xid, then parent, grandparent, etc.
        let tree = self.fork_tree.read().unwrap();
        let ancestors = tree.ancestors(xid);
        drop(tree);

        for ancestor in &ancestors {
            let key = RecordKey::new(*ancestor, *pubkey);
            if let Some(entry) = self.records.get(&key) {
                return Ok(Some(entry.account.clone()));
            }
        }

        // Fall back to published (root) state.
        let published_key = RecordKey::published(*pubkey);
        if let Some(entry) = self.records.get(&published_key) {
            let account = entry.account.clone();
            self.account_cache
                .insert(*pubkey, (account.clone(), entry.version));
            return Ok(Some(account));
        }

        // Final fallback: durable store (disk).
        if let Some(account) = self.load_from_disk(pubkey) {
            let version = self.versions.next();
            let record =
                AccountRecord::new(TransactionId::root(), *pubkey, account.clone(), version);
            self.records.insert(published_key, record);
            self.account_cache
                .insert(*pubkey, (account.clone(), version));
            return Ok(Some(account));
        }

        Ok(None)
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
        Ok(())
    }

    /// Publish a transaction, linearizing its entire ancestry chain.
    ///
    /// All records from the transaction and its ancestors are merged
    /// into published (root) state. Child records override parent records
    /// for the same key. All competing branches (siblings and their
    /// descendants) are cancelled.
    pub fn publish_transaction(&self, xid: TransactionId) -> Result<(), StorageError> {
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
        let mut published_updates: HashMap<Pubkey, (Account, u64)> = HashMap::new();
        for &ancestor in chain.iter().rev() {
            for entry in self.records.iter() {
                if entry.key().xid == ancestor {
                    let pubkey = entry.key().pubkey;
                    let account = entry.value().account.clone();
                    let version = self.versions.next();
                    published_updates.insert(pubkey, (account, version));
                }
            }
        }

        // Write merged records to published state and update owner index.
        // Build a durable write batch for all published updates.
        let mut batch = if self.durable_store.is_some() {
            Some(WriteBatch::new())
        } else {
            None
        };

        for (pubkey, (account, version)) in &published_updates {
            let old_lamports = self
                .records
                .get(&RecordKey::published(*pubkey))
                .map(|e| e.account.meta.lamports);
            let published_key = RecordKey::published(*pubkey);
            let record =
                AccountRecord::new(TransactionId::root(), *pubkey, account.clone(), *version);
            self.records.insert(published_key, record);
            self.account_cache
                .insert(*pubkey, (account.clone(), *version));
            self.owner_index.upsert(
                *pubkey,
                account.meta.owner,
                account.meta.lamports,
                0,
                old_lamports,
            );

            if let Some(ref mut b) = batch {
                let encoded = encode_account(account);
                // Silently drop if batch is full — extremely unlikely with 10k limit.
                let _ = b.put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded);
            }
        }

        // Flush batch to durable store.
        if let (Some(b), Some(ref store)) = (batch, &self.durable_store) {
            if !b.is_empty() {
                if let Err(e) = store.write_batch(&b) {
                    eprintln!("durable store batch write error: {e}");
                }
            }
        }

        // Remove all records from the published chain.
        let chain_set: std::collections::HashSet<TransactionId> = chain.iter().copied().collect();
        // Remove all records from competitors.
        let competitor_set: std::collections::HashSet<TransactionId> =
            competitors.iter().copied().collect();

        self.records
            .retain(|key, _| !chain_set.contains(&key.xid) && !competitor_set.contains(&key.xid));

        // Clean up tree.
        for &c in &competitors {
            tree.remove(c);
        }
        tree.remove_chain(&chain);

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
        let mut to_remove: std::collections::HashSet<TransactionId> =
            descendants.into_iter().collect();
        to_remove.insert(xid);

        self.records.retain(|key, _| !to_remove.contains(&key.xid));

        tree.remove(xid);

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
        let key = RecordKey::published(*pubkey);
        if let Some(entry) = self.records.get(&key) {
            return Some(entry.account.clone());
        }
        // Disk fallback: load from durable store and cache in memory.
        if let Some(account) = self.load_from_disk(pubkey) {
            let version = self.versions.next();
            let record =
                AccountRecord::new(TransactionId::root(), *pubkey, account.clone(), version);
            self.records.insert(key, record);
            self.account_cache
                .insert(*pubkey, (account.clone(), version));
            return Some(account);
        }
        None
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
        let old_lamports = self.get_published_account(&pubkey).map(|a| a.meta.lamports);
        let version = self.versions.next();
        let key = RecordKey::published(pubkey);
        let record = AccountRecord::new(TransactionId::root(), pubkey, account.clone(), version);
        self.records.insert(key, record);
        self.account_cache
            .insert(pubkey, (account.clone(), version));
        self.owner_index.upsert(
            pubkey,
            account.meta.owner,
            account.meta.lamports,
            slot,
            old_lamports,
        );
        self.persist_account(&pubkey, &account);
    }

    pub fn count_records(&self) -> usize {
        self.records.len()
    }

    pub fn count_transaction_records(&self, xid: TransactionId) -> usize {
        self.records
            .iter()
            .filter(|entry| entry.key().xid == xid)
            .count()
    }

    pub fn get_all_published_accounts(&self) -> HashMap<Pubkey, Account> {
        let mut accounts = HashMap::new();
        for entry in self.records.iter() {
            if entry.key().xid.is_root() {
                accounts.insert(entry.key().pubkey, entry.value().account.clone());
            }
        }
        accounts
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
        let mut batch = if self.durable_store.is_some() {
            Some(WriteBatch::new())
        } else {
            None
        };

        for (pubkey, account) in &accounts {
            let version = self.versions.next();
            let published_key = RecordKey::published(*pubkey);
            let record =
                AccountRecord::new(TransactionId::root(), *pubkey, account.clone(), version);
            self.records.insert(published_key, record);
            self.account_cache
                .insert(*pubkey, (account.clone(), version));
            self.owner_index.upsert(
                *pubkey,
                account.meta.owner,
                account.meta.lamports,
                slot,
                None,
            );

            if let Some(ref mut b) = batch {
                let encoded = encode_account(account);
                let _ = b.put(CF_ACCOUNTS, pubkey.as_bytes(), &encoded);
            }
        }

        // Flush batch to durable store.
        if let (Some(b), Some(ref store)) = (batch, &self.durable_store) {
            if !b.is_empty() {
                if let Err(e) = store.write_batch(&b) {
                    eprintln!("durable store batch write error: {e}");
                }
            }
        }

        Ok(())
    }

    pub fn clear_all_accounts(&self) {
        self.records.clear();
        self.account_cache.clear();
        *self.fork_tree.write().unwrap() = ForkTree::new();
        self.owner_index.clear();
    }

    pub fn get_account_count(&self) -> usize {
        self.records
            .iter()
            .filter(|entry| entry.key().xid.is_root())
            .count()
    }

    pub fn get_total_lamports(&self) -> u64 {
        self.records
            .iter()
            .filter(|entry| entry.key().xid.is_root())
            .map(|entry| entry.value().account.meta.lamports)
            .sum()
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
        self.account_cache.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.account_cache.len()
    }

    /// Returns true if this database is backed by persistent storage.
    pub fn has_durable_store(&self) -> bool {
        self.durable_store.is_some()
    }

    /// Insert an account from recovery (disk) without re-persisting to disk.
    ///
    /// Used during startup recovery to load accounts from the durable store
    /// into memory without writing them back out.
    pub fn insert_recovered_account(&self, pubkey: Pubkey, account: Account) {
        let version = self.versions.next();
        let key = RecordKey::published(pubkey);
        let record = AccountRecord::new(TransactionId::root(), pubkey, account.clone(), version);
        self.records.insert(key, record);
        self.account_cache
            .insert(pubkey, (account.clone(), version));
        self.owner_index
            .upsert(pubkey, account.meta.owner, account.meta.lamports, 0, None);
    }

    pub fn compute_state_hash(&self) -> u64 {
        let mut hasher = AHasher::default();

        let mut published_accounts: Vec<_> = self
            .records
            .iter()
            .filter(|entry| entry.key().xid.is_root())
            .collect();

        published_accounts.sort_by(|a, b| a.key().pubkey.as_bytes().cmp(b.key().pubkey.as_bytes()));

        for entry in published_accounts {
            entry.key().pubkey.hash(&mut hasher);
            entry.value().account.meta.lamports.hash(&mut hasher);
            entry.value().account.meta.owner.hash(&mut hasher);
            entry.value().account.data.as_slice().hash(&mut hasher);
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

        let published_accounts = self.get_all_published_accounts();

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
            account_cache: Arc::clone(&self.account_cache),
            fork_tree: Arc::clone(&self.fork_tree),
            owner_index: Arc::clone(&self.owner_index),
            durable_store: self.durable_store.clone(),
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

        // After fallback, should be in memory cache too.
        assert!(db.account_cache.contains_key(&pk));
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
}
