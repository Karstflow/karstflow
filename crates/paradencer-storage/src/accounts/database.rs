use super::fork_tree::ForkTree;
use super::owner_index::OwnerIndex;
use super::primitives::{Account, Pubkey};
use super::record::{AccountRecord, RecordKey, TransactionId, VersionCounter};
use crate::StorageError;
use ahash::AHasher;
use dashmap::DashMap;
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
}

impl AccountDatabase {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::new()),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::with_capacity(capacity)),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::with_capacity(capacity / 10)),
            fork_tree: Arc::new(RwLock::new(ForkTree::new())),
            owner_index: Arc::new(OwnerIndex::new()),
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
            return Ok(self.records.get(&key).map(|e| e.account.clone()));
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
        self.records.get(&key).map(|entry| entry.account.clone())
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
        for (pubkey, account) in accounts {
            let version = self.versions.next();
            let published_key = RecordKey::published(pubkey);
            let record =
                AccountRecord::new(TransactionId::root(), pubkey, account.clone(), version);
            self.records.insert(published_key, record);
            self.account_cache
                .insert(pubkey, (account.clone(), version));
            self.owner_index.upsert(
                pubkey,
                account.meta.owner,
                account.meta.lamports,
                slot,
                None,
            );
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
