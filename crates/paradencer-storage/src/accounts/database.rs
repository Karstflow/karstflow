use super::primitives::{Account, Pubkey};
use super::record::{AccountRecord, RecordKey, TransactionId, VersionCounter};
use crate::StorageError;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use ahash::AHasher;
use std::hash::{Hash, Hasher};

pub struct AccountDatabase {
    records: Arc<DashMap<RecordKey, AccountRecord>>,
    versions: Arc<VersionCounter>,
    account_cache: Arc<DashMap<Pubkey, (Account, u64)>>,
}

impl AccountDatabase {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::with_capacity(capacity)),
            versions: Arc::new(VersionCounter::new()),
            account_cache: Arc::new(DashMap::with_capacity(capacity / 10)),
        }
    }

    pub fn read_account(
        &self,
        xid: TransactionId,
        pubkey: &Pubkey,
    ) -> Result<Option<Account>, StorageError> {
        // Check cache first for published accounts
        if xid.is_root() {
            if let Some(entry) = self.account_cache.get(pubkey) {
                return Ok(Some(entry.0.clone()));
            }
        }

        let key = RecordKey::new(xid, *pubkey);

        if let Some(entry) = self.records.get(&key) {
            return Ok(Some(entry.account.clone()));
        }

        if !xid.is_root() {
            let published_key = RecordKey::published(*pubkey);
            if let Some(entry) = self.records.get(&published_key) {
                let account = entry.account.clone();
                // Update cache
                self.account_cache.insert(*pubkey, (account.clone(), entry.version));
                return Ok(Some(account));
            }
        }

        Ok(None)
    }

    pub fn write_account(
        &self,
        xid: TransactionId,
        pubkey: Pubkey,
        account: Account,
    ) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotModifyPublished);
        }

        let version = self.versions.next();
        let key = RecordKey::new(xid, pubkey);
        let record = AccountRecord::new(xid, pubkey, account, version);

        self.records.insert(key, record);
        Ok(())
    }

    pub fn publish_transaction(&self, xid: TransactionId) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotPublishRoot);
        }

        let mut published_updates = Vec::new();

        for entry in self.records.iter() {
            if entry.key().xid == xid {
                let pubkey = entry.key().pubkey;
                let account = entry.value().account.clone();
                let version = self.versions.next();
                published_updates.push((pubkey, account, version));
            }
        }

        for (pubkey, account, version) in published_updates {
            let published_key = RecordKey::published(pubkey);
            let record = AccountRecord::new(TransactionId::root(), pubkey, account.clone(), version);
            self.records.insert(published_key, record);
            // Update cache
            self.account_cache.insert(pubkey, (account, version));
        }

        self.records.retain(|key, _| key.xid != xid);

        Ok(())
    }

    pub fn cancel_transaction(&self, xid: TransactionId) -> Result<(), StorageError> {
        if xid.is_root() {
            return Err(StorageError::CannotCancelRoot);
        }

        self.records.retain(|key, _| key.xid != xid);
        Ok(())
    }

    pub fn get_published_account(&self, pubkey: &Pubkey) -> Option<Account> {
        let key = RecordKey::published(*pubkey);
        self.records.get(&key).map(|entry| entry.account.clone())
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
        for (pubkey, account) in accounts {
            let version = self.versions.next();
            let published_key = RecordKey::published(pubkey);
            let record = AccountRecord::new(TransactionId::root(), pubkey, account.clone(), version);
            self.records.insert(published_key, record);
            self.account_cache.insert(pubkey, (account, version));
        }
        Ok(())
    }

    pub fn clear_all_accounts(&self) {
        self.records.clear();
        self.account_cache.clear();
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

    pub fn invalidate_cache(&self) {
        self.account_cache.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.account_cache.len()
    }

    pub fn compute_state_hash(&self) -> u64 {
        let mut hasher = AHasher::default();

        let mut published_accounts: Vec<_> = self.records
            .iter()
            .filter(|entry| entry.key().xid.is_root())
            .collect();

        published_accounts.sort_by_key(|entry| entry.key().pubkey.as_bytes());

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
        }
    }
}

impl std::fmt::Debug for AccountDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountDatabase")
            .field("records_count", &self.records.len())
            .field("version_counter", &self.versions)
            .finish()
    }
}
