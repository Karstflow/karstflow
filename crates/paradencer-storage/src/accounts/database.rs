use super::primitives::{Account, Pubkey};
use super::record::{AccountRecord, RecordKey, TransactionId, VersionCounter};
use crate::StorageError;
use dashmap::DashMap;
use std::sync::Arc;

pub struct AccountDatabase {
    records: Arc<DashMap<RecordKey, AccountRecord>>,
    versions: Arc<VersionCounter>,
}

impl AccountDatabase {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            versions: Arc::new(VersionCounter::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::with_capacity(capacity)),
            versions: Arc::new(VersionCounter::new()),
        }
    }

    pub fn read_account(
        &self,
        xid: TransactionId,
        pubkey: &Pubkey,
    ) -> Result<Option<Account>, StorageError> {
        let key = RecordKey::new(xid, *pubkey);

        if let Some(entry) = self.records.get(&key) {
            return Ok(Some(entry.account.clone()));
        }

        if !xid.is_root() {
            let published_key = RecordKey::published(*pubkey);
            if let Some(entry) = self.records.get(&published_key) {
                return Ok(Some(entry.account.clone()));
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
            let record = AccountRecord::new(TransactionId::root(), pubkey, account, version);
            self.records.insert(published_key, record);
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
