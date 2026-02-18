//! Entry Creator for Block Production
//!
//! This module creates entries from transactions using the PoH service.
//! It batches transactions together and manages tick generation.

use super::poh::{PohEntry, PohService, MAX_TRANSACTIONS_PER_ENTRY};
use paradencer_types::Hash;
use std::sync::{Arc, Mutex};

/// Configuration for entry creator
#[derive(Debug, Clone)]
pub struct EntryCreatorConfig {
    /// Maximum transactions per entry
    pub max_txs_per_entry: usize,

    /// Maximum bytes per entry
    pub max_bytes_per_entry: usize,

    /// Number of ticks between transaction entries
    pub ticks_per_slot: u64,
}

impl Default for EntryCreatorConfig {
    fn default() -> Self {
        Self {
            max_txs_per_entry: MAX_TRANSACTIONS_PER_ENTRY,
            max_bytes_per_entry: 1024 * 1024, // 1 MB
            ticks_per_slot: 64,
        }
    }
}

/// Entry creator for assembling transactions into entries
pub struct EntryCreator {
    /// PoH service (shared with producer)
    poh: Arc<Mutex<PohService>>,

    /// Configuration
    config: EntryCreatorConfig,

    /// Buffered transactions
    tx_buffer: Vec<Vec<u8>>,

    /// Buffered transaction bytes
    buffered_bytes: usize,

    /// Entries created
    entries_created: u64,
}

impl EntryCreator {
    /// Create a new entry creator
    pub fn new(poh: Arc<Mutex<PohService>>, config: EntryCreatorConfig) -> Self {
        Self {
            poh,
            config,
            tx_buffer: Vec::new(),
            buffered_bytes: 0,
            entries_created: 0,
        }
    }

    /// Create with default configuration
    pub fn with_poh(poh: Arc<Mutex<PohService>>) -> Self {
        Self::new(poh, EntryCreatorConfig::default())
    }

    /// Add a transaction to the buffer
    pub fn add_transaction(&mut self, tx: Vec<u8>) {
        self.buffered_bytes += tx.len();
        self.tx_buffer.push(tx);
    }

    /// Check if buffer is full and should be flushed
    pub fn should_flush(&self) -> bool {
        self.tx_buffer.len() >= self.config.max_txs_per_entry
            || self.buffered_bytes >= self.config.max_bytes_per_entry
    }

    /// Create an entry from buffered transactions
    pub fn create_entry(&mut self) -> Option<PohEntry> {
        if self.tx_buffer.is_empty() {
            return None;
        }

        let transactions = std::mem::take(&mut self.tx_buffer);
        self.buffered_bytes = 0;

        let mut poh = self.poh.lock().unwrap();
        let entry = poh.record(transactions);
        drop(poh);

        self.entries_created += 1;
        Some(entry)
    }

    /// Create an entry from specific transactions (bypasses buffer)
    pub fn create_entry_from(&mut self, transactions: Vec<Vec<u8>>) -> PohEntry {
        let mut poh = self.poh.lock().unwrap();
        let entry = poh.record(transactions);
        drop(poh);

        self.entries_created += 1;
        entry
    }

    /// Create a tick entry
    pub fn create_tick_entry(&mut self) -> PohEntry {
        let mut poh = self.poh.lock().unwrap();
        let entry = poh.tick();
        drop(poh);

        self.entries_created += 1;
        entry
    }

    /// Flush buffered transactions into an entry
    pub fn flush(&mut self) -> Option<PohEntry> {
        self.create_entry()
    }

    /// Get number of buffered transactions
    pub fn buffered_count(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Get buffered bytes
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Get number of entries created
    pub fn entries_created(&self) -> u64 {
        self.entries_created
    }

    /// Clear buffer without creating an entry
    pub fn clear_buffer(&mut self) {
        self.tx_buffer.clear();
        self.buffered_bytes = 0;
    }

    /// Get configuration
    pub fn config(&self) -> &EntryCreatorConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_poh() -> Arc<Mutex<PohService>> {
        Arc::new(Mutex::new(PohService::new(Hash::new_unique())))
    }

    #[test]
    fn test_entry_creator_creation() {
        let poh = create_test_poh();
        let creator = EntryCreator::with_poh(poh);

        assert_eq!(creator.buffered_count(), 0);
        assert_eq!(creator.buffered_bytes(), 0);
        assert_eq!(creator.entries_created(), 0);
    }

    #[test]
    fn test_add_transaction() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        let tx = vec![1, 2, 3, 4, 5];
        creator.add_transaction(tx.clone());

        assert_eq!(creator.buffered_count(), 1);
        assert_eq!(creator.buffered_bytes(), 5);
    }

    #[test]
    fn test_create_entry() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        creator.add_transaction(vec![1, 2, 3]);
        creator.add_transaction(vec![4, 5, 6]);

        let entry = creator.create_entry().unwrap();

        assert_eq!(entry.transactions.len(), 2);
        assert_eq!(creator.buffered_count(), 0);
        assert_eq!(creator.buffered_bytes(), 0);
        assert_eq!(creator.entries_created(), 1);
    }

    #[test]
    fn test_create_entry_empty_buffer() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        let entry = creator.create_entry();
        assert!(entry.is_none());
    }

    #[test]
    fn test_should_flush_by_count() {
        let poh = create_test_poh();
        let config = EntryCreatorConfig {
            max_txs_per_entry: 3,
            ..Default::default()
        };
        let mut creator = EntryCreator::new(poh, config);

        assert!(!creator.should_flush());

        creator.add_transaction(vec![1]);
        creator.add_transaction(vec![2]);
        assert!(!creator.should_flush());

        creator.add_transaction(vec![3]);
        assert!(creator.should_flush());
    }

    #[test]
    fn test_should_flush_by_bytes() {
        let poh = create_test_poh();
        let config = EntryCreatorConfig {
            max_bytes_per_entry: 10,
            ..Default::default()
        };
        let mut creator = EntryCreator::new(poh, config);

        creator.add_transaction(vec![1, 2, 3, 4, 5]);
        assert!(!creator.should_flush());

        creator.add_transaction(vec![6, 7, 8, 9, 10]);
        assert!(creator.should_flush()); // Total 10 bytes
    }

    #[test]
    fn test_create_tick_entry() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        let entry = creator.create_tick_entry();

        assert!(entry.is_tick());
        assert_eq!(creator.entries_created(), 1);
    }

    #[test]
    fn test_flush() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        creator.add_transaction(vec![1, 2, 3]);

        let entry = creator.flush().unwrap();
        assert_eq!(entry.transactions.len(), 1);
        assert_eq!(creator.buffered_count(), 0);
    }

    #[test]
    fn test_clear_buffer() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        creator.add_transaction(vec![1, 2, 3]);
        creator.add_transaction(vec![4, 5, 6]);

        creator.clear_buffer();

        assert_eq!(creator.buffered_count(), 0);
        assert_eq!(creator.buffered_bytes(), 0);
    }

    #[test]
    fn test_create_entry_from() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        // Add some transactions to buffer (should not be used)
        creator.add_transaction(vec![99, 99, 99]);

        let txs = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let entry = creator.create_entry_from(txs);

        assert_eq!(entry.transactions.len(), 2);
        // Buffer should still have the original transaction
        assert_eq!(creator.buffered_count(), 1);
    }

    #[test]
    fn test_multiple_entries() {
        let poh = create_test_poh();
        let mut creator = EntryCreator::with_poh(poh);

        creator.add_transaction(vec![1]);
        let entry1 = creator.create_entry().unwrap();

        creator.add_transaction(vec![2]);
        let entry2 = creator.create_entry().unwrap();

        // Entries should have different hashes
        assert_ne!(entry1.hash, entry2.hash);
        assert_eq!(creator.entries_created(), 2);
    }

    #[test]
    fn test_config_access() {
        let poh = create_test_poh();
        let config = EntryCreatorConfig {
            max_txs_per_entry: 100,
            max_bytes_per_entry: 2048,
            ticks_per_slot: 128,
        };
        let creator = EntryCreator::new(poh, config.clone());

        assert_eq!(creator.config().max_txs_per_entry, 100);
        assert_eq!(creator.config().max_bytes_per_entry, 2048);
        assert_eq!(creator.config().ticks_per_slot, 128);
    }
}
